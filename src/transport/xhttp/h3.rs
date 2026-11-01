// SPDX-License-Identifier: MPL-2.0
// XHTTP HTTP/3 carrier, using h3 and Quinn with owned endpoint shutdown.
use super::{
    Error,
    config::Config,
    server::{Activity, Carrier, Service, Shared},
};
use crate::{
    buffer::BufferScope,
    network::Stream,
    task::CancellationToken,
    time::OperationContext,
    transport::{Accepted, Listener, Multiplexed, jobs::Jobs},
};
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
pub fn transport(c: &Config, server: bool) -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    // Quinn uses fixed receive windows; the initial window is a conservative
    // ceiling within the configured initial/max interval, without auto-growth.
    t.stream_receive_window(
        quinn::VarInt::from_u64(c.h3_initial_stream_receive_window as u64).expect("bounded window"),
    );
    t.receive_window(
        quinn::VarInt::from_u64(c.h3_initial_connection_receive_window as u64)
            .expect("bounded window"),
    );
    t.max_concurrent_bidi_streams(if server { 64u32.into() } else { 0u32.into() });
    t.max_concurrent_uni_streams(16u32.into());
    t.max_idle_timeout(Some(
        Duration::from_secs(300).try_into().expect("valid timeout"),
    ));
    if c.xmux.h_keep_alive_period > 0 {
        t.keep_alive_interval(Some(Duration::from_secs(c.xmux.h_keep_alive_period as u64)));
    }
    t.datagram_receive_buffer_size(None);
    t.send_window(1 << 20);
    t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Arc::new(t)
}
pub fn server_config(
    tls: Arc<rustls::ServerConfig>,
    c: &Config,
) -> Result<Arc<quinn::ServerConfig>, Error> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from((*tls).clone())
        .map_err(|_| Error::Tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport(c, true));
    Ok(Arc::new(config))
}
pub struct QuicListener(pub quinn::Endpoint);
#[async_trait]
impl Listener for QuicListener {
    fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.0.local_addr()?)
    }
    async fn accept(&self, _: &OperationContext) -> Result<(Stream, SocketAddr), Error> {
        Err(Error::Unsupported)
    }
    async fn accept_carrier(
        &self,
        context: &OperationContext,
    ) -> Result<(Accepted, SocketAddr), Error> {
        let incoming = context
            .run(self.0.accept())
            .await
            .map_err(Error::Stopped)?
            .ok_or(Error::Io(io::ErrorKind::NotConnected))?;
        let peer = incoming.remote_address();
        Ok((
            Accepted::Quic(Box::new(incoming)),
            crate::network::canonical_socket(peer),
        ))
    }
    async fn close(&self) {
        self.0.close(0u32.into(), b"shutdown");
        self.0.wait_idle().await;
    }
}
impl Drop for QuicListener {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"shutdown");
    }
}
struct ConnectionGuard(quinn::Connection);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"closed");
    }
}
struct ServerBody(h3::server::RequestStream<h3_quinn::RecvStream, Bytes>);
impl http_body::Body for ServerBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, io::Error>>> {
        match std::task::ready!(self.0.poll_recv_data(cx)) {
            Ok(Some(mut b)) => Poll::Ready(Some(Ok(http_body::Frame::data(
                b.copy_to_bytes(b.remaining()),
            )))),
            Ok(None) => Poll::Ready(None),
            Err(e) => Poll::Ready(Some(Err(io::Error::other(e)))),
        }
    }
}
pub async fn server(
    incoming: quinn::Incoming,
    config: Arc<quinn::ServerConfig>,
    scope: BufferScope,
    shared: Arc<Shared>,
    context: &OperationContext,
) -> Result<Box<dyn Multiplexed>, Error> {
    shared.start()?;
    let connection = context
        .run(incoming.accept_with(config).map_err(|_| Error::Tls)?)
        .await
        .map_err(Error::Stopped)?
        .map_err(|_| Error::Tls)?;
    let mut builder = h3::server::builder();
    builder.max_field_section_size(shared.config.server_max_header_bytes as u64);
    let mut http = builder
        .build(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|_| Error::Io(io::ErrorKind::InvalidData))?;
    let jobs = Arc::new(Jobs::new(128)?);
    let activity = Activity::new();
    let drain = CancellationToken::new();
    let (send, recv) = tokio::sync::mpsc::channel(crate::transport::MAX_MULTIPLEX_STREAMS);
    let service = Service {
        shared,
        scope,
        streams: send,
        activity: activity.clone(),
    };
    let drain_signal = drain.clone();
    let owned_jobs = jobs.clone();
    let cancel = jobs.cancel.clone();
    let drive = Box::pin(async move {
        let _guard = ConnectionGuard(connection);
        let mut draining = false;
        loop {
            let request = tokio::select! {
                _=cancel.cancelled()=>break,
                _=drain_signal.cancelled(),if !draining=>{draining=true;http.shutdown(0).await.map_err(|_|Error::Io(io::ErrorKind::ConnectionAborted))?;continue;},
                request=http.accept()=>request.map_err(|_|Error::Io(io::ErrorKind::ConnectionAborted))?,
            };
            let Some(request) = request else {
                break;
            };
            let service = service.clone();
            owned_jobs.spawn("xhttp.h3-request", move |cancel| async move {
                let result = async {
                    let (request, stream) =
                        request.resolve_request().await.map_err(io::Error::other)?;
                    let (mut send, recv) = stream.split();
                    let response = service
                        .handle(request.map(|_| ServerBody(recv).boxed_unsync()))
                        .await;
                    let (parts, mut body) = response.into_parts();
                    send.send_response(http::Response::from_parts(parts, ()))
                        .await
                        .map_err(io::Error::other)?;
                    while let Some(frame) = body.frame().await {
                        if let Ok(data) = frame?.into_data() {
                            send.send_data(data).await.map_err(io::Error::other)?;
                        }
                    }
                    send.finish().await.map_err(io::Error::other)
                };
                tokio::select! {_=cancel.cancelled()=>{},_=result=>{}}
                Ok(())
            })?;
        }
        owned_jobs.close().await;
        Ok(())
    });
    Ok(Box::new(Carrier::new(drive, recv, activity, drain, jobs)))
}

pub struct ClientBody(pub h3::client::RequestStream<h3_quinn::RecvStream, Bytes>);
impl http_body::Body for ClientBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, io::Error>>> {
        match std::task::ready!(self.0.poll_recv_data(cx)) {
            Ok(Some(mut b)) => Poll::Ready(Some(Ok(http_body::Frame::data(
                b.copy_to_bytes(b.remaining()),
            )))),
            Ok(None) => Poll::Ready(None),
            Err(e) => Poll::Ready(Some(Err(io::Error::other(e)))),
        }
    }
}

// Each attempt is owned by this future, with at most four UDP endpoints alive.
// Cancelling a losing handshake closes its endpoint through the guard.
struct DialEndpoint(Option<quinn::Endpoint>);
impl Drop for DialEndpoint {
    fn drop(&mut self) {
        if let Some(endpoint) = &self.0 {
            endpoint.close(0u32.into(), b"dial cancelled");
        }
    }
}
pub async fn dial(
    addresses: &[SocketAddr],
    name: &str,
    config: quinn::ClientConfig,
    context: &OperationContext,
) -> Result<(quinn::Endpoint, quinn::Connection, SocketAddr), Error> {
    use futures_util::{StreamExt, stream};
    if addresses.is_empty() || addresses.len() > 64 {
        return Err(Error::Configuration("XHTTP address count"));
    }
    let attempts = stream::iter(addresses.iter().copied().enumerate())
        .map(|(index, peer)| {
            let config = config.clone();
            async move {
                tokio::time::sleep(Duration::from_millis((index.min(3) * 100) as u64)).await;
                let bind = if peer.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let mut endpoint = quinn::Endpoint::client(bind.parse().expect("constant socket"))?;
                endpoint.set_default_client_config(config);
                let mut guard = DialEndpoint(Some(endpoint));
                let connecting = guard
                    .0
                    .as_ref()
                    .expect("dial endpoint")
                    .connect(peer, name)
                    .map_err(|_| Error::Tls)?;
                let result = tokio::time::timeout(Duration::from_secs(3), connecting).await;
                match result {
                    Ok(Ok(connection)) => {
                        Ok((guard.0.take().expect("dial endpoint"), connection, peer))
                    }
                    _ => {
                        let endpoint = guard.0.as_ref().expect("dial endpoint");
                        endpoint.close(0u32.into(), b"dial failed");
                        endpoint.wait_idle().await;
                        Err(Error::Tls)
                    }
                }
            }
        })
        .buffer_unordered(4);
    tokio::pin!(attempts);
    context
        .run(async {
            let mut error = Error::Tls;
            while let Some(result) = attempts.next().await {
                match result {
                    Ok(connected) => return Ok(connected),
                    Err(e) => error = e,
                }
            }
            Err(error)
        })
        .await
        .map_err(Error::Stopped)?
}
