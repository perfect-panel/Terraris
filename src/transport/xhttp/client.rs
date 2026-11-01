// SPDX-License-Identifier: MPL-2.0
// Ported from Polaris 56d52fb44958 XHTTP client/upload_client, Xray b17a88f9b46d.
use super::{
    Error,
    body::{self, Body},
    config::Config,
    pool::{self, Lease, Manager},
};
use crate::{
    buffer::{BufferLayout, BufferScope},
    network::{Stream, pipe::Pipe},
    task::CancellationToken,
    time::{Deadline, OperationContext},
    transport::{Factory, Outbound, Tcp},
};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{StreamExt, stream::FuturesUnordered};
use http_body_util::BodyExt;
use std::{
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub struct Client {
    config: Arc<Config>,
    upload: Arc<Manager>,
    download: Option<Arc<Manager>>,
    authority: String,
    download_authority: String,
    download_address: Option<(String, u16)>,
    resolver: Option<Arc<crate::dns::system::System>>,
}
impl Client {
    pub fn new(
        c: &crate::panel::Outbound,
        roots: Arc<rustls::ClientConfig>,
    ) -> Result<Self, Error> {
        let config = Arc::new(Config::parse(
            &c.host,
            &c.path,
            &c.xhttp_mode,
            &c.xhttp_extra,
        )?);
        let upload = manager(c, config.clone(), roots.clone())?;
        let authority = authority(c);
        let (mut download, mut download_authority, mut download_address) =
            (None, String::new(), None);
        if let Some(d) = &config.download {
            let mut endpoint = c.clone();
            endpoint.address = d.address.clone();
            endpoint.port = d.port;
            endpoint.security = d.security.clone();
            endpoint.sni = d.tls_settings.server_name.clone();
            endpoint.allow_insecure = d.tls_settings.allow_insecure;
            endpoint.alpn = d.tls_settings.alpn.clone();
            let cfg = d
                .xhttp
                .as_ref()
                .or(d.splithttp.as_ref())
                .expect("validated download settings");
            endpoint.host = cfg.host.clone();
            endpoint.path = cfg.path.clone();
            endpoint.xhttp_mode = cfg.mode.clone();
            endpoint.xhttp_extra.clear();
            download_authority = authority_for(&endpoint);
            download_address = Some((
                endpoint.address.trim_matches(['[', ']']).to_owned(),
                endpoint.port,
            ));
            download = Some(manager(&endpoint, Arc::new((**cfg).clone()), roots)?);
        }
        let resolver = download_address
            .as_ref()
            .map(|_| crate::dns::system::System::new(4));
        Ok(Self {
            config,
            upload,
            download,
            authority,
            download_authority,
            download_address,
            resolver,
        })
    }
}
fn authority(c: &crate::panel::Outbound) -> String {
    authority_for(c)
}
fn authority_for(c: &crate::panel::Outbound) -> String {
    if !c.host.is_empty() {
        c.host.clone()
    } else if !c.sni.is_empty() {
        c.sni.clone()
    } else {
        let h = c.address.trim_matches(['[', ']']);
        if h.contains(':') {
            format!("[{h}]")
        } else {
            h.to_owned()
        }
    }
}
fn manager(
    c: &crate::panel::Outbound,
    config: Arc<Config>,
    roots: Arc<rustls::ClientConfig>,
) -> Result<Arc<Manager>, Error> {
    let mut base = c.clone();
    base.host.clear();
    base.path.clear();
    base.xhttp_mode.clear();
    base.xhttp_extra.clear();
    let version = if c.security == "tls" {
        if c.alpn == ["h3"] {
            pool::Version::H3
        } else if c.alpn == ["http/1.1"] {
            pool::Version::H1
        } else {
            if c.alpn
                .iter()
                .any(|v| !matches!(v.as_str(), "h2" | "http/1.1"))
            {
                return Err(Error::Configuration("XHTTP ALPN"));
            }
            base.alpn = vec!["h2".into()];
            pool::Version::H2
        }
    } else {
        pool::Version::H1
    };
    let tls = crate::transport::tls::configure(&base, roots.clone())?;
    let dial = Tcp.outbound(&base, roots)?;
    let name = if c.sni.is_empty() {
        c.address.trim_matches(['[', ']']).to_owned()
    } else {
        c.sni.clone()
    };
    Manager::new(
        config,
        pool::Endpoint {
            version,
            dial,
            tls,
            name,
        },
    )
}
#[async_trait]
impl Outbound for Client {
    fn abort(&self) {
        self.upload.abort();
        if let Some(d) = &self.download {
            d.abort();
        }
        if let Some(r) = &self.resolver {
            r.abort();
        }
    }
    fn idle(&self) -> bool {
        self.upload.idle()
            && self.download.as_ref().is_none_or(|d| d.idle())
            && self.resolver.as_ref().is_none_or(|r| r.idle())
    }
    async fn close(&self, context: &OperationContext) -> Result<(), Error> {
        self.abort();
        self.upload.close().await;
        if let Some(d) = &self.download {
            d.close().await;
        }
        if let Some(r) = &self.resolver {
            r.close(context)
                .await
                .map_err(|_| Error::Io(io::ErrorKind::Interrupted))?;
        }
        Ok(())
    }
    async fn connect(
        &self,
        addresses: &[SocketAddr],
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<(Stream, SocketAddr), Error> {
        let cancel = CancellationToken::new();
        let mut fail = CancelOnDrop(Some(cancel.clone()));
        let mut upload = self.upload.acquire()?;
        let mode = if self.config.mode == "auto" {
            "packet-up"
        } else {
            self.config.mode.as_str()
        };
        let secure = self.upload.endpoint.tls.is_some();
        let (stream, peer, download_lease) = if mode == "stream-one" {
            let (writer, input) = body::response_pipe(scope)?;
            let request = self
                .config
                .request(&self.authority, secure, "", None, true, None)?
                .map(|_| input);
            let request = stream_request(&self.upload, request);
            let open = self
                .upload
                .open(&mut upload, addresses, scope, context, request)
                .await?;
            (
                Box::new(body::Joined {
                    reader: LazyResponse::new(open.response),
                    writer,
                }) as Stream,
                open.peer,
                upload.clone(),
            )
        } else {
            let id = self.config.session_id()?;
            let manager = self.download.as_ref().unwrap_or(&self.upload);
            let mut download = if self.download.is_some() {
                manager.acquire()?
            } else {
                upload.clone()
            };
            let mut download_addresses = Vec::new();
            if let Some((host, port)) = &self.download_address {
                for ip in self
                    .resolver
                    .as_ref()
                    .expect("download resolver")
                    .lookup(host, context)
                    .await
                    .map_err(|_| Error::Io(io::ErrorKind::NotFound))?
                {
                    download_addresses.push(SocketAddr::new(ip, *port));
                }
            }
            let download_addresses = if self.download.is_some() {
                download_addresses.as_slice()
            } else {
                addresses
            };
            let authority = if self.download.is_some() {
                &self.download_authority
            } else {
                &self.authority
            };
            let request = manager
                .config
                .request(
                    authority,
                    manager.endpoint.tls.is_some(),
                    &id,
                    None,
                    false,
                    None,
                )?
                .map(|_| body::empty());
            let request = stream_request(manager, request);
            let open = manager
                .open(&mut download, download_addresses, scope, context, request)
                .await?;
            let response = context.run(open.response).await.map_err(Error::Stopped)??;
            let reader = body::Reader::new(checked(response)?);
            let peer = open.peer;
            let (writer, input) = crate::network::pipe::pair(scope.clone(), 4)?;
            if mode == "stream-up" {
                let request = self
                    .config
                    .request(&self.authority, secure, &id, None, true, None)?
                    .map(|_| body::ReadBody::boxed(input, scope.clone()));
                let request = stream_request(&self.upload, request);
                let open = self
                    .upload
                    .open(&mut upload, addresses, scope, context, request)
                    .await?;
                let cancelled = cancel.clone();
                self.upload.jobs.spawn("xhttp.stream-upload",move|stop|async move{let work=async{let mut body=checked(open.response.await?)?;while let Some(frame)=body.frame().await{frame.map_err(Error::from)?;}Ok::<_,Error>(())};tokio::select!{_=stop.cancelled()=>{},_=cancelled.cancelled()=>{},r=work=>{if r.is_err(){cancelled.cancel();}}}Ok(())})?;
            } else {
                let manager = self.upload.clone();
                let endpoint = addresses.to_vec();
                let scope = scope.clone();
                let authority = self.authority.clone();
                let cancelled = cancel.clone();
                let upload = upload.clone();
                self.upload.jobs.spawn("xhttp.packet-upload",move|stop|async move{let work=upload_packets(manager,upload,endpoint,scope,authority,id,input,cancelled.clone());tokio::select!{_=stop.cancelled()=>{},_=cancelled.cancelled()=>{},result=work=>{if result.is_err(){cancelled.cancel();}}}Ok(())})?;
            }
            (
                Box::new(body::Joined { reader, writer }) as Stream,
                peer,
                download,
            )
        };
        context.check().map_err(Error::Stopped)?;
        fail.0 = None;
        Ok((
            Box::new(Managed {
                inner: stream,
                cancelled: Box::pin(cancel.clone().cancelled_owned()),
                cancel,
                _leases: (upload, download_lease),
                eof: false,
            }),
            peer,
        ))
    }
}
struct CancelOnDrop(Option<CancellationToken>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(c) = &self.0 {
            c.cancel();
        }
    }
}
fn checked(response: http::Response<Body>) -> Result<Body, Error> {
    if response.status() != http::StatusCode::OK {
        Err(Error::Io(io::ErrorKind::PermissionDenied))
    } else {
        Ok(response.into_body())
    }
}
struct LazyResponse {
    future: Option<pool::ResponseFuture>,
    reader: Option<body::Reader>,
    failed: bool,
}
impl LazyResponse {
    fn new(f: pool::ResponseFuture) -> Self {
        Self {
            future: Some(f),
            reader: None,
            failed: false,
        }
    }
}
impl AsyncRead for LazyResponse {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        if let Some(f) = &mut self.future {
            let result = std::task::ready!(f.as_mut().poll(cx)).and_then(checked);
            self.future = None;
            match result {
                Ok(body) => self.reader = Some(body::Reader::new(body)),
                Err(e) => {
                    self.failed = true;
                    return Poll::Ready(Err(io::Error::other(e)));
                }
            }
        }
        Pin::new(self.reader.as_mut().expect("response body")).poll_read(cx, out)
    }
}
struct Managed {
    inner: Stream,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    cancel: CancellationToken,
    _leases: (Lease, Lease),
    eof: bool,
}
impl Drop for Managed {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl AsyncRead for Managed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 || self.eof {
            return Poll::Ready(Ok(()));
        }
        if self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        let before = out.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, out);
        if matches!(result, Poll::Ready(Ok(()))) && out.filled().len() == before {
            self.eof = true;
            self.cancel.cancel();
        }
        result
    }
}
impl AsyncWrite for Managed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
#[allow(clippy::too_many_arguments)]
async fn upload_packets(
    manager: Arc<Manager>,
    mut lease: Lease,
    addresses: Vec<SocketAddr>,
    scope: BufferScope,
    authority: String,
    id: String,
    mut input: Pipe,
    cancel: CancellationToken,
) -> Result<(), Error> {
    let config = manager.config.clone();
    let mut requests =
        FuturesUnordered::<Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>>::new();
    let mut sequence = 0u64;
    let mut last = None;
    loop {
        while requests.len() >= config.sc_max_buffered_posts {
            requests.next().await.expect("pending upload")?;
        }
        while let Some(Some(result)) = requests.next().now_or_never() {
            result?;
        }
        let max = if matches!(config.uplink_data_placement.as_str(), "header" | "cookie") {
            config
                .sc_max_each_post_bytes
                .random()
                .min(
                    config
                        .server_max_header_bytes
                        .saturating_sub(config.xpadding_bytes.to + 2048)
                        * 3
                        / 4,
                )
                .min(scope.max_allocation())
        } else {
            config.sc_max_each_post_bytes.random()
        };
        if max == 0 {
            return Err(Error::Configuration(
                "XHTTP payload headers exceed header limit",
            ));
        }
        let read = read_packet(&mut input, &scope, max);
        tokio::pin!(read);
        let packet = loop {
            tokio::select! {biased;r=requests.next(),if !requests.is_empty()=>{r.expect("pending request")?;},packet=&mut read=>break packet?}
        };
        let Some(packet) = packet else {
            break;
        };
        if let Some(last) = last {
            tokio::time::sleep_until(
                last + Duration::from_millis(config.sc_min_posts_interval_ms.random() as u64),
            )
            .await;
        }
        let payload = if matches!(config.uplink_data_placement.as_str(), "header" | "cookie") {
            let len = packet.iter().map(|c| c.len()).sum();
            let mut lease = scope
                .try_lease(BufferLayout::new(0, len, 0).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
            for c in &packet {
                lease.append_payload(c).map_err(io::Error::other)?;
            }
            Some(Bytes::from_owner(lease))
        } else {
            None
        };
        let req = config.request(
            &authority,
            manager.endpoint.tls.is_some(),
            &id,
            Some(sequence),
            true,
            payload.as_deref(),
        )?;
        let body = if payload.is_some() {
            body::empty()
        } else {
            let len = packet.iter().map(|c| c.len()).sum::<usize>();
            let stream = futures_util::stream::iter(
                packet
                    .into_iter()
                    .map(|b| Ok::<_, io::Error>(http_body::Frame::data(b))),
            );
            let mut req = req;
            req.headers_mut().insert(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_str(&len.to_string())
                    .map_err(|_| Error::Configuration("XHTTP length"))?,
            );
            let body = http_body_util::StreamBody::new(stream).boxed_unsync();
            let request = req.map(|_| body);
            let context = OperationContext::new(
                cancel.clone(),
                Some(
                    Deadline::after(Duration::from_secs(60))
                        .map_err(|_| Error::Configuration("XHTTP deadline"))?,
                ),
            );
            let open = manager
                .open(&mut lease, &addresses, &scope, &context, request)
                .await?;
            requests.push(packet_result(open.response, context));
            sequence = sequence
                .checked_add(1)
                .ok_or(Error::Configuration("XHTTP sequence overflow"))?;
            last = Some(tokio::time::Instant::now());
            continue;
        };
        let context = OperationContext::new(
            cancel.clone(),
            Some(
                Deadline::after(Duration::from_secs(60))
                    .map_err(|_| Error::Configuration("XHTTP deadline"))?,
            ),
        );
        let open = manager
            .open(&mut lease, &addresses, &scope, &context, req.map(|_| body))
            .await?;
        requests.push(packet_result(open.response, context));
        sequence = sequence
            .checked_add(1)
            .ok_or(Error::Configuration("XHTTP sequence overflow"))?;
        last = Some(tokio::time::Instant::now());
    }
    while let Some(result) = requests.next().await {
        result?;
    }
    Ok(())
}
use futures_util::FutureExt;
fn packet_result(
    future: pool::ResponseFuture,
    context: OperationContext,
) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send>> {
    Box::pin(async move {
        context
            .run(async {
                let mut body = checked(future.await?)?;
                while let Some(frame) = body.frame().await {
                    frame.map_err(Error::from)?;
                }
                Ok(())
            })
            .await
            .map_err(Error::Stopped)?
    })
}
async fn read_packet(
    input: &mut Pipe,
    scope: &BufferScope,
    max: usize,
) -> Result<Option<Vec<Bytes>>, Error> {
    let mut chunks = Vec::new();
    let mut size = 0;
    let mut deadline = None;
    while size < max {
        let mut buffer = scope
            .try_lease(BufferLayout::new(0, (max - size).min(16384), 0).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
        let read = poll_fn(|cx| {
            buffer.poll_payload(cx, |cx, out| Pin::new(&mut *input).poll_read(cx, out))
        });
        let result = if let Some(deadline) = deadline {
            match tokio::time::timeout_at(deadline, read).await {
                Ok(v) => v,
                Err(_) => break,
            }
        } else {
            read.await
        };
        let (_, n) = result?;
        if n == 0 {
            break;
        }
        size += n;
        chunks.push(Bytes::from_owner(buffer));
        if deadline.is_none() {
            deadline = Some(tokio::time::Instant::now() + Duration::from_millis(1));
        }
    }
    Ok(if chunks.is_empty() {
        None
    } else {
        Some(chunks)
    })
}

fn stream_request<B>(manager: &Manager, mut request: http::Request<B>) -> http::Request<B> {
    if manager.endpoint.version == pool::Version::H1 {
        request.headers_mut().insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("close"),
        );
    }
    request
}
