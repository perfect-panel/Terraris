// SPDX-License-Identifier: GPL-3.0-only
//! Bounded HTTP/1 upgrades. Bytes read beyond the headers remain in the stream.
use super::{
    Error,
    web::{Kind, Options},
};
use crate::{
    buffer::{BufferLayout, BufferScope, SharedBuffer},
    network::Stream,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use std::{
    collections::BTreeMap,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
const MAX_HEADER: usize = 16384;
struct Head {
    method: Option<String>,
    path: Option<String>,
    status: Option<u16>,
    headers: BTreeMap<String, String>,
    prefix: SharedBuffer,
}
impl Head {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers.get(key).map(String::as_str)
    }
    fn token(&self, key: &str, token: &str) -> bool {
        self.get(key)
            .is_some_and(|s| s.split(',').any(|v| v.trim().eq_ignore_ascii_case(token)))
    }
    fn upgrade(&self) -> bool {
        self.token("connection", "upgrade")
            && self
                .get("upgrade")
                .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
            && self.get("transfer-encoding").is_none()
            && self.get("content-length").is_none_or(|v| v == "0")
    }
}
async fn read(stream: &mut Stream, scope: &BufferScope, request: bool) -> Result<Head, Error> {
    let mut data = scope
        .try_lease(
            BufferLayout::new(0, MAX_HEADER, 0).map_err(|_| Error::Configuration("HTTP buffer"))?,
        )
        .map_err(|_| Error::Configuration("HTTP buffer budget"))?;
    data.append_zeroed(MAX_HEADER)
        .map_err(|_| Error::Configuration("HTTP buffer"))?;
    let mut have = 0;
    loop {
        if have == MAX_HEADER {
            return Err(Error::Configuration("HTTP headers too large"));
        }
        let n = stream.read(&mut data.as_mut_slice()[have..]).await?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        have += n;
        if !data.as_slice()[..have].windows(4).any(|w| w == b"\r\n\r\n") {
            continue;
        }
        let mut fields = [httparse::EMPTY_HEADER; 64];
        let (end, method, path, status, headers) = if request {
            let mut message = httparse::Request::new(&mut fields);
            let httparse::Status::Complete(end) = message
                .parse(&data.as_slice()[..have])
                .map_err(|_| Error::Configuration("invalid HTTP request"))?
            else {
                return Err(Error::Configuration("incomplete HTTP request"));
            };
            if message.version != Some(1) {
                return Err(Error::Unsupported);
            }
            (
                end,
                message.method.map(str::to_owned),
                message.path.map(str::to_owned),
                None,
                message.headers,
            )
        } else {
            let mut message = httparse::Response::new(&mut fields);
            let httparse::Status::Complete(end) = message
                .parse(&data.as_slice()[..have])
                .map_err(|_| Error::Configuration("invalid HTTP response"))?
            else {
                return Err(Error::Configuration("incomplete HTTP response"));
            };
            if message.version != Some(1) {
                return Err(Error::Unsupported);
            }
            (end, None, None, message.code, message.headers)
        };
        let mut map = BTreeMap::new();
        for header in headers {
            let value = std::str::from_utf8(header.value)
                .map_err(|_| Error::Configuration("HTTP header value"))?;
            if map
                .insert(header.name.to_ascii_lowercase(), value.trim().to_owned())
                .is_some()
            {
                return Err(Error::Configuration("duplicate HTTP header"));
            }
        }
        let prefix = data
            .freeze()
            .slice(end..have)
            .map_err(|_| Error::Configuration("HTTP prefix"))?;
        return Ok(Head {
            method,
            path,
            status,
            headers: map,
            prefix,
        });
    }
}
fn accept(key: &str) -> String {
    tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes())
}
fn valid_key(key: &str) -> bool {
    STANDARD.decode(key).is_ok_and(|v| v.len() == 16)
}
async fn reject(stream: &mut Stream, not_found: bool) -> Result<(), Error> {
    stream
        .write_all(if not_found {
            b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        } else {
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        })
        .await?;
    stream.flush().await?;
    Ok(())
}
pub(super) async fn server(
    mut stream: Stream,
    scope: BufferScope,
    options: &Options,
) -> Result<Stream, Error> {
    let head = match read(&mut stream, &scope, true).await {
        Ok(h) => h,
        Err(e) => {
            let _ = reject(&mut stream, false).await;
            return Err(e);
        }
    };
    if head.method.as_deref() != Some("GET") || !head.upgrade() {
        reject(&mut stream, false).await?;
        return Err(Error::Unsupported);
    }
    if !options.matches(
        head.get("host").unwrap_or(""),
        head.path.as_deref().unwrap_or(""),
    ) {
        reject(&mut stream, true).await?;
        return Err(Error::Unsupported);
    }
    let key = head.get("sec-websocket-key");
    if (options.kind == Kind::WebSocket
        && (key.is_none() || head.get("sec-websocket-version") != Some("13")))
        || key.is_some_and(|key| !valid_key(key))
    {
        reject(&mut stream, false).await?;
        return Err(Error::Unsupported);
    }
    let mut response =
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
            .to_owned();
    if let Some(key) = key {
        response.push_str(&format!("Sec-WebSocket-Accept: {}\r\n", accept(key)));
    }
    let mut early = None;
    if options.kind == Kind::WebSocket
        && let Some(protocol) = head.get("sec-websocket-protocol")
    {
        if protocol.len() > 4096 {
            reject(&mut stream, false).await?;
            return Err(Error::Configuration("WebSocket early data too large"));
        }
        let normalized = protocol
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_owned();
        if let Ok(data) = URL_SAFE_NO_PAD.decode(normalized)
            && !data.is_empty()
        {
            let mut buffer = scope
                .try_lease(
                    BufferLayout::new(0, data.len(), 0)
                        .map_err(|_| Error::Configuration("early data"))?,
                )
                .map_err(|_| Error::Configuration("early data budget"))?;
            buffer
                .append_payload(&data)
                .map_err(|_| Error::Configuration("early data"))?;
            early = Some(buffer.freeze());
            response.push_str(&format!("Sec-WebSocket-Protocol: {protocol}\r\n"));
        }
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    let stream = prefix(stream, head.prefix);
    if options.kind == Kind::WebSocket {
        let stream = super::websocket::wrap(stream, scope, false).await;
        Ok(if let Some(early) = early {
            prefix(stream, early)
        } else {
            stream
        })
    } else {
        Ok(stream)
    }
}
pub(super) async fn client(
    stream: Stream,
    scope: BufferScope,
    options: &Options,
) -> Result<Stream, Error> {
    client_early(stream, scope, options, None).await
}
pub(super) async fn client_early(
    mut stream: Stream,
    scope: BufferScope,
    options: &Options,
    early: Option<&[u8]>,
) -> Result<Stream, Error> {
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| Error::Configuration("HTTP nonce"))?;
    let key = STANDARD.encode(nonce);
    let protocol = early.map(|data| URL_SAFE_NO_PAD.encode(data));
    let extra = protocol
        .as_ref()
        .map(|value| format!("Sec-WebSocket-Protocol: {value}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n{extra}\r\n",
        options.path, options.host
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let head = read(&mut stream, &scope, false).await?;
    if head.status != Some(101)
        || !head.upgrade()
        || head.get("sec-websocket-extensions").is_some()
        || head
            .get("sec-websocket-protocol")
            .is_some_and(|value| Some(value) != protocol.as_deref())
    {
        return Err(Error::Unsupported);
    }
    if (options.kind == Kind::WebSocket
        && head.get("sec-websocket-accept") != Some(accept(&key).as_str()))
        || head
            .get("sec-websocket-accept")
            .is_some_and(|value| value != accept(&key))
    {
        return Err(Error::Unsupported);
    }
    let stream = prefix(stream, head.prefix);
    Ok(if options.kind == Kind::WebSocket {
        super::websocket::wrap(stream, scope, true).await
    } else {
        stream
    })
}
pub(super) fn prefix(stream: Stream, data: SharedBuffer) -> Stream {
    if data.is_empty() {
        stream
    } else {
        Box::new(Prefix {
            stream,
            data: Some(data),
            offset: 0,
        })
    }
}
struct Prefix {
    stream: Stream,
    data: Option<SharedBuffer>,
    offset: usize,
}
impl AsyncRead for Prefix {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(data) = &this.data {
            let n = (data.len() - this.offset).min(output.remaining());
            output.put_slice(&data.as_slice()[this.offset..this.offset + n]);
            this.offset += n;
            if this.offset == data.len() {
                this.data = None;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.stream).poll_read(cx, output)
    }
}
impl AsyncWrite for Prefix {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{Budget, Limits};
    fn resources() -> (Budget, BufferScope) {
        let budget = Budget::new(Limits::new(1 << 20, 64).unwrap());
        let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
        (budget, scope)
    }
    fn options(kind: Kind) -> Options {
        Options {
            kind,
            host: "example.com".into(),
            path: "/relay".into(),
            service: String::new(),
            early_data: 0,
        }
    }
    async fn header(io: &mut (impl AsyncRead + Unpin)) -> String {
        let mut out = Vec::new();
        while !out.ends_with(b"\r\n\r\n") {
            assert!(out.len() < MAX_HEADER);
            out.push(io.read_u8().await.unwrap());
        }
        String::from_utf8(out).unwrap()
    }
    #[tokio::test]
    async fn http_upgrade_keeps_coalesced_first_payload() {
        let (budget, scope) = resources();
        let (client, remote) = tokio::io::duplex(32768);
        let mut client: Stream = Box::new(client);
        let task = tokio::spawn(async move {
            let mut stream = server(Box::new(remote), scope, &options(Kind::HttpUpgrade))
                .await
                .unwrap();
            let mut bytes = [0; 5];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"hello");
            stream.write_all(b"world").await.unwrap();
            stream.flush().await.unwrap();
        });
        client.write_all(b"GET /relay?x=1 HTTP/1.1\r\nHost: example.com:443\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\nhello").await.unwrap();
        assert!(header(&mut client).await.starts_with("HTTP/1.1 101"));
        let mut reply = [0; 5];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"world");
        task.await.unwrap();
        drop(client);
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
    #[tokio::test]
    async fn websocket_early_data_is_delivered_before_frames() {
        let (budget, scope) = resources();
        let (mut client, remote) = tokio::io::duplex(32768);
        let task = tokio::spawn(async move {
            let mut stream = server(Box::new(remote), scope, &options(Kind::WebSocket))
                .await
                .unwrap();
            let mut bytes = [0; 3];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"abc");
            stream.write_all(b"reply").await.unwrap();
            stream.flush().await.unwrap();
        });
        client.write_all(b"GET /relay HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: YWJj\r\n\r\n").await.unwrap();
        let response = header(&mut client).await;
        assert!(response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        assert!(response.contains("Sec-WebSocket-Protocol: YWJj"));
        let mut frame = [0; 7];
        client.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, b"\x82\x05reply");
        task.await.unwrap();
        drop(client);
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
    #[tokio::test]
    async fn upgrades_reject_wrong_routes_ambiguous_headers_and_bodies() {
        for request in [
            "GET /wrong HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            "GET /relay HTTP/1.1\r\nHost: other.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            "GET /relay HTTP/1.1\r\nHost: example.com\r\nHost: other.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            "GET /relay HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 1\r\n\r\nx",
            "GET /relay HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            let (budget, scope) = resources();
            let (mut client, remote) = tokio::io::duplex(32768);
            let task = tokio::spawn(async move {
                assert!(
                    server(Box::new(remote), scope, &options(Kind::HttpUpgrade))
                        .await
                        .is_err()
                );
            });
            client.write_all(request.as_bytes()).await.unwrap();
            let response = header(&mut client).await;
            assert!(response.starts_with("HTTP/1.1 4"));
            task.await.unwrap();
            drop(client);
            assert_eq!(budget.snapshot().used().bytes(), 0);
        }
    }
}
