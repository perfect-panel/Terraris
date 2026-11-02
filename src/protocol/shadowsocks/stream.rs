// SPDX-License-Identifier: GPL-3.0-only
//! Budgeted AEAD records. Read state owns partial I/O across cancellation;
//! writes acknowledge plaintext only after its entire authenticated record.
use super::{
    method::{self, Counter, Key, Method, TAG, bad},
    replay::Protection,
};
use crate::{
    buffer::{BufferLayout, BufferLease, BufferScope},
    network::Stream,
    protocol::socksaddr::{Endpoint, Format},
    time::OperationContext,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use zeroize::Zeroizing;

pub struct Keys {
    pub all: Vec<Arc<Key>>,
    pub identities: HashMap<[u8; 16], Arc<Key>>,
}
impl Keys {
    pub fn new(all: Vec<Arc<Key>>, indexed: bool) -> io::Result<Self> {
        if !indexed && all.len() > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Shadowsocks trial-key limit (1024)",
            ));
        }
        let mut identities = HashMap::new();
        for key in &all {
            if identities.insert(key.identity, key.clone()).is_some() {
                return Err(bad());
            }
        }
        Ok(Self { all, identities })
    }
}
struct Prefix<R> {
    inner: R,
    prefix: Option<BufferLease>,
}
impl<R: AsyncRead + Unpin> AsyncRead for Prefix<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(prefix) = &mut this.prefix {
            let n = out.remaining().min(prefix.len());
            out.put_slice(&prefix.as_slice()[..n]);
            prefix.consume(n).map_err(io::Error::other)?;
            if prefix.is_empty() {
                this.prefix = None;
            }
            if n > 0 {
                return Poll::Ready(Ok(()));
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, out)
    }
}
impl<R: AsyncWrite + Unpin> AsyncWrite for Prefix<R> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, b)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
async fn chunk<R: AsyncRead + Unpin>(
    raw: &mut R,
    cipher: &mut Counter,
    length: usize,
    scope: &BufferScope,
) -> io::Result<BufferLease> {
    let mut buffer = scope
        .lease_when_available(BufferLayout::new(0, length + TAG, 0).map_err(io::Error::other)?)
        .await
        .map_err(io::Error::other)?;
    while buffer.len() < length + TAG {
        if buffer.read_from(raw).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }
    let mut tag = [0; TAG];
    tag.copy_from_slice(&buffer.as_slice()[length..]);
    cipher.open(&mut buffer.as_mut_slice()[..length], &tag)?;
    buffer.truncate(length).map_err(io::Error::other)?;
    Ok(buffer)
}
fn append_sealed(out: &mut BufferLease, cipher: &mut Counter, plaintext: &[u8]) -> io::Result<()> {
    let offset = out.len();
    out.append_payload(plaintext).map_err(io::Error::other)?;
    let tag = cipher.seal(&mut out.as_mut_slice()[offset..])?;
    out.append_payload(&tag).map_err(io::Error::other)
}
async fn first_read<R: AsyncRead + Unpin>(
    raw: &mut R,
    scope: &BufferScope,
) -> io::Result<BufferLease> {
    let mut buffer = scope
        .lease_when_available(BufferLayout::new(0, 4096, 0).map_err(io::Error::other)?)
        .await
        .map_err(io::Error::other)?;
    buffer.read_from(raw).await?;
    Ok(buffer)
}
/// Unknown-key failures use a common FIN/drain policy bounded by the handshake
/// context. There is no response payload or per-key error sent to the peer.
async fn reject(raw: &mut Stream, already_read: usize, context: &OperationContext) {
    let work = async {
        let _ = raw.shutdown().await;
        let mut remaining = 65536usize.saturating_sub(already_read);
        let mut discard = [0; 4096];
        while remaining > 0 {
            let count = discard.len().min(remaining);
            match raw.read(&mut discard[..count]).await {
                Ok(0) | Err(_) => return,
                Ok(n) => remaining -= n,
            }
        }
        std::future::pending::<()>().await;
    };
    let _ = context.run(work).await;
}
pub struct Accepted {
    pub key: [u8; 32],
    pub target: Endpoint,
    pub stream: Stream,
}
pub async fn accept(
    mut raw: Stream,
    method: Method,
    server: Option<&Key>,
    keys: &Keys,
    protection: Arc<Protection>,
    scope: &BufferScope,
    context: &OperationContext,
) -> io::Result<Accepted> {
    let mut prefix = first_read(&mut raw, scope).await?;
    let fixed = if method.modern() { 11 } else { 2 };
    let identity = usize::from(server.is_some()) * 16;
    let needed = method.key_len() + identity + fixed + TAG;
    if !method.modern() {
        while prefix.len() < needed {
            if prefix.read_from(&mut raw).await? == 0 {
                break;
            }
        }
    }
    if prefix.len() < needed {
        reject(&mut raw, prefix.len(), context).await;
        return Err(bad());
    }
    let mut salt = vec![0; method.key_len()];
    salt.copy_from_slice(&prefix.as_slice()[..method.key_len()]);
    let offset = method.key_len() + identity;
    let selected = if let Some(server) = server {
        let mut id = [0; 16];
        id.copy_from_slice(&prefix.as_slice()[method.key_len()..offset]);
        method.identity_cipher(server, &salt, &mut id, false)?;
        keys.identities
            .get(&id)
            .cloned()
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        keys.all.clone()
    };
    let mut accepted = None;
    for (index, key) in selected.into_iter().enumerate() {
        if index % 16 == 0 {
            context.check().map_err(|_| io::ErrorKind::Interrupted)?;
            tokio::task::yield_now().await;
        }
        let mut cipher = method.session(&key, &salt)?;
        let mut header = [0; 11];
        header[..fixed].copy_from_slice(&prefix.as_slice()[offset..offset + fixed]);
        if cipher
            .open(
                &mut header[..fixed],
                &prefix.as_slice()[offset + fixed..needed],
            )
            .is_ok()
        {
            accepted = Some((key, cipher, header));
            break;
        }
    }
    let Some((key, mut cipher, header)) = accepted else {
        reject(&mut raw, prefix.len(), context).await;
        return Err(bad());
    };
    let valid = if method.modern() {
        header[0] == 0
            && method::timestamp(u64::from_be_bytes(header[1..9].try_into().unwrap())).is_ok()
    } else {
        true
    };
    let length = u16::from_be_bytes(header[fixed - 2..fixed].try_into().unwrap()) as usize;
    if !valid
        || length > method.record_limit()
        || protection.tcp_salt(key.id, &salt, method.modern()).is_err()
    {
        reject(&mut raw, prefix.len(), context).await;
        return Err(bad());
    }
    prefix.consume(needed).map_err(io::Error::other)?;
    let mut raw = Prefix {
        inner: raw,
        prefix: Some(prefix),
    };
    let mut first = chunk(&mut raw, &mut cipher, length, scope).await?;
    let target = if method.modern() {
        let (target, n) = Endpoint::parse(first.as_slice(), Format::Socks)?.ok_or_else(bad)?;
        if first.len() < n + 2 {
            return Err(bad());
        }
        let padding = u16::from_be_bytes(first.as_slice()[n..n + 2].try_into().unwrap()) as usize;
        if padding > 900 || first.len() < n + 2 + padding || padding == 0 && first.len() == n + 2 {
            return Err(bad());
        }
        first.consume(n + 2 + padding).map_err(io::Error::other)?;
        Some(target)
    } else {
        None
    };
    let (read, write) = tokio::io::split(Box::new(raw) as Stream);
    let mut stream = RecordStream::new(
        Reader {
            raw: Prefix {
                inner: read,
                prefix: None,
            },
            method,
            key: key.clone(),
            cipher: Some(cipher),
            expected: None,
            protection: protection.clone(),
            scope: scope.clone(),
        },
        Writer {
            raw: write,
            method,
            key: key.clone(),
            cipher: None,
            request_salt: salt,
            protection,
            scope: scope.clone(),
            pending: None,
            allocation: None,
            closed: false,
        },
        Some(first),
    );
    let target = if let Some(target) = target {
        target
    } else {
        Endpoint::read(&mut stream, Format::Socks).await?
    };
    Ok(Accepted {
        key: key.id,
        target,
        stream: Box::new(stream),
    })
}
pub async fn connect(
    mut raw: Stream,
    method: Method,
    keys: &[Arc<Key>],
    target: &Endpoint,
    protection: Arc<Protection>,
    scope: &BufferScope,
    context: &OperationContext,
) -> io::Result<Stream> {
    let key = keys.last().ok_or_else(bad)?.clone();
    let mut salt = vec![0; method.key_len()];
    method::random(&mut salt)?;
    if !method.modern() {
        protection.tcp_salt(key.id, &salt, false)?;
    }
    let mut cipher = method.session(&key, &salt)?;
    let address = target.encode(Format::Socks)?;
    let mut buffer = scope
        .lease_when_available(BufferLayout::new(0, 2048, 0).map_err(io::Error::other)?)
        .await
        .map_err(io::Error::other)?;
    buffer.append_payload(&salt).map_err(io::Error::other)?;
    if method.modern() {
        for pair in keys.windows(2) {
            let mut header = pair[1].identity;
            method.identity_cipher(&pair[0], &salt, &mut header, true)?;
            buffer.append_payload(&header).map_err(io::Error::other)?;
        }
        let mut entropy = [0; 1];
        method::random(&mut entropy)?;
        let padding = usize::from(entropy[0]) + 1;
        let length = address.len() + 2 + padding;
        let mut header = [0; 11];
        header[1..9].copy_from_slice(&method::now()?.to_be_bytes());
        header[9..].copy_from_slice(&(length as u16).to_be_bytes());
        append_sealed(&mut buffer, &mut cipher, &header)?;
        let mut variable = Zeroizing::new(vec![0; length]);
        variable[..address.len()].copy_from_slice(&address);
        variable[address.len()..address.len() + 2].copy_from_slice(&(padding as u16).to_be_bytes());
        method::random(&mut variable[address.len() + 2..])?;
        append_sealed(&mut buffer, &mut cipher, &variable)?;
    } else {
        append_sealed(
            &mut buffer,
            &mut cipher,
            &(address.len() as u16).to_be_bytes(),
        )?;
        append_sealed(&mut buffer, &mut cipher, &address)?;
    }
    context
        .run(raw.write_all(buffer.as_slice()))
        .await
        .map_err(|_| io::ErrorKind::Interrupted)??;
    context
        .run(raw.flush())
        .await
        .map_err(|_| io::ErrorKind::Interrupted)??;
    drop(buffer);
    let (read, write) = tokio::io::split(raw);
    Ok(Box::new(RecordStream::new(
        Reader {
            raw: Prefix {
                inner: read,
                prefix: None,
            },
            method,
            key: key.clone(),
            cipher: None,
            expected: Some(salt.clone()),
            protection: protection.clone(),
            scope: scope.clone(),
        },
        Writer {
            raw: write,
            method,
            key,
            cipher: Some(cipher),
            request_salt: salt,
            protection,
            scope: scope.clone(),
            pending: None,
            allocation: None,
            closed: false,
        },
        None,
    )))
}
struct Reader {
    raw: Prefix<ReadHalf<Stream>>,
    method: Method,
    key: Arc<Key>,
    cipher: Option<Counter>,
    expected: Option<Vec<u8>>,
    protection: Arc<Protection>,
    scope: BufferScope,
}
impl Reader {
    async fn next(&mut self) -> io::Result<Option<BufferLease>> {
        let initial = self.cipher.is_none();
        let mut first_length = None;
        let mut response_salt = None;
        if initial {
            let salt_len = self.method.key_len();
            if self.method.modern() {
                let fixed = 1 + 8 + salt_len + 2;
                let needed = salt_len + fixed + TAG;
                let mut prefix = first_read(&mut self.raw, &self.scope).await?;
                if prefix.is_empty() {
                    return Ok(None);
                }
                if prefix.len() < needed {
                    return Err(bad());
                }
                let salt = &prefix.as_slice()[..salt_len];
                let mut cipher = self.method.session(&self.key, salt)?;
                let mut header = [0; 43];
                header[..fixed].copy_from_slice(&prefix.as_slice()[salt_len..salt_len + fixed]);
                cipher.open(
                    &mut header[..fixed],
                    &prefix.as_slice()[salt_len + fixed..needed],
                )?;
                if header[0] != 1 {
                    return Err(bad());
                }
                method::timestamp(u64::from_be_bytes(header[1..9].try_into().unwrap()))?;
                let expected = self.expected.as_ref().ok_or_else(bad)?;
                if !bool::from(header[9..9 + salt_len].ct_eq(expected)) {
                    return Err(bad());
                }
                let length =
                    u16::from_be_bytes(header[fixed - 2..fixed].try_into().unwrap()) as usize;
                if length == 0 {
                    return Err(bad());
                }
                prefix.consume(needed).map_err(io::Error::other)?;
                self.raw.prefix = Some(prefix);
                self.cipher = Some(cipher);
                first_length = Some(length);
            } else {
                let mut salt = vec![0; salt_len];
                if self.raw.read(&mut salt[..1]).await? == 0 {
                    return Ok(None);
                }
                self.raw.read_exact(&mut salt[1..]).await?;
                self.cipher = Some(self.method.session(&self.key, &salt)?);
                response_salt = Some(salt);
            }
        }
        let cipher = self.cipher.as_mut().ok_or_else(bad)?;
        let length = if let Some(n) = first_length {
            n
        } else {
            let mut header = [0; 18];
            if self.raw.read(&mut header[..1]).await? == 0 {
                return if initial {
                    Err(io::ErrorKind::UnexpectedEof.into())
                } else {
                    Ok(None)
                };
            }
            self.raw.read_exact(&mut header[1..]).await?;
            let (data, tag) = header.split_at_mut(2);
            cipher.open(data, tag)?;
            u16::from_be_bytes(data.try_into().unwrap()) as usize
        };
        if length > self.method.record_limit() {
            return Err(bad());
        }
        if let Some(salt) = response_salt {
            self.protection.tcp_salt(self.key.id, &salt, false)?;
        }
        Ok(Some(
            chunk(&mut self.raw, cipher, length, &self.scope).await?,
        ))
    }
    async fn owned(mut self) -> (Self, io::Result<Option<BufferLease>>) {
        let result = self.next().await;
        (self, result)
    }
}
type ReadJob = Pin<Box<dyn Future<Output = (Reader, io::Result<Option<BufferLease>>)> + Send>>;
type Allocation = Pin<Box<dyn Future<Output = Result<BufferLease, crate::buffer::Error>> + Send>>;
struct Pending {
    buffer: BufferLease,
    sent: usize,
    plain: usize,
    digest: Zeroizing<[u8; 32]>,
}
struct Writer {
    raw: WriteHalf<Stream>,
    method: Method,
    key: Arc<Key>,
    cipher: Option<Counter>,
    request_salt: Vec<u8>,
    protection: Arc<Protection>,
    scope: BufferScope,
    pending: Option<Pending>,
    allocation: Option<(usize, Allocation)>,
    closed: bool,
}
impl Writer {
    fn fill(&mut self, mut buffer: BufferLease, plaintext: &[u8]) -> io::Result<Pending> {
        let first = self.cipher.is_none();
        if first {
            let mut salt = vec![0; self.method.key_len()];
            method::random(&mut salt)?;
            if !self.method.modern() {
                self.protection.tcp_salt(self.key.id, &salt, false)?;
            }
            self.cipher = Some(self.method.session(&self.key, &salt)?);
            buffer.append_payload(&salt).map_err(io::Error::other)?;
        }
        let cipher = self.cipher.as_mut().ok_or_else(bad)?;
        if first && self.method.modern() {
            let length = 1 + 8 + self.method.key_len() + 2;
            let mut header = [0; 43];
            header[0] = 1;
            header[1..9].copy_from_slice(&method::now()?.to_be_bytes());
            header[9..length - 2].copy_from_slice(&self.request_salt);
            header[length - 2..length].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
            append_sealed(&mut buffer, cipher, &header[..length])?;
        } else {
            append_sealed(&mut buffer, cipher, &(plaintext.len() as u16).to_be_bytes())?;
        }
        append_sealed(&mut buffer, cipher, plaintext)?;
        Ok(Pending {
            buffer,
            sent: 0,
            plain: plaintext.len(),
            digest: Zeroizing::new(Sha256::digest(plaintext).into()),
        })
    }
    fn poll_write(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pending.is_none() {
            if self.allocation.is_none() {
                let count = data.len().min(16383);
                let scope = self.scope.clone();
                let layout = BufferLayout::new(0, count + 128, 0).map_err(io::Error::other)?;
                self.allocation = Some((
                    count,
                    Box::pin(async move { scope.lease_when_available(layout).await }),
                ));
            }
            let (wanted, job) = self.allocation.as_mut().unwrap();
            let buffer = ready!(job.as_mut().poll(cx)).map_err(io::Error::other)?;
            let count = (*wanted).min(data.len());
            self.allocation = None;
            self.pending = Some(self.fill(buffer, &data[..count])?);
        }
        let pending = self.pending.as_mut().unwrap();
        if data.len() < pending.plain
            || !bool::from(
                pending
                    .digest
                    .as_ref()
                    .ct_eq(Sha256::digest(&data[..pending.plain]).as_slice()),
            )
        {
            self.closed = true;
            return Poll::Ready(Err(bad()));
        }
        while pending.sent < pending.buffer.len() {
            let n = ready!(
                Pin::new(&mut self.raw).poll_write(cx, &pending.buffer.as_slice()[pending.sent..])
            )?;
            if n == 0 {
                self.closed = true;
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            pending.sent += n;
        }
        let n = pending.plain;
        self.pending = None;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(&mut self, cx: &mut Context<'_>, shutdown: bool) -> Poll<io::Result<()>> {
        if self.pending.is_some() {
            self.closed = true;
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        self.allocation = None;
        if shutdown {
            ready!(Pin::new(&mut self.raw).poll_shutdown(cx))?;
            self.closed = true;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.raw).poll_flush(cx)
        }
    }
}
struct RecordStream {
    reader: Option<Reader>,
    read_job: Option<ReadJob>,
    plain: Option<BufferLease>,
    writer: Writer,
    eof: bool,
    failed: bool,
}
impl RecordStream {
    fn new(reader: Reader, writer: Writer, plain: Option<BufferLease>) -> Self {
        Self {
            reader: Some(reader),
            read_job: None,
            plain,
            writer,
            eof: false,
            failed: false,
        }
    }
}
impl AsyncRead for RecordStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(bad()));
        }
        for _ in 0..64 {
            if let Some(plain) = &mut this.plain {
                let n = plain.len().min(out.remaining());
                out.put_slice(&plain.as_slice()[..n]);
                plain.consume(n).map_err(io::Error::other)?;
                if plain.is_empty() {
                    this.plain = None;
                }
                if n > 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if this.read_job.is_none() {
                this.read_job = Some(Box::pin(this.reader.take().unwrap().owned()));
            }
            let (reader, result) = ready!(this.read_job.as_mut().unwrap().as_mut().poll(cx));
            this.read_job = None;
            this.reader = Some(reader);
            match result {
                Ok(Some(data)) => this.plain = Some(data),
                Ok(None) => this.eof = true,
                Err(e) => {
                    this.failed = true;
                    return Poll::Ready(Err(e));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for RecordStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let result = this.writer.poll_write(cx, data);
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = this.writer.poll_flush(cx, false);
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = this.writer.poll_flush(cx, true);
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        resource::{Budget, Limits},
        task::CancellationToken,
        time::Deadline,
    };
    use std::time::Duration;
    fn ctx() -> OperationContext {
        OperationContext::new(
            CancellationToken::new(),
            Some(Deadline::after(Duration::from_secs(2)).unwrap()),
        )
    }
    fn scope() -> (Budget, BufferScope) {
        let budget = Budget::new(Limits::new(4 << 20, 256).unwrap());
        let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
        (budget, scope)
    }
    fn destination() -> Endpoint {
        Endpoint::from_address(
            &crate::network::Address::from_socket("127.0.0.1:443".parse().unwrap()).unwrap(),
        )
        .unwrap()
    }
    #[tokio::test]
    async fn fragmented_records_survive_cancelled_reads_and_same_write_but_reject_changed_write() {
        for method in [Method::Aes128, Method::XChaCha20, Method::Aes256_2022] {
            let (memory, scope) = scope();
            let key = Key::new(method, &vec![7; method.key_len()]).unwrap();
            let keys = Keys::new(vec![key.clone()], false).unwrap();
            let (raw_client, raw_server) = tokio::io::duplex(128);
            let server_context = ctx();
            let client_context = ctx();
            let client_keys = [key];
            let target = destination();
            let (server, client) = tokio::join!(
                accept(
                    Box::new(raw_server),
                    method,
                    None,
                    &keys,
                    Protection::new(),
                    &scope,
                    &server_context
                ),
                connect(
                    Box::new(raw_client),
                    method,
                    &client_keys,
                    &target,
                    Protection::new(),
                    &scope,
                    &client_context
                )
            );
            let mut server = server.unwrap().stream;
            let mut client = client.unwrap();
            let payload = vec![91; 8192];
            assert!(
                tokio::time::timeout(Duration::from_millis(5), client.write_all(&payload))
                    .await
                    .is_err()
            );
            let mut reply = vec![0; payload.len()];
            context_exchange(&mut client, &mut server, &payload, &mut reply).await;
            assert_eq!(reply, payload);
            assert!(
                tokio::time::timeout(Duration::from_millis(5), server.write_all(&payload))
                    .await
                    .is_err()
            );
            let mut byte = [0];
            assert!(
                tokio::time::timeout(Duration::from_millis(5), client.read(&mut byte))
                    .await
                    .is_err()
            );
            context_exchange(&mut server, &mut client, &payload, &mut reply).await;
            assert_eq!(reply, payload);
            assert!(
                tokio::time::timeout(Duration::from_millis(5), client.write_all(&payload))
                    .await
                    .is_err()
            );
            assert!(client.write_all(b"different").await.is_err());
            drop(client);
            assert!(
                ctx()
                    .run(server.read_exact(&mut reply))
                    .await
                    .unwrap()
                    .is_err()
            );
            drop(server);
            assert_eq!(memory.snapshot().used().bytes(), 0);
            assert_eq!(memory.snapshot().used().allocations(), 0);
        }
    }
    async fn context_exchange(
        sender: &mut Stream,
        receiver: &mut Stream,
        payload: &[u8],
        output: &mut [u8],
    ) {
        ctx()
            .run(async { tokio::try_join!(sender.write_all(payload), receiver.read_exact(output)) })
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn unauthenticated_classic_response_salts_do_not_poison_replay_history() {
        let method = Method::Aes128;
        let key = Key::new(method, &[7; 16]).unwrap();
        let protection = Protection::new();
        let (memory, scope) = scope();
        let salt = [19; 16];
        for corrupt in [true, false] {
            let (mut server, client) = tokio::io::duplex(4096);
            let (read, _write) = tokio::io::split(Box::new(client) as Stream);
            let mut wire = scope
                .try_lease(BufferLayout::new(0, 128, 0).unwrap())
                .unwrap();
            wire.append_payload(&salt).unwrap();
            let mut cipher = method.session(&key, &salt).unwrap();
            append_sealed(&mut wire, &mut cipher, &5u16.to_be_bytes()).unwrap();
            append_sealed(&mut wire, &mut cipher, b"valid").unwrap();
            if corrupt {
                wire.as_mut_slice()[18] ^= 1;
            }
            server.write_all(wire.as_slice()).await.unwrap();
            drop(wire);
            let mut reader = Reader {
                raw: Prefix {
                    inner: read,
                    prefix: None,
                },
                method,
                key: key.clone(),
                cipher: None,
                expected: None,
                protection: protection.clone(),
                scope: scope.clone(),
            };
            let result = reader.next().await;
            if corrupt {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap().unwrap().as_slice(), b"valid");
            }
            drop(reader);
        }
        assert!(protection.tcp_salt(key.id, &salt, false).is_err());
        assert_eq!(memory.snapshot().used().bytes(), 0);
    }
    #[tokio::test]
    async fn modern_response_requires_exact_request_salt_type_and_timestamp() {
        for method in [
            Method::Aes128_2022,
            Method::Aes256_2022,
            Method::ChaCha20_2022,
        ] {
            for invalid in ["salt", "type", "time", "none"] {
                let (memory, scope) = scope();
                let key = Key::new(method, &vec![7; method.key_len()]).unwrap();
                let request_salt = vec![0x77; method.key_len()];
                let server_salt = vec![0x55; method.key_len()];
                let (mut server, client) = tokio::io::duplex(4096);
                let (read, _write) = tokio::io::split(Box::new(client) as Stream);
                let mut header = vec![if invalid == "type" { 0 } else { 1 }];
                header.extend(
                    if invalid == "time" {
                        0
                    } else {
                        method::now().unwrap()
                    }
                    .to_be_bytes(),
                );
                header.extend(vec![
                    if invalid == "salt" { 0x66 } else { 0x77 };
                    method.key_len()
                ]);
                header.extend(5u16.to_be_bytes());
                let mut output = scope
                    .try_lease(BufferLayout::new(0, 512, 0).unwrap())
                    .unwrap();
                output.append_payload(&server_salt).unwrap();
                let mut counter = method.session(&key, &server_salt).unwrap();
                append_sealed(&mut output, &mut counter, &header).unwrap();
                append_sealed(&mut output, &mut counter, b"bound").unwrap();
                server.write_all(output.as_slice()).await.unwrap();
                drop(output);
                let mut reader = Reader {
                    raw: Prefix {
                        inner: read,
                        prefix: None,
                    },
                    method,
                    key,
                    cipher: None,
                    expected: Some(request_salt),
                    protection: Protection::new(),
                    scope: scope.clone(),
                };
                let result = reader.next().await;
                if invalid == "none" {
                    assert_eq!(result.unwrap().unwrap().as_slice(), b"bound");
                } else {
                    assert!(result.is_err(), "{invalid}");
                }
                drop(reader);
                assert_eq!(memory.snapshot().used().bytes(), 0);
            }
        }
    }
}
