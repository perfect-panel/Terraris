// SPDX-License-Identifier: MPL-2.0
// See THIRD_PARTY.md for protocol sources.

use super::{
    Error,
    crypto::{Aead, Mask, hash},
};
use crate::buffer::{BufferLayout, BufferLease, BufferScope};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

pub(crate) const MAX_RECORD: usize = 16640;
pub(crate) struct State {
    pub(crate) read: Aead,
    pub(crate) write: Aead,
    pub(crate) key: Zeroizing<[u8; 96]>,
    pub(crate) read_mask: Option<Mask>,
    pub(crate) write_mask: Option<Mask>,
}
/// AEAD records retain partial reads and writes within fixed budgeted buffers.
/// A pending write must be retried with the same plaintext prefix. Cancelling a
/// write and then supplying different bytes poisons the stream rather than
/// silently acknowledging bytes from the abandoned call. Closing it is safe.
pub struct EncryptedStream<S> {
    io: S,
    state: State,
    input: BufferLease,
    output: BufferLease,
    header_have: usize,
    body_have: usize,
    body_length: Option<usize>,
    plain: (usize, usize),
    write_pos: usize,
    pending_write: usize,
    pending_hash: [u8; 32],
    failed: bool,
}
impl<S> EncryptedStream<S> {
    pub(crate) fn new(io: S, state: State, buffers: &BufferScope) -> Result<Self, Error> {
        let layout = |n| BufferLayout::new(0, n, 0).map_err(|_| Error::Resource);
        let mut buffers = buffers
            .try_lease_many(&[layout(5 + MAX_RECORD)?, layout(5 + 8192 + 16)?])
            .map_err(|_| Error::Resource)?;
        let output = buffers.pop().expect("two buffers");
        let mut input = buffers.pop().expect("two buffers");
        input
            .append_zeroed(5 + MAX_RECORD)
            .map_err(|_| Error::Resource)?;
        Ok(Self {
            io,
            state,
            input,
            output,
            header_have: 0,
            body_have: 0,
            body_length: None,
            plain: (0, 0),
            write_pos: 0,
            pending_write: 0,
            pending_hash: [0; 32],
            failed: false,
        })
    }
    fn fail<T>(&mut self, error: impl Into<io::Error>) -> Poll<io::Result<T>> {
        self.failed = true;
        Poll::Ready(Err(error.into()))
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return this.fail(Error::Closed);
        }
        if read.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.plain.0 < this.plain.1 {
            let n = read.remaining().min(this.plain.1 - this.plain.0);
            read.put_slice(&this.input.as_slice()[5 + this.plain.0..5 + this.plain.0 + n]);
            this.plain.0 += n;
            return Poll::Ready(Ok(()));
        }
        while this.header_have < 5 {
            let mut part = ReadBuf::new(&mut this.input.as_mut_slice()[this.header_have..5]);
            match Pin::new(&mut this.io).poll_read(cx, &mut part) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return this.fail(e),
                Poll::Ready(Ok(())) => {
                    let n = part.filled().len();
                    if n == 0 {
                        if this.header_have == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        return this.fail(io::ErrorKind::UnexpectedEof);
                    }
                    this.header_have += n;
                }
            }
        }
        if this.body_length.is_none() {
            if let Some(mask) = &mut this.state.read_mask
                && let Err(e) = mask.apply(&mut this.input.as_mut_slice()[..5])
            {
                return this.fail(e);
            }
            let h = &this.input.as_slice()[..5];
            let n = u16::from_be_bytes([h[3], h[4]]) as usize;
            if h[..3] != [23, 3, 3] || !(17..=MAX_RECORD).contains(&n) {
                return this.fail(Error::InvalidRecord);
            }
            this.body_length = Some(n);
        }
        let n = this.body_length.expect("decoded header");
        while this.body_have < n {
            let mut part = ReadBuf::new(&mut this.input.as_mut_slice()[5 + this.body_have..5 + n]);
            match Pin::new(&mut this.io).poll_read(cx, &mut part) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return this.fail(e),
                Poll::Ready(Ok(())) => {
                    let n = part.filled().len();
                    if n == 0 {
                        return this.fail(io::ErrorKind::UnexpectedEof);
                    }
                    this.body_have += n;
                }
            }
        }
        let header: [u8; 5] = this.input.as_slice()[..5].try_into().expect("header");
        let rekey = (this.state.read.nonce == [255; 12]).then(|| {
            Aead::new(
                &this.input.as_slice()[..5 + n],
                this.state.key.as_ref(),
                this.state.read.cipher,
            )
        });
        let length =
            match this
                .state
                .read
                .open(&mut this.input.as_mut_slice()[5..5 + n], &header, None)
            {
                Ok(n) => n,
                Err(e) => return this.fail(e),
            };
        if let Some(next) = rekey {
            this.state.read = next;
        }
        this.header_have = 0;
        this.body_have = 0;
        this.body_length = None;
        let n = read.remaining().min(length);
        read.put_slice(&this.input.as_slice()[5..5 + n]);
        this.plain = (n, length);
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> EncryptedStream<S> {
    fn send_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.output.len() {
            match Pin::new(&mut self.io).poll_write(cx, &self.output.as_slice()[self.write_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return self.fail(e),
                Poll::Ready(Ok(0)) => return self.fail(io::ErrorKind::WriteZero),
                Poll::Ready(Ok(n)) => self.write_pos += n,
            }
        }
        self.output.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return this.fail(Error::Closed);
        }
        if this.pending_write > 0 {
            if data.len() < this.pending_write
                || hash(&data[..this.pending_write]) != this.pending_hash
            {
                return this.fail(Error::InvalidRecord);
            }
            ready!(this.send_pending(cx))?;
            let n = this.pending_write;
            this.pending_write = 0;
            return Poll::Ready(Ok(n));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(8192);
        let length = (n + 16) as u16;
        let header = [23, 3, 3, (length >> 8) as u8, length as u8];
        this.output
            .append_payload(&header)
            .expect("fixed output capacity");
        this.output
            .append_payload(&data[..n])
            .expect("fixed output capacity");
        this.output.append_zeroed(16).expect("fixed tag capacity");
        let rekey = this.state.write.nonce == [255; 12];
        if let Err(e) = this
            .state
            .write
            .seal(&mut this.output.as_mut_slice()[5..], &header, None)
        {
            return this.fail(e);
        }
        if rekey {
            this.state.write = Aead::new(
                this.output.as_slice(),
                this.state.key.as_ref(),
                this.state.write.cipher,
            );
        }
        if let Some(mask) = &mut this.state.write_mask
            && let Err(e) = mask.apply(&mut this.output.as_mut_slice()[..5])
        {
            return this.fail(e);
        }
        this.pending_write = n;
        this.pending_hash = hash(&data[..n]);
        ready!(this.send_pending(cx))?;
        this.pending_write = 0;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed || this.pending_write > 0 {
            return this.fail(Error::InvalidRecord);
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed || this.pending_write > 0 {
            return this.fail(Error::InvalidRecord);
        }
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}
