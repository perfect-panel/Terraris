// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    buffer::{BufferLayout, BufferLease, BufferScope, SharedBuffer},
    network::Stream,
    task::CancellationToken,
    time::{Deadline, OperationContext},
};
use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, WriteHalf},
    sync::Mutex as AsyncMutex,
};
pub const WASTE: u8 = 0;
pub const SYN: u8 = 1;
pub const PSH: u8 = 2;
pub const FIN: u8 = 3;
pub const SETTINGS: u8 = 4;
pub const ALERT: u8 = 5;
pub const PADDING: u8 = 6;
pub const SYNACK: u8 = 7;
pub const HEART_REQUEST: u8 = 8;
pub const HEART_RESPONSE: u8 = 9;
pub const SERVER_SETTINGS: u8 = 10;
pub struct Frame {
    pub command: u8,
    pub id: u32,
    pub data: SharedBuffer,
}
pub struct Reader<R> {
    io: R,
    scope: BufferScope,
    header: [u8; 7],
    have: usize,
    body: Option<BufferLease>,
    body_have: usize,
    poisoned: bool,
}
impl<R: AsyncRead + Unpin> Reader<R> {
    pub fn new(io: R, scope: BufferScope) -> Self {
        Self {
            io,
            scope,
            header: [0; 7],
            have: 0,
            body: None,
            body_have: 0,
            poisoned: false,
        }
    }
    pub async fn next(&mut self) -> io::Result<Option<Frame>> {
        if self.poisoned {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let result = self.inner().await;
        if result.is_err() {
            self.poisoned = true;
            self.body.take();
        }
        result
    }
    async fn inner(&mut self) -> io::Result<Option<Frame>> {
        while self.have < 7 {
            let n = self.io.read(&mut self.header[self.have..]).await?;
            if n == 0 {
                return if self.have == 0 {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
            self.have += n;
        }
        let length = u16::from_be_bytes([self.header[5], self.header[6]]) as usize;
        if self.body.is_none() {
            let mut body = self
                .scope
                .try_lease(BufferLayout::new(0, length, 0).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
            body.append_zeroed(length).map_err(io::Error::other)?;
            self.body = Some(body);
        }
        while self.body_have < length {
            let n = self
                .io
                .read(&mut self.body.as_mut().expect("body").as_mut_slice()[self.body_have..])
                .await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.body_have += n;
        }
        let frame = Frame {
            command: self.header[0],
            id: u32::from_be_bytes(self.header[1..5].try_into().expect("id")),
            data: self.body.take().expect("body").freeze(),
        };
        self.have = 0;
        self.body_have = 0;
        Ok(Some(frame))
    }
}
pub struct Writer {
    io: AsyncMutex<WriteHalf<Stream>>,
    pub scope: BufferScope,
    pub cancel: CancellationToken,
    timeout: Duration,
    last: Mutex<tokio::time::Instant>,
}
impl Writer {
    pub fn new(
        io: WriteHalf<Stream>,
        scope: BufferScope,
        cancel: CancellationToken,
        timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            io: AsyncMutex::new(io),
            scope,
            cancel,
            timeout,
            last: Mutex::new(tokio::time::Instant::now()),
        })
    }
    pub fn touch(&self) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = tokio::time::Instant::now();
    }
    pub fn last(&self) -> tokio::time::Instant {
        *self.last.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub async fn bytes(&self, command: u8, id: u32, data: &[u8]) -> io::Result<()> {
        let mut buffer = self
            .scope
            .try_lease(BufferLayout::new(0, data.len(), 0).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
        buffer.append_payload(data).map_err(io::Error::other)?;
        self.frame(command, id, buffer.freeze()).await
    }
    pub async fn frame(&self, command: u8, id: u32, data: SharedBuffer) -> io::Result<()> {
        let length = u16::try_from(data.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let context = OperationContext::new(
            self.cancel.clone(),
            Some(Deadline::after(self.timeout).map_err(io::Error::other)?),
        );
        context
            .run(async {
                let mut io = self.io.lock().await;
                let mut guard = WriteGuard {
                    cancel: self.cancel.clone(),
                    complete: false,
                };
                let mut header = [0; 7];
                header[0] = command;
                header[1..5].copy_from_slice(&id.to_be_bytes());
                header[5..].copy_from_slice(&length.to_be_bytes());
                io.write_all(&header).await?;
                io.write_all(data.as_slice()).await?;
                io.flush().await?;
                guard.complete = true;
                self.touch();
                Ok(())
            })
            .await
            .map_err(io::Error::other)?
    }
}
struct WriteGuard {
    cancel: CancellationToken,
    complete: bool,
}
impl Drop for WriteGuard {
    fn drop(&mut self) {
        if !self.complete {
            self.cancel.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cancelled_partial_frame_closes_carrier_and_releases_buffers() {
        let budget =
            crate::resource::Budget::new(crate::resource::Limits::new(1 << 20, 32).unwrap());
        let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
        let (a, _b) = tokio::io::duplex(1);
        let stream: Stream = Box::new(a);
        let (_read, write) = tokio::io::split(stream);
        let cancel = CancellationToken::new();
        let writer = Writer::new(write, scope, cancel.clone(), Duration::from_secs(1));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), writer.bytes(PSH, 1, b"partial"))
                .await
                .is_err()
        );
        assert!(cancel.is_cancelled());
        assert!(writer.bytes(PSH, 2, b"next").await.is_err());
        drop(writer);
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
}
