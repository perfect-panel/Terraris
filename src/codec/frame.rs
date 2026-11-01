// SPDX-License-Identifier: GPL-3.0-only

use super::Error;
use crate::{
    buffer::{BufferLayout, BufferLease, BufferScope, SharedBuffer},
    telemetry::{Counter, Metrics},
};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LengthPrefix {
    U16,
    U32,
}
impl LengthPrefix {
    pub fn width(self) -> usize {
        match self {
            Self::U16 => 2,
            Self::U32 => 4,
        }
    }
    pub fn maximum(self) -> usize {
        match self {
            Self::U16 => u16::MAX as usize,
            Self::U32 => u32::MAX as usize,
        }
    }
}

#[derive(Debug)]
pub struct DecodeStep {
    pub consumed: usize,
    pub frame: Option<SharedBuffer>,
}

/// Incremental, single-frame-at-a-time decoder. It never retains a caller's
/// chunk or builds an unbounded output list. A decode failure poisons the state
/// and releases its partial buffer; reset is only safe at a known boundary.
///
/// ```
/// use terraris::{buffer::BufferScope, resource::{Budget, Limits}, codec::{FrameDecoder, LengthPrefix}, telemetry::Metrics};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let budget = Budget::new(Limits::new(1024, 8)?);
/// let scope = BufferScope::new(budget.root_scope(), 512)?;
/// let mut decoder = FrameDecoder::new(scope, LengthPrefix::U16, 128, Metrics::default())?;
/// assert!(decoder.feed(b"\0\x03a")?.frame.is_none());
/// let step = decoder.feed(b"bcnext-frame")?;
/// assert_eq!(step.consumed, 2);
/// assert_eq!(step.frame.unwrap().as_slice(), b"abc");
/// decoder.finish()?;
/// # Ok(())
/// # }
/// ```
pub struct FrameDecoder {
    scope: BufferScope,
    prefix: LengthPrefix,
    maximum: usize,
    header: [u8; 4],
    header_used: usize,
    expected: usize,
    payload: Option<BufferLease>,
    poisoned: bool,
    metrics: Metrics,
}
impl FrameDecoder {
    pub fn new(
        scope: BufferScope,
        prefix: LengthPrefix,
        maximum: usize,
        metrics: Metrics,
    ) -> Result<Self, Error> {
        if maximum > prefix.maximum()
            || maximum > scope.max_allocation()
            || maximum > scope.snapshot().limits().bytes()
        {
            return Err(Error::InvalidFrameLimit);
        }
        Ok(Self {
            scope,
            prefix,
            maximum,
            header: [0; 4],
            header_used: 0,
            expected: 0,
            payload: None,
            poisoned: false,
            metrics,
        })
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn buffered_bytes(&self) -> usize {
        self.payload.as_ref().map_or(0, BufferLease::len)
    }
    pub fn reset(&mut self) {
        self.payload = None;
        self.header = [0; 4];
        self.header_used = 0;
        self.expected = 0;
        self.poisoned = false;
    }
    pub fn feed(&mut self, input: &[u8]) -> Result<DecodeStep, Error> {
        if self.poisoned {
            return Err(Error::DecoderPoisoned);
        }
        let result = self.feed_inner(input);
        if let Err(error) = result {
            self.fail(error);
        }
        result
    }
    fn feed_inner(&mut self, input: &[u8]) -> Result<DecodeStep, Error> {
        let mut consumed = 0;
        if self.header_used < self.prefix.width() {
            let count = (self.prefix.width() - self.header_used).min(input.len());
            self.header[self.header_used..self.header_used + count]
                .copy_from_slice(&input[..count]);
            self.header_used += count;
            consumed += count;
            if self.header_used < self.prefix.width() {
                return Ok(DecodeStep {
                    consumed,
                    frame: None,
                });
            }
            self.expected = match self.prefix {
                LengthPrefix::U16 => u16::from_be_bytes([self.header[0], self.header[1]]) as usize,
                LengthPrefix::U32 => u32::from_be_bytes(self.header) as usize,
            };
            if self.expected > self.maximum {
                return Err(Error::LimitExceeded {
                    requested: self.expected,
                    limit: self.maximum,
                });
            }
            self.payload = Some(
                self.scope
                    .try_lease(BufferLayout::new(0, self.expected, 0)?)?,
            );
        }
        let payload = self
            .payload
            .as_mut()
            .expect("complete header owns a payload buffer");
        let count = (self.expected - payload.len()).min(input.len() - consumed);
        payload.append_payload(&input[consumed..consumed + count])?;
        consumed += count;
        if payload.len() == self.expected {
            let frame = self.payload.take().expect("complete frame").freeze();
            self.header_used = 0;
            self.expected = 0;
            self.header = [0; 4];
            self.metrics.increment(Counter::FramesDecoded);
            Ok(DecodeStep {
                consumed,
                frame: Some(frame),
            })
        } else {
            Ok(DecodeStep {
                consumed,
                frame: None,
            })
        }
    }
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::DecoderPoisoned);
        }
        if self.header_used != 0 || self.payload.is_some() {
            let error = Error::UnexpectedEof;
            self.fail(error);
            return Err(error);
        }
        Ok(())
    }
    fn fail(&mut self, error: Error) {
        self.payload = None;
        self.poisoned = true;
        self.metrics.increment(Counter::CodecRejected);
        if matches!(error, Error::Buffer(_)) {
            self.metrics.increment(Counter::BufferRejected);
        }
    }
}
impl fmt::Debug for FrameDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameDecoder")
            .field("maximum", &self.maximum)
            .field("buffered_bytes", &self.buffered_bytes())
            .field("poisoned", &self.poisoned)
            .finish()
    }
}
