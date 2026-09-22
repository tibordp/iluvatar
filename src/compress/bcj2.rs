//! BCJ2, 7-Zip's four-stream x86 branch converter, as a decoding stage.
//!
//! The main stream is the code with the targets of converted CALL (E8),
//! JMP (E9) and Jcc (0F 8x) instructions cut out; the CALL and JUMP
//! streams hold those targets as big-endian absolute addresses, and a
//! range-coded bit stream says, for every marker byte, whether it was
//! converted. Only the main stream flows through the chain: the caller
//! decodes the three side streams whole beforehand and the stage holds
//! them, so a checkpoint is the coder state plus positions in them.
//!
//! A marker byte at the very end of the stream still has a bit (7-Zip's
//! encoder writes a 0 for it), and a converted target ending in 0F
//! followed by 8x counts as a marker again. Ported from 7-Zip's Bcj2.c
//! (public domain).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::compress::checkpoint::{Bcj2CheckpointState, Checkpoint, CheckpointState};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::error::{Error, Result};

const TOP: u32 = 1 << 24;
const BIT_MODEL_TOTAL: u16 = 1 << 11;
const MOVE_BITS: u32 = 5;

/// Contexts: Jcc, E9, then E8 by the preceding byte.
const NUM_PROBS: usize = 2 + 256;

/// The side streams of one BCJ2 folder, decoded.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bcj2Streams {
    pub call: Vec<u8>,
    pub jump: Vec<u8>,
    pub rc: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct State {
    probs: Vec<u16>,
    range: u32,
    code: u32,
    rc_pos: usize,
    call_pos: usize,
    jump_pos: usize,
    /// Output position, wrapping like the encoder's.
    ip: u32,
    prev: u8,
    /// Converted target bytes the last output buffer could not take.
    pending: Vec<u8>,
    finished: bool,
}

pub struct Bcj2Decompressor {
    streams: Arc<Bcj2Streams>,
    state: State,
}

impl Bcj2Decompressor {
    pub fn new(streams: Arc<Bcj2Streams>) -> Result<Self> {
        let state = Self::initial(&streams)?;
        Ok(Self { streams, state })
    }

    /// The range coder's first five bytes: a zero, then the initial code.
    fn initial(streams: &Bcj2Streams) -> Result<State> {
        let head = streams
            .rc
            .get(..5)
            .ok_or_else(|| Error::DecompressionError("BCJ2 range coder stream truncated".into()))?;
        let code = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
        if head[0] != 0 || code == u32::MAX {
            return Err(Error::DecompressionError(
                "BCJ2 range coder stream corrupt".into(),
            ));
        }
        Ok(State {
            probs: vec![BIT_MODEL_TOTAL >> 1; NUM_PROBS],
            range: u32::MAX,
            code,
            rc_pos: 5,
            call_pos: 0,
            jump_pos: 0,
            ip: 0,
            prev: 0,
            pending: Vec::new(),
            finished: false,
        })
    }

    fn bit(&mut self, context: usize) -> Result<bool> {
        let st = &mut self.state;
        if st.range < TOP {
            let byte = *self.streams.rc.get(st.rc_pos).ok_or_else(|| {
                Error::DecompressionError("BCJ2 range coder stream exhausted".into())
            })?;
            st.rc_pos += 1;
            st.range <<= 8;
            st.code = (st.code << 8) | u32::from(byte);
        }
        let p = st.probs[context];
        let bound = (st.range >> 11) * u32::from(p);
        if st.code < bound {
            st.range = bound;
            st.probs[context] = p + ((BIT_MODEL_TOTAL - p) >> MOVE_BITS);
            Ok(false)
        } else {
            st.range -= bound;
            st.code -= bound;
            st.probs[context] = p - (p >> MOVE_BITS);
            Ok(true)
        }
    }

    /// The next converted target from the CALL or JUMP stream, as the
    /// relative address the code originally held.
    fn target(&mut self, call: bool) -> Result<u32> {
        let st = &mut self.state;
        let (stream, pos) = if call {
            (&self.streams.call, &mut st.call_pos)
        } else {
            (&self.streams.jump, &mut st.jump_pos)
        };
        let src = stream.get(*pos..*pos + 4).ok_or_else(|| {
            Error::DecompressionError(format!(
                "BCJ2 {} stream exhausted",
                if call { "call" } else { "jump" }
            ))
        })?;
        *pos += 4;
        let src = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
        st.ip = st.ip.wrapping_add(4);
        Ok(src.wrapping_sub(st.ip))
    }
}

impl Decompressor for Bcj2Decompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        let mut produced = 0;
        let mut consumed = 0;
        let take = self.state.pending.len().min(output.len());
        output[..take].copy_from_slice(&self.state.pending[..take]);
        self.state.pending.drain(..take);
        produced += take;

        while self.state.pending.is_empty() && consumed < input.len() && produced < output.len() {
            let b = input[consumed];
            consumed += 1;
            output[produced] = b;
            produced += 1;
            let prev = self.state.prev;
            self.state.ip = self.state.ip.wrapping_add(1);
            self.state.prev = b;
            let context = match b {
                0xE8 => 2 + usize::from(prev),
                0xE9 => 1,
                0x80..=0x8F if prev == 0x0F => 0,
                _ => continue,
            };
            if !self.bit(context)? {
                continue;
            }
            let bytes = self.target(b == 0xE8)?.to_le_bytes();
            self.state.prev = bytes[3];
            let take = bytes.len().min(output.len() - produced);
            output[produced..produced + take].copy_from_slice(&bytes[..take]);
            produced += take;
            self.state.pending.extend_from_slice(&bytes[take..]);
        }

        if input.is_empty() {
            self.state.finished = true;
        }
        Ok(DecompressResult {
            bytes_consumed: consumed,
            bytes_produced: produced,
            status: if self.state.finished && self.state.pending.is_empty() {
                DecompressStatus::StreamEnd
            } else {
                DecompressStatus::Continue
            },
        })
    }

    fn checkpoint(
        &self,
        compressed_offset: u64,
        uncompressed_offset: u64,
    ) -> Result<Option<Checkpoint>> {
        Ok(Some(Checkpoint {
            compressed_offset,
            bit_offset: 0,
            uncompressed_offset,
            state: CheckpointState::Bcj2(Bcj2CheckpointState {
                state: bincode::serialize(&self.state)
                    .map_err(|e| Error::CheckpointError(format!("serialize bcj2: {}", e)))?,
            }),
        }))
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        match &checkpoint.state {
            CheckpointState::Bcj2(s) => {
                let state: State = bincode::deserialize(&s.state)
                    .map_err(|e| Error::CheckpointError(format!("deserialize bcj2: {}", e)))?;
                if state.probs.len() != NUM_PROBS
                    || state.rc_pos > self.streams.rc.len()
                    || state.call_pos > self.streams.call.len()
                    || state.jump_pos > self.streams.jump.len()
                {
                    return Err(Error::CheckpointError(
                        "bcj2 checkpoint does not fit its side streams".into(),
                    ));
                }
                self.state = state;
                Ok(())
            }
            CheckpointState::None => {
                self.state = Self::initial(&self.streams)?;
                Ok(())
            }
            _ => Err(Error::CheckpointError(
                "expected bcj2 checkpoint state".into(),
            )),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The classic LZMA range encoder, enough to write BCJ2 bit streams.
    struct RangeEncoder {
        low: u64,
        range: u32,
        cache: u8,
        cache_size: u64,
        out: Vec<u8>,
    }

    impl RangeEncoder {
        fn new() -> Self {
            Self {
                low: 0,
                range: u32::MAX,
                cache: 0,
                cache_size: 1,
                out: Vec::new(),
            }
        }

        fn shift_low(&mut self) {
            if (self.low as u32) < 0xFF00_0000 || (self.low >> 32) != 0 {
                let carry = (self.low >> 32) as u8;
                let mut temp = self.cache;
                loop {
                    self.out.push(temp.wrapping_add(carry));
                    temp = 0xFF;
                    self.cache_size -= 1;
                    if self.cache_size == 0 {
                        break;
                    }
                }
                self.cache = (self.low >> 24) as u8;
            }
            self.cache_size += 1;
            self.low = (self.low & 0x00FF_FFFF) << 8;
        }

        fn encode(&mut self, prob: &mut u16, bit: bool) {
            let bound = (self.range >> 11) * u32::from(*prob);
            if !bit {
                self.range = bound;
                *prob += (BIT_MODEL_TOTAL - *prob) >> MOVE_BITS;
            } else {
                self.low += u64::from(bound);
                self.range -= bound;
                *prob -= *prob >> MOVE_BITS;
            }
            while self.range < TOP {
                self.range <<= 8;
                self.shift_low();
            }
        }

        fn finish(mut self) -> Vec<u8> {
            for _ in 0..5 {
                self.shift_low();
            }
            self.out
        }
    }

    /// Encode `data` the way 7-Zip does: every marker gets a bit, and a
    /// target is converted when `convert` says so and four bytes follow.
    pub(crate) fn encode(
        data: &[u8],
        mut convert: impl FnMut(usize) -> bool,
    ) -> (Vec<u8>, Bcj2Streams) {
        let mut main = Vec::new();
        let mut call = Vec::new();
        let mut jump = Vec::new();
        let mut rc = RangeEncoder::new();
        let mut probs = vec![BIT_MODEL_TOTAL >> 1; NUM_PROBS];
        let mut prev = 0u8;
        let mut i = 0;
        while i < data.len() {
            let b = data[i];
            main.push(b);
            let context = match b {
                0xE8 => 2 + usize::from(prev),
                0xE9 => 1,
                0x80..=0x8F if prev == 0x0F => 0,
                _ => {
                    prev = b;
                    i += 1;
                    continue;
                }
            };
            let bit = i + 5 <= data.len() && convert(i);
            rc.encode(&mut probs[context], bit);
            if bit {
                let rel = u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
                let abs = rel.wrapping_add((i + 5) as u32);
                if b == 0xE8 {
                    call.extend_from_slice(&abs.to_be_bytes());
                } else {
                    jump.extend_from_slice(&abs.to_be_bytes());
                }
                prev = data[i + 4];
                i += 5;
            } else {
                prev = b;
                i += 1;
            }
        }
        (
            main,
            Bcj2Streams {
                call,
                jump,
                rc: rc.finish(),
            },
        )
    }

    fn code_like(seed: u64, len: usize) -> Vec<u8> {
        let mut s = seed;
        let mut out = Vec::with_capacity(len + 24);
        while out.len() < len {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let r = (s >> 33) as u32;
            match r % 7 {
                0 => {
                    out.push(0xE8);
                    out.extend_from_slice(&((r >> 8) % 4096).to_le_bytes());
                }
                1 => {
                    out.push(0xE9);
                    out.extend_from_slice(&(r % 100_000).to_le_bytes());
                }
                2 => {
                    out.extend_from_slice(&[0x0F, 0x80 | (r & 0x0F) as u8]);
                    out.extend_from_slice(&(r % 5000).to_le_bytes());
                }
                3 => out.extend_from_slice(b"the quick brown fox "),
                _ => out.extend_from_slice(&r.to_le_bytes()),
            }
        }
        out.truncate(len);
        out
    }

    fn drive(dec: &mut Bcj2Decompressor, main: &[u8], chunk: usize, out_chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; out_chunk];
        let mut pos = 0;
        loop {
            let end = (pos + chunk).min(main.len());
            let r = dec.decompress(&main[pos..end], &mut buf).unwrap();
            pos += r.bytes_consumed;
            out.extend_from_slice(&buf[..r.bytes_produced]);
            if r.status == DecompressStatus::StreamEnd {
                return out;
            }
        }
    }

    #[test]
    fn round_trips_in_odd_chunks() {
        let data = code_like(7, 50_000);
        let (main, streams) = encode(&data, |i| i % 3 != 0);
        assert!(streams.call.len() > 100 && streams.jump.len() > 100);
        let streams = Arc::new(streams);
        for (chunk, out_chunk) in [(1, 1), (7, 3), (4096, 5), (50_000, 64 * 1024)] {
            let mut dec = Bcj2Decompressor::new(streams.clone()).unwrap();
            assert_eq!(
                drive(&mut dec, &main, chunk, out_chunk),
                data,
                "{}/{}",
                chunk,
                out_chunk
            );
        }
    }

    #[test]
    fn trailing_markers_and_overlap() {
        // A converted target ending in 0F followed by 8x is a marker again;
        // markers in the last four bytes carry a bit but no target.
        let mut data = code_like(3, 2000);
        data.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x0F, 0x85, 0x01, 0x02, 0x03, 0x04]);
        data.extend_from_slice(&[0xE8, 0x01, 0x02]);
        for tail in [&data[..], &data[..data.len() - 3], &[0xE8][..], &[][..]] {
            let (main, streams) = encode(tail, |_| true);
            let mut dec = Bcj2Decompressor::new(Arc::new(streams)).unwrap();
            assert_eq!(drive(&mut dec, &main, 13, 13), tail);
        }
    }

    #[test]
    fn checkpoint_restores_mid_stream() {
        let data = code_like(11, 30_000);
        let (main, streams) = encode(&data, |i| i % 2 == 0);
        let streams = Arc::new(streams);
        let mut dec = Bcj2Decompressor::new(streams.clone()).unwrap();
        let mut buf = vec![0u8; 100];
        let mut out = Vec::new();
        let mut pos = 0;
        while out.len() < 10_000 {
            let r = dec.decompress(&main[pos..pos + 50], &mut buf).unwrap();
            pos += r.bytes_consumed;
            out.extend_from_slice(&buf[..r.bytes_produced]);
        }
        let cp = dec
            .checkpoint(pos as u64, out.len() as u64)
            .unwrap()
            .unwrap();
        let mut rest = Bcj2Decompressor::new(streams).unwrap();
        rest.restore(&cp).unwrap();
        let tail = drive(&mut rest, &main[pos..], 999, 77);
        out.extend_from_slice(&tail);
        assert_eq!(out, data);
    }

    #[test]
    fn corrupt_side_streams_are_errors() {
        assert!(Bcj2Decompressor::new(Arc::new(Bcj2Streams::default())).is_err());
        let data = code_like(5, 500);
        let (main, mut streams) = encode(&data, |_| true);
        streams.call.truncate(4);
        let mut dec = Bcj2Decompressor::new(Arc::new(streams)).unwrap();
        let mut buf = vec![0u8; 4096];
        assert!(dec.decompress(&main, &mut buf).is_err());
    }
}
