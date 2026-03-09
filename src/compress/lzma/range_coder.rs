//! Range decoder for LZMA.
//!
//! Implements the arithmetic coding decoder used by LZMA. The range decoder
//! maintains two u32 values (`range` and `code`) and consumes input bytes
//! incrementally from a provided slice.
//!
//! This is a sans-I/O implementation: all input comes from `&[u8]` slices
//! passed to `init()` and `normalize()`. The decoder tracks how many bytes
//! it has consumed from the current slice.

use serde::{Deserialize, Serialize};

const K_TOP_VALUE: u32 = 1 << 24;
const K_NUM_BIT_MODEL_TOTAL_BITS: u32 = 11;
const K_BIT_MODEL_TOTAL: u32 = 1 << K_NUM_BIT_MODEL_TOTAL_BITS;
const K_NUM_MOVE_BITS: u32 = 5;

/// Initial probability value (equal probability for 0 and 1).
pub const PROB_INIT_VAL: u16 = (K_BIT_MODEL_TOTAL / 2) as u16;

/// The range decoder state. All fields are serializable for checkpointing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeDecoder {
    pub range: u32,
    pub code: u32,
    /// Whether corruption has been detected (informational; decoding continues).
    pub corrupted: bool,
}

/// Result of a range decoder operation that may need more input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeCoderStatus {
    Ok,
    NeedInput,
}

impl RangeDecoder {
    /// Create a new uninitialized range decoder.
    pub fn new() -> Self {
        Self {
            range: 0xFFFF_FFFF,
            code: 0,
            corrupted: false,
        }
    }

    /// Initialize the range decoder from the first 5 bytes of LZMA data.
    /// Returns how many bytes were consumed (up to 5), or NeedInput if
    /// not enough bytes are available.
    pub fn init(&mut self, input: &[u8]) -> (RangeCoderStatus, usize) {
        if input.len() < 5 {
            return (RangeCoderStatus::NeedInput, 0);
        }
        self.corrupted = false;
        self.range = 0xFFFF_FFFF;

        let b0 = input[0];
        self.code = (input[1] as u32) << 24
            | (input[2] as u32) << 16
            | (input[3] as u32) << 8
            | (input[4] as u32);

        if b0 != 0 || self.code == self.range {
            self.corrupted = true;
        }

        (RangeCoderStatus::Ok, 5)
    }

    /// Normalize the range decoder, consuming one byte from input if needed.
    /// Returns (status, bytes_consumed).
    #[inline]
    pub fn normalize(&mut self, input: &[u8], pos: usize) -> (RangeCoderStatus, usize) {
        if self.range < K_TOP_VALUE {
            if pos >= input.len() {
                return (RangeCoderStatus::NeedInput, 0);
            }
            self.range <<= 8;
            self.code = (self.code << 8) | (input[pos] as u32);
            (RangeCoderStatus::Ok, 1)
        } else {
            (RangeCoderStatus::Ok, 0)
        }
    }

    /// Decode a single bit using a probability model.
    /// Normalizes BEFORE decoding so that if input is needed, no state is modified.
    /// Returns (bit, bytes_consumed_by_normalize).
    #[inline]
    pub fn decode_bit(
        &mut self,
        prob: &mut u16,
        input: &[u8],
        pos: usize,
    ) -> Result<(u32, usize), RangeCoderStatus> {
        // Normalize first (may need one input byte)
        let (status, consumed) = self.normalize(input, pos);
        if status == RangeCoderStatus::NeedInput {
            return Err(RangeCoderStatus::NeedInput);
        }

        let v = *prob as u32;
        let bound = (self.range >> K_NUM_BIT_MODEL_TOTAL_BITS) * v;
        let symbol;
        if self.code < bound {
            *prob = (v + ((K_BIT_MODEL_TOTAL - v) >> K_NUM_MOVE_BITS)) as u16;
            self.range = bound;
            symbol = 0;
        } else {
            *prob = (v - (v >> K_NUM_MOVE_BITS)) as u16;
            self.code -= bound;
            self.range -= bound;
            symbol = 1;
        }
        Ok((symbol, consumed))
    }

    /// Decode a single direct bit (no probability model).
    /// Normalizes BEFORE decoding.
    /// Returns (bit, bytes_consumed).
    #[inline]
    pub fn decode_direct_bit(
        &mut self,
        input: &[u8],
        pos: usize,
    ) -> Result<(u32, usize), RangeCoderStatus> {
        // Normalize first
        let (status, consumed) = self.normalize(input, pos);
        if status == RangeCoderStatus::NeedInput {
            return Err(RangeCoderStatus::NeedInput);
        }

        self.range >>= 1;
        self.code = self.code.wrapping_sub(self.range);
        let t = 0u32.wrapping_sub(self.code >> 31);
        self.code = self.code.wrapping_add(self.range & t);

        if self.code == self.range {
            self.corrupted = true;
        }

        Ok((t.wrapping_add(1), consumed))
    }

    /// Check if decoding finished correctly.
    pub fn is_finished_ok(&self) -> bool {
        self.code == 0
    }
}

impl Default for RangeDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state() {
        let rc = RangeDecoder::new();
        assert_eq!(rc.range, 0xFFFF_FFFF);
        assert_eq!(rc.code, 0);
        assert!(!rc.corrupted);
    }

    #[test]
    fn test_init_valid() {
        let mut rc = RangeDecoder::new();
        let data = [0u8, 0x12, 0x34, 0x56, 0x78];
        let (status, consumed) = rc.init(&data);
        assert_eq!(status, RangeCoderStatus::Ok);
        assert_eq!(consumed, 5);
        assert_eq!(rc.code, 0x12345678);
        assert_eq!(rc.range, 0xFFFF_FFFF);
        assert!(!rc.corrupted);
    }

    #[test]
    fn test_init_corrupted_first_byte() {
        let mut rc = RangeDecoder::new();
        let data = [1u8, 0x12, 0x34, 0x56, 0x78];
        let (status, consumed) = rc.init(&data);
        assert_eq!(status, RangeCoderStatus::Ok);
        assert_eq!(consumed, 5);
        assert!(rc.corrupted);
    }

    #[test]
    fn test_init_not_enough_data() {
        let mut rc = RangeDecoder::new();
        let data = [0u8, 0x12, 0x34];
        let (status, consumed) = rc.init(&data);
        assert_eq!(status, RangeCoderStatus::NeedInput);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn test_prob_init_val() {
        assert_eq!(PROB_INIT_VAL, 1024);
    }

    #[test]
    fn test_normalize_no_shift() {
        let mut rc = RangeDecoder::new();
        // range >= K_TOP_VALUE, so no normalization needed
        rc.range = K_TOP_VALUE;
        let (status, consumed) = rc.normalize(&[], 0);
        assert_eq!(status, RangeCoderStatus::Ok);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn test_normalize_needs_shift() {
        let mut rc = RangeDecoder::new();
        rc.range = K_TOP_VALUE - 1;
        rc.code = 0;
        let input = [0xABu8];
        let (status, consumed) = rc.normalize(&input, 0);
        assert_eq!(status, RangeCoderStatus::Ok);
        assert_eq!(consumed, 1);
        assert_eq!(rc.code, 0xAB);
        assert_eq!(rc.range, (K_TOP_VALUE - 1) << 8);
    }

    #[test]
    fn test_normalize_needs_input() {
        let mut rc = RangeDecoder::new();
        rc.range = K_TOP_VALUE - 1;
        let (status, consumed) = rc.normalize(&[], 0);
        assert_eq!(status, RangeCoderStatus::NeedInput);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let rc = RangeDecoder {
            range: 0x12345678,
            code: 0xABCDEF01,
            corrupted: false,
        };
        let serialized = bincode::serialize(&rc).unwrap();
        let rc2: RangeDecoder = bincode::deserialize(&serialized).unwrap();
        assert_eq!(rc2.range, rc.range);
        assert_eq!(rc2.code, rc.code);
        assert_eq!(rc2.corrupted, rc.corrupted);
    }
}
