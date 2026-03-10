use crate::compress::checkpoint::{Bzip2CheckpointState, Checkpoint, CheckpointState};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::error::{Error, Result};
use bzip2::Decompress as BzDecompress;

// ─── Block Boundary Scanner ──────────────────────────────────────────

/// 48-bit block start magic: pi in BCD = 0x314159265359
const BLOCK_MAGIC: u64 = 0x314159265359;
/// 48-bit end-of-stream magic: sqrt(pi) in BCD = 0x177245385090
const EOS_MAGIC: u64 = 0x177245385090;
/// Mask for low 48 bits.
const MAGIC_MASK: u64 = (1u64 << 48) - 1;

/// Scans compressed bytes for the 48-bit block magic at every bit position.
///
/// bzip2 blocks can start at arbitrary bit positions (not byte-aligned),
/// so we maintain a 48-bit sliding window across the bitstream.
#[derive(Clone)]
struct MagicScanner {
    /// 48-bit sliding window (low 48 bits).
    window: u64,
    /// Total bits processed so far.
    total_bits: u64,
    /// Number of block magics found (including block 0).
    block_count: u64,
    /// Last block boundary (after block 0).
    last_boundary: Option<BlockBoundary>,
    /// Whether end-of-stream marker was found.
    eos_found: bool,
}

#[derive(Debug, Clone)]
struct BlockBoundary {
    /// Byte offset in the compressed stream.
    byte_offset: u64,
    /// Bit offset within that byte (0-7, MSB-first).
    bit_offset: u8,
    /// Block index (1-indexed; block 0 is the stream start).
    block_index: u64,
    /// Total uncompressed bytes output before this block.
    uncompressed_offset: u64,
}

impl MagicScanner {
    fn new() -> Self {
        Self {
            window: 0,
            total_bits: 0,
            block_count: 0,
            last_boundary: None,
            eos_found: false,
        }
    }

    /// Process a single byte, returning true if a new block boundary was
    /// detected (retrievable via `take_boundary`).
    fn scan_byte(&mut self, byte: u8) -> bool {
        let mut found = false;
        for bit_idx in (0..8).rev() {
            let bit = ((byte >> bit_idx) & 1) as u64;
            self.window = ((self.window << 1) | bit) & MAGIC_MASK;
            self.total_bits += 1;

            if self.total_bits < 48 {
                continue;
            }

            if self.window == BLOCK_MAGIC {
                self.block_count += 1;
                if self.block_count > 1 {
                    let start_bit = self.total_bits - 48;
                    self.last_boundary = Some(BlockBoundary {
                        byte_offset: start_bit / 8,
                        bit_offset: (start_bit % 8) as u8,
                        block_index: self.block_count - 1,
                        uncompressed_offset: 0, // filled in later
                    });
                    found = true;
                }
            } else if self.window == EOS_MAGIC {
                self.eos_found = true;
            }
        }
        found
    }

    /// Feed compressed bytes to the scanner, recording `total_out` as the
    /// uncompressed offset for any boundary detected.
    fn feed(&mut self, data: &[u8], total_out: u64) {
        for &byte in data {
            if self.scan_byte(byte) {
                if let Some(ref mut b) = self.last_boundary {
                    b.uncompressed_offset = total_out;
                }
            }
        }
    }

    /// Pre-scan `data` (without modifying self) and return byte indices within
    /// `data` where block boundaries are detected.  Cheap bit-manipulation only.
    fn find_boundary_positions(&self, data: &[u8]) -> Vec<usize> {
        let mut clone = self.clone();
        let mut positions = Vec::new();
        for (i, &byte) in data.iter().enumerate() {
            if clone.scan_byte(byte) {
                positions.push(i);
                clone.last_boundary = None; // don't accumulate
            }
        }
        positions
    }

    fn take_boundary(&mut self) -> Option<BlockBoundary> {
        self.last_boundary.take()
    }
}

// ─── Bit Shifter ─────────────────────────────────────────────────────

/// Shifts a byte stream by `bit_offset` bits to the left, aligning block
/// data that starts at an arbitrary bit position to a byte boundary.
///
/// For bit_offset b, the formula is:
///   shifted[i] = (input[i] << b) | (input[i+1] >> (8 - b))
///
/// In streaming mode, we maintain a carry byte from the previous input.
struct BitShifter {
    bit_offset: u8,
    carry: u8,
    has_carry: bool,
}

impl BitShifter {
    fn new(bit_offset: u8) -> Self {
        debug_assert!(bit_offset < 8);
        Self {
            bit_offset,
            carry: 0,
            has_carry: false,
        }
    }

    /// Shift input bytes, writing output to `out`. Returns the number of
    /// shifted bytes written. The first call produces `input.len() - 1`
    /// bytes (one byte is consumed as carry); subsequent calls produce
    /// `input.len()` bytes.
    fn shift(&mut self, input: &[u8], out: &mut Vec<u8>) -> usize {
        if self.bit_offset == 0 {
            out.extend_from_slice(input);
            return input.len();
        }
        let b = self.bit_offset;
        let mut count = 0;
        for &byte in input {
            if self.has_carry {
                let shifted = (self.carry << b) | (byte >> (8 - b));
                out.push(shifted);
                count += 1;
            }
            self.carry = byte;
            self.has_carry = true;
        }
        count
    }
}

// ─── Bzip2 Decompressor ─────────────────────────────────────────────

/// Bzip2 decompressor with block-boundary checkpoint support.
///
/// Scans the compressed bitstream for the 48-bit block magic
/// (`0x314159265359`) to detect block boundaries. On restore, reconstructs
/// a valid bzip2 stream by prepending the stream header and bit-shifting
/// the data to align the block at a byte boundary.
pub struct Bzip2Decompressor {
    inner: BzDecompress,
    total_in: u64,
    total_out: u64,
    /// The stream header level byte ('1'-'9'), read from the stream.
    stream_level: u8,
    /// Whether we've parsed the stream header.
    header_parsed: bool,
    /// Block counter (from scanner).
    block_count: u64,
    /// Block boundary scanner.
    scanner: MagicScanner,
    /// Last block boundary for checkpointing.
    last_block_boundary: Option<BlockBoundary>,
    /// Whether we're in restore mode (mid-stream resume).
    restore_active: bool,
    /// Stream header to prepend on restore.
    restore_header: Vec<u8>,
    /// Bit shifter for non-byte-aligned restore.
    bit_shifter: Option<BitShifter>,
    /// Buffer of shifted bytes not yet consumed by the decoder.
    shift_buffer: Vec<u8>,
}

impl Bzip2Decompressor {
    pub fn new() -> Self {
        Self {
            inner: BzDecompress::new(false),
            total_in: 0,
            total_out: 0,
            stream_level: 0,
            header_parsed: false,
            block_count: 0,
            scanner: MagicScanner::new(),
            last_block_boundary: None,
            restore_active: false,
            restore_header: Vec::new(),
            bit_shifter: None,
            shift_buffer: Vec::new(),
        }
    }
}

impl Bzip2Decompressor {
    /// Decompress a chunk normally (single call to inner decompressor) and
    /// feed consumed bytes to the scanner with the post-call `total_out`.
    fn decompress_and_scan(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        let before_in = self.inner.total_in();
        let before_out = self.inner.total_out();

        let status = self
            .inner
            .decompress(input, output)
            .map_err(|e| Error::DecompressionError(format!("bzip2: {}", e)))?;

        let consumed = (self.inner.total_in() - before_in) as usize;
        let produced = (self.inner.total_out() - before_out) as usize;
        self.total_in += consumed as u64;
        self.total_out += produced as u64;

        if consumed > 0 {
            self.scanner.feed(&input[..consumed], self.total_out);
            if let Some(boundary) = self.scanner.take_boundary() {
                self.block_count = boundary.block_index;
                self.last_block_boundary = Some(boundary);
            }
        }

        let status = match status {
            bzip2::Status::Ok => DecompressStatus::Continue,
            bzip2::Status::MemNeeded => DecompressStatus::Continue,
            bzip2::Status::RunOk | bzip2::Status::FlushOk | bzip2::Status::FinishOk => {
                DecompressStatus::Continue
            }
            bzip2::Status::StreamEnd => DecompressStatus::StreamEnd,
        };

        Ok(DecompressResult {
            bytes_consumed: consumed,
            bytes_produced: produced,
            status,
        })
    }
}

impl Default for Bzip2Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Decompressor for Bzip2Decompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        // ── Restore mode: bit-shift input and prepend header ──
        if self.restore_active {
            return self.decompress_restore(input, output);
        }

        // ── Normal mode ──

        // Capture the stream level from the header if not yet parsed
        if !self.header_parsed && input.len() >= 4 && &input[0..2] == b"BZ" && input[2] == b'h' {
            self.stream_level = input[3];
            self.header_parsed = true;
        }

        // Pre-scan the input for block boundary positions (cheap bit ops only).
        // If none are found, decompress the whole chunk in one call (fast path).
        // If boundaries exist, split the decompression at each boundary byte so
        // that total_out is precise when the scanner records the boundary.
        let boundary_positions = self.scanner.find_boundary_positions(input);

        if boundary_positions.is_empty() {
            return self.decompress_and_scan(input, output);
        }

        // Build segment endpoints: each boundary detection byte ends a segment,
        // plus one final segment for the remainder.
        let mut total_consumed = 0;
        let mut total_produced = 0;
        let mut final_status = DecompressStatus::Continue;

        let mut segment_starts: Vec<usize> = vec![0];
        for &pos in &boundary_positions {
            segment_starts.push(pos + 1);
        }

        for (seg_idx, &seg_start) in segment_starts.iter().enumerate() {
            let seg_end = if seg_idx < boundary_positions.len() {
                boundary_positions[seg_idx] + 1
            } else {
                input.len()
            };
            if seg_start >= input.len() || seg_start >= seg_end {
                break;
            }

            // Decompress this segment (may need multiple calls if the
            // decompressor doesn't consume it all at once).
            let mut seg_consumed = 0;
            while seg_start + seg_consumed < seg_end {
                let seg_input = &input[seg_start + seg_consumed..seg_end];
                let out_slice = &mut output[total_produced..];
                if out_slice.is_empty() {
                    // Output buffer full — report partial progress.
                    return Ok(DecompressResult {
                        bytes_consumed: total_consumed + seg_consumed,
                        bytes_produced: total_produced,
                        status: final_status,
                    });
                }
                let result = self.decompress_and_scan(seg_input, out_slice)?;
                seg_consumed += result.bytes_consumed;
                total_produced += result.bytes_produced;
                if result.status == DecompressStatus::StreamEnd {
                    final_status = DecompressStatus::StreamEnd;
                    break;
                }
                if result.bytes_consumed == 0 && result.bytes_produced == 0 {
                    break;
                }
            }
            total_consumed += seg_consumed;
            if final_status == DecompressStatus::StreamEnd {
                break;
            }
        }

        Ok(DecompressResult {
            bytes_consumed: total_consumed,
            bytes_produced: total_produced,
            status: final_status,
        })
    }

    fn checkpoint(&self, _compressed_offset: u64, _uncompressed_offset: u64) -> Result<Checkpoint> {
        // Return the last block boundary (like gzip/xz pattern).
        if let Some(ref boundary) = self.last_block_boundary {
            Ok(Checkpoint {
                compressed_offset: boundary.byte_offset,
                bit_offset: boundary.bit_offset,
                uncompressed_offset: boundary.uncompressed_offset,
                state: CheckpointState::Bzip2(Bzip2CheckpointState {
                    block_number: boundary.block_index,
                    stream_header: vec![b'B', b'Z', b'h', self.stream_level],
                }),
            })
        } else {
            // No block boundary yet — fall back to stream start.
            Ok(Checkpoint {
                compressed_offset: 0,
                bit_offset: 0,
                uncompressed_offset: 0,
                state: CheckpointState::None,
            })
        }
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        match &checkpoint.state {
            CheckpointState::Bzip2(s) => {
                self.inner = BzDecompress::new(false);
                self.total_in = checkpoint.compressed_offset;
                self.total_out = checkpoint.uncompressed_offset;
                self.block_count = s.block_number;
                self.stream_level = *s.stream_header.last().unwrap_or(&0);
                self.header_parsed = true;
                self.restore_active = true;

                // Save stream header for prepending
                self.restore_header = s.stream_header.clone();

                // Set up bit-shifter if block is not byte-aligned
                if checkpoint.bit_offset > 0 {
                    self.bit_shifter = Some(BitShifter::new(checkpoint.bit_offset));
                } else {
                    self.bit_shifter = None;
                }
                self.shift_buffer.clear();

                // Reset scanner for the restored stream
                self.scanner = MagicScanner::new();
                self.last_block_boundary = None;
                Ok(())
            }
            CheckpointState::None => {
                self.inner = BzDecompress::new(false);
                self.total_in = 0;
                self.total_out = 0;
                self.block_count = 0;
                self.stream_level = 0;
                self.header_parsed = false;
                self.restore_active = false;
                self.restore_header.clear();
                self.bit_shifter = None;
                self.shift_buffer.clear();
                self.scanner = MagicScanner::new();
                self.last_block_boundary = None;
                Ok(())
            }
            _ => Err(Error::CheckpointError(
                "expected bzip2 checkpoint state".into(),
            )),
        }
    }
}

impl Bzip2Decompressor {
    /// Decompress in restore mode: prepend stream header, bit-shift input,
    /// and suppress CRC validation error at end of stream.
    fn decompress_restore(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        // Phase 1: Feed the stream header to the fresh decoder
        if !self.restore_header.is_empty() {
            let header = std::mem::take(&mut self.restore_header);
            let before_in = self.inner.total_in();
            let before_out = self.inner.total_out();
            let result = self.inner.decompress(&header, output);

            let consumed_h = (self.inner.total_in() - before_in) as usize;
            let produced = (self.inner.total_out() - before_out) as usize;

            match result {
                Ok(_) => {
                    if consumed_h < header.len() {
                        // Header not fully consumed — save remainder
                        self.restore_header = header[consumed_h..].to_vec();
                    }
                    if produced > 0 {
                        self.total_out += produced as u64;
                        return Ok(DecompressResult {
                            bytes_consumed: 0,
                            bytes_produced: produced,
                            status: DecompressStatus::Continue,
                        });
                    }
                    if !self.restore_header.is_empty() {
                        return Ok(DecompressResult {
                            bytes_consumed: 0,
                            bytes_produced: 0,
                            status: DecompressStatus::Continue,
                        });
                    }
                    // Header fully consumed, fall through to process input
                }
                Err(e) => {
                    return Err(Error::DecompressionError(format!("bzip2 header: {}", e)));
                }
            }
        }

        // Phase 2: Bit-shift input and feed to decoder

        // Build the feed buffer: any leftover shifted bytes + newly shifted bytes
        let mut feed = std::mem::take(&mut self.shift_buffer);
        if let Some(ref mut shifter) = self.bit_shifter {
            shifter.shift(input, &mut feed);
        } else {
            feed.extend_from_slice(input);
        }

        if feed.is_empty() {
            return Ok(DecompressResult {
                bytes_consumed: input.len(),
                bytes_produced: 0,
                status: DecompressStatus::Continue,
            });
        }

        let before_in = self.inner.total_in();
        let before_out = self.inner.total_out();

        let result = self.inner.decompress(&feed, output);

        let consumed_d = (self.inner.total_in() - before_in) as usize;
        let produced = (self.inner.total_out() - before_out) as usize;
        self.total_out += produced as u64;

        // Buffer any shifted bytes not consumed by the decoder
        if consumed_d < feed.len() {
            self.shift_buffer = feed[consumed_d..].to_vec();
        }

        // We always consume all input bytes (the shifter processed them).
        // Unconsumed shifted bytes are buffered for the next call.
        let original_consumed = input.len();

        match result {
            Ok(status) => {
                let status = match status {
                    bzip2::Status::Ok => DecompressStatus::Continue,
                    bzip2::Status::MemNeeded => DecompressStatus::Continue,
                    bzip2::Status::RunOk | bzip2::Status::FlushOk | bzip2::Status::FinishOk => {
                        DecompressStatus::Continue
                    }
                    bzip2::Status::StreamEnd => DecompressStatus::StreamEnd,
                };
                Ok(DecompressResult {
                    bytes_consumed: original_consumed,
                    bytes_produced: produced,
                    status,
                })
            }
            Err(_) => {
                // In restore mode, the combined CRC at end-of-stream won't
                // match (it includes blocks we skipped). If the decoder has
                // produced output, treat this as StreamEnd.
                if produced > 0 || self.total_out > 0 {
                    Ok(DecompressResult {
                        bytes_consumed: original_consumed,
                        bytes_produced: produced,
                        status: DecompressStatus::StreamEnd,
                    })
                } else {
                    Err(Error::DecompressionError(
                        "bzip2 restore: decompression error before any output".into(),
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bzip2::write::BzEncoder;
    use bzip2::Compression;
    use std::io::Write;

    fn compress_bz2(data: &[u8]) -> Vec<u8> {
        let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Compress data with the smallest block size (100KB) to produce
    /// multiple blocks from relatively small input.
    fn compress_bz2_small_blocks(data: &[u8]) -> Vec<u8> {
        let mut encoder = BzEncoder::new(Vec::new(), Compression::new(1));
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Full decompression loop for testing.
    fn full_decompress(compressed: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut dec = Bzip2Decompressor::new();
        let mut all_output = Vec::new();
        let mut offset = 0;

        loop {
            let end = (offset + chunk_size).min(compressed.len());
            let input = if offset < compressed.len() {
                &compressed[offset..end]
            } else {
                &[]
            };

            let mut output = vec![0u8; 1024 * 1024];
            let result = dec.decompress(input, &mut output).unwrap();
            all_output.extend_from_slice(&output[..result.bytes_produced]);
            offset += result.bytes_consumed;

            if result.status == DecompressStatus::StreamEnd {
                break;
            }
            if result.bytes_consumed == 0
                && result.bytes_produced == 0
                && offset >= compressed.len()
            {
                break;
            }
        }

        all_output
    }

    #[test]
    fn test_basic_decompress() {
        let original = b"Hello, world! This is a test of bzip2 decompression.";
        let compressed = compress_bz2(original);

        let mut dec = Bzip2Decompressor::new();
        let mut output = vec![0u8; 256];
        let result = dec.decompress(&compressed, &mut output).unwrap();

        assert_eq!(result.bytes_produced, original.len());
        assert_eq!(&output[..result.bytes_produced], &original[..]);
    }

    #[test]
    fn test_incremental_decompress() {
        let original = b"Hello, world! This is a test of bzip2 decompression with chunks.";
        let compressed = compress_bz2(original);

        let mut dec = Bzip2Decompressor::new();
        let mut all_output = Vec::new();
        let mut offset = 0;

        while offset < compressed.len() {
            let chunk_end = (offset + 10).min(compressed.len());
            let mut output = vec![0u8; 256];
            let result = dec
                .decompress(&compressed[offset..chunk_end], &mut output)
                .unwrap();
            all_output.extend_from_slice(&output[..result.bytes_produced]);
            offset += result.bytes_consumed;
            if result.status == DecompressStatus::StreamEnd {
                break;
            }
        }

        assert_eq!(&all_output, &original[..]);
    }

    #[test]
    fn test_stream_level_detection() {
        let original = b"test data";
        let compressed = compress_bz2(original);

        let mut dec = Bzip2Decompressor::new();
        let mut output = vec![0u8; 256];
        let _result = dec.decompress(&compressed, &mut output).unwrap();

        assert!(dec.header_parsed);
        assert!(dec.stream_level >= b'1' && dec.stream_level <= b'9');
    }

    #[test]
    fn test_checkpoint() {
        let original = b"test data for checkpoint";
        let compressed = compress_bz2(original);

        let mut dec = Bzip2Decompressor::new();
        let mut output = vec![0u8; 256];
        let _result = dec.decompress(&compressed, &mut output).unwrap();

        let cp = dec.checkpoint(100, 200).unwrap();
        // Single-block data — no mid-stream boundary, falls back to start
        assert_eq!(cp.compressed_offset, 0);
        assert_eq!(cp.uncompressed_offset, 0);
    }

    #[test]
    fn test_magic_scanner_detects_blocks() {
        // Use enough data to create multiple bzip2 blocks (100KB block size)
        let original: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
        let compressed = compress_bz2_small_blocks(&original);

        let output = full_decompress(&compressed, 4096);
        assert_eq!(output, original);

        // Run again with scanner tracking
        let mut dec = Bzip2Decompressor::new();
        let mut all_output = Vec::new();
        let mut offset = 0;
        loop {
            let end = (offset + 4096).min(compressed.len());
            let input = if offset < compressed.len() {
                &compressed[offset..end]
            } else {
                &[]
            };
            let mut out = vec![0u8; 1024 * 1024];
            let result = dec.decompress(input, &mut out).unwrap();
            all_output.extend_from_slice(&out[..result.bytes_produced]);
            offset += result.bytes_consumed;
            if result.status == DecompressStatus::StreamEnd
                || (result.bytes_consumed == 0
                    && result.bytes_produced == 0
                    && offset >= compressed.len())
            {
                break;
            }
        }
        assert_eq!(all_output, original);

        // Should have found multiple blocks
        assert!(
            dec.scanner.block_count >= 2,
            "expected multiple blocks with 300KB data at blocksize 1, got {}",
            dec.scanner.block_count
        );
        // Should have a checkpoint boundary
        assert!(
            dec.last_block_boundary.is_some(),
            "should have recorded a block boundary"
        );
    }

    #[test]
    fn test_bit_shifter_zero_offset() {
        let mut shifter = BitShifter::new(0);
        let input = [0x12, 0x34, 0x56, 0x78];
        let mut out = Vec::new();
        let count = shifter.shift(&input, &mut out);
        assert_eq!(count, 4);
        assert_eq!(out, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_bit_shifter_nonzero_offset() {
        let mut shifter = BitShifter::new(3);
        // Input: 0xAB = 10101011, 0xCD = 11001101, 0xEF = 11101111
        // Shifted by 3: first byte saved as carry
        // Output[0] = (0xAB << 3) | (0xCD >> 5) = 01011000 | 00000110 = 01011110
        // Output[1] = (0xCD << 3) | (0xEF >> 5) = 01101000 | 00000111 = 01101111
        let input = [0xAB, 0xCD, 0xEF];
        let mut out = Vec::new();
        let count = shifter.shift(&input, &mut out);
        assert_eq!(count, 2); // 3 input → 2 output (first is carry)
        assert_eq!(out[0], (0xABu8.wrapping_shl(3)) | (0xCD >> 5));
        assert_eq!(out[1], (0xCDu8.wrapping_shl(3)) | (0xEF >> 5));
    }

    #[test]
    fn test_bit_shifter_streaming() {
        // Test that the shifter works across multiple calls
        let mut shifter = BitShifter::new(4);
        let mut out = Vec::new();

        // First call: 2 bytes → 1 output
        let count = shifter.shift(&[0xAB, 0xCD], &mut out);
        assert_eq!(count, 1);
        assert_eq!(out[0], (0xABu8.wrapping_shl(4)) | (0xCD >> 4));

        // Second call: 1 byte → 1 output (using carry from previous)
        let count = shifter.shift(&[0xEF], &mut out);
        assert_eq!(count, 1);
        assert_eq!(out[1], (0xCDu8.wrapping_shl(4)) | (0xEF >> 4));
    }

    #[test]
    fn test_checkpoint_restore_multiblock() {
        // Create multi-block bzip2 data (100KB blocks, 300KB data = ~3 blocks)
        let original: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
        let compressed = compress_bz2_small_blocks(&original);

        // First pass: full decompress to capture checkpoint
        let mut dec = Bzip2Decompressor::new();
        let mut all_output = Vec::new();
        let mut offset = 0;
        loop {
            let end = (offset + 4096).min(compressed.len());
            let input = if offset < compressed.len() {
                &compressed[offset..end]
            } else {
                &[]
            };
            let mut out = vec![0u8; 1024 * 1024];
            let result = dec.decompress(input, &mut out).unwrap();
            all_output.extend_from_slice(&out[..result.bytes_produced]);
            offset += result.bytes_consumed;
            if result.status == DecompressStatus::StreamEnd
                || (result.bytes_consumed == 0
                    && result.bytes_produced == 0
                    && offset >= compressed.len())
            {
                break;
            }
        }
        assert_eq!(all_output, original);

        let cp = dec.checkpoint(0, 0).unwrap();
        if cp.compressed_offset == 0 {
            // Single block — no mid-stream checkpoint possible
            return;
        }

        // Restore and decompress from checkpoint
        let mut dec2 = Bzip2Decompressor::new();
        dec2.restore(&cp).unwrap();

        let mut restored_output = Vec::new();
        let mut off2 = cp.compressed_offset as usize;
        loop {
            let end = (off2 + 4096).min(compressed.len());
            let input = if off2 < compressed.len() {
                &compressed[off2..end]
            } else {
                &[]
            };
            let mut out = vec![0u8; 1024 * 1024];
            let result = dec2.decompress(input, &mut out).unwrap();
            restored_output.extend_from_slice(&out[..result.bytes_produced]);
            off2 += result.bytes_consumed;
            if result.status == DecompressStatus::StreamEnd
                || (result.bytes_consumed == 0
                    && result.bytes_produced == 0
                    && off2 >= compressed.len())
            {
                break;
            }
        }

        let expected_tail = &original[cp.uncompressed_offset as usize..];
        assert_eq!(
            restored_output.len(),
            expected_tail.len(),
            "restored output length ({}) doesn't match expected tail ({})",
            restored_output.len(),
            expected_tail.len()
        );
        assert_eq!(
            restored_output, expected_tail,
            "restored output doesn't match expected tail"
        );
    }

    #[test]
    fn test_checkpoint_restore_earlier_boundary() {
        // Restore from the FIRST boundary (not the last) to test
        // decompressing multiple blocks after restore.
        let original: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
        let compressed = compress_bz2_small_blocks(&original);

        // Full decompress to find all boundaries
        let mut dec = Bzip2Decompressor::new();
        let mut all_output = Vec::new();
        let mut offset = 0;
        let mut boundaries: Vec<BlockBoundary> = Vec::new();
        loop {
            let end = (offset + 100).min(compressed.len());
            let input = if offset < compressed.len() {
                &compressed[offset..end]
            } else {
                &[]
            };
            let mut out = vec![0u8; 1024 * 1024];
            let result = dec.decompress(input, &mut out).unwrap();
            all_output.extend_from_slice(&out[..result.bytes_produced]);
            offset += result.bytes_consumed;
            if let Some(ref b) = dec.last_block_boundary {
                if boundaries.last().map(|x| x.byte_offset) != Some(b.byte_offset) {
                    boundaries.push(b.clone());
                }
            }
            if result.status == DecompressStatus::StreamEnd
                || (result.bytes_consumed == 0
                    && result.bytes_produced == 0
                    && offset >= compressed.len())
            {
                break;
            }
        }
        assert_eq!(all_output, original);

        assert!(boundaries.len() >= 2, "need at least 2 boundaries");

        // Restore from the FIRST boundary
        let boundary = &boundaries[0];

        let cp = Checkpoint {
            compressed_offset: boundary.byte_offset,
            bit_offset: boundary.bit_offset,
            uncompressed_offset: boundary.uncompressed_offset,
            state: CheckpointState::Bzip2(Bzip2CheckpointState {
                block_number: boundary.block_index,
                stream_header: vec![b'B', b'Z', b'h', b'1'],
            }),
        };

        let mut dec2 = Bzip2Decompressor::new();
        dec2.restore(&cp).unwrap();

        let mut restored_output = Vec::new();
        let mut off2 = cp.compressed_offset as usize;
        loop {
            let end = (off2 + 4096).min(compressed.len());
            let input = if off2 < compressed.len() {
                &compressed[off2..end]
            } else {
                &[]
            };
            let mut out = vec![0u8; 1024 * 1024];
            let result = dec2.decompress(input, &mut out).unwrap();
            restored_output.extend_from_slice(&out[..result.bytes_produced]);
            off2 += result.bytes_consumed;
            if result.status == DecompressStatus::StreamEnd
                || (result.bytes_consumed == 0
                    && result.bytes_produced == 0
                    && off2 >= compressed.len())
            {
                break;
            }
        }

        let expected_tail = &original[boundary.uncompressed_offset as usize..];
        assert_eq!(
            restored_output.len(),
            expected_tail.len(),
            "restored {} bytes, expected {} bytes",
            restored_output.len(),
            expected_tail.len()
        );
        assert_eq!(
            restored_output, expected_tail,
            "restored output doesn't match expected tail"
        );
    }

    #[test]
    fn test_checkpoint_restore_with_rle_data() {
        // Data with many 4-byte repeated runs triggers bzip2's RLE1 step,
        // which changes the byte count per block.  A formula-based
        // uncompressed_offset (block_index * block_capacity) will drift;
        // only tracking actual decompressor output is correct.
        let mut original = Vec::with_capacity(400_000);
        for i in 0..400_000u32 {
            // Mix normal bytes with long runs of identical bytes
            if i % 500 < 20 {
                original.push(0xAA); // runs of 20 identical bytes
            } else {
                original.push((i % 251) as u8);
            }
        }
        let compressed = compress_bz2_small_blocks(&original);

        // Full decompress to capture checkpoint
        let mut dec = Bzip2Decompressor::new();
        let mut all_output = Vec::new();
        let mut offset = 0;
        loop {
            let end = (offset + 4096).min(compressed.len());
            let input = if offset < compressed.len() {
                &compressed[offset..end]
            } else {
                &[]
            };
            let mut out = vec![0u8; 1024 * 1024];
            let result = dec.decompress(input, &mut out).unwrap();
            all_output.extend_from_slice(&out[..result.bytes_produced]);
            offset += result.bytes_consumed;
            if result.status == DecompressStatus::StreamEnd
                || (result.bytes_consumed == 0
                    && result.bytes_produced == 0
                    && offset >= compressed.len())
            {
                break;
            }
        }
        assert_eq!(all_output, original);

        let cp = dec.checkpoint(0, 0).unwrap();
        if cp.compressed_offset == 0 {
            return; // single block, nothing to test
        }

        // The tracked offset must NOT equal the formula-based one
        // (RLE changes byte counts), unless they happen to coincide.
        // More importantly: restore + decompress must match.
        let mut dec2 = Bzip2Decompressor::new();
        dec2.restore(&cp).unwrap();

        let mut restored_output = Vec::new();
        let mut off2 = cp.compressed_offset as usize;
        loop {
            let end = (off2 + 4096).min(compressed.len());
            let input = if off2 < compressed.len() {
                &compressed[off2..end]
            } else {
                &[]
            };
            let mut out = vec![0u8; 1024 * 1024];
            let result = dec2.decompress(input, &mut out).unwrap();
            restored_output.extend_from_slice(&out[..result.bytes_produced]);
            off2 += result.bytes_consumed;
            if result.status == DecompressStatus::StreamEnd
                || (result.bytes_consumed == 0
                    && result.bytes_produced == 0
                    && off2 >= compressed.len())
            {
                break;
            }
        }

        let expected_tail = &original[cp.uncompressed_offset as usize..];
        assert_eq!(
            restored_output.len(),
            expected_tail.len(),
            "restored output length ({}) doesn't match expected tail ({})",
            restored_output.len(),
            expected_tail.len()
        );
        assert_eq!(
            restored_output, expected_tail,
            "restored output doesn't match expected tail"
        );
    }
}
