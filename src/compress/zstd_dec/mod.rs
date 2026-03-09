//! Zstd (Zstandard) decoder with full-state checkpointing.
//!
//! This module implements a sans-I/O zstd decompressor that processes
//! input slices and produces output. Unlike the C-library wrapper (`zstd` crate),
//! this decoder can checkpoint its FULL internal state at any byte offset
//! in the uncompressed stream, enabling efficient random access.
//!
//! Architecture:
//! - `frame.rs` — Frame header parsing (magic, descriptor, window size)
//! - `block.rs` — Block header parsing and block decompression
//! - `fse.rs` — FSE (Finite State Entropy) table building and decoding
//! - `huffman.rs` — Huffman table building and literal decompression
//! - `sequences.rs` — Sequence (LLL, Offset, ML) decoding and execution
//! - `bits.rs` — Bit readers (forward and backward)
//!
//! # Known limitations
//!
//! - **Content checksum (XXH64)**: The checksum flag is parsed and the 4
//!   trailing bytes are skipped, but the hash is not computed or verified.
//!   Corrupted data that is structurally valid will decompress without error.
//!
//! - **Content size validation**: Frame Content Size is parsed from the
//!   header but not enforced against actual decompressed output. A frame
//!   that produces more or fewer bytes than declared is not rejected.
//!
//! - **Dictionary support**: Dictionary IDs are parsed from the frame
//!   header but dictionaries are not supported. Frames that require a
//!   predefined dictionary will fail during decompression (missing context)
//!   rather than being cleanly rejected upfront.
//!
//! - **Window size limits**: Window size from the frame header is used for
//!   the sliding window, but no upper bound is enforced. A malicious frame
//!   could declare a very large window size causing high memory usage.
//!
//! - **Legacy frame formats**: Only the current zstd frame format (magic
//!   `0xFD2FB528`) and skippable frames are supported. Legacy formats from
//!   pre-1.0 zstd are not recognized.

pub(crate) mod bits;
pub(crate) mod block;
pub(crate) mod fse;
pub(crate) mod frame;
pub(crate) mod huffman;
pub(crate) mod sequences;

use serde::{Deserialize, Serialize};

use crate::compress::checkpoint::{Checkpoint, CheckpointState, ZstdFullCheckpointState};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::error::{Result, Error};

use block::{
    block_compressed_size, decompress_block, parse_block_header, BlockDecoderState, BlockType,
};
use frame::{check_skippable_frame, parse_frame_header, FrameHeader, ZSTD_MAGIC};

/// Processing state of the decompressor.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum DecoderPhase {
    /// Waiting for a frame header (or end of stream).
    FrameHeader,
    /// Currently decoding blocks within a frame.
    BlockHeader,
    /// Reading block data for decompression.
    BlockData {
        header_last: bool,
        block_type_raw: u8,
        block_size: usize,
        compressed_size: usize,
    },
    /// Frame finished, may read checksum.
    FrameChecksum {
        has_checksum: bool,
    },
    /// Stream is complete.
    Done,
}

/// Zstd decompressor with full-state checkpointing.
///
/// Implements the `Decompressor` trait for sans-I/O usage.
pub struct ZstdDecompressor {
    /// Current processing phase.
    phase: DecoderPhase,
    /// Internal buffer for accumulating partial input.
    buffer: Vec<u8>,
    /// Current frame header (set when parsing a frame).
    frame_header: Option<FrameHeader>,
    /// Block-level decoder state (FSE/Huffman tables, repeat offsets).
    block_state: BlockDecoderState,
    /// Window: recent output for back-references.
    window: Vec<u8>,
    /// Maximum window size for current frame.
    window_size: usize,
    /// Staged output: decoded bytes not yet delivered to the caller.
    staged_output: Vec<u8>,
    /// Position within staged_output.
    staged_pos: usize,
    /// Total compressed bytes consumed.
    total_in: u64,
    /// Total uncompressed bytes produced.
    total_out: u64,
    /// Whether the decompressor has reached the end.
    finished: bool,
}

impl Default for ZstdDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl ZstdDecompressor {
    /// Create a new zstd decompressor.
    pub fn new() -> Self {
        Self {
            phase: DecoderPhase::FrameHeader,
            buffer: Vec::new(),
            frame_header: None,
            block_state: BlockDecoderState::new(),
            window: Vec::new(),
            window_size: 0,
            staged_output: Vec::new(),
            staged_pos: 0,
            total_in: 0,
            total_out: 0,
            finished: false,
        }
    }

    /// Deliver staged output to the caller's output buffer.
    fn drain_staged(&mut self, output: &mut [u8]) -> usize {
        let available = self.staged_output.len() - self.staged_pos;
        let to_copy = available.min(output.len());
        if to_copy > 0 {
            output[..to_copy]
                .copy_from_slice(&self.staged_output[self.staged_pos..self.staged_pos + to_copy]);
            self.staged_pos += to_copy;
            if self.staged_pos >= self.staged_output.len() {
                self.staged_output.clear();
                self.staged_pos = 0;
            }
        }
        to_copy
    }

    /// Append data to the window, maintaining max window_size.
    fn append_to_window(&mut self, data: &[u8]) {
        self.window.extend_from_slice(data);
        if self.window.len() > self.window_size {
            let excess = self.window.len() - self.window_size;
            self.window.drain(..excess);
        }
    }

    /// Get the serializable state for checkpointing.
    fn get_checkpoint_state(&self) -> ZstdFullCheckpointState {
        ZstdFullCheckpointState {
            block_state: bincode::serialize(&self.block_state).unwrap_or_default(),
            window: self.window.clone(),
            window_size: self.window_size,
            phase: bincode::serialize(&self.phase).unwrap_or_default(),
            frame_header: self
                .frame_header
                .as_ref()
                .map(|h| bincode::serialize(h).unwrap_or_default()),
            buffer: self.buffer.clone(),
            staged_output: self.staged_output.clone(),
            staged_pos: self.staged_pos,
        }
    }

    /// Restore state from a checkpoint.
    fn restore_from_checkpoint_state(&mut self, state: &ZstdFullCheckpointState) -> Result<()> {
        self.block_state = bincode::deserialize(&state.block_state)
            .map_err(|e| Error::CheckpointError(format!("deserialize block_state: {}", e)))?;
        self.window = state.window.clone();
        self.window_size = state.window_size;
        self.phase = bincode::deserialize(&state.phase)
            .map_err(|e| Error::CheckpointError(format!("deserialize phase: {}", e)))?;
        self.frame_header = if let Some(ref fh_bytes) = state.frame_header {
            Some(
                bincode::deserialize(fh_bytes).map_err(|e| {
                    Error::CheckpointError(format!("deserialize frame_header: {}", e))
                })?,
            )
        } else {
            None
        };
        self.buffer = state.buffer.clone();
        self.staged_output = state.staged_output.clone();
        self.staged_pos = state.staged_pos;
        self.finished = false;
        Ok(())
    }
}

impl Decompressor for ZstdDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        // If we have staged output from a previous call, deliver it first
        if self.staged_pos < self.staged_output.len() {
            let produced = self.drain_staged(output);
            self.total_out += produced as u64;
            return Ok(DecompressResult {
                bytes_consumed: 0,
                bytes_produced: produced,
                status: if self.finished && self.staged_pos >= self.staged_output.len() {
                    DecompressStatus::StreamEnd
                } else {
                    DecompressStatus::Continue
                },
            });
        }

        if self.finished {
            return Ok(DecompressResult {
                bytes_consumed: 0,
                bytes_produced: 0,
                status: DecompressStatus::StreamEnd,
            });
        }

        if input.is_empty() && self.buffer.is_empty() {
            // No input available and nothing buffered — caller may have more data.
            // Don't set finished; the engine handles EOF via signal_eof() and
            // the 0/0 progress check.
            return Ok(DecompressResult {
                bytes_consumed: 0,
                bytes_produced: 0,
                status: DecompressStatus::Continue,
            });
        }

        // Append any new input to our internal buffer for accumulation.
        if !input.is_empty() {
            self.buffer.extend_from_slice(input);
        }
        let mut pos = 0;

        loop {
            match self.phase.clone() {
                DecoderPhase::FrameHeader => {
                    if pos + 4 > self.buffer.len() {
                        // Need more data
                        break;
                    }

                    // Check for skippable frame
                    if let Some(skip_size) = check_skippable_frame(&self.buffer[pos..]) {
                        if pos + skip_size > self.buffer.len() {
                            // Need more data for the skip
                            break;
                        }
                        pos += skip_size;
                        continue;
                    }

                    // Check magic
                    let magic = u32::from_le_bytes([
                        self.buffer[pos],
                        self.buffer[pos + 1],
                        self.buffer[pos + 2],
                        self.buffer[pos + 3],
                    ]);
                    if magic != ZSTD_MAGIC {
                        // Not a zstd frame, check if we got 0x00 bytes (padding)
                        // or just declare end of stream
                        self.finished = true;
                        self.phase = DecoderPhase::Done;
                        break;
                    }

                    // Try to parse frame header (need at least 5 bytes)
                    let available = &self.buffer[pos..];
                    match parse_frame_header(available) {
                        Ok(header) => {
                            self.window_size = header.window_size.max(1024);
                            // Clear block state for new frame
                            self.block_state = BlockDecoderState::new();
                            pos += header.header_size;
                            self.frame_header = Some(header);
                            self.phase = DecoderPhase::BlockHeader;
                        }
                        Err(_) => {
                            // May need more data
                            break;
                        }
                    }
                }
                DecoderPhase::BlockHeader => {
                    if pos + 3 > self.buffer.len() {
                        break;
                    }

                    let header = parse_block_header(&self.buffer[pos..]).map_err(|e| {
                        Error::DecompressionError(format!("block header: {}", e))
                    })?;
                    pos += 3;

                    let compressed_size = block_compressed_size(&header);

                    self.phase = DecoderPhase::BlockData {
                        header_last: header.is_last,
                        block_type_raw: header.block_type as u8,
                        block_size: header.block_size,
                        compressed_size,
                    };
                }
                DecoderPhase::BlockData {
                    header_last,
                    block_type_raw,
                    block_size,
                    compressed_size,
                } => {
                    if pos + compressed_size > self.buffer.len() {
                        break;
                    }

                    let block_type = match block_type_raw {
                        0 => BlockType::Raw,
                        1 => BlockType::Rle,
                        2 => BlockType::Compressed,
                        _ => {
                            return Err(Error::DecompressionError(
                                "invalid block type".into(),
                            ))
                        }
                    };

                    let block_header = block::BlockHeader {
                        is_last: header_last,
                        block_type,
                        block_size,
                    };

                    let block_data = &self.buffer[pos..pos + compressed_size];
                    let mut block_output = Vec::new();

                    decompress_block(
                        &block_header,
                        block_data,
                        &mut self.block_state,
                        &self.window,
                        &mut block_output,
                    )
                    .map_err(|e| {
                        Error::DecompressionError(format!("block decompress: {}", e))
                    })?;

                    pos += compressed_size;

                    // Append output to window
                    self.append_to_window(&block_output);

                    // Stage the output for delivery
                    self.staged_output.extend_from_slice(&block_output);

                    if header_last {
                        // Frame's last block
                        let has_checksum = self
                            .frame_header
                            .as_ref()
                            .map(|h| h.checksum_flag)
                            .unwrap_or(false);
                        self.phase = DecoderPhase::FrameChecksum { has_checksum };
                    } else {
                        self.phase = DecoderPhase::BlockHeader;
                    }

                    // Continue processing more blocks from the buffer
                    // to keep the buffer bounded (don't break here).
                }
                DecoderPhase::FrameChecksum { has_checksum } => {
                    if has_checksum {
                        if pos + 4 > self.buffer.len() {
                            break;
                        }
                        // Skip the checksum (we don't verify it)
                        pos += 4;
                    }
                    self.frame_header = None;
                    // Ready for next frame
                    self.phase = DecoderPhase::FrameHeader;
                }
                DecoderPhase::Done => {
                    self.finished = true;
                    break;
                }
            }
        }

        // We always buffer all input, so all input bytes are consumed.
        let bytes_consumed_from_input = input.len();

        // Remove consumed data from buffer
        if pos > 0 {
            self.buffer.drain(..pos);
        }

        self.total_in += bytes_consumed_from_input as u64;

        // Deliver staged output
        let produced = self.drain_staged(output);
        self.total_out += produced as u64;

        let status = if self.finished && self.staged_pos >= self.staged_output.len() {
            DecompressStatus::StreamEnd
        } else {
            DecompressStatus::Continue
        };

        Ok(DecompressResult {
            bytes_consumed: bytes_consumed_from_input,
            bytes_produced: produced,
            status,
        })
    }

    fn checkpoint(&self, compressed_offset: u64, uncompressed_offset: u64) -> Result<Checkpoint> {
        let state = self.get_checkpoint_state();
        Ok(Checkpoint {
            compressed_offset,
            bit_offset: 0,
            uncompressed_offset,
            state: CheckpointState::ZstdFull(state),
        })
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        match &checkpoint.state {
            CheckpointState::ZstdFull(state) => {
                self.restore_from_checkpoint_state(state)?;
                self.total_in = checkpoint.compressed_offset;
                self.total_out = checkpoint.uncompressed_offset;
                Ok(())
            }
            CheckpointState::None => {
                self.reset();
                Ok(())
            }
            _ => Err(Error::CheckpointError(
                "expected ZstdFull checkpoint state".into(),
            )),
        }
    }

    fn reset(&mut self) {
        self.phase = DecoderPhase::FrameHeader;
        self.buffer.clear();
        self.frame_header = None;
        self.block_state = BlockDecoderState::new();
        self.window.clear();
        self.window_size = 0;
        self.staged_output.clear();
        self.staged_pos = 0;
        self.total_in = 0;
        self.total_out = 0;
        self.finished = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::decompressor::{DecompressStatus, Decompressor};

    fn compress_zstd(data: &[u8]) -> Vec<u8> {
        zstd::encode_all(std::io::Cursor::new(data), 1).unwrap()
    }

    fn compress_zstd_level(data: &[u8], level: i32) -> Vec<u8> {
        zstd::encode_all(std::io::Cursor::new(data), level).unwrap()
    }

    fn compress_zstd_multiframe(data: &[u8], frame_size: usize) -> Vec<u8> {
        let mut result = Vec::new();
        for chunk in data.chunks(frame_size) {
            result.extend_from_slice(&zstd::encode_all(std::io::Cursor::new(chunk), 1).unwrap());
        }
        result
    }

    /// Full decompression loop.
    fn full_decompress(compressed: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut dec = ZstdDecompressor::new();
        let mut all_output = Vec::new();
        let mut offset = 0;

        loop {
            let end = (offset + chunk_size).min(compressed.len());
            let input = if offset < compressed.len() {
                &compressed[offset..end]
            } else {
                &[]
            };

            let mut output = vec![0u8; 256 * 1024];
            let result = dec.decompress(input, &mut output).unwrap();
            all_output.extend_from_slice(&output[..result.bytes_produced]);
            offset += result.bytes_consumed;

            if result.status == DecompressStatus::StreamEnd {
                break;
            }
            if result.bytes_consumed == 0 && result.bytes_produced == 0 && offset >= compressed.len()
            {
                // Need to flush with empty input
                let result = dec.decompress(&[], &mut output).unwrap();
                all_output.extend_from_slice(&output[..result.bytes_produced]);
                if result.status == DecompressStatus::StreamEnd {
                    break;
                }
                break;
            }
        }

        // Drain any remaining staged output
        loop {
            let mut output = vec![0u8; 65536];
            let result = dec.decompress(&[], &mut output).unwrap();
            if result.bytes_produced > 0 {
                all_output.extend_from_slice(&output[..result.bytes_produced]);
            }
            if result.bytes_produced == 0 {
                break;
            }
        }

        all_output
    }

    #[test]
    fn test_basic_decompress_small() {
        let original = b"Hello, world!";
        let compressed = compress_zstd(original);
        let output = full_decompress(&compressed, compressed.len());
        assert_eq!(&output, &original[..]);
    }

    #[test]
    fn test_basic_decompress_empty() {
        let original = b"";
        let compressed = compress_zstd(original);
        let output = full_decompress(&compressed, compressed.len());
        assert_eq!(&output, &original[..]);
    }

    #[test]
    fn test_decompress_repeated_data() {
        let original = "abcdefgh".repeat(100);
        let compressed = compress_zstd(original.as_bytes());
        let output = full_decompress(&compressed, compressed.len());
        assert_eq!(output, original.as_bytes());
    }

    #[test]
    fn test_decompress_incremental() {
        let original = b"Hello, world! This is a test of the zstd decoder.";
        let compressed = compress_zstd(original);
        let output = full_decompress(&compressed, 10);
        assert_eq!(&output, &original[..]);
    }

    #[test]
    fn test_decompress_large_data() {
        let original: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let compressed = compress_zstd(&original);
        let output = full_decompress(&compressed, 4096);
        assert_eq!(output, original);
    }

    #[test]
    fn test_decompress_multiframe() {
        let original: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        let compressed = compress_zstd_multiframe(&original, 2000);
        let output = full_decompress(&compressed, 4096);
        assert_eq!(output, original);
    }

    #[test]
    fn test_checkpoint_restore() {
        let original: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        let compressed = compress_zstd_multiframe(&original, 2000);

        // Decompress partially, take checkpoint
        let mut dec = ZstdDecompressor::new();
        let mut all_output = Vec::new();
        let mut offset = 0;
        let mut checkpoint_saved = None;

        while offset < compressed.len() {
            let end = (offset + 4096).min(compressed.len());
            let mut output = vec![0u8; 65536];
            let result = dec
                .decompress(&compressed[offset..end], &mut output)
                .unwrap();
            all_output.extend_from_slice(&output[..result.bytes_produced]);
            offset += result.bytes_consumed;

            // Take checkpoint after producing some output
            if all_output.len() >= 3000 && checkpoint_saved.is_none() {
                checkpoint_saved = Some(dec.checkpoint(offset as u64, all_output.len() as u64).unwrap());
            }

            if result.status == DecompressStatus::StreamEnd {
                break;
            }
        }
        // Drain remaining
        loop {
            let mut output = vec![0u8; 65536];
            let result = dec.decompress(&[], &mut output).unwrap();
            if result.bytes_produced > 0 {
                all_output.extend_from_slice(&output[..result.bytes_produced]);
            }
            if result.bytes_produced == 0 {
                break;
            }
        }
        assert_eq!(all_output, original);

        // Restore from checkpoint
        if let Some(cp) = checkpoint_saved {
            let mut dec2 = ZstdDecompressor::new();
            dec2.restore(&cp).unwrap();

            let mut restored_output = Vec::new();
            let mut off2 = cp.compressed_offset as usize;

            while off2 < compressed.len() {
                let end = (off2 + 4096).min(compressed.len());
                let mut output = vec![0u8; 65536];
                let result = dec2
                    .decompress(&compressed[off2..end], &mut output)
                    .unwrap();
                restored_output.extend_from_slice(&output[..result.bytes_produced]);
                off2 += result.bytes_consumed;

                if result.status == DecompressStatus::StreamEnd {
                    break;
                }
            }
            // Drain
            loop {
                let mut output = vec![0u8; 65536];
                let result = dec2.decompress(&[], &mut output).unwrap();
                if result.bytes_produced > 0 {
                    restored_output.extend_from_slice(&output[..result.bytes_produced]);
                }
                if result.bytes_produced == 0 {
                    break;
                }
            }

            let expected_tail = &original[cp.uncompressed_offset as usize..];
            assert_eq!(
                restored_output, expected_tail,
                "restored output ({} bytes) doesn't match expected ({} bytes)",
                restored_output.len(),
                expected_tail.len()
            );
        }
    }

    #[test]
    fn test_reset() {
        let original = b"Hello, world!";
        let compressed = compress_zstd(original);

        let mut dec = ZstdDecompressor::new();
        let output = full_decompress(&compressed, compressed.len());
        assert_eq!(&output, &original[..]);

        dec.reset();
        // Should be able to decompress again
        let output2 = full_decompress(&compressed, compressed.len());
        assert_eq!(&output2, &original[..]);
    }

    #[test]
    fn test_decompress_high_compression_level() {
        // Higher compression levels use Huffman-coded literals with FSE-compressed
        // weight tables more often, exercising the two-interleaved-state FSE decode.
        let original: Vec<u8> = (0..50_000)
            .map(|i| {
                // Mix of patterns to encourage Huffman coding
                let v = ((i * 7 + 13) % 256) as u8;
                if i % 100 < 50 { v } else { v ^ 0xFF }
            })
            .collect();
        let compressed = compress_zstd_level(&original, 19);
        let output = full_decompress(&compressed, 4096);
        assert_eq!(output, original);
    }

    // ─── Golden reference file tests ───
    //
    // These test against the official zstd golden decompression vectors from
    // the zstd 1.5.6 source tree. They exercise edge cases that the reference
    // implementation explicitly tests for.

    /// Decompress a golden file and compare against the reference zstd crate.
    fn verify_golden(compressed: &[u8], chunk_size: usize) {
        let expected = zstd::decode_all(std::io::Cursor::new(compressed)).unwrap();
        let output = full_decompress(compressed, chunk_size);
        assert_eq!(output.len(), expected.len(), "length mismatch");
        assert_eq!(output, expected);
    }

    #[test]
    fn test_golden_rle_first_block() {
        // 1 MiB of zeros, encoded with an RLE block as the first block.
        let compressed = include_bytes!(
            "../../../tests/vectors/zstd/golden-decompression/rle-first-block.zst"
        );
        verify_golden(compressed, 4096);
    }

    #[test]
    fn test_golden_empty_block() {
        // Frame containing an empty block — decompresses to 0 bytes.
        let compressed = include_bytes!(
            "../../../tests/vectors/zstd/golden-decompression/empty-block.zst"
        );
        verify_golden(compressed, compressed.len());
    }

    #[test]
    fn test_golden_block_128k() {
        // Frame with a 128 KiB block.
        let compressed = include_bytes!(
            "../../../tests/vectors/zstd/golden-decompression/block-128k.zst"
        );
        verify_golden(compressed, 4096);
    }

    #[test]
    fn test_golden_zero_seq_2b() {
        // Minimal frame with a 2-byte zero sequence section.
        let compressed = include_bytes!(
            "../../../tests/vectors/zstd/golden-decompression/zeroSeq_2B.zst"
        );
        verify_golden(compressed, compressed.len());
    }

    #[test]
    fn test_golden_rle_first_block_incremental() {
        // Same as above but fed in tiny 64-byte chunks.
        let compressed = include_bytes!(
            "../../../tests/vectors/zstd/golden-decompression/rle-first-block.zst"
        );
        verify_golden(compressed, 64);
    }

    #[test]
    fn test_golden_block_128k_incremental() {
        let compressed = include_bytes!(
            "../../../tests/vectors/zstd/golden-decompression/block-128k.zst"
        );
        verify_golden(compressed, 64);
    }

    // ─── Golden compression round-trip tests ───
    //
    // Compress the official golden compression test inputs at various levels,
    // then decompress with our decoder.

    #[test]
    fn test_golden_compress_http() {
        let original = include_bytes!(
            "../../../tests/vectors/zstd/golden-compression/http"
        );
        for level in [1, 3, 9, 15, 19] {
            let compressed = compress_zstd_level(original, level);
            let output = full_decompress(&compressed, 4096);
            assert_eq!(&output, &original[..], "mismatch at level {level}");
        }
    }

    #[test]
    fn test_golden_compress_huffman_compressed_larger() {
        // This input expands under compression — tests raw/RLE block fallback.
        let original = include_bytes!(
            "../../../tests/vectors/zstd/golden-compression/huffman-compressed-larger"
        );
        for level in [1, 3, 9, 15, 19] {
            let compressed = compress_zstd_level(original, level);
            let output = full_decompress(&compressed, 4096);
            assert_eq!(&output, &original[..], "mismatch at level {level}");
        }
    }

    #[test]
    fn test_golden_compress_large_literal_and_match_lengths() {
        // 200 KB of data that exercises large literal and match length codes.
        let original = include_bytes!(
            "../../../tests/vectors/zstd/golden-compression/large-literal-and-match-lengths"
        );
        for level in [1, 3, 9, 19] {
            let compressed = compress_zstd_level(original, level);
            let output = full_decompress(&compressed, 4096);
            assert_eq!(output.len(), original.len(), "length mismatch at level {level}");
            assert_eq!(&output, &original[..], "mismatch at level {level}");
        }
    }

    #[test]
    fn test_golden_compress_block_splitter() {
        // 256 KB regression test for block splitter corruption.
        let original = include_bytes!(
            "../../../tests/vectors/zstd/golden-compression/PR-3517-block-splitter-corruption-test"
        );
        for level in [1, 9, 19] {
            let compressed = compress_zstd_level(original, level);
            let output = full_decompress(&compressed, 4096);
            assert_eq!(output.len(), original.len(), "length mismatch at level {level}");
            assert_eq!(&output, &original[..], "mismatch at level {level}");
        }
    }

    // ─── Diverse data pattern tests ───

    /// Simple deterministic PRNG for reproducible test data.
    fn prng_data(seed: u64, size: usize) -> Vec<u8> {
        let mut state = seed;
        (0..size)
            .map(|_| {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (state >> 33) as u8
            })
            .collect()
    }

    #[test]
    fn test_all_compression_levels() {
        // Exercises every zstd compression level (1-19).
        // Different levels produce fundamentally different block structures:
        // 1-3: greedy/fast, 4-9: lazy matching, 10-19: optimal parsing + Huffman literals.
        let original = prng_data(12345, 50_000);
        for level in 1..=19 {
            let compressed = compress_zstd_level(&original, level);
            let output = full_decompress(&compressed, 4096);
            assert_eq!(output, original, "mismatch at level {level}");
        }
    }

    #[test]
    fn test_all_zeros() {
        // All-zero data triggers RLE blocks.
        let original = vec![0u8; 100_000];
        let compressed = compress_zstd(&original);
        let output = full_decompress(&compressed, 4096);
        assert_eq!(output, original);
    }

    #[test]
    fn test_single_byte() {
        let original = vec![42u8; 1];
        let compressed = compress_zstd(&original);
        let output = full_decompress(&compressed, 4096);
        assert_eq!(output, original);
    }

    #[test]
    fn test_incompressible_random() {
        // Highly random data — likely produces raw (uncompressed) blocks.
        let original = prng_data(99999, 100_000);
        let compressed = compress_zstd_level(&original, 1);
        let output = full_decompress(&compressed, 4096);
        assert_eq!(output, original);
    }

    #[test]
    fn test_repeating_pattern_various_periods() {
        // Varying repeat periods exercise different match-distance encodings.
        for period in [1, 2, 3, 7, 16, 255, 1024] {
            let original: Vec<u8> = (0..50_000).map(|i| (i % period) as u8).collect();
            let compressed = compress_zstd(&original);
            let output = full_decompress(&compressed, 4096);
            assert_eq!(output, original, "mismatch for period {period}");
        }
    }

    #[test]
    fn test_multiframe_various_sizes() {
        // Multi-frame with varying frame sizes.
        let original = prng_data(54321, 100_000);
        for frame_size in [500, 2048, 8192, 32768] {
            let compressed = compress_zstd_multiframe(&original, frame_size);
            let output = full_decompress(&compressed, 4096);
            assert_eq!(output, original, "mismatch for frame_size {frame_size}");
        }
    }

    #[test]
    fn test_tiny_input_chunks() {
        // Feed compressed data 1 byte at a time.
        let original = prng_data(11111, 10_000);
        let compressed = compress_zstd(&original);
        let output = full_decompress(&compressed, 1);
        assert_eq!(output, original);
    }

    #[test]
    fn test_checkpoint_restore_golden() {
        // Checkpoint/restore with the large golden compression file.
        let original = include_bytes!(
            "../../../tests/vectors/zstd/golden-compression/large-literal-and-match-lengths"
        );
        let compressed = compress_zstd_level(original, 3);

        let mut dec = ZstdDecompressor::new();
        let mut all_output = Vec::new();
        let mut offset = 0;
        let mut checkpoint_saved = None;
        let mut output_at_checkpoint = 0;

        // Decompress until we have >50KB, then checkpoint
        while offset < compressed.len() {
            let end = (offset + 4096).min(compressed.len());
            let mut output = vec![0u8; 256 * 1024];
            let result = dec.decompress(&compressed[offset..end], &mut output).unwrap();
            all_output.extend_from_slice(&output[..result.bytes_produced]);
            offset += result.bytes_consumed;

            if all_output.len() >= 50_000 && checkpoint_saved.is_none() {
                checkpoint_saved = Some(dec.checkpoint(offset as u64, all_output.len() as u64).unwrap());
                output_at_checkpoint = all_output.len();
            }

            if result.status == DecompressStatus::StreamEnd {
                break;
            }
        }

        // Drain
        loop {
            let mut output = vec![0u8; 65536];
            let result = dec.decompress(&[], &mut output).unwrap();
            if result.bytes_produced > 0 {
                all_output.extend_from_slice(&output[..result.bytes_produced]);
            } else {
                break;
            }
        }

        assert_eq!(&all_output, &original[..]);

        // Now restore from checkpoint and decompress the rest
        let checkpoint = checkpoint_saved.unwrap();
        let restore_offset = checkpoint.compressed_offset as usize;
        let mut dec2 = ZstdDecompressor::new();
        dec2.restore(&checkpoint).unwrap();

        let mut restored_output = Vec::new();
        let mut offset = restore_offset;

        while offset < compressed.len() {
            let end = (offset + 4096).min(compressed.len());
            let mut output = vec![0u8; 256 * 1024];
            let result = dec2.decompress(&compressed[offset..end], &mut output).unwrap();
            restored_output.extend_from_slice(&output[..result.bytes_produced]);
            offset += result.bytes_consumed;

            if result.status == DecompressStatus::StreamEnd {
                break;
            }
        }

        loop {
            let mut output = vec![0u8; 65536];
            let result = dec2.decompress(&[], &mut output).unwrap();
            if result.bytes_produced > 0 {
                restored_output.extend_from_slice(&output[..result.bytes_produced]);
            } else {
                break;
            }
        }

        assert_eq!(restored_output, all_output[output_at_checkpoint..]);
    }
}
