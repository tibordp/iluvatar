//! Pure-Rust XZ decompressor with full-state checkpointing.
//!
//! Parses the XZ container format (stream header, block headers, index) and
//! delegates LZMA2 payload decompression to the pure-Rust LZMA2 decoder.
//! All internal state is serializable, enabling checkpoints at any byte offset.

use serde::{Deserialize, Serialize};

use crate::compress::checkpoint::{Checkpoint, CheckpointState, XzFullCheckpointState};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::compress::lzma::Lzma2Decompressor;
use crate::error::{Result, SupertarError};

/// XZ stream header magic bytes.
const XZ_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];

/// Check type sizes indexed by the check type ID from stream flags.
fn check_size_for_id(id: u8) -> usize {
    match id {
        0x00 => 0,  // None
        0x01 => 4,  // CRC32
        0x04 => 8,  // CRC64
        0x0A => 32, // SHA-256
        _ => 0,     // Unknown/reserved
    }
}

/// Decode an XZ variable-length integer (VLI) from data.
/// Returns (value, bytes_consumed) or None if incomplete.
fn decode_vli(data: &[u8]) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 9 {
            return None; // VLI too long
        }
        val |= ((byte & 0x7F) as u64) << (i * 7);
        if byte & 0x80 == 0 {
            return Some((val, i + 1));
        }
    }
    None // Incomplete
}

/// Processing phase of the XZ decompressor.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum XzPhase {
    /// Reading the 12-byte stream header.
    StreamHeader,
    /// Expecting block indicator byte (>0 = block, 0 = index).
    BlockStart,
    /// Reading block header bytes.
    BlockHeader { total_size: usize },
    /// Decompressing LZMA2 data within a block.
    Lzma2Data,
    /// Skipping integrity check bytes after LZMA2 data.
    Check { remaining: usize },
    /// Skipping block padding (0-3 bytes to 4-byte alignment).
    Padding { remaining: usize },
    /// Skipping the XZ index (we don't verify it).
    Index,
    /// Stream complete.
    Done,
}

/// Pure-Rust XZ decompressor with full-state checkpointing.
pub struct XzDecompressor {
    phase: XzPhase,
    /// Internal buffer for accumulating partial input.
    buffer: Vec<u8>,
    /// LZMA2 decoder for the current block's payload.
    lzma2: Option<Lzma2Decompressor>,
    /// Check type size (from stream header flags).
    check_size: usize,
    /// Saved stream header (12 bytes).
    stream_header: [u8; 12],
    /// Bytes consumed in the current block's LZMA2+check+padding region.
    /// Used to compute padding alignment.
    block_data_bytes: u64,
    /// Block header size for the current block.
    block_header_size: usize,
    /// Staged output waiting to be delivered.
    staged_output: Vec<u8>,
    staged_pos: usize,
    /// Total compressed bytes consumed.
    total_in: u64,
    /// Total uncompressed bytes produced.
    total_out: u64,
    finished: bool,
}

impl Default for XzDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl XzDecompressor {
    pub fn new() -> Self {
        Self {
            phase: XzPhase::StreamHeader,
            buffer: Vec::new(),
            lzma2: None,
            check_size: 0,
            stream_header: [0u8; 12],
            block_data_bytes: 0,
            block_header_size: 0,
            staged_output: Vec::new(),
            staged_pos: 0,
            total_in: 0,
            total_out: 0,
            finished: false,
        }
    }

    /// Drain staged output to the caller's output buffer.
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

    /// Parse a block header to extract the LZMA2 dictionary size property byte.
    fn parse_block_header(header_data: &[u8]) -> std::result::Result<u8, String> {
        if header_data.len() < 6 {
            return Err("block header too short".into());
        }

        let flags = header_data[1];
        let num_filters = (flags & 0x03) + 1;
        if num_filters != 1 {
            return Err(format!("unsupported filter count: {}", num_filters));
        }

        let mut pos = 2;

        // Skip optional compressed size
        if flags & 0x40 != 0 {
            if let Some((_, len)) = decode_vli(&header_data[pos..]) {
                pos += len;
            } else {
                return Err("bad compressed size VLI".into());
            }
        }

        // Skip optional uncompressed size
        if flags & 0x80 != 0 {
            if let Some((_, len)) = decode_vli(&header_data[pos..]) {
                pos += len;
            } else {
                return Err("bad uncompressed size VLI".into());
            }
        }

        // Parse filter: expect LZMA2 (filter ID 0x21)
        if pos >= header_data.len() {
            return Err("block header truncated at filter".into());
        }
        let (filter_id, id_len) =
            decode_vli(&header_data[pos..]).ok_or("bad filter ID VLI")?;
        pos += id_len;

        if filter_id != 0x21 {
            return Err(format!("unsupported filter ID: 0x{:x} (expected LZMA2 0x21)", filter_id));
        }

        // Properties size (should be 1 for LZMA2)
        let (props_size, ps_len) =
            decode_vli(&header_data[pos..]).ok_or("bad props size VLI")?;
        pos += ps_len;

        if props_size != 1 {
            return Err(format!("unexpected LZMA2 props size: {}", props_size));
        }

        if pos >= header_data.len() {
            return Err("block header truncated at LZMA2 props".into());
        }

        Ok(header_data[pos])
    }
}

impl Decompressor for XzDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        // Drain staged output first
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

        if input.is_empty() && self.buffer.is_empty() && self.lzma2.is_none() {
            self.finished = true;
            return Ok(DecompressResult {
                bytes_consumed: 0,
                bytes_produced: 0,
                status: DecompressStatus::StreamEnd,
            });
        }

        if !input.is_empty() {
            self.buffer.extend_from_slice(input);
        }
        let mut pos = 0;

        loop {
            match self.phase.clone() {
                XzPhase::StreamHeader => {
                    if pos + 12 > self.buffer.len() {
                        break;
                    }
                    if self.buffer[pos..pos + 6] != XZ_MAGIC {
                        return Err(SupertarError::DecompressionError(
                            "invalid XZ magic".into(),
                        ));
                    }
                    self.stream_header.copy_from_slice(&self.buffer[pos..pos + 12]);
                    self.check_size = check_size_for_id(self.stream_header[7] & 0x0F);
                    pos += 12;
                    self.phase = XzPhase::BlockStart;
                }

                XzPhase::BlockStart => {
                    if pos >= self.buffer.len() {
                        break;
                    }
                    let byte = self.buffer[pos];
                    if byte == 0x00 {
                        // Index marker — stream is done
                        self.phase = XzPhase::Index;
                        pos += 1;
                        continue;
                    }
                    let total_size = (byte as usize + 1) * 4;
                    self.block_header_size = total_size;
                    self.phase = XzPhase::BlockHeader { total_size };
                }

                XzPhase::BlockHeader { total_size } => {
                    if pos + total_size > self.buffer.len() {
                        break;
                    }
                    let header_data = &self.buffer[pos..pos + total_size];
                    let prop_byte = Self::parse_block_header(header_data).map_err(|e| {
                        SupertarError::DecompressionError(format!("XZ block header: {}", e))
                    })?;
                    pos += total_size;

                    // Initialize LZMA2 decoder for this block
                    let lzma2 = Lzma2Decompressor::from_prop_byte(prop_byte)?;
                    self.lzma2 = Some(lzma2);
                    self.block_data_bytes = 0;
                    self.phase = XzPhase::Lzma2Data;
                    // Break to deliver any output from the first LZMA2 call
                    break;
                }

                XzPhase::Lzma2Data => {
                    let lzma2 = self.lzma2.as_mut().ok_or_else(|| {
                        SupertarError::DecompressionError("no LZMA2 decoder".into())
                    })?;

                    let available = &self.buffer[pos..];
                    if available.is_empty() {
                        break;
                    }

                    let mut lzma2_out = vec![0u8; 256 * 1024];
                    let result = lzma2.decompress(available, &mut lzma2_out)?;
                    pos += result.bytes_consumed;
                    self.block_data_bytes += result.bytes_consumed as u64;

                    if result.bytes_produced > 0 {
                        self.staged_output
                            .extend_from_slice(&lzma2_out[..result.bytes_produced]);
                    }

                    if result.status == DecompressStatus::StreamEnd {
                        // LZMA2 stream for this block is done
                        self.lzma2 = None;
                        // Next: check bytes
                        self.phase = XzPhase::Check {
                            remaining: self.check_size,
                        };
                        // Break to deliver LZMA2 output
                        break;
                    }

                    if result.bytes_consumed == 0 && result.bytes_produced == 0 {
                        break; // Need more input
                    }

                    // If we produced output, break to deliver it
                    if result.bytes_produced > 0 {
                        break;
                    }
                }

                XzPhase::Check { remaining } => {
                    let skip = remaining.min(self.buffer.len() - pos);
                    pos += skip;
                    self.block_data_bytes += skip as u64;
                    let new_remaining = remaining - skip;
                    if new_remaining == 0 {
                        // Compute padding: unpadded_size = header + lzma2_data + check
                        // Round up to multiple of 4
                        let unpadded = self.block_header_size as u64 + self.block_data_bytes;
                        let padded = (unpadded + 3) & !3;
                        let padding = (padded - unpadded) as usize;
                        if padding == 0 {
                            self.phase = XzPhase::BlockStart;
                        } else {
                            self.phase = XzPhase::Padding {
                                remaining: padding,
                            };
                        }
                    } else {
                        self.phase = XzPhase::Check {
                            remaining: new_remaining,
                        };
                        break;
                    }
                }

                XzPhase::Padding { remaining } => {
                    let skip = remaining.min(self.buffer.len() - pos);
                    pos += skip;
                    let new_remaining = remaining - skip;
                    if new_remaining == 0 {
                        self.phase = XzPhase::BlockStart;
                    } else {
                        self.phase = XzPhase::Padding {
                            remaining: new_remaining,
                        };
                        break;
                    }
                }

                XzPhase::Index => {
                    // Skip the index and stream footer. We don't verify them.
                    // Just consume everything remaining and declare done.
                    pos = self.buffer.len();
                    self.finished = true;
                    self.phase = XzPhase::Done;
                    break;
                }

                XzPhase::Done => {
                    self.finished = true;
                    break;
                }
            }
        }

        let bytes_consumed_from_input = input.len();

        if pos > 0 {
            self.buffer.drain(..pos);
        }

        self.total_in += bytes_consumed_from_input as u64;

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
        let lzma2_checkpoint = self.lzma2.as_ref().and_then(|dec| {
            dec.checkpoint(0, 0)
                .ok()
                .and_then(|cp| {
                    if let CheckpointState::Lzma2(state) = cp.state {
                        Some(state)
                    } else {
                        None
                    }
                })
        });

        let state = XzFullCheckpointState {
            phase: bincode::serialize(&self.phase).unwrap_or_default(),
            stream_header: self.stream_header.to_vec(),
            check_size: self.check_size,
            block_data_bytes: self.block_data_bytes,
            block_header_size: self.block_header_size,
            lzma2_state: lzma2_checkpoint.map(|s| bincode::serialize(&s).unwrap_or_default()),
            buffer: self.buffer.clone(),
        };

        Ok(Checkpoint {
            compressed_offset,
            bit_offset: 0,
            uncompressed_offset,
            state: CheckpointState::XzFull(state),
        })
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        match &checkpoint.state {
            CheckpointState::XzFull(state) => {
                self.phase = bincode::deserialize(&state.phase).map_err(|e| {
                    SupertarError::CheckpointError(format!("deserialize xz phase: {}", e))
                })?;
                if state.stream_header.len() == 12 {
                    self.stream_header.copy_from_slice(&state.stream_header);
                }
                self.check_size = state.check_size;
                self.block_data_bytes = state.block_data_bytes;
                self.block_header_size = state.block_header_size;
                self.buffer = state.buffer.clone();
                self.staged_output.clear();
                self.staged_pos = 0;
                self.finished = false;
                self.total_in = checkpoint.compressed_offset;
                self.total_out = checkpoint.uncompressed_offset;

                // Restore LZMA2 decoder if we were in the middle of LZMA2 data
                if let Some(ref lzma2_bytes) = state.lzma2_state {
                    use crate::compress::checkpoint::Lzma2FullCheckpointState;
                    let lzma2_state: Lzma2FullCheckpointState =
                        bincode::deserialize(lzma2_bytes).map_err(|e| {
                            SupertarError::CheckpointError(format!(
                                "deserialize lzma2 state: {}",
                                e
                            ))
                        })?;
                    let mut dec = Lzma2Decompressor::new(1 << 24); // Will be overwritten by restore
                    dec.restore(&Checkpoint {
                        compressed_offset: lzma2_state.total_in,
                        bit_offset: 0,
                        uncompressed_offset: lzma2_state.total_out,
                        state: CheckpointState::Lzma2(lzma2_state),
                    })?;
                    self.lzma2 = Some(dec);
                } else {
                    self.lzma2 = None;
                }

                Ok(())
            }
            CheckpointState::None => {
                self.reset();
                Ok(())
            }
            _ => Err(SupertarError::CheckpointError(
                "expected XzFull checkpoint state".into(),
            )),
        }
    }

    fn reset(&mut self) {
        self.phase = XzPhase::StreamHeader;
        self.buffer.clear();
        self.lzma2 = None;
        self.check_size = 0;
        self.stream_header = [0u8; 12];
        self.block_data_bytes = 0;
        self.block_header_size = 0;
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
    use std::io::Write;
    use xz2::write::XzEncoder;

    fn compress_xz(data: &[u8]) -> Vec<u8> {
        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn full_decompress(compressed: &[u8], chunk_size: usize) -> Vec<u8> {
        let mut dec = XzDecompressor::new();
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
                let result = dec.decompress(&[], &mut output).unwrap();
                all_output.extend_from_slice(&output[..result.bytes_produced]);
                break;
            }
        }

        // Drain remaining staged output
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
    fn test_multiblock_file() {
        // Read the multi-block XZ test file
        let path = "/tmp/test_multiblock_data.xz";
        if !std::path::Path::new(path).exists() {
            eprintln!("Skipping: {} not found", path);
            return;
        }
        let compressed = std::fs::read(path).unwrap();
        let original = std::fs::read("/tmp/test_multiblock_data").unwrap();
        eprintln!("Compressed: {} bytes, Original: {} bytes", compressed.len(), original.len());
        let output = full_decompress(&compressed, 4096);
        assert_eq!(output.len(), original.len(), "length mismatch");
        assert_eq!(output, original, "content mismatch");
    }

    #[test]
    fn test_basic_decompress() {
        let original = b"Hello, world! This is a test of XZ decompression.";
        let compressed = compress_xz(original);
        let output = full_decompress(&compressed, compressed.len());
        assert_eq!(&output, &original[..]);
    }

    #[test]
    fn test_incremental_decompress() {
        let original = b"Hello, world! This is a test of XZ decompression with chunks.";
        let compressed = compress_xz(original);
        let output = full_decompress(&compressed, 10);
        assert_eq!(&output, &original[..]);
    }

    #[test]
    fn test_large_data() {
        let original: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let compressed = compress_xz(&original);
        let output = full_decompress(&compressed, 4096);
        assert_eq!(output, original);
    }

    #[test]
    fn test_checkpoint_restore() {
        let original: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();
        let compressed = compress_xz(&original);

        // Decompress partially, take checkpoint
        let mut dec = XzDecompressor::new();
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

            if all_output.len() >= 10000 && checkpoint_saved.is_none() {
                checkpoint_saved =
                    Some(dec.checkpoint(offset as u64, all_output.len() as u64).unwrap());
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
            }
            if result.bytes_produced == 0 {
                break;
            }
        }
        assert_eq!(all_output, original);

        // Restore from checkpoint
        if let Some(cp) = checkpoint_saved {
            let mut dec2 = XzDecompressor::new();
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
}
