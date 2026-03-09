//! LZMA and LZMA2 decoder with full-state checkpointing.
//!
//! This module provides a sans-I/O LZMA2 decoder that implements the
//! `Decompressor` trait. All internal state is serializable, allowing
//! checkpoints at any byte offset in the decompressed stream.

pub mod decoder;
pub mod lzma2;
pub mod range_coder;

use crate::compress::checkpoint::{Checkpoint, CheckpointState, Lzma2FullCheckpointState};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::error::{Error, Result};

use lzma2::{Lzma2DecodeStatus, Lzma2Decoder};

/// LZMA2 decompressor implementing the `Decompressor` trait.
///
/// Handles raw LZMA2 streams. For XZ container format, use the XZ
/// decompressor which delegates to this for the LZMA2 payload.
pub struct Lzma2Decompressor {
    inner: Lzma2Decoder,
    /// Total compressed bytes consumed.
    total_in: u64,
    /// Total uncompressed bytes produced.
    total_out: u64,
    /// Whether the stream has ended.
    finished: bool,
}

impl Lzma2Decompressor {
    /// Create a new LZMA2 decompressor with the given dictionary size.
    pub fn new(dict_size: u32) -> Self {
        Self {
            inner: Lzma2Decoder::new(dict_size),
            total_in: 0,
            total_out: 0,
            finished: false,
        }
    }

    /// Create from an LZMA2 dictionary size property byte (0-40).
    pub fn from_prop_byte(prop: u8) -> Result<Self> {
        let inner = Lzma2Decoder::from_prop_byte(prop).ok_or_else(|| {
            Error::DecompressionError(format!("invalid LZMA2 property byte: {}", prop))
        })?;
        Ok(Self {
            inner,
            total_in: 0,
            total_out: 0,
            finished: false,
        })
    }
}

impl Decompressor for Lzma2Decompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        if self.finished {
            return Ok(DecompressResult {
                bytes_consumed: 0,
                bytes_produced: 0,
                status: DecompressStatus::StreamEnd,
            });
        }

        let result = self.inner.decode(input, output);
        self.total_in += result.bytes_consumed as u64;
        self.total_out += result.bytes_produced as u64;

        match result.status {
            Lzma2DecodeStatus::Error => Err(Error::DecompressionError("corrupt LZMA2 data".into())),
            Lzma2DecodeStatus::Finished => {
                self.finished = true;
                Ok(DecompressResult {
                    bytes_consumed: result.bytes_consumed,
                    bytes_produced: result.bytes_produced,
                    status: DecompressStatus::StreamEnd,
                })
            }
            Lzma2DecodeStatus::Continue | Lzma2DecodeStatus::NeedInput => Ok(DecompressResult {
                bytes_consumed: result.bytes_consumed,
                bytes_produced: result.bytes_produced,
                status: DecompressStatus::Continue,
            }),
        }
    }

    fn checkpoint(&self, compressed_offset: u64, uncompressed_offset: u64) -> Result<Checkpoint> {
        let state = self.inner.get_state();
        Ok(Checkpoint {
            compressed_offset,
            bit_offset: 0,
            uncompressed_offset,
            state: CheckpointState::Lzma2(Lzma2FullCheckpointState {
                decoder_state: bincode::serialize(&state)
                    .map_err(|e| Error::CheckpointError(format!("serialize lzma2 state: {}", e)))?,
                total_in: self.total_in,
                total_out: self.total_out,
                finished: self.finished,
            }),
        })
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        match &checkpoint.state {
            CheckpointState::Lzma2(state) => {
                let decoder_state: lzma2::Lzma2DecoderState =
                    bincode::deserialize(&state.decoder_state).map_err(|e| {
                        Error::CheckpointError(format!("deserialize lzma2 state: {}", e))
                    })?;
                self.inner.restore_state(&decoder_state);
                self.total_in = state.total_in;
                self.total_out = state.total_out;
                self.finished = state.finished;
                Ok(())
            }
            CheckpointState::None => {
                self.reset();
                Ok(())
            }
            _ => Err(Error::CheckpointError(
                "expected LZMA2 checkpoint state".into(),
            )),
        }
    }
}

impl Lzma2Decompressor {
    fn reset(&mut self) {
        self.inner = Lzma2Decoder::new(self.inner.inner_decoder().dict_size);
        self.total_in = 0;
        self.total_out = 0;
        self.finished = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Helper: compress data using xz2 with raw LZMA2 (no XZ container).
    /// We use XZ container and strip the header/footer to get raw LZMA2.
    fn compress_lzma2(data: &[u8]) -> Vec<u8> {
        // Use xz2 to create a complete XZ stream
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
        encoder.write_all(data).unwrap();
        let xz_data = encoder.finish().unwrap();
        // Parse XZ to extract raw LZMA2 data
        // XZ format: 12-byte header, then blocks
        // Block: block_header, LZMA2 data, padding, check
        // We need to parse enough to find the LZMA2 data

        // Stream header: 12 bytes
        // Block header: starts at byte 12
        //   First byte: (block_header_size / 4) - 1
        //   Then: flags, filter(s), padding, CRC32
        let block_header_size_raw = xz_data[12] as usize;
        let block_header_size = (block_header_size_raw + 1) * 4;
        let lzma2_start = 12 + block_header_size;

        // Find the end of LZMA2 data. The LZMA2 stream ends with 0x00 byte.
        // After that comes the check value and padding.
        // We'll scan for the LZMA2 end marker and include it.
        let mut pos = lzma2_start;
        loop {
            if pos >= xz_data.len() {
                break;
            }
            let control = xz_data[pos];
            if control == 0x00 {
                // End marker
                pos += 1;
                break;
            }
            if control < 0x80 {
                // Uncompressed chunk: control(1) + unpack_hi(1) + unpack_lo(1) + data
                let unpack_size =
                    ((xz_data[pos + 1] as usize) << 8 | xz_data[pos + 2] as usize) + 1;
                pos += 3 + unpack_size;
            } else {
                // LZMA chunk
                let has_props = control & 0x40 != 0;
                let unpack_size_hi = (control & 0x1F) as usize;
                let unpack_hi = xz_data[pos + 1] as usize;
                let unpack_lo = xz_data[pos + 2] as usize;
                let _unpack_size = (unpack_size_hi << 16) | (unpack_hi << 8) | unpack_lo;
                let pack_hi = xz_data[pos + 3] as usize;
                let pack_lo = xz_data[pos + 4] as usize;
                let pack_size = (pack_hi << 8 | pack_lo) + 1;
                let header_len = if has_props { 6 } else { 5 };
                pos += header_len + pack_size;
            }
        }

        xz_data[lzma2_start..pos].to_vec()
    }

    /// Fully decompress an LZMA2 stream using our decoder.
    fn full_decompress(data: &[u8], chunk_in: usize, chunk_out: usize) -> Vec<u8> {
        // We need to know the dict size. Extract from the XZ stream.
        // For simplicity, use a large dict size (the default for preset 1).
        let mut dec = Lzma2Decompressor::new(1 << 20); // 1 MiB dict
        let mut all_output = Vec::new();
        let mut offset = 0;

        loop {
            let end = (offset + chunk_in).min(data.len());
            let input = if offset < data.len() {
                &data[offset..end]
            } else {
                &[]
            };
            let mut output = vec![0u8; chunk_out];
            let result = dec.decompress(input, &mut output).unwrap();
            all_output.extend_from_slice(&output[..result.bytes_produced]);
            offset += result.bytes_consumed;

            if result.status == DecompressStatus::StreamEnd {
                break;
            }
            if result.bytes_consumed == 0 && result.bytes_produced == 0 && offset >= data.len() {
                break;
            }
        }

        all_output
    }

    #[test]
    fn test_empty_stream() {
        // Just the LZMA2 end marker
        let data = [0x00u8];
        let result = full_decompress(&data, 1, 64);
        assert!(result.is_empty());
    }

    #[test]
    fn test_basic_decompress() {
        let original = b"Hello, world! This is a test of LZMA2 decompression.";
        let compressed = compress_lzma2(original);
        let output = full_decompress(&compressed, compressed.len(), 65536);
        assert_eq!(
            &output,
            &original[..],
            "decompressed {} bytes, expected {} bytes",
            output.len(),
            original.len()
        );
    }

    #[test]
    fn test_incremental_input() {
        let original = b"Hello, world! This is a test of incremental LZMA2 decompression.";
        let compressed = compress_lzma2(original);
        // Feed 1 byte at a time
        let output = full_decompress(&compressed, 1, 65536);
        assert_eq!(
            &output,
            &original[..],
            "decompressed {} bytes, expected {} bytes",
            output.len(),
            original.len()
        );
    }

    #[test]
    fn test_small_output_buffer() {
        let original = b"Hello, world! This is a test of LZMA2 with small output.";
        let compressed = compress_lzma2(original);
        // Small output buffer
        let output = full_decompress(&compressed, compressed.len(), 4);
        assert_eq!(
            &output,
            &original[..],
            "decompressed {} bytes, expected {} bytes",
            output.len(),
            original.len()
        );
    }

    #[test]
    fn test_larger_data() {
        let original: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();
        let compressed = compress_lzma2(&original);

        let mut dec = Lzma2Decompressor::new(1 << 20);
        let mut all_output = Vec::new();
        let mut offset = 0;
        loop {
            let end = (offset + 4096).min(compressed.len());
            let input = if offset < compressed.len() {
                &compressed[offset..end]
            } else {
                &[]
            };
            let mut output = vec![0u8; 65536];
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

        assert_eq!(
            all_output.len(),
            original.len(),
            "output len {} != expected len {}",
            all_output.len(),
            original.len()
        );
        assert_eq!(all_output, original);
    }

    #[test]
    fn test_repetitive_data() {
        // Highly repetitive data tests match/rep decoding
        let original: Vec<u8> = "ABCDEFGH".repeat(5000).into_bytes();
        let compressed = compress_lzma2(&original);
        let output = full_decompress(&compressed, 4096, 65536);
        assert_eq!(output, original);
    }

    #[test]
    fn test_chunk_decompress_20k() {
        let original: Vec<u8> = (0..20_000).map(|i| (i % 251) as u8).collect();
        let compressed = compress_lzma2(&original);

        let mut dec = Lzma2Decompressor::new(1 << 20);
        let mut all_output = Vec::new();
        let mut offset = 0;
        loop {
            let end = (offset + 256).min(compressed.len());
            let input = if offset < compressed.len() {
                &compressed[offset..end]
            } else {
                &[]
            };
            let mut output = vec![0u8; 65536];
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

        assert_eq!(
            all_output.len(),
            original.len(),
            "output len mismatch: {} vs {}",
            all_output.len(),
            original.len()
        );
    }

    #[test]
    fn test_checkpoint_restore() {
        let original: Vec<u8> = (0..20_000).map(|i| (i % 251) as u8).collect();
        let compressed = compress_lzma2(&original);

        // Decompress partway, take checkpoint, then continue from checkpoint
        let mut dec = Lzma2Decompressor::new(1 << 20);
        let mut all_output = Vec::new();
        let mut offset = 0;

        // Feed about half the compressed data
        let mid = compressed.len() / 2;
        while offset < mid {
            let end = (offset + 256).min(compressed.len());
            let input = &compressed[offset..end];
            let mut output = vec![0u8; 65536];
            let result = dec.decompress(input, &mut output).unwrap();
            all_output.extend_from_slice(&output[..result.bytes_produced]);
            offset += result.bytes_consumed;
            if result.status == DecompressStatus::StreamEnd {
                break;
            }
        }

        // Take checkpoint
        let cp = dec
            .checkpoint(offset as u64, all_output.len() as u64)
            .unwrap();

        // Continue decompression to verify we get correct output
        let mut rest_output = Vec::new();
        loop {
            let end = (offset + 256).min(compressed.len());
            let input = if offset < compressed.len() {
                &compressed[offset..end]
            } else {
                &[]
            };
            let mut output = vec![0u8; 65536];
            let result = dec.decompress(input, &mut output).unwrap();
            rest_output.extend_from_slice(&output[..result.bytes_produced]);
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

        all_output.extend_from_slice(&rest_output);
        assert_eq!(all_output, original);

        // Now restore from checkpoint and verify we get the same rest
        let mut dec2 = Lzma2Decompressor::new(1 << 20);
        dec2.restore(&cp).unwrap();

        let mut restored_output = Vec::new();
        let mut offset2 = cp.compressed_offset as usize;
        loop {
            let end = (offset2 + 256).min(compressed.len());
            let input = if offset2 < compressed.len() {
                &compressed[offset2..end]
            } else {
                &[]
            };
            let mut output = vec![0u8; 65536];
            let result = dec2.decompress(input, &mut output).unwrap();
            restored_output.extend_from_slice(&output[..result.bytes_produced]);
            offset2 += result.bytes_consumed;
            if result.status == DecompressStatus::StreamEnd {
                break;
            }
            if result.bytes_consumed == 0
                && result.bytes_produced == 0
                && offset2 >= compressed.len()
            {
                break;
            }
        }

        assert_eq!(
            restored_output,
            rest_output,
            "restored output ({} bytes) != expected ({} bytes)",
            restored_output.len(),
            rest_output.len()
        );
    }

    #[test]
    fn test_decompressor_trait() {
        // Verify the Decompressor trait is properly implemented
        let original = b"Test the Decompressor trait interface";
        let compressed = compress_lzma2(original);

        let mut dec: Box<dyn Decompressor> = Box::new(Lzma2Decompressor::new(1 << 20));
        let mut all_output = Vec::new();
        let mut offset = 0;

        loop {
            let end = (offset + 4096).min(compressed.len());
            let input = if offset < compressed.len() {
                &compressed[offset..end]
            } else {
                &[]
            };
            let mut output = vec![0u8; 65536];
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

        assert_eq!(&all_output, &original[..]);
    }
}
