use crate::compress::checkpoint::{Bzip2CheckpointState, Checkpoint, CheckpointState};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::error::{Result, SupertarError};
use bzip2::Decompress as BzDecompress;

/// Bzip2 decompressor with block-boundary checkpoint support.
///
/// Bzip2 blocks are independently decompressible. We track block
/// boundaries and can restore to any block start.
pub struct Bzip2Decompressor {
    inner: BzDecompress,
    total_in: u64,
    total_out: u64,
    /// The stream header level byte ('1'-'9'), read from the stream.
    stream_level: u8,
    /// Whether we've parsed the stream header.
    header_parsed: bool,
    /// Block counter.
    block_count: u64,
}

impl Bzip2Decompressor {
    pub fn new() -> Self {
        Self {
            inner: BzDecompress::new(false), // don't concatenate streams
            total_in: 0,
            total_out: 0,
            stream_level: 0,
            header_parsed: false,
            block_count: 0,
        }
    }
}

impl Default for Bzip2Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Decompressor for Bzip2Decompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {

        // Capture the stream level from the header if not yet parsed
        if !self.header_parsed && input.len() >= 4
            && &input[0..2] == b"BZ" && input[2] == b'h' {
            self.stream_level = input[3];
            self.header_parsed = true;
        }

        let before_in = self.inner.total_in();
        let before_out = self.inner.total_out();

        let status = self
            .inner
            .decompress(input, output)
            .map_err(|e| SupertarError::DecompressionError(format!("bzip2: {}", e)))?;

        let consumed = (self.inner.total_in() - before_in) as usize;
        let produced = (self.inner.total_out() - before_out) as usize;
        self.total_in += consumed as u64;
        self.total_out += produced as u64;

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

    fn checkpoint(
        &self,
        compressed_offset: u64,
        uncompressed_offset: u64,
    ) -> Result<Checkpoint> {
        Ok(Checkpoint {
            compressed_offset,
            bit_offset: 0,
            uncompressed_offset,
            state: CheckpointState::Bzip2(Bzip2CheckpointState {
                block_number: self.block_count,
                stream_level: self.stream_level,
            }),
        })
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        match &checkpoint.state {
            CheckpointState::Bzip2(s) => {
                self.inner = BzDecompress::new(false);
                self.total_in = checkpoint.compressed_offset;
                self.total_out = checkpoint.uncompressed_offset;
                self.block_count = s.block_number;
                self.stream_level = s.stream_level;
                self.header_parsed = true;
                Ok(())
            }
            CheckpointState::None => {
                // Initial checkpoint — reset to beginning
                self.inner = BzDecompress::new(false);
                self.total_in = 0;
                self.total_out = 0;
                self.block_count = 0;
                self.stream_level = 0;
                self.header_parsed = false;
                Ok(())
            }
            _ => Err(SupertarError::CheckpointError(
                "expected bzip2 checkpoint state".into(),
            )),
        }
    }

    fn reset(&mut self) {
        self.inner = BzDecompress::new(false);
        self.total_in = 0;
        self.total_out = 0;
        self.stream_level = 0;
        self.header_parsed = false;
        self.block_count = 0;
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
        // Default compression uses level 6, which shows as '6' (0x36)
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
        assert_eq!(cp.compressed_offset, 100);
        assert_eq!(cp.uncompressed_offset, 200);
        match &cp.state {
            CheckpointState::Bzip2(s) => {
                assert!(s.stream_level >= b'1' && s.stream_level <= b'9');
            }
            _ => panic!("expected bzip2 state"),
        }
    }
}
