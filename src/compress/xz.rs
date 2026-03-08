use crate::compress::checkpoint::{Checkpoint, CheckpointState, XzCheckpointState};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::error::{Result, SupertarError};
use xz2::stream::{Action, Status, Stream};

/// XZ decompressor with block-boundary checkpoint support.
///
/// XZ format natively supports random access via its block index.
/// Each block can be independently decompressed.
pub struct XzDecompressor {
    inner: Stream,
    total_in: u64,
    total_out: u64,
    block_index: u32,
}

impl XzDecompressor {
    pub fn new() -> Result<Self> {
        let stream = Stream::new_stream_decoder(u64::MAX, 0)
            .map_err(|e| SupertarError::DecompressionError(format!("xz init: {}", e)))?;
        Ok(Self {
            inner: stream,
            total_in: 0,
            total_out: 0,
            block_index: 0,
        })
    }
}

impl Decompressor for XzDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {

        let before_in = self.inner.total_in();
        let before_out = self.inner.total_out();

        let status = self
            .inner
            .process(input, output, Action::Run)
            .map_err(|e| SupertarError::DecompressionError(format!("xz: {}", e)))?;

        let consumed = (self.inner.total_in() - before_in) as usize;
        let produced = (self.inner.total_out() - before_out) as usize;
        self.total_in += consumed as u64;
        self.total_out += produced as u64;

        let status = match status {
            Status::Ok => DecompressStatus::Continue,
            Status::MemNeeded => DecompressStatus::Continue,
            Status::GetCheck => DecompressStatus::Continue,
            Status::StreamEnd => DecompressStatus::StreamEnd,
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
            state: CheckpointState::Xz(XzCheckpointState {
                block_index: self.block_index,
            }),
        })
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        match &checkpoint.state {
            CheckpointState::Xz(s) => {
                self.inner = Stream::new_stream_decoder(u64::MAX, 0).map_err(|e| {
                    SupertarError::CheckpointError(format!("xz restore: {}", e))
                })?;
                self.total_in = checkpoint.compressed_offset;
                self.total_out = checkpoint.uncompressed_offset;
                self.block_index = s.block_index;
                Ok(())
            }
            CheckpointState::None => {
                self.inner = Stream::new_stream_decoder(u64::MAX, 0).map_err(|e| {
                    SupertarError::CheckpointError(format!("xz restore: {}", e))
                })?;
                self.total_in = 0;
                self.total_out = 0;
                self.block_index = 0;
                Ok(())
            }
            _ => Err(SupertarError::CheckpointError(
                "expected xz checkpoint state".into(),
            )),
        }
    }

    fn reset(&mut self) {
        if let Ok(stream) = Stream::new_stream_decoder(u64::MAX, 0) {
            self.inner = stream;
        }
        self.total_in = 0;
        self.total_out = 0;
        self.block_index = 0;
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

    #[test]
    fn test_basic_decompress() {
        let original = b"Hello, world! This is a test of XZ decompression.";
        let compressed = compress_xz(original);

        let mut dec = XzDecompressor::new().unwrap();
        let mut output = vec![0u8; 256];
        let result = dec.decompress(&compressed, &mut output).unwrap();

        assert_eq!(result.bytes_produced, original.len());
        assert_eq!(&output[..result.bytes_produced], &original[..]);
    }

    #[test]
    fn test_incremental_decompress() {
        let original = b"Hello, world! This is a test of XZ decompression with chunks.";
        let compressed = compress_xz(original);

        let mut dec = XzDecompressor::new().unwrap();
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
    fn test_large_data() {
        let original: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let compressed = compress_xz(&original);

        let mut dec = XzDecompressor::new().unwrap();
        let mut all_output = Vec::new();
        let mut offset = 0;

        while offset < compressed.len() {
            let chunk_end = (offset + 4096).min(compressed.len());
            let mut output = vec![0u8; 65536];
            let result = dec
                .decompress(&compressed[offset..chunk_end], &mut output)
                .unwrap();
            all_output.extend_from_slice(&output[..result.bytes_produced]);
            offset += result.bytes_consumed;
            if result.status == DecompressStatus::StreamEnd {
                break;
            }
        }

        assert_eq!(all_output, original);
    }

    #[test]
    fn test_checkpoint() {
        let dec = XzDecompressor::new().unwrap();
        let cp = dec.checkpoint(100, 200).unwrap();
        assert_eq!(cp.compressed_offset, 100);
        assert_eq!(cp.uncompressed_offset, 200);
        match &cp.state {
            CheckpointState::Xz(s) => assert_eq!(s.block_index, 0),
            _ => panic!("expected xz state"),
        }
    }
}
