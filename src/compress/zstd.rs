use crate::compress::checkpoint::{Checkpoint, CheckpointState, ZstdCheckpointState};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::error::{Result, SupertarError};

/// Zstd decompressor with frame-boundary checkpoint support.
///
/// Zstd streams consist of independent frames. Each frame can be
/// decompressed independently, making them natural checkpoint points.
pub struct ZstdDecompressor {
    inner: zstd::bulk::Decompressor<'static>,
    /// Buffer for accumulating a complete frame's compressed data.
    frame_buf: Vec<u8>,
    /// Tracks the current compressed stream position.
    total_in: u64,
    total_out: u64,
    /// Frame counter.
    frame_index: u32,
    /// Leftover decompressed data from the current frame.
    output_buf: Vec<u8>,
    output_pos: usize,
}

impl ZstdDecompressor {
    pub fn new() -> Result<Self> {
        let inner = zstd::bulk::Decompressor::new()
            .map_err(|e| SupertarError::DecompressionError(format!("zstd init: {}", e)))?;
        Ok(Self {
            inner,
            frame_buf: Vec::new(),
            total_in: 0,
            total_out: 0,
            frame_index: 0,
            output_buf: Vec::new(),
            output_pos: 0,
        })
    }

    /// Try to find and decompress one complete zstd frame from the buffer.
    fn try_decompress_frame(&mut self) -> Result<Option<Vec<u8>>> {
        if self.frame_buf.len() < 4 {
            return Ok(None);
        }

        // Try to decompress what we have. zstd will fail if the frame is incomplete.
        // We use a generous upper bound for decompressed size.
        let max_output = self.frame_buf.len() * 20 + 65536;
        match self.inner.decompress(&self.frame_buf, max_output) {
            Ok(decompressed) => {
                self.frame_buf.clear();
                self.frame_index += 1;
                Ok(Some(decompressed))
            }
            Err(_) => {
                // Frame likely incomplete, need more data
                Ok(None)
            }
        }
    }
}

impl Decompressor for ZstdDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        // First, drain any leftover output from previous frame
        if self.output_pos < self.output_buf.len() {
            let available = self.output_buf.len() - self.output_pos;
            let n = available.min(output.len());
            output[..n].copy_from_slice(&self.output_buf[self.output_pos..self.output_pos + n]);
            self.output_pos += n;
            if self.output_pos >= self.output_buf.len() {
                self.output_buf.clear();
                self.output_pos = 0;
            }
            return Ok(DecompressResult {
                bytes_consumed: 0,
                bytes_produced: n,
                status: DecompressStatus::Continue,
            });
        }

        if input.is_empty() {
            // Try to flush any remaining data in frame_buf
            if !self.frame_buf.is_empty() {
                if let Some(decompressed) = self.try_decompress_frame()? {
                    let n = decompressed.len().min(output.len());
                    output[..n].copy_from_slice(&decompressed[..n]);
                    self.total_out += decompressed.len() as u64;
                    if n < decompressed.len() {
                        self.output_buf = decompressed;
                        self.output_pos = n;
                    }
                    return Ok(DecompressResult {
                        bytes_consumed: 0,
                        bytes_produced: n,
                        status: DecompressStatus::Continue,
                    });
                }
            }
            return Ok(DecompressResult {
                bytes_consumed: 0,
                bytes_produced: 0,
                status: DecompressStatus::StreamEnd,
            });
        }

        // Append input to frame buffer
        let consumed = input.len();
        self.frame_buf.extend_from_slice(input);
        self.total_in += consumed as u64;

        // Try to decompress
        if let Some(decompressed) = self.try_decompress_frame()? {
            let n = decompressed.len().min(output.len());
            output[..n].copy_from_slice(&decompressed[..n]);
            self.total_out += decompressed.len() as u64;
            if n < decompressed.len() {
                self.output_buf = decompressed;
                self.output_pos = n;
            }
            Ok(DecompressResult {
                bytes_consumed: consumed,
                bytes_produced: n,
                status: DecompressStatus::Continue,
            })
        } else {
            // Need more data to complete the frame
            Ok(DecompressResult {
                bytes_consumed: consumed,
                bytes_produced: 0,
                status: DecompressStatus::Continue,
            })
        }
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
            state: CheckpointState::Zstd(ZstdCheckpointState {
                frame_index: self.frame_index,
            }),
        })
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        match &checkpoint.state {
            CheckpointState::Zstd(s) => {
                self.inner = zstd::bulk::Decompressor::new().map_err(|e| {
                    SupertarError::CheckpointError(format!("zstd restore: {}", e))
                })?;
                self.frame_buf.clear();
                self.output_buf.clear();
                self.output_pos = 0;
                self.total_in = checkpoint.compressed_offset;
                self.total_out = checkpoint.uncompressed_offset;
                self.frame_index = s.frame_index;
                Ok(())
            }
            CheckpointState::None => {
                self.inner = zstd::bulk::Decompressor::new().map_err(|e| {
                    SupertarError::CheckpointError(format!("zstd restore: {}", e))
                })?;
                self.frame_buf.clear();
                self.output_buf.clear();
                self.output_pos = 0;
                self.total_in = 0;
                self.total_out = 0;
                self.frame_index = 0;
                Ok(())
            }
            _ => Err(SupertarError::CheckpointError(
                "expected zstd checkpoint state".into(),
            )),
        }
    }

    fn reset(&mut self) {
        if let Ok(inner) = zstd::bulk::Decompressor::new() {
            self.inner = inner;
        }
        self.frame_buf.clear();
        self.output_buf.clear();
        self.output_pos = 0;
        self.total_in = 0;
        self.total_out = 0;
        self.frame_index = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compress_zstd(data: &[u8]) -> Vec<u8> {
        zstd::encode_all(std::io::Cursor::new(data), 3).unwrap()
    }

    #[test]
    fn test_basic_decompress() {
        let original = b"Hello, world! This is a test of zstd decompression.";
        let compressed = compress_zstd(original);

        let mut dec = ZstdDecompressor::new().unwrap();
        let mut output = vec![0u8; 256];

        // Feed all compressed data
        let result = dec.decompress(&compressed, &mut output).unwrap();

        // May need to signal EOF
        let mut all_output = Vec::new();
        all_output.extend_from_slice(&output[..result.bytes_produced]);

        if result.bytes_produced == 0 {
            // Data buffered, signal EOF to flush
            let result2 = dec.decompress(&[], &mut output).unwrap();
            all_output.extend_from_slice(&output[..result2.bytes_produced]);
        }

        assert_eq!(&all_output, &original[..]);
    }

    #[test]
    fn test_checkpoint() {
        let dec = ZstdDecompressor::new().unwrap();
        let cp = dec.checkpoint(100, 200).unwrap();
        assert_eq!(cp.compressed_offset, 100);
        assert_eq!(cp.uncompressed_offset, 200);
        match &cp.state {
            CheckpointState::Zstd(s) => assert_eq!(s.frame_index, 0),
            _ => panic!("expected zstd state"),
        }
    }
}
