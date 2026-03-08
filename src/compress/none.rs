use crate::compress::checkpoint::{Checkpoint, CheckpointState};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::error::Result;

/// Passthrough "decompressor" for uncompressed tar archives.
pub struct NoneDecompressor {
    total_in: u64,
    total_out: u64,
}

impl NoneDecompressor {
    pub fn new() -> Self {
        Self {
            total_in: 0,
            total_out: 0,
        }
    }
}

impl Default for NoneDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Decompressor for NoneDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        if input.is_empty() {
            return Ok(DecompressResult {
                bytes_consumed: 0,
                bytes_produced: 0,
                status: DecompressStatus::Continue,
            });
        }

        let n = input.len().min(output.len());
        output[..n].copy_from_slice(&input[..n]);
        self.total_in += n as u64;
        self.total_out += n as u64;

        Ok(DecompressResult {
            bytes_consumed: n,
            bytes_produced: n,
            status: DecompressStatus::Continue,
        })
    }

    fn checkpoint(&self, compressed_offset: u64, uncompressed_offset: u64) -> Result<Checkpoint> {
        Ok(Checkpoint {
            compressed_offset,
            bit_offset: 0,
            uncompressed_offset,
            state: CheckpointState::None,
        })
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        self.total_in = checkpoint.compressed_offset;
        self.total_out = checkpoint.uncompressed_offset;
        Ok(())
    }

    fn reset(&mut self) {
        self.total_in = 0;
        self.total_out = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passthrough() {
        let mut dec = NoneDecompressor::new();
        let input = b"Hello, world!";
        let mut output = vec![0u8; 64];
        let result = dec.decompress(input, &mut output).unwrap();
        assert_eq!(result.bytes_consumed, 13);
        assert_eq!(result.bytes_produced, 13);
        assert_eq!(&output[..13], b"Hello, world!");
    }

    #[test]
    fn test_partial_output() {
        let mut dec = NoneDecompressor::new();
        let input = b"Hello, world!";
        let mut output = vec![0u8; 5];
        let result = dec.decompress(input, &mut output).unwrap();
        assert_eq!(result.bytes_consumed, 5);
        assert_eq!(result.bytes_produced, 5);
        assert_eq!(&output, b"Hello");
    }

    #[test]
    fn test_checkpoint_restore() {
        let mut dec = NoneDecompressor::new();
        let cp = dec.checkpoint(100, 100).unwrap();
        assert_eq!(cp.compressed_offset, 100);
        assert_eq!(cp.uncompressed_offset, 100);
        dec.restore(&cp).unwrap();
        assert_eq!(dec.total_in, 100);
        assert_eq!(dec.total_out, 100);
    }

    #[test]
    fn test_empty_input() {
        let mut dec = NoneDecompressor::new();
        let mut output = vec![0u8; 64];
        let result = dec.decompress(&[], &mut output).unwrap();
        assert_eq!(result.bytes_consumed, 0);
        assert_eq!(result.bytes_produced, 0);
        assert_eq!(result.status, DecompressStatus::Continue);
    }
}
