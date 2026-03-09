use crate::compress::checkpoint::Checkpoint;
use crate::error::Result;

/// Result of a single decompression step.
#[derive(Debug)]
pub struct DecompressResult {
    /// Number of compressed input bytes consumed.
    pub bytes_consumed: usize,
    /// Number of decompressed bytes written to output.
    pub bytes_produced: usize,
    /// Status of the decompression.
    pub status: DecompressStatus,
}

/// Status after a decompression step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompressStatus {
    /// More data may be available; call decompress again.
    Continue,
    /// The compressed stream has ended.
    StreamEnd,
}

/// A format-agnostic decompressor. Sans-I/O: feed compressed bytes in,
/// get decompressed bytes out.
pub trait Decompressor: Send {
    /// Decompress from `input` into `output`.
    ///
    /// Returns how many bytes were consumed from input and produced into output.
    /// If output buffer is full, call again with remaining input.
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult>;

    /// Take a checkpoint of the current decompressor state.
    fn checkpoint(&self, compressed_offset: u64, uncompressed_offset: u64) -> Result<Checkpoint>;

    /// Restore decompressor state from a checkpoint.
    /// After restoration, the decompressor can resume decompression from
    /// the checkpoint's compressed position.
    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()>;
}
