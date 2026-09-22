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
///
/// Empty `input` means the compressed stream has ended: a decompressor
/// drains whatever it still holds and then reports
/// [`DecompressStatus::StreamEnd`].
pub trait Decompressor: Send {
    /// Decompress from `input` into `output`.
    ///
    /// Returns how many bytes were consumed from input and produced into output.
    /// If output buffer is full, call again with remaining input.
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult>;

    /// Snapshot the decompressor at its current position, so decoding can
    /// resume there later.
    ///
    /// `compressed_offset` and `uncompressed_offset` are the caller's counts
    /// of bytes fed in and taken out so far; the returned checkpoint carries
    /// exactly those offsets. `None` means no checkpoint is possible right
    /// now — formats that resume only at block boundaries (deflate, bzip2)
    /// answer `None` between boundaries, and formats that cannot resume at
    /// all always answer `None`. Callers ask again after later steps.
    fn checkpoint(
        &self,
        compressed_offset: u64,
        uncompressed_offset: u64,
    ) -> Result<Option<Checkpoint>>;

    /// Restore decompressor state from a checkpoint.
    /// After restoration, the decompressor can resume decompression from
    /// the checkpoint's compressed position.
    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()>;
}
