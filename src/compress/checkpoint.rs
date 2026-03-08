use serde::{Deserialize, Serialize};

/// A serializable snapshot of decompressor state at a known position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Byte offset in the compressed stream.
    pub compressed_offset: u64,
    /// Bit offset within that byte (relevant for deflate/bzip2).
    pub bit_offset: u8,
    /// Byte offset in the uncompressed stream.
    pub uncompressed_offset: u64,
    /// Format-specific state needed to resume decompression.
    pub state: CheckpointState,
}

/// Format-specific checkpoint state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckpointState {
    /// No decompressor state needed (uncompressed or trivially seekable).
    None,
    /// Gzip/Deflate: block boundary state + 32 KiB sliding window.
    Gzip(GzipCheckpointState),
    /// Bzip2: block boundary info.
    Bzip2(Bzip2CheckpointState),
    /// XZ: block boundary info.
    Xz(XzCheckpointState),
    /// Zstd: frame boundary info.
    Zstd(ZstdCheckpointState),
}

/// Gzip checkpoint: deflate block boundary state plus 32 KiB sliding window.
///
/// When `block_state` is `Some`, the decompressor can resume from the
/// checkpoint's compressed offset without re-decompressing from the beginning.
/// When `None`, falls back to restarting from offset 0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GzipCheckpointState {
    /// The sliding window (up to 32 KiB of preceding decompressed data).
    pub window: Vec<u8>,
    /// Deflate block boundary state for mid-stream resume.
    pub block_state: Option<GzipBlockBoundary>,
    /// Size of the gzip header in bytes.
    pub header_size: usize,
}

/// Serializable snapshot of deflate decompressor state at a block boundary.
///
/// Mirrors `miniz_oxide::inflate::core::BlockBoundaryState` but is
/// independently serializable without depending on miniz_oxide's serde feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GzipBlockBoundary {
    pub num_bits: u8,
    pub bit_buf: u8,
    pub z_header0: u32,
    pub z_header1: u32,
    pub check_adler32: u32,
}

/// Bzip2 checkpoint: block boundaries are independently decompressible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bzip2CheckpointState {
    /// Block number (0-indexed).
    pub block_number: u64,
    /// The stream header byte (block size level, '1'-'9').
    pub stream_level: u8,
}

/// XZ checkpoint: blocks are independently decompressible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XzCheckpointState {
    /// Block index in the XZ stream.
    pub block_index: u32,
}

/// Zstd checkpoint: frames are independently decompressible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZstdCheckpointState {
    /// Frame index in the zstd stream.
    pub frame_index: u32,
}
