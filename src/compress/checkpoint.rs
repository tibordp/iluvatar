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
    /// XZ: full decompressor state for mid-stream checkpoint (pure-Rust decoder).
    XzFull(XzFullCheckpointState),
    /// Zstd: frame boundary info.
    Zstd(ZstdCheckpointState),
    /// Zstd: full decompressor state for mid-stream checkpoint (pure-Rust decoder).
    ZstdFull(ZstdFullCheckpointState),
    /// LZMA2: full decompressor state for mid-stream checkpoint.
    Lzma2(Lzma2FullCheckpointState),
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
///
/// Stores the 4-byte stream header (`BZh` + level) so that on restore
/// we can prepend it before the block data, allowing a fresh libbz2
/// decoder to start at any block boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bzip2CheckpointState {
    /// Block number (0-indexed).
    pub block_number: u64,
    /// The 4-byte bzip2 stream header (`BZh` + level byte).
    pub stream_header: Vec<u8>,
}

/// XZ checkpoint: blocks are independently decompressible.
///
/// Stores the XZ stream header so that on restore we can prepend it
/// before the block data, allowing a fresh liblzma decoder to start
/// at any block boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XzCheckpointState {
    /// Block index in the XZ stream.
    pub block_index: u32,
    /// The 12-byte XZ stream header (needed to initialize a fresh decoder).
    pub stream_header: Vec<u8>,
}

/// Zstd checkpoint: frames are independently decompressible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZstdCheckpointState {
    /// Frame index in the zstd stream.
    pub frame_index: u32,
}

/// XZ checkpoint: full decompressor state for mid-stream resume (pure-Rust decoder).
///
/// Captures the complete XZ container parsing state and the inner LZMA2 decoder
/// state, enabling decompression resume from any byte offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XzFullCheckpointState {
    /// Serialized XZ parser phase (bincode).
    pub phase: Vec<u8>,
    /// The 12-byte XZ stream header.
    pub stream_header: Vec<u8>,
    /// Check type size.
    pub check_size: usize,
    /// Bytes consumed in current block's data region.
    pub block_data_bytes: u64,
    /// Block header size for current block.
    pub block_header_size: usize,
    /// Serialized LZMA2 checkpoint state (if mid-block).
    pub lzma2_state: Option<Vec<u8>>,
    /// Internal input buffer.
    #[serde(default)]
    pub buffer: Vec<u8>,
}

/// Zstd checkpoint: full decompressor state for mid-stream resume (pure-Rust decoder).
///
/// Unlike the frame-boundary-only `ZstdCheckpointState`, this captures the
/// complete decoder state (FSE/Huffman tables, repeat offsets, window buffer,
/// processing phase) so decompression can resume from any byte offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZstdFullCheckpointState {
    /// Serialized `BlockDecoderState` (bincode): FSE tables, Huffman table, repeat offsets.
    pub block_state: Vec<u8>,
    /// Window buffer: recent decompressed output for back-references.
    pub window: Vec<u8>,
    /// Maximum window size for the current frame.
    pub window_size: usize,
    /// Serialized decoder phase (bincode).
    pub phase: Vec<u8>,
    /// Serialized frame header (bincode), if currently within a frame.
    pub frame_header: Option<Vec<u8>>,
    /// Internal input buffer (unprocessed bytes that were consumed from caller but not yet decoded).
    #[serde(default)]
    pub buffer: Vec<u8>,
    /// Staged output: decoded bytes not yet delivered to the caller.
    #[serde(default)]
    pub staged_output: Vec<u8>,
    /// Position within staged_output.
    #[serde(default)]
    pub staged_pos: usize,
}

/// LZMA2 checkpoint: full decompressor state serialized with bincode.
///
/// Unlike other formats that checkpoint at block/frame boundaries,
/// LZMA2 checkpoints capture the complete decompressor state so
/// decompression can resume from any byte offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lzma2FullCheckpointState {
    /// Serialized `Lzma2DecoderState` (bincode).
    pub decoder_state: Vec<u8>,
    /// Total compressed bytes consumed at checkpoint.
    pub total_in: u64,
    /// Total uncompressed bytes produced at checkpoint.
    pub total_out: u64,
    /// Whether the stream had finished at checkpoint.
    pub finished: bool,
}
