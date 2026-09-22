use serde::{Deserialize, Serialize};

/// A serializable snapshot of decompressor state at a known position.
///
/// Each checkpoint records both compressed and uncompressed stream offsets,
/// plus enough internal state to resume decompression from that point.
/// Checkpoints are stored in [`ArchiveIndex::checkpoints`](crate::ArchiveIndex).
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
    /// XZ: full decompressor state for mid-stream checkpoint.
    Xz(XzFullCheckpointState),
    /// Zstd: full decompressor state for mid-stream checkpoint.
    Zstd(ZstdFullCheckpointState),
    /// LZMA2: full decompressor state for mid-stream checkpoint.
    Lzma2(Lzma2FullCheckpointState),
    /// Raw LZMA1: full decoder state.
    Lzma(LzmaCheckpointState),
    /// A BCJ or Delta filter: position and the bytes it still holds.
    Filter(FilterCheckpointState),
    /// BCJ2: the range coder, contexts and side-stream positions.
    Bcj2(Bcj2CheckpointState),
    /// AES-CBC: the previous ciphertext block and any partial block.
    Aes(AesCheckpointState),
    /// A codec chain: one checkpoint per stage plus the bytes in flight
    /// between stages.
    Chain(ChainCheckpointState),
}

/// Raw LZMA1 checkpoint: the whole decoder, bincode-serialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LzmaCheckpointState {
    pub decoder_state: Vec<u8>,
    pub finished: bool,
}

/// Filter checkpoint. `held` are input bytes the filter has taken but not
/// yet emitted (a possible instruction straddling the chunk end); `pos` is
/// the stream position of the first held byte.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterCheckpointState {
    pub pos: u64,
    pub held: Vec<u8>,
    /// Prefix of `held` already converted (output-ready).
    pub filtered: usize,
    /// Filter-specific state, bincode-serialized (x86's `prev_mask` and
    /// `prev_pos`; delta's history ring).
    pub extra: Vec<u8>,
    pub finished: bool,
}

/// BCJ2 checkpoint: the whole coder state, bincode-serialized. The side
/// streams themselves belong to the codec spec, not the checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcj2CheckpointState {
    pub state: Vec<u8>,
}

/// AES-CBC checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AesCheckpointState {
    /// Previous ciphertext block (the IV for the next block).
    pub prev: [u8; 16],
    /// Partial ciphertext block received but not yet decryptable.
    pub carry: Vec<u8>,
    /// Decrypted bytes not yet handed out.
    pub staged: Vec<u8>,
    /// Plaintext bytes emitted so far (for the length limit).
    pub produced: u64,
    pub finished: bool,
}

/// Chain checkpoint: stage `i` resumes from `stages[i]` with `pending[i]`
/// (empty for the last stage) already sitting in the buffer that feeds
/// stage `i + 1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainCheckpointState {
    pub stages: Vec<Checkpoint>,
    pub pending: Vec<Vec<u8>>,
    /// Which stages have reported end of stream.
    pub ended: Vec<bool>,
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

/// XZ checkpoint: full decompressor state for mid-stream resume.
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
    /// Decoded output not yet delivered to the caller at checkpoint time.
    #[serde(default)]
    pub staged_output: Vec<u8>,
}

/// Zstd checkpoint: full decompressor state for mid-stream resume.
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

impl CheckpointState {
    /// Estimate the serialized size of this checkpoint state in bytes.
    ///
    /// This is a fast approximation that avoids actual serialization.
    /// Used by adaptive checkpoint strategies to track index size growth.
    pub fn estimated_size(&self) -> usize {
        match self {
            CheckpointState::None => 0,
            CheckpointState::Gzip(s) => s.window.len() + 32,
            CheckpointState::Bzip2(s) => s.stream_header.len() + 8,
            CheckpointState::Xz(s) => {
                s.phase.len()
                    + s.stream_header.len()
                    + s.lzma2_state.as_ref().map_or(0, |v| v.len())
                    + s.buffer.len()
                    + s.staged_output.len()
                    + 32
            }
            CheckpointState::Zstd(s) => {
                s.block_state.len()
                    + s.window.len()
                    + s.phase.len()
                    + s.frame_header.as_ref().map_or(0, |v| v.len())
                    + s.buffer.len()
                    + s.staged_output.len()
                    + 32
            }
            CheckpointState::Lzma2(s) => s.decoder_state.len() + 24,
            CheckpointState::Lzma(s) => s.decoder_state.len() + 8,
            CheckpointState::Filter(s) => s.held.len() + s.extra.len() + 16,
            CheckpointState::Bcj2(s) => s.state.len() + 8,
            CheckpointState::Aes(s) => s.carry.len() + s.staged.len() + 40,
            CheckpointState::Chain(s) => {
                s.stages.iter().map(|c| c.estimated_size()).sum::<usize>()
                    + s.pending.iter().map(|p| p.len() + 8).sum::<usize>()
                    + s.ended.len()
            }
        }
    }
}

impl Checkpoint {
    /// Estimate the total serialized size of this checkpoint in bytes.
    pub fn estimated_size(&self) -> usize {
        // Two u64 offsets + u8 bit_offset + state
        17 + self.state.estimated_size()
    }
}
