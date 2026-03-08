use crate::archive::EntryType;
use serde::{Deserialize, Serialize};

/// An entry in the archive index, recording a file's metadata and position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Full path of the file within the archive.
    pub path: String,
    /// Size of the file data in bytes.
    pub size: u64,
    /// Type of entry.
    pub entry_type: EntryType,
    /// File mode (permissions).
    pub mode: u32,
    /// Owner user ID.
    pub uid: u64,
    /// Owner group ID.
    pub gid: u64,
    /// Modification time (Unix timestamp).
    pub mtime: u64,
    /// Link target for hard/symlinks.
    pub link_target: Option<String>,
    /// Byte offset in the uncompressed stream where file data starts.
    pub uncompressed_offset: u64,
    /// Index into `TarIndex::checkpoints` for the nearest preceding checkpoint.
    pub checkpoint_index: usize,
}
