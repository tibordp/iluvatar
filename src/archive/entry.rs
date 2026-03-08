use serde::{Deserialize, Serialize};

/// Format-agnostic entry type for any archive format (tar, cpio, etc.).
///
/// Format-specific metadata entries (PAX headers, GNU long names, cpio trailers)
/// are handled internally by each parser and never surface here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryType {
    Regular,
    HardLink,
    SymLink,
    CharDevice,
    BlockDevice,
    Directory,
    Fifo,
    /// Socket (cpio supports this; tar typically does not).
    Socket,
    /// Unknown or unrecognized type.
    Other(u8),
}

impl EntryType {
    pub fn is_regular(&self) -> bool {
        matches!(self, EntryType::Regular)
    }

    pub fn is_directory(&self) -> bool {
        matches!(self, EntryType::Directory)
    }
}

/// A parsed archive entry with path, metadata, and location info.
///
/// Produced by any `ArchiveParser` implementation. Contains the union
/// of metadata fields meaningful across tar and cpio.
#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    /// Path of the entry within the archive.
    pub path: String,
    /// Size of the file data in bytes.
    pub size: u64,
    /// Type of entry.
    pub entry_type: EntryType,
    /// Unix permissions (lower 12 bits).
    pub mode: u32,
    /// Owner user ID.
    pub uid: u64,
    /// Owner group ID.
    pub gid: u64,
    /// Modification time (seconds since epoch).
    pub mtime: u64,
    /// Link target for symlinks and hardlinks.
    pub link_target: Option<String>,
    /// Byte offset in the uncompressed stream where file data begins.
    pub data_offset: u64,
}
