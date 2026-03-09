use serde::{Deserialize, Serialize};

/// Format-agnostic entry type for any archive format (tar, cpio, etc.).
///
/// Format-specific metadata entries (PAX headers, GNU long names, cpio trailers)
/// are handled internally by each parser and never surface here.
///
/// # Example
///
/// ```
/// use iluvatar::EntryType;
///
/// let ty = EntryType::Regular;
/// assert!(ty.is_regular());
/// assert!(!ty.is_directory());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryType {
    /// A regular file with data content.
    Regular,
    /// A hard link to another file in the archive.
    HardLink,
    /// A symbolic link.
    SymLink,
    /// A character device node.
    CharDevice,
    /// A block device node.
    BlockDevice,
    /// A directory.
    Directory,
    /// A FIFO (named pipe).
    Fifo,
    /// A Unix domain socket (cpio supports this; tar typically does not).
    Socket,
    /// Unknown or unrecognized type with the raw type byte.
    Other(u8),
}

impl EntryType {
    /// Returns `true` if this is a regular file.
    pub fn is_regular(&self) -> bool {
        matches!(self, EntryType::Regular)
    }

    /// Returns `true` if this is a directory.
    pub fn is_directory(&self) -> bool {
        matches!(self, EntryType::Directory)
    }
}

/// A parsed archive entry with path, metadata, and location info.
///
/// Produced by any `ArchiveParser` implementation. Contains the union
/// of metadata fields meaningful across tar and cpio.
#[derive(Debug, Clone)]
pub(crate) struct ArchiveEntry {
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
