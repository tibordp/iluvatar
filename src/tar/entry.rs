use serde::{Deserialize, Serialize};

/// Type of a tar entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TarEntryType {
    Regular,
    HardLink,
    SymLink,
    CharDevice,
    BlockDevice,
    Directory,
    Fifo,
    /// GNU long name metadata entry.
    GnuLongName,
    /// GNU long link metadata entry.
    GnuLongLink,
    /// PAX extended header.
    PaxExtended,
    /// PAX global extended header.
    PaxGlobal,
    /// Unknown type.
    Other(u8),
}

impl TarEntryType {
    /// Parse from the typeflag byte in a tar header.
    pub fn from_byte(b: u8) -> Self {
        match b {
            b'0' | 0 => TarEntryType::Regular,
            b'1' => TarEntryType::HardLink,
            b'2' => TarEntryType::SymLink,
            b'3' => TarEntryType::CharDevice,
            b'4' => TarEntryType::BlockDevice,
            b'5' => TarEntryType::Directory,
            b'6' => TarEntryType::Fifo,
            b'L' => TarEntryType::GnuLongName,
            b'K' => TarEntryType::GnuLongLink,
            b'x' => TarEntryType::PaxExtended,
            b'g' => TarEntryType::PaxGlobal,
            other => TarEntryType::Other(other),
        }
    }

    /// Whether this is a regular file (has data content).
    pub fn is_regular(&self) -> bool {
        matches!(self, TarEntryType::Regular)
    }

    /// Whether this is a metadata entry (pax/gnu long name).
    pub fn is_metadata(&self) -> bool {
        matches!(
            self,
            TarEntryType::GnuLongName
                | TarEntryType::GnuLongLink
                | TarEntryType::PaxExtended
                | TarEntryType::PaxGlobal
        )
    }
}

/// A parsed tar entry with path, metadata, and location info.
#[derive(Debug, Clone)]
pub struct TarEntry {
    /// Full path of the entry.
    pub path: String,
    /// Size of the file data in bytes.
    pub size: u64,
    /// Type of entry.
    pub entry_type: TarEntryType,
    /// File mode (permissions).
    pub mode: u32,
    /// Owner user ID.
    pub uid: u64,
    /// Owner group ID.
    pub gid: u64,
    /// Modification time (Unix timestamp).
    pub mtime: u64,
    /// Owner user name.
    pub uname: Option<String>,
    /// Owner group name.
    pub gname: Option<String>,
    /// Link target for hard/symlinks.
    pub link_target: Option<String>,
    /// Byte offset in the *uncompressed* stream where file data begins
    /// (right after the 512-byte header block).
    pub data_offset: u64,
}

impl From<TarEntryType> for crate::archive::EntryType {
    fn from(t: TarEntryType) -> Self {
        use crate::archive::EntryType;
        match t {
            TarEntryType::Regular => EntryType::Regular,
            TarEntryType::HardLink => EntryType::HardLink,
            TarEntryType::SymLink => EntryType::SymLink,
            TarEntryType::CharDevice => EntryType::CharDevice,
            TarEntryType::BlockDevice => EntryType::BlockDevice,
            TarEntryType::Directory => EntryType::Directory,
            TarEntryType::Fifo => EntryType::Fifo,
            TarEntryType::GnuLongName => EntryType::Other(b'L'),
            TarEntryType::GnuLongLink => EntryType::Other(b'K'),
            TarEntryType::PaxExtended => EntryType::Other(b'x'),
            TarEntryType::PaxGlobal => EntryType::Other(b'g'),
            TarEntryType::Other(b) => EntryType::Other(b),
        }
    }
}

impl From<TarEntry> for crate::archive::ArchiveEntry {
    fn from(e: TarEntry) -> Self {
        crate::archive::ArchiveEntry {
            path: e.path,
            size: e.size,
            entry_type: e.entry_type.into(),
            mode: e.mode,
            uid: e.uid,
            gid: e.gid,
            mtime: e.mtime,
            link_target: e.link_target,
            data_offset: e.data_offset,
        }
    }
}
