use crate::archive::EntryType;
use serde::{Deserialize, Serialize};

/// An entry in the archive index, recording a file's metadata and position.
///
/// Obtained from [`ArchiveIndex::get()`](crate::ArchiveIndex::get) or
/// [`ArchiveIndex::list()`](crate::ArchiveIndex::list).
///
/// # Example
///
/// ```no_run
/// # fn example(archive: &mut iluvatar::sync::Archive<std::fs::File>) {
/// use iluvatar::EntryType;
///
/// for entry in archive.list() {
///     match entry.entry_type {
///         EntryType::Regular => println!("{} ({} bytes)", entry.path, entry.size),
///         EntryType::Directory => println!("{}/", entry.path),
///         EntryType::SymLink => {
///             println!("{} -> {}", entry.path, entry.link_target.as_deref().unwrap_or("?"))
///         }
///         _ => println!("{} (special)", entry.path),
///     }
/// }
/// # }
/// ```
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
    /// Index into `ArchiveIndex::checkpoints` for the nearest preceding checkpoint.
    pub checkpoint_index: usize,
}
