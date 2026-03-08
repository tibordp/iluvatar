use crate::archive::ArchiveFormat;
use crate::compress::checkpoint::Checkpoint;
use crate::compress::CompressionFormat;
use crate::index::entry::IndexEntry;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Current index format version.
pub const INDEX_VERSION: u32 = 2;

/// Metadata about the indexed archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexMetadata {
    /// Version of the index format.
    pub version: u32,
    /// Compression format of the source archive.
    pub compression: CompressionFormat,
    /// Archive container format.
    #[serde(default = "default_archive_format")]
    pub archive_format: ArchiveFormat,
    /// Size of the compressed archive in bytes.
    pub archive_size: u64,
    /// Total uncompressed size.
    pub uncompressed_size: u64,
    /// Whether this index covers the entire archive.
    /// A partial index can still be used to read any file that was
    /// discovered before indexing was stopped.
    #[serde(default = "default_complete")]
    pub complete: bool,
}

fn default_complete() -> bool {
    true
}

fn default_archive_format() -> ArchiveFormat {
    ArchiveFormat::Tar
}

/// The complete index for a compressed tar archive.
///
/// Contains all the information needed to efficiently seek to and read
/// any file within the archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveIndex {
    /// Archive metadata.
    pub metadata: IndexMetadata,
    /// Sorted list of decompressor checkpoints by uncompressed offset.
    pub checkpoints: Vec<Checkpoint>,
    /// Map from file path to index entry.
    pub entries: HashMap<String, IndexEntry>,
}

impl ArchiveIndex {
    /// Look up a file by its path.
    pub fn get(&self, path: &str) -> Option<&IndexEntry> {
        self.entries.get(path).or_else(|| {
            // Try with/without trailing slash for directories
            if path.ends_with('/') {
                self.entries.get(path.trim_end_matches('/'))
            } else {
                self.entries.get(&format!("{}/", path))
            }
        })
    }

    /// List all entries, optionally filtered by a directory prefix.
    pub fn list(&self, prefix: Option<&str>) -> Vec<&IndexEntry> {
        match prefix {
            Some(prefix) => {
                let prefix = prefix.trim_end_matches('/');
                self.entries
                    .values()
                    .filter(|e| {
                        e.path.starts_with(prefix)
                            && (e.path.len() == prefix.len()
                                || e.path.as_bytes().get(prefix.len()) == Some(&b'/'))
                    })
                    .collect()
            }
            None => self.entries.values().collect(),
        }
    }

    /// Find the checkpoint to use for reading a given entry.
    ///
    /// Returns the nearest checkpoint at or before the entry's data offset.
    pub fn checkpoint_for(&self, entry: &IndexEntry) -> &Checkpoint {
        &self.checkpoints[entry.checkpoint_index]
    }

    /// Find the best checkpoint for an arbitrary uncompressed offset.
    ///
    /// Returns the index and reference to the checkpoint with the largest
    /// `uncompressed_offset` that is `<=` the target. This enables
    /// efficient range reads within large files by picking a checkpoint
    /// close to the target byte rather than one before the file's start.
    pub fn best_checkpoint_for_offset(&self, uncompressed_offset: u64) -> (usize, &Checkpoint) {
        let idx = self
            .checkpoints
            .partition_point(|cp| cp.uncompressed_offset <= uncompressed_offset)
            .saturating_sub(1);
        (idx, &self.checkpoints[idx])
    }

    /// Number of files in the index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::EntryType;
    use crate::compress::checkpoint::CheckpointState;

    fn make_test_index() -> ArchiveIndex {
        let mut entries = HashMap::new();
        entries.insert(
            "file1.txt".into(),
            IndexEntry {
                path: "file1.txt".into(),
                size: 100,
                entry_type: EntryType::Regular,
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                mtime: 0,
                link_target: None,
                uncompressed_offset: 512,
                checkpoint_index: 0,
            },
        );
        entries.insert(
            "dir/file2.txt".into(),
            IndexEntry {
                path: "dir/file2.txt".into(),
                size: 200,
                entry_type: EntryType::Regular,
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                mtime: 0,
                link_target: None,
                uncompressed_offset: 2048,
                checkpoint_index: 0,
            },
        );
        entries.insert(
            "dir/".into(),
            IndexEntry {
                path: "dir/".into(),
                size: 0,
                entry_type: EntryType::Directory,
                mode: 0o755,
                uid: 1000,
                gid: 1000,
                mtime: 0,
                link_target: None,
                uncompressed_offset: 1536,
                checkpoint_index: 0,
            },
        );

        ArchiveIndex {
            metadata: IndexMetadata {
                version: INDEX_VERSION,
                compression: CompressionFormat::Gzip,
                archive_format: ArchiveFormat::Tar,
                archive_size: 1000,
                uncompressed_size: 5000,
                complete: true,
            },
            checkpoints: vec![Checkpoint {
                compressed_offset: 0,
                bit_offset: 0,
                uncompressed_offset: 0,
                state: CheckpointState::None,
            }],
            entries,
        }
    }

    #[test]
    fn test_get_by_path() {
        let index = make_test_index();
        assert!(index.get("file1.txt").is_some());
        assert!(index.get("dir/file2.txt").is_some());
        assert!(index.get("nonexistent").is_none());
    }

    #[test]
    fn test_get_directory_with_slash() {
        let index = make_test_index();
        assert!(index.get("dir/").is_some());
        assert!(index.get("dir").is_some()); // should find dir/ too
    }

    #[test]
    fn test_list_all() {
        let index = make_test_index();
        let entries = index.list(None);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_list_prefix() {
        let index = make_test_index();
        let entries = index.list(Some("dir"));
        assert_eq!(entries.len(), 2); // dir/ and dir/file2.txt
    }

    #[test]
    fn test_len() {
        let index = make_test_index();
        assert_eq!(index.len(), 3);
        assert!(!index.is_empty());
    }
}
