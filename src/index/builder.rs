use crate::archive::{ArchiveEntry, ArchiveFormat};
use crate::compress::checkpoint::Checkpoint;
use crate::compress::CompressionFormat;
use crate::index::entry::IndexEntry;
use crate::index::store::{ArchiveIndex, IndexMetadata, INDEX_VERSION};
use std::collections::HashMap;

/// Accumulates entries and checkpoints during the indexing pass.
pub struct IndexBuilder {
    entries: HashMap<String, IndexEntry>,
    checkpoints: Vec<Checkpoint>,
    compression: CompressionFormat,
    archive_format: ArchiveFormat,
    archive_size: u64,
    last_entry_path: Option<String>,
}

impl IndexBuilder {
    /// Create a new index builder.
    pub fn new(
        compression: CompressionFormat,
        archive_format: ArchiveFormat,
        archive_size: u64,
    ) -> Self {
        Self {
            entries: HashMap::new(),
            checkpoints: Vec::new(),
            compression,
            archive_format,
            archive_size,
            last_entry_path: None,
        }
    }

    /// Add an archive entry to the index.
    ///
    /// The entry is associated with the latest checkpoint whose uncompressed
    /// offset does not exceed the entry's data offset — a later checkpoint
    /// (e.g. one taken at the end of the decompressed chunk in which this
    /// entry was discovered) cannot be used to read the entry.
    pub fn add_entry(&mut self, entry: ArchiveEntry) {
        let checkpoint_index = self
            .checkpoints
            .iter()
            .rposition(|cp| cp.uncompressed_offset <= entry.data_offset)
            .unwrap_or(0);
        self.last_entry_path = Some(entry.path.clone());
        let index_entry = IndexEntry {
            path: entry.path.clone(),
            size: entry.size,
            entry_type: entry.entry_type,
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            mtime: entry.mtime,
            link_target: entry.link_target,
            uncompressed_offset: entry.data_offset,
            checkpoint_index,
        };
        self.entries.insert(entry.path, index_entry);
    }

    /// Add a decompressor checkpoint.
    pub fn add_checkpoint(&mut self, checkpoint: Checkpoint) {
        self.checkpoints.push(checkpoint);
    }

    /// Number of checkpoints added so far.
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }

    /// Number of entries added so far.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Total compressed archive size.
    pub fn archive_size(&self) -> u64 {
        self.archive_size
    }

    /// Path of the most recently added entry, if any.
    pub fn last_entry_path(&self) -> Option<&str> {
        self.last_entry_path.as_deref()
    }

    /// Clone the current state into a usable partial `ArchiveIndex`.
    ///
    /// The engine continues to be usable for further indexing.
    pub fn snapshot(&self, uncompressed_size: u64) -> ArchiveIndex {
        ArchiveIndex {
            metadata: IndexMetadata {
                version: INDEX_VERSION,
                compression: self.compression,
                archive_format: self.archive_format,
                archive_size: self.archive_size,
                uncompressed_size,
                complete: false,
            },
            checkpoints: self.checkpoints.clone(),
            entries: self.entries.clone(),
        }
    }

    /// Consume the builder into a partial `ArchiveIndex`.
    pub fn finish_partial(self, uncompressed_size: u64) -> ArchiveIndex {
        ArchiveIndex {
            metadata: IndexMetadata {
                version: INDEX_VERSION,
                compression: self.compression,
                archive_format: self.archive_format,
                archive_size: self.archive_size,
                uncompressed_size,
                complete: false,
            },
            checkpoints: self.checkpoints,
            entries: self.entries,
        }
    }

    /// Consume the builder and produce a complete `ArchiveIndex`.
    pub fn finish(self, uncompressed_size: u64) -> ArchiveIndex {
        ArchiveIndex {
            metadata: IndexMetadata {
                version: INDEX_VERSION,
                compression: self.compression,
                archive_format: self.archive_format,
                archive_size: self.archive_size,
                uncompressed_size,
                complete: true,
            },
            checkpoints: self.checkpoints,
            entries: self.entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::EntryType;
    use crate::compress::checkpoint::CheckpointState;

    fn make_entry(path: &str, size: u64, data_offset: u64) -> ArchiveEntry {
        ArchiveEntry {
            path: path.into(),
            size,
            entry_type: EntryType::Regular,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            mtime: 0,
            link_target: None,
            data_offset,
        }
    }

    #[test]
    fn test_build_index() {
        let mut builder = IndexBuilder::new(CompressionFormat::Gzip, ArchiveFormat::Tar, 1000);

        builder.add_checkpoint(Checkpoint {
            compressed_offset: 0,
            bit_offset: 0,
            uncompressed_offset: 0,
            state: CheckpointState::None,
        });

        builder.add_entry(make_entry("test.txt", 100, 512));

        assert_eq!(builder.checkpoint_count(), 1);
        assert_eq!(builder.entry_count(), 1);

        let index = builder.finish(2048);
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.checkpoints.len(), 1);
        assert_eq!(index.metadata.uncompressed_size, 2048);
        assert_eq!(index.metadata.compression, CompressionFormat::Gzip);
        assert!(index.metadata.complete);
    }

    #[test]
    fn test_snapshot() {
        let mut builder = IndexBuilder::new(CompressionFormat::Gzip, ArchiveFormat::Tar, 5000);

        builder.add_checkpoint(Checkpoint {
            compressed_offset: 0,
            bit_offset: 0,
            uncompressed_offset: 0,
            state: CheckpointState::None,
        });

        builder.add_entry(make_entry("a.txt", 100, 512));

        let snap = builder.snapshot(1024);
        assert_eq!(snap.entries.len(), 1);
        assert!(!snap.metadata.complete);
        assert!(snap.get("a.txt").is_some());

        // Builder is still usable
        builder.add_entry(make_entry("b.txt", 200, 2048));
        assert_eq!(builder.entry_count(), 2);

        let final_index = builder.finish(4096);
        assert_eq!(final_index.entries.len(), 2);
        assert!(final_index.metadata.complete);
    }

    #[test]
    fn test_last_entry_path() {
        let mut builder = IndexBuilder::new(CompressionFormat::None, ArchiveFormat::Tar, 0);
        assert_eq!(builder.last_entry_path(), None);

        builder.add_entry(make_entry("first.txt", 10, 512));
        assert_eq!(builder.last_entry_path(), Some("first.txt"));

        builder.add_entry(make_entry("second.txt", 20, 1024));
        assert_eq!(builder.last_entry_path(), Some("second.txt"));
    }

    #[test]
    fn test_finish_partial() {
        let mut builder = IndexBuilder::new(CompressionFormat::Gzip, ArchiveFormat::Tar, 1000);
        builder.add_checkpoint(Checkpoint {
            compressed_offset: 0,
            bit_offset: 0,
            uncompressed_offset: 0,
            state: CheckpointState::None,
        });
        builder.add_entry(make_entry("file.txt", 100, 512));

        let index = builder.finish_partial(1024);
        assert!(!index.metadata.complete);
        assert_eq!(index.entries.len(), 1);
    }

    #[test]
    fn test_entry_associated_with_checkpoint_at_or_before_data() {
        let mut builder = IndexBuilder::new(CompressionFormat::Gzip, ArchiveFormat::Tar, 1000);
        builder.add_checkpoint(Checkpoint {
            compressed_offset: 0,
            bit_offset: 0,
            uncompressed_offset: 0,
            state: CheckpointState::None,
        });
        builder.add_checkpoint(Checkpoint {
            compressed_offset: 500,
            bit_offset: 0,
            uncompressed_offset: 1000,
            state: CheckpointState::None,
        });

        // Entry data starts BEFORE the latest checkpoint: must use the earlier one.
        builder.add_entry(make_entry("early.txt", 100, 800));
        // Entry data starts after the latest checkpoint: uses it.
        builder.add_entry(make_entry("late.txt", 100, 1500));

        let index = builder.finish(4096);
        let early = index.get("early.txt").unwrap();
        let late = index.get("late.txt").unwrap();
        assert_eq!(early.checkpoint_index, 0);
        assert_eq!(late.checkpoint_index, 1);
        assert!(
            index.checkpoints[early.checkpoint_index].uncompressed_offset
                <= early.uncompressed_offset
        );
    }
}
