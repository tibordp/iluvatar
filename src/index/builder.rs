use crate::archive::{ArchiveEntry, ArchiveFormat};
use crate::compress::CompressionFormat;
use crate::index::entry::IndexEntry;
use crate::index::store::{ArchiveIndex, IndexMetadata, INDEX_VERSION};
use crate::stream::StreamIndex;
use std::collections::HashMap;

/// Accumulates entries during the indexing pass; the checkpoints come from
/// the stream indexer when the index is assembled.
pub struct IndexBuilder {
    entries: HashMap<String, IndexEntry>,
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
            compression,
            archive_format,
            archive_size,
            last_entry_path: None,
        }
    }

    /// Record the detected container format.
    pub fn set_archive_format(&mut self, format: ArchiveFormat) {
        self.archive_format = format;
    }

    /// Add an archive entry to the index.
    pub fn add_entry(&mut self, entry: ArchiveEntry) {
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
            checkpoint_index: 0,
        };
        self.entries.insert(entry.path, index_entry);
    }

    /// Number of entries added so far.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Path of the most recently added entry, if any.
    pub fn last_entry_path(&self) -> Option<&str> {
        self.last_entry_path.as_deref()
    }

    /// Clone the current state into a usable partial `ArchiveIndex`.
    ///
    /// The engine continues to be usable for further indexing.
    pub fn snapshot(&self, stream: StreamIndex) -> ArchiveIndex {
        assemble(
            self.entries.clone(),
            self.compression,
            self.archive_format,
            self.archive_size,
            stream,
            false,
        )
    }

    /// Consume the builder into an `ArchiveIndex`; `complete` records
    /// whether the whole archive was seen.
    pub fn finish(self, stream: StreamIndex, complete: bool) -> ArchiveIndex {
        assemble(
            self.entries,
            self.compression,
            self.archive_format,
            self.archive_size,
            stream,
            complete,
        )
    }
}

/// Associate every entry with the latest checkpoint at or before its data
/// — a later checkpoint (one taken at the end of the chunk the entry was
/// discovered in) cannot be used to read it.
fn assemble(
    mut entries: HashMap<String, IndexEntry>,
    compression: CompressionFormat,
    archive_format: ArchiveFormat,
    archive_size: u64,
    stream: StreamIndex,
    complete: bool,
) -> ArchiveIndex {
    for entry in entries.values_mut() {
        entry.checkpoint_index = stream
            .best_checkpoint_for_offset(entry.uncompressed_offset)
            .0;
    }
    ArchiveIndex {
        metadata: IndexMetadata {
            version: INDEX_VERSION,
            compression,
            archive_format,
            archive_size,
            uncompressed_size: stream.indexed_to,
            complete,
        },
        stream,
        entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::EntryType;
    use crate::compress::checkpoint::{Checkpoint, CheckpointState};

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

    fn stream(checkpoints: &[(u64, u64)], indexed_to: u64) -> StreamIndex {
        let mut s = StreamIndex::new(CompressionFormat::Gzip.into(), Some(1000));
        for &(c, u) in &checkpoints[1..] {
            s.checkpoints.push(Checkpoint {
                compressed_offset: c,
                bit_offset: 0,
                uncompressed_offset: u,
                state: CheckpointState::None,
            });
        }
        s.indexed_to = indexed_to;
        s
    }

    #[test]
    fn test_build_index() {
        let mut builder = IndexBuilder::new(CompressionFormat::Gzip, ArchiveFormat::Tar, 1000);
        builder.add_entry(make_entry("test.txt", 100, 512));
        assert_eq!(builder.entry_count(), 1);

        let index = builder.finish(stream(&[(0, 0)], 2048), true);
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.checkpoints().len(), 1);
        assert_eq!(index.metadata.uncompressed_size, 2048);
        assert_eq!(index.metadata.compression, CompressionFormat::Gzip);
        assert!(index.metadata.complete);
    }

    #[test]
    fn test_snapshot() {
        let mut builder = IndexBuilder::new(CompressionFormat::Gzip, ArchiveFormat::Tar, 5000);
        builder.add_entry(make_entry("a.txt", 100, 512));

        let snap = builder.snapshot(stream(&[(0, 0)], 1024));
        assert_eq!(snap.entries.len(), 1);
        assert!(!snap.metadata.complete);
        assert!(snap.get("a.txt").is_some());

        // Builder is still usable
        builder.add_entry(make_entry("b.txt", 200, 2048));
        assert_eq!(builder.entry_count(), 2);

        let final_index = builder.finish(stream(&[(0, 0)], 4096), true);
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
        builder.add_entry(make_entry("file.txt", 100, 512));

        let index = builder.finish(stream(&[(0, 0)], 1024), false);
        assert!(!index.metadata.complete);
        assert_eq!(index.entries.len(), 1);
    }

    #[test]
    fn test_entry_associated_with_checkpoint_at_or_before_data() {
        let mut builder = IndexBuilder::new(CompressionFormat::Gzip, ArchiveFormat::Tar, 1000);
        // Entry data starts BEFORE the latest checkpoint: must use the earlier one.
        builder.add_entry(make_entry("early.txt", 100, 800));
        // Entry data starts after the latest checkpoint: uses it.
        builder.add_entry(make_entry("late.txt", 100, 1500));

        let index = builder.finish(stream(&[(0, 0), (500, 1000)], 4096), true);
        let early = index.get("early.txt").unwrap();
        let late = index.get("late.txt").unwrap();
        assert_eq!(early.checkpoint_index, 0);
        assert_eq!(late.checkpoint_index, 1);
        assert!(index.checkpoint_for(early).uncompressed_offset <= early.uncompressed_offset);
    }
}
