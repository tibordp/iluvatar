use crate::error::{Result, SupertarError};
use crate::index::store::{ArchiveIndex, INDEX_VERSION};

/// Magic bytes for the supertar index file format.
const INDEX_MAGIC: &[u8; 8] = b"STRIDX\x00\x01";

impl ArchiveIndex {
    /// Serialize the index to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.extend_from_slice(INDEX_MAGIC);
        bincode::serialize_into(&mut buf, self)
            .map_err(|e| SupertarError::Serialization(e.to_string()))?;
        Ok(buf)
    }

    /// Deserialize an index from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < INDEX_MAGIC.len() {
            return Err(SupertarError::IndexError("data too short".into()));
        }

        if &data[..INDEX_MAGIC.len()] != INDEX_MAGIC {
            return Err(SupertarError::IndexError("invalid index magic".into()));
        }

        let index: ArchiveIndex = bincode::deserialize(&data[INDEX_MAGIC.len()..])
            .map_err(|e| SupertarError::Serialization(e.to_string()))?;

        if index.metadata.version != INDEX_VERSION {
            return Err(SupertarError::IndexVersionMismatch {
                expected: INDEX_VERSION,
                got: index.metadata.version,
            });
        }

        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ArchiveFormat, EntryType};
    use crate::compress::checkpoint::{Checkpoint, CheckpointState, GzipCheckpointState};
    use crate::compress::CompressionFormat;
    use crate::index::entry::IndexEntry;
    use crate::index::store::IndexMetadata;
    use std::collections::HashMap;

    fn make_test_index() -> ArchiveIndex {
        let mut entries = HashMap::new();
        entries.insert(
            "test.txt".into(),
            IndexEntry {
                path: "test.txt".into(),
                size: 1234,
                entry_type: EntryType::Regular,
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                mtime: 1700000000,
                link_target: None,
                uncompressed_offset: 512,
                checkpoint_index: 0,
            },
        );

        ArchiveIndex {
            metadata: IndexMetadata {
                version: INDEX_VERSION,
                compression: CompressionFormat::Gzip,
                archive_format: ArchiveFormat::Tar,
                archive_size: 5000,
                uncompressed_size: 10000,
                complete: true,
            },
            checkpoints: vec![
                Checkpoint {
                    compressed_offset: 0,
                    bit_offset: 0,
                    uncompressed_offset: 0,
                    state: CheckpointState::None,
                },
                Checkpoint {
                    compressed_offset: 2500,
                    bit_offset: 0,
                    uncompressed_offset: 5000,
                    state: CheckpointState::Gzip(GzipCheckpointState {
                        window: vec![1, 2, 3, 4, 5],
                        block_state: None,
                        header_size: 10,
                    }),
                },
            ],
            entries,
        }
    }

    #[test]
    fn test_roundtrip() {
        let index = make_test_index();
        let bytes = index.to_bytes().unwrap();
        let restored = ArchiveIndex::from_bytes(&bytes).unwrap();

        assert_eq!(restored.metadata.version, index.metadata.version);
        assert_eq!(restored.metadata.compression, index.metadata.compression);
        assert_eq!(restored.metadata.archive_size, index.metadata.archive_size);
        assert_eq!(
            restored.metadata.uncompressed_size,
            index.metadata.uncompressed_size
        );
        assert_eq!(restored.checkpoints.len(), 2);
        assert_eq!(restored.entries.len(), 1);

        let entry = restored.get("test.txt").unwrap();
        assert_eq!(entry.size, 1234);
        assert_eq!(entry.uncompressed_offset, 512);
    }

    #[test]
    fn test_invalid_magic() {
        let result = ArchiveIndex::from_bytes(b"INVALID\x00data");
        assert!(result.is_err());
    }

    #[test]
    fn test_too_short() {
        let result = ArchiveIndex::from_bytes(b"SHORT");
        assert!(result.is_err());
    }

    #[test]
    fn test_serialized_size_is_reasonable() {
        let index = make_test_index();
        let bytes = index.to_bytes().unwrap();
        // Should be relatively compact
        assert!(bytes.len() < 1000);
    }
}
