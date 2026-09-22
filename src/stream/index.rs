use serde::{Deserialize, Serialize};

use crate::compress::checkpoint::{Checkpoint, CheckpointState};
use crate::compress::codec::CodecSpec;

/// The checkpoint table of one compressed stream.
///
/// Always holds the offset-0 checkpoint, so any position can be reached by
/// decoding forward from *some* checkpoint. `indexed_to` is how far the
/// indexer has decoded; a partial index is usable up to there and can be
/// extended with [`StreamIndexer::resume`](crate::StreamIndexer::resume).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamIndex {
    pub codec: CodecSpec,
    /// Packed length, when the caller knows it.
    pub compressed_len: Option<u64>,
    /// Unpacked length: known once the stream end was reached, or declared
    /// by the container up front.
    pub unpacked_len: Option<u64>,
    /// Sorted by unpacked offset.
    pub checkpoints: Vec<Checkpoint>,
    /// Unpacked position the indexer has decoded up to.
    pub indexed_to: u64,
    /// Whether the indexer reached the end of the stream.
    pub complete: bool,
}

impl StreamIndex {
    /// An index that knows nothing yet but the start.
    pub fn new(codec: CodecSpec, compressed_len: Option<u64>) -> Self {
        Self {
            codec,
            compressed_len,
            unpacked_len: None,
            checkpoints: vec![Checkpoint {
                compressed_offset: 0,
                bit_offset: 0,
                uncompressed_offset: 0,
                state: CheckpointState::None,
            }],
            indexed_to: 0,
            complete: false,
        }
    }

    /// The checkpoint with the largest unpacked offset at or before
    /// `unpacked_offset`, and its index.
    pub fn best_checkpoint_for_offset(&self, unpacked_offset: u64) -> (usize, &Checkpoint) {
        let idx = self
            .checkpoints
            .partition_point(|cp| cp.uncompressed_offset <= unpacked_offset)
            .saturating_sub(1);
        (idx, &self.checkpoints[idx])
    }

    pub fn last_checkpoint(&self) -> &Checkpoint {
        self.checkpoints
            .last()
            .expect("a stream index always holds the start checkpoint")
    }

    /// Estimated bytes of checkpoint state.
    pub fn checkpoint_data_bytes(&self) -> u64 {
        self.checkpoints
            .iter()
            .map(|cp| cp.estimated_size() as u64)
            .sum()
    }

    /// Structural checks for an index that came from untrusted bytes.
    pub(crate) fn validate(&self) -> crate::error::Result<()> {
        if self.checkpoints.is_empty() {
            return Err(crate::error::Error::IndexError(
                "stream index contains no checkpoints".into(),
            ));
        }
        if self.checkpoints[0].uncompressed_offset != 0 {
            return Err(crate::error::Error::IndexError(
                "stream index does not start at offset 0".into(),
            ));
        }
        if self
            .checkpoints
            .windows(2)
            .any(|w| w[0].uncompressed_offset > w[1].uncompressed_offset)
        {
            return Err(crate::error::Error::IndexError(
                "stream index checkpoints are not sorted".into(),
            ));
        }
        Ok(())
    }
}
