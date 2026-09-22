/// A snapshot of a [`StreamIndexer`](crate::StreamIndexer)'s progress.
#[derive(Debug, Clone)]
pub struct StreamProgress {
    /// Packed bytes consumed so far.
    pub compressed_pos: u64,
    /// Packed length, if known.
    pub compressed_len: Option<u64>,
    /// Unpacked bytes decoded so far.
    pub unpacked_pos: u64,
    /// Unpacked length, if known.
    pub unpacked_len: Option<u64>,
    pub checkpoints: usize,
    /// Estimated bytes of checkpoint state so far.
    pub checkpoint_data_bytes: u64,
    /// Whether the indexer has stopped (at the stream end or a stop offset).
    pub done: bool,
}

impl StreamProgress {
    /// Fraction of the stream processed, from whichever length is known.
    pub fn fraction(&self) -> Option<f64> {
        match (self.unpacked_len, self.compressed_len) {
            (Some(len), _) if len > 0 => Some(self.unpacked_pos as f64 / len as f64),
            (_, Some(len)) if len > 0 => Some(self.compressed_pos as f64 / len as f64),
            _ => None,
        }
    }
}
