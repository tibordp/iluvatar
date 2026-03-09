/// A snapshot of the current indexing progress.
///
/// This is a plain data struct with no references back to the engine,
/// making it safe to send across threads or store for later comparison.
///
/// Obtained by calling [`IndexingEngine::progress()`](crate::IndexingEngine::progress).
///
/// # Example
///
/// ```
/// # fn show_progress(progress: &iluvatar::IndexProgress) {
/// if let Some(pct) = progress.fraction() {
///     println!(
///         "{:.1}% — {} entries, {} checkpoints",
///         pct * 100.0,
///         progress.entries_found,
///         progress.checkpoints_created,
///     );
/// }
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct IndexProgress {
    /// Number of compressed bytes consumed so far.
    pub compressed_bytes_processed: u64,
    /// Total compressed archive size (as provided at construction).
    /// Zero if unknown.
    pub compressed_bytes_total: u64,
    /// Number of uncompressed bytes produced so far.
    pub uncompressed_bytes_processed: u64,
    /// Number of file entries discovered so far (excludes metadata entries).
    pub entries_found: usize,
    /// Number of decompressor checkpoints created so far.
    pub checkpoints_created: usize,
    /// Total bytes of checkpoint state data accumulated so far.
    pub checkpoint_data_bytes: u64,
    /// Path of the most recently discovered entry, if any.
    pub last_entry_path: Option<String>,
    /// Whether indexing is complete.
    pub is_complete: bool,
}

impl IndexProgress {
    /// Fraction of the compressed archive processed (0.0 to 1.0).
    ///
    /// Returns `None` if the total archive size is unknown (zero).
    pub fn fraction(&self) -> Option<f64> {
        if self.compressed_bytes_total == 0 {
            None
        } else {
            Some(self.compressed_bytes_processed as f64 / self.compressed_bytes_total as f64)
        }
    }
}
