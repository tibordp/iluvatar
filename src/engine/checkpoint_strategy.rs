use crate::compress::CompressionFormat;

/// Information available when making a checkpoint decision.
///
/// Passed to [`CheckpointStrategy::should_checkpoint`] on every
/// decompression step that produces output.
pub struct CheckpointContext {
    /// Current position in the uncompressed stream.
    pub uncompressed_pos: u64,
    /// Current position in the compressed stream.
    pub compressed_pos: u64,
    /// Uncompressed position of the last checkpoint.
    pub last_checkpoint_uncompressed_pos: u64,
    /// Number of checkpoints created so far (including the initial offset-0 one).
    pub checkpoint_count: usize,
    /// Total bytes of checkpoint state data accumulated so far.
    pub total_checkpoint_data_bytes: u64,
    /// Total compressed archive size (0 if unknown).
    pub archive_size: u64,
}

/// Decides when to take decompressor checkpoints during indexing.
///
/// The engine calls [`should_checkpoint`](CheckpointStrategy::should_checkpoint)
/// after each decompression step that produces output. Returning `true`
/// causes the engine to snapshot the decompressor state.
///
/// Used as a type parameter on [`IndexingEngine`](crate::IndexingEngine),
/// so strategies are monomorphized — no dynamic dispatch overhead on the
/// hot decompression path.
///
/// # Built-in strategies
///
/// - [`FixedInterval`] — checkpoint every N bytes of uncompressed output
/// - [`Budget`] — keep total checkpoint data under a byte limit
/// - [`BudgetRatio`] — keep checkpoint data under a fraction of archive size
///
/// # Implementing a custom strategy
///
/// ```
/// use iluvatar::{CheckpointStrategy, CheckpointContext};
///
/// /// Checkpoint every N entries instead of every N bytes.
/// struct EveryNEntries { n: usize, count: usize }
///
/// impl CheckpointStrategy for EveryNEntries {
///     fn should_checkpoint(&mut self, ctx: &CheckpointContext) -> bool {
///         // Simple example: checkpoint every 1 MiB regardless
///         ctx.uncompressed_pos - ctx.last_checkpoint_uncompressed_pos >= 1024 * 1024
///     }
/// }
/// ```
pub trait CheckpointStrategy {
    /// Returns `true` if a checkpoint should be created now.
    fn should_checkpoint(&mut self, ctx: &CheckpointContext) -> bool;

    /// Called after a checkpoint is created, with the checkpoint data size.
    ///
    /// Adaptive strategies use this to refine their estimates. The default
    /// implementation is a no-op.
    fn on_checkpoint_created(&mut self, _ctx: &CheckpointContext, _data_size: usize) {}
}

/// Checkpoint at fixed intervals of uncompressed data.
///
/// This is the simplest strategy: a checkpoint is created every `interval`
/// bytes of uncompressed output, regardless of checkpoint size. It is the
/// default strategy used by [`IndexingEngine::new`](crate::IndexingEngine::new),
/// with a format-aware interval from [`default_interval_for_format`].
///
/// # Example
///
/// ```
/// use iluvatar::FixedInterval;
///
/// // Checkpoint every 4 MiB of decompressed output
/// let strategy = FixedInterval::new(4 * 1024 * 1024);
/// ```
pub struct FixedInterval {
    interval: u64,
}

impl FixedInterval {
    /// Create a new fixed-interval strategy.
    ///
    /// `interval` is the number of uncompressed bytes between checkpoints.
    pub fn new(interval: u64) -> Self {
        Self { interval }
    }
}

impl CheckpointStrategy for FixedInterval {
    fn should_checkpoint(&mut self, ctx: &CheckpointContext) -> bool {
        ctx.uncompressed_pos - ctx.last_checkpoint_uncompressed_pos >= self.interval
    }
}

/// Adaptive strategy that targets a maximum total size for checkpoint data.
///
/// After the first checkpoint, it estimates the optimal interval based on
/// observed checkpoint sizes and compression ratio. The interval is adjusted
/// after each checkpoint to spread the remaining budget evenly across the
/// remaining uncompressed data.
///
/// Requires a known archive size for adaptation; with unknown size it still
/// works but uses a conservative fixed interval.
///
/// # Example
///
/// ```
/// use iluvatar::Budget;
///
/// // Keep total checkpoint data under 10 MiB
/// let strategy = Budget::new(10 * 1024 * 1024);
///
/// // Same, but with a custom minimum interval floor
/// let strategy = Budget::new(10 * 1024 * 1024)
///     .with_min_interval(512 * 1024);
/// ```
pub struct Budget {
    /// Maximum total bytes for all checkpoint data.
    budget: u64,
    /// Minimum interval to prevent excessive checkpoints.
    min_interval: u64,
    /// Current effective interval (adjusted dynamically).
    current_interval: u64,
}

impl Budget {
    /// Create a budget strategy with the given maximum total checkpoint data size.
    ///
    /// Uses a minimum interval of 256 KiB and an initial interval of 1 MiB
    /// (before the first checkpoint provides size data for adaptation).
    pub fn new(budget: u64) -> Self {
        Self {
            budget,
            min_interval: 256 * 1024,
            current_interval: 1024 * 1024,
        }
    }

    /// Set the minimum interval between checkpoints.
    pub fn with_min_interval(mut self, min_interval: u64) -> Self {
        self.min_interval = min_interval;
        self
    }
}

impl CheckpointStrategy for Budget {
    fn should_checkpoint(&mut self, ctx: &CheckpointContext) -> bool {
        // Don't exceed budget
        if ctx.total_checkpoint_data_bytes >= self.budget {
            return false;
        }
        ctx.uncompressed_pos - ctx.last_checkpoint_uncompressed_pos >= self.current_interval
    }

    fn on_checkpoint_created(&mut self, ctx: &CheckpointContext, data_size: usize) {
        // Need at least one real checkpoint (not the offset-0 one) to estimate
        let real_checkpoints = ctx.checkpoint_count.saturating_sub(1);
        if real_checkpoints == 0 || ctx.compressed_pos == 0 || ctx.archive_size == 0 {
            return;
        }

        let avg_size = ctx.total_checkpoint_data_bytes as f64 / real_checkpoints as f64;
        if avg_size <= 0.0 {
            return;
        }

        let compression_ratio = ctx.uncompressed_pos as f64 / ctx.compressed_pos as f64;
        let estimated_total_uncompressed = ctx.archive_size as f64 * compression_ratio;

        let remaining_budget = self.budget.saturating_sub(ctx.total_checkpoint_data_bytes);
        let remaining_checkpoints = remaining_budget as f64 / avg_size;
        let remaining_uncompressed = estimated_total_uncompressed - ctx.uncompressed_pos as f64;

        if remaining_checkpoints > 0.0 && remaining_uncompressed > 0.0 {
            let optimal = (remaining_uncompressed / remaining_checkpoints) as u64;
            self.current_interval = optimal.max(self.min_interval);
        }

        let _ = data_size;
    }
}

/// Adaptive strategy that targets a checkpoint-data-to-archive-size ratio.
///
/// For example, `BudgetRatio::new(0.1)` tries to keep total checkpoint data
/// under 10% of the compressed archive size. Requires a known archive size.
///
/// Falls back to a fixed 16 MiB interval if the archive size is unknown.
///
/// # Example
///
/// ```
/// use iluvatar::BudgetRatio;
///
/// // Keep checkpoint data under 5% of archive size
/// let strategy = BudgetRatio::new(0.05);
/// ```
pub struct BudgetRatio {
    ratio: f64,
    inner: Budget,
    /// Fallback interval when archive size is unknown.
    fallback_interval: u64,
    initialized: bool,
}

impl BudgetRatio {
    /// Create a ratio strategy. `ratio` is a fraction (e.g. 0.1 = 10%).
    pub fn new(ratio: f64) -> Self {
        Self {
            ratio,
            inner: Budget::new(0), // placeholder, set on first call
            fallback_interval: 16 * 1024 * 1024,
            initialized: false,
        }
    }
}

impl CheckpointStrategy for BudgetRatio {
    fn should_checkpoint(&mut self, ctx: &CheckpointContext) -> bool {
        if !self.initialized {
            self.initialized = true;
            if ctx.archive_size > 0 {
                let budget = (ctx.archive_size as f64 * self.ratio) as u64;
                self.inner = Budget::new(budget.max(1024));
            }
        }

        if ctx.archive_size == 0 {
            // Unknown size — fall back to fixed interval
            return ctx.uncompressed_pos - ctx.last_checkpoint_uncompressed_pos
                >= self.fallback_interval;
        }

        self.inner.should_checkpoint(ctx)
    }

    fn on_checkpoint_created(&mut self, ctx: &CheckpointContext, data_size: usize) {
        if ctx.archive_size > 0 {
            self.inner.on_checkpoint_created(ctx, data_size);
        }
    }
}

/// Returns a sensible default checkpoint interval for the given compression format.
///
/// Checkpoint state sizes vary dramatically by format, so the default interval
/// is tuned to keep index overhead reasonable:
///
/// | Format | Interval | Approx. checkpoint size |
/// |--------|----------|------------------------|
/// | None   | 1 MiB   | 0 bytes                |
/// | Bzip2  | 1 MiB   | ~12 bytes              |
/// | Gzip   | 16 MiB  | ~33 KB                 |
/// | Zstd   | 64 MiB  | 50–200 KB              |
/// | XZ     | 64 MiB  | 100–500 KB             |
///
/// # Example
///
/// ```
/// use iluvatar::{CompressionFormat, default_interval_for_format};
///
/// assert_eq!(default_interval_for_format(CompressionFormat::None), 1024 * 1024);
/// ```
pub fn default_interval_for_format(format: CompressionFormat) -> u64 {
    match format {
        CompressionFormat::None => 1024 * 1024,

        #[cfg(feature = "bz2")]
        CompressionFormat::Bzip2 => 1024 * 1024,

        #[cfg(feature = "gzip")]
        CompressionFormat::Gzip => 16 * 1024 * 1024,

        #[cfg(feature = "zstandard")]
        CompressionFormat::Zstd => 64 * 1024 * 1024,

        #[cfg(feature = "xz")]
        CompressionFormat::Xz => 64 * 1024 * 1024,

        #[allow(unreachable_patterns)]
        _ => 1024 * 1024,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(
        uncompressed_pos: u64,
        compressed_pos: u64,
        last_cp: u64,
        cp_count: usize,
        cp_bytes: u64,
        archive_size: u64,
    ) -> CheckpointContext {
        CheckpointContext {
            uncompressed_pos,
            compressed_pos,
            last_checkpoint_uncompressed_pos: last_cp,
            checkpoint_count: cp_count,
            total_checkpoint_data_bytes: cp_bytes,
            archive_size,
        }
    }

    #[test]
    fn test_fixed_interval() {
        let mut s = FixedInterval::new(1024);
        assert!(!s.should_checkpoint(&make_ctx(512, 100, 0, 1, 0, 0)));
        assert!(s.should_checkpoint(&make_ctx(1024, 200, 0, 1, 0, 0)));
        assert!(s.should_checkpoint(&make_ctx(2000, 400, 0, 1, 0, 0)));
        assert!(!s.should_checkpoint(&make_ctx(2000, 400, 1500, 2, 100, 0)));
        assert!(s.should_checkpoint(&make_ctx(3000, 600, 1500, 2, 100, 0)));
    }

    #[test]
    fn test_budget_stops_when_exhausted() {
        let mut s = Budget::new(1000);
        // Budget already spent
        assert!(!s.should_checkpoint(&make_ctx(2_000_000, 1000, 0, 1, 1000, 10000)));
    }

    #[test]
    fn test_budget_adapts_interval() {
        let mut s = Budget::new(10_000_000).with_min_interval(1024);
        // Simulate: archive_size=100MB compressed, ratio ~2x, so ~200MB uncompressed
        // First checkpoint at 10MB uncompressed, data_size=100KB
        let ctx = make_ctx(10_000_000, 5_000_000, 0, 2, 100_000, 100_000_000);
        s.on_checkpoint_created(&ctx, 100_000);

        // remaining_budget = 9_900_000, avg_size = 100_000, remaining_cp = 99
        // remaining_uncompressed = 200_000_000 - 10_000_000 = 190_000_000
        // optimal = 190_000_000 / 99 ≈ 1_919_191
        assert!(
            s.current_interval > 1_500_000,
            "interval {} should be > 1_500_000",
            s.current_interval
        );
        assert!(
            s.current_interval < 2_500_000,
            "interval {} should be < 2_500_000",
            s.current_interval
        );
    }

    #[test]
    fn test_budget_ratio_unknown_size() {
        let mut s = BudgetRatio::new(0.1);
        // archive_size = 0 (unknown) — should fall back to fixed 16 MiB
        assert!(!s.should_checkpoint(&make_ctx(1_000_000, 500_000, 0, 1, 0, 0)));
        assert!(s.should_checkpoint(&make_ctx(20_000_000, 10_000_000, 0, 1, 0, 0)));
    }

    #[test]
    fn test_budget_ratio_known_size() {
        let mut s = BudgetRatio::new(0.1);
        // archive_size = 1MB, so budget = 100KB
        // Should checkpoint at default 1MB interval initially
        assert!(s.should_checkpoint(&make_ctx(1_100_000, 500_000, 0, 1, 0, 1_000_000)));
    }

    #[test]
    fn test_default_intervals() {
        assert_eq!(
            default_interval_for_format(CompressionFormat::None),
            1024 * 1024
        );
    }
}
