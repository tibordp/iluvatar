use crate::compress::codec::CodecSpec;
use crate::compress::decompressor::{DecompressStatus, Decompressor};
use crate::engine::checkpoint_strategy::{CheckpointContext, CheckpointStrategy};
use crate::engine::request::EngineRequest;
use crate::error::{Error, Result};
use crate::stream::index::StreamIndex;
use crate::stream::progress::StreamProgress;
use crate::stream::BUF_SIZE;

enum State {
    /// Waiting for `provide_data` or `signal_eof`.
    NeedInput,
    /// A resumed indexer wants the caller positioned at `offset` first.
    Seek {
        offset: u64,
    },
    Processing,
    Done,
}

/// Lays checkpoints over one compressed stream, sans-I/O.
///
/// Drive it like the other engines: `step()`, satisfy the request, repeat.
/// The decoded bytes are discarded unless [`emit_output`](Self::emit_output)
/// is on, in which case each decoded chunk is handed out through
/// [`EngineRequest::OutputReady`] and [`read_output`](Self::read_output)
/// before decoding continues (this is how the archive parsers see the
/// stream).
///
/// An indexer can stop early ([`stop_at`](Self::stop_at)) and a partial
/// index can be extended later ([`resume`](Self::resume)) without
/// re-decoding what an earlier pass covered.
///
/// Checkpoints can disappear as well as appear while indexing: a strategy
/// may have the indexer thin them
/// ([`CheckpointStrategy::should_thin`]), so a checkpoint's position in
/// [`StreamIndex::checkpoints`] is only meaningful within one
/// [`snapshot`](Self::snapshot).
pub struct StreamIndexer<S: CheckpointStrategy> {
    decompressor: Box<dyn Decompressor>,
    index: StreamIndex,
    strategy: S,
    state: State,
    compressed_pos: u64,
    unpacked_pos: u64,
    last_checkpoint_pos: u64,
    checkpoint_data_bytes: u64,
    stop_at: Option<u64>,
    emit_output: bool,
    input_buf: Vec<u8>,
    input_pos: usize,
    eof: bool,
    out_buf: Vec<u8>,
    out_len: usize,
    out_read: usize,
}

impl<S: CheckpointStrategy> StreamIndexer<S> {
    /// Index a stream from its start.
    pub fn new(codec: CodecSpec, strategy: S, compressed_len: Option<u64>) -> Result<Self> {
        let decompressor = codec.create()?;
        let index = StreamIndex::new(codec, compressed_len);
        Ok(Self::with_parts(
            decompressor,
            index,
            strategy,
            State::NeedInput,
            0,
            0,
        ))
    }

    /// Continue an existing index from its last checkpoint. The caller
    /// gets a [`EngineRequest::SeekAndRead`] for the checkpoint's packed
    /// offset (or `NeedInput` when that is 0) before decoding resumes.
    /// Output below `indexed_to` is never emitted and lays no checkpoints.
    pub fn resume(index: StreamIndex, strategy: S) -> Result<Self> {
        if index.complete {
            return Err(Error::InvalidState(
                "stream index is already complete".into(),
            ));
        }
        let mut decompressor = index.codec.create()?;
        let cp = index.last_checkpoint();
        decompressor.restore(cp)?;
        let (compressed_pos, unpacked_pos) = (cp.compressed_offset, cp.uncompressed_offset);
        let state = if compressed_pos == 0 {
            State::NeedInput
        } else {
            State::Seek {
                offset: compressed_pos,
            }
        };
        Ok(Self::with_parts(
            decompressor,
            index,
            strategy,
            state,
            compressed_pos,
            unpacked_pos,
        ))
    }

    fn with_parts(
        decompressor: Box<dyn Decompressor>,
        index: StreamIndex,
        strategy: S,
        state: State,
        compressed_pos: u64,
        unpacked_pos: u64,
    ) -> Self {
        let checkpoint_data_bytes = index.checkpoint_data_bytes();
        Self {
            decompressor,
            index,
            strategy,
            state,
            compressed_pos,
            unpacked_pos,
            last_checkpoint_pos: unpacked_pos,
            checkpoint_data_bytes,
            stop_at: None,
            emit_output: false,
            input_buf: Vec::new(),
            input_pos: 0,
            eof: false,
            out_buf: vec![0; BUF_SIZE],
            out_len: 0,
            out_read: 0,
        }
    }

    /// Hand decoded bytes to the caller instead of discarding them.
    pub fn emit_output(&mut self, emit: bool) {
        self.emit_output = emit;
    }

    /// Stop once decoding has reached or passed this unpacked offset. The
    /// index then ends with a checkpoint at the stopping point when the
    /// codec allows one, so a later `resume` picks up exactly there.
    pub fn stop_at(&mut self, unpacked_offset: u64) {
        self.stop_at = Some(unpacked_offset);
    }

    /// Declare the unpacked length (a container may know it up front).
    pub fn set_unpacked_len(&mut self, len: u64) {
        self.index.unpacked_len = Some(len);
    }

    /// Drive the indexer. Returns what it needs next.
    pub fn step(&mut self) -> EngineRequest {
        loop {
            match self.step_once() {
                Some(request) => return request,
                None => continue,
            }
        }
    }

    fn step_once(&mut self) -> Option<EngineRequest> {
        match self.state {
            State::Done => return Some(EngineRequest::Done),
            State::Seek { offset } => {
                self.state = State::NeedInput;
                return Some(EngineRequest::SeekAndRead {
                    offset,
                    len: BUF_SIZE,
                });
            }
            State::NeedInput => {
                if !self.eof {
                    return Some(EngineRequest::NeedInput);
                }
                self.state = State::Processing;
            }
            State::Processing => {}
        }
        if self.out_read < self.out_len {
            return Some(EngineRequest::OutputReady);
        }

        let input = if self.input_pos < self.input_buf.len() {
            &self.input_buf[self.input_pos..]
        } else if self.eof {
            &[]
        } else {
            self.state = State::NeedInput;
            return Some(EngineRequest::NeedInput);
        };
        let had_input = !input.is_empty();

        let result = match self.decompressor.decompress(input, &mut self.out_buf) {
            Ok(r) => r,
            Err(e) => return Some(EngineRequest::Error(e)),
        };
        self.input_pos += result.bytes_consumed;
        self.compressed_pos += result.bytes_consumed as u64;
        let produced = result.bytes_produced;
        let before = self.unpacked_pos;
        self.unpacked_pos += produced as u64;

        // Bytes an earlier pass already covered (after `resume`) are
        // neither emitted nor checkpointed.
        let fresh = self.unpacked_pos > self.index.indexed_to;
        if produced > 0 && fresh {
            let ctx = self.context();
            if self.strategy.should_checkpoint(&ctx) {
                if let Err(e) = self.try_checkpoint(true) {
                    return Some(EngineRequest::Error(e));
                }
            }
            if self.emit_output {
                let skip = self.index.indexed_to.saturating_sub(before) as usize;
                self.out_read = skip;
                self.out_len = produced;
            }
        }
        if fresh {
            self.index.indexed_to = self.unpacked_pos;
        }

        let stopped = self.stop_at.is_some_and(|stop| self.unpacked_pos >= stop);
        // Out of input with nothing left to give but no end of stream: the
        // compressed stream was cut short. An empty file is an empty stream.
        let idle_at_eof = !had_input && result.bytes_consumed == 0 && produced == 0;
        if idle_at_eof && result.status != DecompressStatus::StreamEnd && self.compressed_pos > 0 {
            return Some(EngineRequest::Error(Error::TruncatedInput));
        }
        let ended = result.status == DecompressStatus::StreamEnd || idle_at_eof;
        if ended || stopped {
            if ended {
                self.index.complete = true;
                self.index.unpacked_len = Some(self.unpacked_pos);
            } else if let Err(e) = self.try_checkpoint(false) {
                return Some(EngineRequest::Error(e));
            }
            self.state = State::Done;
            return Some(if self.out_read < self.out_len {
                EngineRequest::OutputReady
            } else {
                EngineRequest::Done
            });
        }

        if self.out_read < self.out_len {
            return Some(EngineRequest::OutputReady);
        }
        if self.input_pos >= self.input_buf.len() {
            if self.eof {
                // Drain internally buffered output before concluding.
                return Some(EngineRequest::NeedInput);
            }
            self.state = State::NeedInput;
            return Some(EngineRequest::NeedInput);
        }
        if result.bytes_consumed == 0 && produced == 0 {
            return Some(EngineRequest::Error(Error::DecompressionError(
                "decompressor made no progress with input remaining".into(),
            )));
        }
        None
    }

    fn context(&self) -> CheckpointContext {
        CheckpointContext {
            uncompressed_pos: self.unpacked_pos,
            compressed_pos: self.compressed_pos,
            last_checkpoint_uncompressed_pos: self.last_checkpoint_pos,
            checkpoint_count: self.index.checkpoints.len(),
            total_checkpoint_data_bytes: self.checkpoint_data_bytes,
            archive_size: self.index.compressed_len.unwrap_or(0),
        }
    }

    /// Lay a checkpoint at the current position if the codec can, then
    /// thin while the strategy asks. `notify` tells the strategy about the
    /// new checkpoint (a stop checkpoint is not its doing).
    fn try_checkpoint(&mut self, notify: bool) -> Result<()> {
        if self.unpacked_pos == self.last_checkpoint_pos
            && self.index.last_checkpoint().uncompressed_offset == self.unpacked_pos
        {
            return Ok(());
        }
        let cp = match self
            .decompressor
            .checkpoint(self.compressed_pos, self.unpacked_pos)?
        {
            Some(cp) => cp,
            None => return Ok(()),
        };
        let size = cp.estimated_size();
        self.checkpoint_data_bytes += size as u64;
        self.index.checkpoints.push(cp);
        self.last_checkpoint_pos = self.unpacked_pos;
        if notify {
            let ctx = self.context();
            self.strategy.on_checkpoint_created(&ctx, size);
        }
        while self.strategy.should_thin(&self.context()) && self.index.thin() {
            self.checkpoint_data_bytes = self.index.checkpoint_data_bytes();
            self.last_checkpoint_pos = self.index.last_checkpoint().uncompressed_offset;
        }
        Ok(())
    }

    /// Provide compressed data after `NeedInput` or `SeekAndRead`.
    pub fn provide_data(&mut self, data: &[u8]) {
        self.input_buf.clear();
        self.input_buf.extend_from_slice(data);
        self.input_pos = 0;
        self.state = State::Processing;
    }

    /// The compressed stream has no more bytes. If it stopped short of its
    /// end marker, stepping on fails with
    /// [`Error::TruncatedInput`]; no bytes at
    /// all is an empty stream.
    pub fn signal_eof(&mut self) {
        self.eof = true;
        self.state = State::Processing;
    }

    /// Take decoded bytes after `OutputReady`. Returns 0 when the chunk
    /// is drained; the next `step` then continues decoding.
    pub fn read_output(&mut self, buf: &mut [u8]) -> usize {
        let available = self.out_len - self.out_read;
        if available == 0 {
            return 0;
        }
        let n = available.min(buf.len());
        buf[..n].copy_from_slice(&self.out_buf[self.out_read..self.out_read + n]);
        self.out_read += n;
        if self.out_read >= self.out_len {
            self.out_len = 0;
            self.out_read = 0;
        }
        n
    }

    /// A snapshot of progress so far.
    pub fn progress(&self) -> StreamProgress {
        StreamProgress {
            compressed_pos: self.compressed_pos,
            compressed_len: self.index.compressed_len,
            unpacked_pos: self.unpacked_pos,
            unpacked_len: self.index.unpacked_len,
            checkpoints: self.index.checkpoints.len(),
            checkpoint_data_bytes: self.checkpoint_data_bytes,
            done: matches!(self.state, State::Done),
        }
    }

    /// The index as it stands; the indexer stays usable.
    pub fn snapshot(&self) -> StreamIndex {
        self.index.clone()
    }

    /// Consume the indexer. The index is complete if the stream end was
    /// reached, partial otherwise.
    pub fn finish(self) -> StreamIndex {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::checkpoint::{Bzip2CheckpointState, Checkpoint, CheckpointState};
    use crate::compress::codec::Codec;
    use crate::compress::decompressor::DecompressResult;
    use crate::engine::checkpoint_strategy::{Budget, ThinningBudget};

    const MIB: u64 = 1024 * 1024;

    /// A stream of `early` packed bytes that unpack 2:1, then `late` packed
    /// bytes that unpack 1024:1 (the empty tail of a disk image). Every
    /// position can be checkpointed, at `CP_STATE` bytes of state.
    struct RatioJump {
        early: u64,
        late: u64,
        consumed: u64,
    }

    const CP_STATE: usize = 1000;

    impl Decompressor for RatioJump {
        fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
            let (mut used, mut produced) = (0, 0);
            while used < input.len() && self.consumed < self.early + self.late {
                let ratio = if self.consumed < self.early { 2 } else { 1024 };
                if produced + ratio > output.len() {
                    break;
                }
                used += 1;
                produced += ratio;
                self.consumed += 1;
            }
            let status = if self.consumed == self.early + self.late {
                DecompressStatus::StreamEnd
            } else {
                DecompressStatus::Continue
            };
            Ok(DecompressResult {
                bytes_consumed: used,
                bytes_produced: produced,
                status,
            })
        }

        fn checkpoint(&self, compressed: u64, uncompressed: u64) -> Result<Option<Checkpoint>> {
            Ok(Some(Checkpoint {
                compressed_offset: compressed,
                bit_offset: 0,
                uncompressed_offset: uncompressed,
                state: CheckpointState::Bzip2(Bzip2CheckpointState {
                    block_number: 0,
                    stream_header: vec![0; CP_STATE],
                }),
            }))
        }

        fn restore(&mut self, _: &Checkpoint) -> Result<()> {
            unreachable!()
        }
    }

    fn index_ratio_jump<S: CheckpointStrategy>(early: u64, late: u64, strategy: S) -> StreamIndex {
        let decompressor = RatioJump {
            early,
            late,
            consumed: 0,
        };
        let index = StreamIndex::new(CodecSpec::single(Codec::Copy), Some(early + late));
        let mut indexer = StreamIndexer::with_parts(
            Box::new(decompressor),
            index,
            strategy,
            State::NeedInput,
            0,
            0,
        );
        let chunk = vec![0u8; BUF_SIZE];
        let mut fed = 0;
        loop {
            match indexer.step() {
                EngineRequest::NeedInput if fed == early + late => indexer.signal_eof(),
                EngineRequest::NeedInput => {
                    let n = (early + late - fed).min(chunk.len() as u64);
                    indexer.provide_data(&chunk[..n as usize]);
                    fed += n;
                }
                EngineRequest::Done => break,
                other => panic!("unexpected {other:?}"),
            }
            assert_eq!(
                indexer.checkpoint_data_bytes,
                indexer.index.checkpoint_data_bytes()
            );
        }
        indexer.finish()
    }

    /// The widest gap between consecutive checkpoints, or from the last
    /// checkpoint to the end of the stream.
    fn widest_gap(index: &StreamIndex) -> u64 {
        let offsets: Vec<u64> = index
            .checkpoints
            .iter()
            .map(|cp| cp.uncompressed_offset)
            .chain(index.unpacked_len)
            .collect();
        offsets.windows(2).map(|w| w[1] - w[0]).max().unwrap()
    }

    #[test]
    fn thinning_budget_covers_a_late_ratio_jump() {
        // 32 MiB unpacked from the first 16 MiB packed, then 1 GiB from 1 MiB.
        let (early, late) = (16 * MIB, MIB);
        let budget = 64 * 1024;
        let cp_size = (17 + CP_STATE + 8) as u64;

        let index = index_ratio_jump(early, late, ThinningBudget::new(budget));
        assert!(index.complete);
        let len = index.unpacked_len.unwrap();
        assert_eq!(len, 2 * early + 1024 * late);
        assert_eq!(index.checkpoints[0].uncompressed_offset, 0);
        assert!(index
            .checkpoints
            .windows(2)
            .all(|w| w[0].uncompressed_offset < w[1].uncompressed_offset));
        assert!(index.checkpoint_data_bytes() <= budget);
        // Thinning leaves at least half the budget's worth of checkpoints,
        // evenly spaced, so no gap exceeds twice the even spacing of that.
        let even = len / (budget / (2 * cp_size));
        assert!(
            widest_gap(&index) <= 2 * even,
            "widest gap {} over {} checkpoints",
            widest_gap(&index),
            index.checkpoints.len()
        );

        // `Budget` extrapolates the early ratio and spends everything on
        // the first 34 MiB it expects, leaving the tail uncovered.
        let index = index_ratio_jump(early, late, Budget::new(budget));
        assert!(index.checkpoint_data_bytes() <= budget + cp_size);
        assert!(widest_gap(&index) > len / 2);
    }

    #[test]
    fn thinning_keeps_the_newest_and_the_first() {
        let mut index = StreamIndex::new(CodecSpec::single(Codec::Copy), None);
        for off in 1..=6 {
            index.checkpoints.push(Checkpoint {
                compressed_offset: off,
                bit_offset: 0,
                uncompressed_offset: off * 10,
                state: CheckpointState::None,
            });
        }
        let offsets = |index: &StreamIndex| -> Vec<u64> {
            index
                .checkpoints
                .iter()
                .map(|cp| cp.uncompressed_offset)
                .collect()
        };
        assert!(index.thin());
        assert_eq!(offsets(&index), [0, 20, 40, 60]);
        assert!(index.thin());
        assert_eq!(offsets(&index), [0, 40, 60]);
        assert!(index.thin());
        assert_eq!(offsets(&index), [0, 60]);
        assert!(index.thin());
        assert_eq!(offsets(&index), [0]);
        assert!(!index.thin());
    }

    #[test]
    fn budget_smaller_than_a_checkpoint_keeps_only_the_start() {
        let index = index_ratio_jump(
            MIB,
            0,
            ThinningBudget::new(100).with_min_interval(64 * 1024),
        );
        assert!(index.complete);
        assert_eq!(index.checkpoints.len(), 1);
    }
}
