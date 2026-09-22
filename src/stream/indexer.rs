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
/// before decoding continues (this is how the tar and cpio parsers see the
/// stream).
///
/// An indexer can stop early ([`stop_at`](Self::stop_at)) and a partial
/// index can be extended later ([`resume`](Self::resume)) without
/// re-decoding what an earlier pass covered.
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
        let ended = result.status == DecompressStatus::StreamEnd
            || (!had_input && result.bytes_consumed == 0 && produced == 0);
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

    /// Lay a checkpoint at the current position if the codec can. `notify`
    /// tells the strategy about it (a stop checkpoint is not its doing).
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
        Ok(())
    }

    /// Provide compressed data after `NeedInput` or `SeekAndRead`.
    pub fn provide_data(&mut self, data: &[u8]) {
        self.input_buf.clear();
        self.input_buf.extend_from_slice(data);
        self.input_pos = 0;
        self.state = State::Processing;
    }

    /// The compressed stream has no more bytes.
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
