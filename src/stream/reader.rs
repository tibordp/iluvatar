use crate::compress::checkpoint::Checkpoint;
use crate::compress::decompressor::{DecompressStatus, Decompressor};
use crate::engine::request::EngineRequest;
use crate::error::{Error, Result};
use crate::stream::index::StreamIndex;
use crate::stream::BUF_SIZE;

#[derive(Debug)]
enum State {
    /// Restore the checkpoint and ask for its packed bytes.
    SeekToCheckpoint,
    /// Decoding and discarding until the target offset.
    Skipping {
        remaining: u64,
    },
    /// Decoding target bytes.
    Emitting {
        remaining: u64,
    },
    /// Waiting for input while skipping.
    NeedInputSkipping {
        remaining: u64,
    },
    /// Waiting for input while emitting.
    NeedInputEmitting {
        remaining: u64,
    },
    Done,
}

/// Decodes an unpacked byte range of a stream, sans-I/O.
///
/// Restores the nearest checkpoint at or before the range and decodes
/// forward. A reader stays live after its range is delivered:
/// [`seek_forward`](Self::seek_forward) retargets it at a later range
/// without restoring anything, so sequential reads cost only the new
/// bytes.
pub struct StreamReader {
    decompressor: Box<dyn Decompressor>,
    checkpoint: Checkpoint,
    target_offset: u64,
    target_len: u64,
    state: State,
    /// Decoded bytes not yet handed out live at `output_read..output_len`.
    /// They may extend past the current range: `range_left` caps what
    /// `read_output` serves, and the rest waits for a `seek_forward`.
    output_buf: Vec<u8>,
    skip_buf: Vec<u8>,
    output_len: usize,
    output_read: usize,
    range_left: u64,
    input_buf: Vec<u8>,
    input_pos: usize,
    /// Packed offset of the next byte the caller should provide.
    compressed_pos: u64,
    /// Unpacked position of the decoder (end of `output_buf`).
    unpacked_pos: u64,
    eof: bool,
    /// The decoder reported the end of the stream.
    stream_ended: bool,
}

impl StreamReader {
    /// Read `len` unpacked bytes starting at `offset`. A range past the
    /// data the stream holds is cut short; one starting at or past the end
    /// completes with no output.
    pub fn new(index: &StreamIndex, offset: u64, len: u64) -> Result<Self> {
        let decompressor = index.codec.create()?;
        let (_, checkpoint) = index.best_checkpoint_for_offset(offset);
        let mut len = len;
        if let Some(total) = index.unpacked_len {
            len = len.min(total.saturating_sub(offset));
        }
        Ok(Self {
            decompressor,
            checkpoint: checkpoint.clone(),
            target_offset: offset,
            target_len: len,
            state: if len == 0 {
                State::Done
            } else {
                State::SeekToCheckpoint
            },
            output_buf: vec![0; BUF_SIZE],
            skip_buf: vec![0; BUF_SIZE],
            output_len: 0,
            output_read: 0,
            range_left: len,
            input_buf: Vec::new(),
            input_pos: 0,
            compressed_pos: checkpoint.compressed_offset,
            unpacked_pos: 0,
            eof: false,
            stream_ended: false,
        })
    }

    /// Decoded bytes the caller may take right now.
    fn serveable(&self) -> usize {
        ((self.output_len - self.output_read) as u64).min(self.range_left) as usize
    }

    /// Unpacked position of the next byte `read_output` would return.
    pub fn position(&self) -> u64 {
        self.unpacked_pos - (self.output_len - self.output_read) as u64
    }

    /// Packed offset the next [`EngineRequest::NeedInput`] should be
    /// answered from. A caller keeping a reader alive across calls reads
    /// from here rather than from wherever its handle happens to stand.
    pub fn compressed_position(&self) -> u64 {
        self.compressed_pos
    }

    /// Retarget a live reader at `offset..offset + len`, which must not
    /// start before [`position`](Self::position). Output already decoded
    /// past the new offset is served from the buffer; the rest is decoded
    /// forward from where the decoder stands, with no checkpoint restore.
    pub fn seek_forward(&mut self, offset: u64, len: u64) -> Result<()> {
        if matches!(self.state, State::SeekToCheckpoint) {
            return Err(Error::InvalidState(
                "seek_forward before the reader has started".into(),
            ));
        }
        let position = self.position();
        if offset < position {
            return Err(Error::InvalidState(format!(
                "seek_forward to {} behind position {}",
                offset, position
            )));
        }
        // Discard buffered output before the new offset; whatever is
        // buffered past it serves the start of the range.
        let buffered = (self.output_len - self.output_read) as u64;
        let drop = (offset - position).min(buffered);
        self.output_read += drop as usize;
        if self.output_read == self.output_len {
            self.output_len = 0;
            self.output_read = 0;
        }
        let beyond = offset - position - drop;
        self.target_offset = offset;
        self.target_len = len;
        self.range_left = len;
        let remaining = len - self.serveable() as u64;
        self.state = if remaining == 0 || self.stream_ended {
            State::Done
        } else if beyond > 0 {
            State::Skipping { remaining: beyond }
        } else {
            State::Emitting { remaining }
        };
        Ok(())
    }

    /// Drive the reader. Returns what it needs next.
    pub fn step(&mut self) -> EngineRequest {
        loop {
            match self.step_once() {
                Some(request) => return request,
                None => continue,
            }
        }
    }

    fn step_once(&mut self) -> Option<EngineRequest> {
        if self.serveable() > 0 {
            return Some(EngineRequest::OutputReady);
        }
        Some(match &self.state {
            State::SeekToCheckpoint => {
                if let Err(e) = self.decompressor.restore(&self.checkpoint) {
                    return Some(EngineRequest::Error(e));
                }
                let compressed_start = self.checkpoint.compressed_offset;
                self.compressed_pos = compressed_start;
                self.unpacked_pos = self.checkpoint.uncompressed_offset;
                let skip = self.target_offset.saturating_sub(self.unpacked_pos);
                self.state = if skip > 0 {
                    State::NeedInputSkipping { remaining: skip }
                } else {
                    State::NeedInputEmitting {
                        remaining: self.target_len,
                    }
                };
                // Always an explicit seek, even to 0: the caller's handle
                // may stand anywhere (after indexing, or after a previous
                // read through the same handle).
                EngineRequest::SeekAndRead {
                    offset: compressed_start,
                    len: BUF_SIZE,
                }
            }
            State::NeedInputSkipping { remaining } => {
                let remaining = *remaining;
                if self.eof {
                    self.state = State::Skipping { remaining };
                    return self.skip(remaining);
                }
                EngineRequest::NeedInput
            }
            State::NeedInputEmitting { remaining } => {
                let remaining = *remaining;
                if self.eof {
                    self.state = State::Emitting { remaining };
                    return self.emit(remaining);
                }
                EngineRequest::NeedInput
            }
            State::Skipping { remaining } => {
                let remaining = *remaining;
                return self.skip(remaining);
            }
            State::Emitting { remaining } => {
                let remaining = *remaining;
                return self.emit(remaining);
            }
            State::Done => EngineRequest::Done,
        })
    }

    /// Provide compressed data after `NeedInput` or `SeekAndRead`.
    pub fn provide_data(&mut self, data: &[u8]) {
        self.input_buf.clear();
        self.input_buf.extend_from_slice(data);
        self.input_pos = 0;
        self.compressed_pos += data.len() as u64;
        match &self.state {
            State::NeedInputSkipping { remaining } => {
                self.state = State::Skipping {
                    remaining: *remaining,
                };
            }
            State::NeedInputEmitting { remaining } => {
                self.state = State::Emitting {
                    remaining: *remaining,
                };
            }
            _ => {}
        }
    }

    /// The compressed stream has no more bytes.
    pub fn signal_eof(&mut self) {
        self.eof = true;
    }

    /// Take decoded bytes after `OutputReady`. Returns 0 when drained.
    pub fn read_output(&mut self, buf: &mut [u8]) -> usize {
        let n = self.serveable().min(buf.len());
        if n == 0 {
            return 0;
        }
        buf[..n].copy_from_slice(&self.output_buf[self.output_read..self.output_read + n]);
        self.output_read += n;
        self.range_left -= n as u64;
        if self.output_read >= self.output_len {
            self.output_len = 0;
            self.output_read = 0;
        }
        n
    }

    fn skip(&mut self, mut remaining: u64) -> Option<EngineRequest> {
        let input = &self.input_buf[self.input_pos..];
        let had_input = !input.is_empty();
        if !had_input && !self.eof {
            self.state = State::NeedInputSkipping { remaining };
            return Some(EngineRequest::NeedInput);
        }
        let result = match self.decompressor.decompress(input, &mut self.skip_buf) {
            Ok(r) => r,
            Err(e) => return Some(EngineRequest::Error(e)),
        };
        self.input_pos += result.bytes_consumed;
        let produced = result.bytes_produced as u64;
        self.unpacked_pos += produced;

        if produced > remaining {
            // Overshot into the range: everything past the target is kept,
            // including bytes beyond the range that a later `seek_forward`
            // may want.
            let start = remaining as usize;
            let take = produced as usize - start;
            self.output_buf[..take].copy_from_slice(&self.skip_buf[start..start + take]);
            self.output_len = take;
            self.output_read = 0;
            let left = self.target_len.saturating_sub(take as u64);
            self.state = if left == 0 {
                State::Done
            } else {
                State::Emitting { remaining: left }
            };
            if result.status == DecompressStatus::StreamEnd {
                self.stream_ended = true;
                self.state = State::Done;
            }
            return Some(EngineRequest::OutputReady);
        }
        remaining -= produced;
        if remaining == 0 {
            self.state = State::Emitting {
                remaining: self.target_len,
            };
        } else {
            self.state = State::Skipping { remaining };
        }
        self.after_decode(&result, had_input)
    }

    fn emit(&mut self, remaining: u64) -> Option<EngineRequest> {
        let input = &self.input_buf[self.input_pos..];
        let had_input = !input.is_empty();
        if !had_input && !self.eof {
            self.state = State::NeedInputEmitting { remaining };
            return Some(EngineRequest::NeedInput);
        }
        let max_output = (remaining as usize).min(self.output_buf.len());
        let result = match self
            .decompressor
            .decompress(input, &mut self.output_buf[..max_output])
        {
            Ok(r) => r,
            Err(e) => return Some(EngineRequest::Error(e)),
        };
        self.input_pos += result.bytes_consumed;
        self.unpacked_pos += result.bytes_produced as u64;

        if result.bytes_produced > 0 {
            self.output_len = result.bytes_produced;
            self.output_read = 0;
            let left = remaining - result.bytes_produced as u64;
            self.state = if left == 0 {
                State::Done
            } else {
                State::Emitting { remaining: left }
            };
            if result.status == DecompressStatus::StreamEnd {
                self.stream_ended = true;
                self.state = State::Done;
            }
            return Some(EngineRequest::OutputReady);
        }
        self.state = State::Emitting { remaining };
        self.after_decode(&result, had_input)
    }

    /// Common tail for a decode step that produced nothing for the caller.
    fn after_decode(
        &mut self,
        result: &crate::compress::decompressor::DecompressResult,
        had_input: bool,
    ) -> Option<EngineRequest> {
        if result.status == DecompressStatus::StreamEnd && had_input {
            self.stream_ended = true;
            self.state = State::Done;
            return Some(EngineRequest::Done);
        }
        if self.input_pos >= self.input_buf.len() {
            if self.eof {
                if result.bytes_consumed == 0 && result.bytes_produced == 0 {
                    self.stream_ended = true;
                    self.state = State::Done;
                    return Some(EngineRequest::Done);
                }
                // Keep draining internally buffered output.
                return Some(EngineRequest::NeedInput);
            }
            self.state = match &self.state {
                State::Skipping { remaining } => State::NeedInputSkipping {
                    remaining: *remaining,
                },
                State::Emitting { remaining } => State::NeedInputEmitting {
                    remaining: *remaining,
                },
                _ => return Some(EngineRequest::NeedInput),
            };
            return Some(EngineRequest::NeedInput);
        }
        if result.bytes_consumed == 0 && result.bytes_produced == 0 {
            return Some(EngineRequest::Error(Error::DecompressionError(
                "decompressor made no progress with input remaining".into(),
            )));
        }
        None
    }
}
