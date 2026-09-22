//! A pipeline of decoding stages behaving as one `Decompressor`: packed
//! bytes enter the first stage, each stage's output feeds the next through
//! a bounded buffer, and the last stage's output is the chain's.

use crate::compress::checkpoint::{ChainCheckpointState, Checkpoint, CheckpointState};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::error::{Error, Result};

/// Capacity of each inter-stage buffer.
const STAGE_BUF: usize = 64 * 1024;

pub struct ChainDecompressor {
    stages: Vec<Box<dyn Decompressor>>,
    /// `bufs[i]` holds stage `i`'s output not yet consumed by stage `i + 1`;
    /// `read[i]` is the consumed prefix.
    bufs: Vec<Vec<u8>>,
    read: Vec<usize>,
    /// Per-stage (bytes in, bytes out), the offsets each stage checkpoints at.
    totals: Vec<(u64, u64)>,
    ended: Vec<bool>,
}

impl ChainDecompressor {
    /// `stages` in packed-to-unpacked order; at least two.
    pub fn new(stages: Vec<Box<dyn Decompressor>>) -> Result<Self> {
        if stages.len() < 2 {
            return Err(Error::InvalidState(
                "a chain needs at least two stages".into(),
            ));
        }
        let n = stages.len();
        Ok(Self {
            stages,
            bufs: vec![Vec::new(); n - 1],
            read: vec![0; n - 1],
            totals: vec![(0, 0); n],
            ended: vec![false; n],
        })
    }

    fn finished(&self) -> bool {
        *self.ended.last().unwrap()
    }
}

impl Decompressor for ChainDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        let n = self.stages.len();
        let mut in_pos = 0;
        let mut out_pos = 0;
        while !self.finished() && out_pos < output.len() {
            let mut progress = false;

            // Stage 0 reads the caller's input. Empty input is the caller's
            // end-of-stream, which the stage must see to flush.
            if !self.ended[0] && self.bufs[0].len() < STAGE_BUF {
                let avail = &input[in_pos..];
                if !avail.is_empty() || input.is_empty() {
                    let start = self.bufs[0].len();
                    self.bufs[0].resize(STAGE_BUF, 0);
                    let r = self.stages[0].decompress(avail, &mut self.bufs[0][start..]);
                    let r = match r {
                        Ok(r) => r,
                        Err(e) => {
                            self.bufs[0].truncate(start);
                            return Err(e);
                        }
                    };
                    self.bufs[0].truncate(start + r.bytes_produced);
                    in_pos += r.bytes_consumed;
                    self.totals[0].0 += r.bytes_consumed as u64;
                    self.totals[0].1 += r.bytes_produced as u64;
                    progress |= r.bytes_consumed > 0 || r.bytes_produced > 0;
                    if r.status == DecompressStatus::StreamEnd {
                        self.ended[0] = true;
                    }
                }
            }

            for i in 1..n {
                if self.ended[i] {
                    continue;
                }
                let src_len = self.bufs[i - 1].len() - self.read[i - 1];
                if src_len == 0 && !self.ended[i - 1] {
                    continue;
                }
                let r = if i == n - 1 {
                    if out_pos == output.len() {
                        continue;
                    }
                    let (bufs, stages) = (&self.bufs, &mut self.stages);
                    let src = &bufs[i - 1][self.read[i - 1]..];
                    stages[i].decompress(src, &mut output[out_pos..])?
                } else {
                    if self.bufs[i].len() >= STAGE_BUF {
                        continue;
                    }
                    let (left, right) = self.bufs.split_at_mut(i);
                    let src = &left[i - 1][self.read[i - 1]..];
                    let dst = &mut right[0];
                    let start = dst.len();
                    dst.resize(STAGE_BUF, 0);
                    let r = self.stages[i].decompress(src, &mut dst[start..]);
                    let r = match r {
                        Ok(r) => r,
                        Err(e) => {
                            dst.truncate(start);
                            return Err(e);
                        }
                    };
                    dst.truncate(start + r.bytes_produced);
                    r
                };
                self.read[i - 1] += r.bytes_consumed;
                if self.read[i - 1] == self.bufs[i - 1].len() {
                    self.bufs[i - 1].clear();
                    self.read[i - 1] = 0;
                }
                if i == n - 1 {
                    out_pos += r.bytes_produced;
                }
                self.totals[i].0 += r.bytes_consumed as u64;
                self.totals[i].1 += r.bytes_produced as u64;
                progress |= r.bytes_consumed > 0 || r.bytes_produced > 0;
                if r.status == DecompressStatus::StreamEnd {
                    self.ended[i] = true;
                }
            }

            if !progress {
                break;
            }
        }
        Ok(DecompressResult {
            bytes_consumed: in_pos,
            bytes_produced: out_pos,
            status: if self.finished() {
                DecompressStatus::StreamEnd
            } else {
                DecompressStatus::Continue
            },
        })
    }

    fn checkpoint(
        &self,
        _compressed_offset: u64,
        uncompressed_offset: u64,
    ) -> Result<Option<Checkpoint>> {
        // A block format (deflate, bzip2) may resume a few bytes behind
        // the count it was given. Stage 0 is fed from the seekable stream,
        // so the chain simply resumes there too; an inner stage is fed
        // from `pending`, which starts at the count, so it must be exact.
        let mut stages = Vec::with_capacity(self.stages.len());
        for (i, (stage, &(cin, cout))) in self.stages.iter().zip(&self.totals).enumerate() {
            match stage.checkpoint(cin, cout)? {
                Some(cp) if i == 0 || cp.compressed_offset == cin => stages.push(cp),
                _ => return Ok(None),
            }
        }
        let compressed_offset = stages[0].compressed_offset;
        let pending = self
            .bufs
            .iter()
            .zip(&self.read)
            .map(|(b, &r)| b[r..].to_vec())
            .collect();
        Ok(Some(Checkpoint {
            compressed_offset,
            bit_offset: stages[0].bit_offset,
            uncompressed_offset,
            state: CheckpointState::Chain(ChainCheckpointState {
                stages,
                pending,
                ended: self.ended.clone(),
            }),
        }))
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        let n = self.stages.len();
        match &checkpoint.state {
            CheckpointState::Chain(s) => {
                if s.stages.len() != n || s.pending.len() != n - 1 || s.ended.len() != n {
                    return Err(Error::CheckpointError(
                        "chain checkpoint does not match the chain".into(),
                    ));
                }
                for (stage, cp) in self.stages.iter_mut().zip(&s.stages) {
                    stage.restore(cp)?;
                }
                for (i, cp) in s.stages.iter().enumerate() {
                    self.totals[i] = (cp.compressed_offset, cp.uncompressed_offset);
                }
                self.bufs = s.pending.clone();
                self.read = vec![0; n - 1];
                self.ended = s.ended.clone();
                Ok(())
            }
            CheckpointState::None => {
                for stage in &mut self.stages {
                    stage.restore(checkpoint)?;
                }
                self.bufs = vec![Vec::new(); n - 1];
                self.read = vec![0; n - 1];
                self.totals = vec![(0, 0); n];
                self.ended = vec![false; n];
                Ok(())
            }
            _ => Err(Error::CheckpointError(
                "expected chain checkpoint state".into(),
            )),
        }
    }
}
