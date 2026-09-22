//! Branch/call/jump (BCJ) converters and the Delta filter, as decoding
//! stages. Ported from XZ Utils' simple filters (0BSD) and delta decoder;
//! 7-Zip's coders of the same names produce identical streams with a start
//! offset of zero.
//!
//! A filter never changes the byte count, but a BCJ converter may need up
//! to a few bytes past an instruction before it can rewrite it, so a stage
//! holds back the tail of each chunk until more input or the end of the
//! stream arrives.

use serde::{Deserialize, Serialize};

use crate::compress::checkpoint::{Checkpoint, CheckpointState, FilterCheckpointState};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::error::{Error, Result};

/// Input taken per `decompress` call; bounds the held buffer.
const CHUNK: usize = 64 * 1024;

/// Delta distances are 1..=256.
const DELTA_HISTORY: usize = 256;

/// Instruction-set families with a BCJ converter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BcjArch {
    X86,
    PowerPc,
    Ia64,
    Arm,
    ArmThumb,
    Sparc,
    Arm64,
    RiscV,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum FilterState {
    Bcj {
        arch: BcjArch,
        prev_mask: u32,
        prev_pos: u32,
    },
    Delta {
        distance: usize,
        history: Vec<u8>,
        hist_pos: u8,
    },
}

/// A BCJ or Delta decoding stage.
pub struct FilterDecompressor {
    state: FilterState,
    /// Stream position of `buf[0]`.
    pos: u64,
    /// Held input: `[..filtered]` is converted and waiting to be emitted,
    /// `[filtered..]` is still raw.
    buf: Vec<u8>,
    filtered: usize,
    finished: bool,
}

impl FilterDecompressor {
    pub fn bcj(arch: BcjArch) -> Self {
        Self::with_state(FilterState::Bcj {
            arch,
            prev_mask: 0,
            prev_pos: 0u32.wrapping_sub(5),
        })
    }

    /// `distance` is 1..=256 (the stored property byte plus one).
    pub fn delta(distance: usize) -> Result<Self> {
        if !(1..=DELTA_HISTORY).contains(&distance) {
            return Err(Error::DecompressionError(format!(
                "invalid delta distance: {}",
                distance
            )));
        }
        Ok(Self::with_state(FilterState::Delta {
            distance,
            history: vec![0; DELTA_HISTORY],
            hist_pos: 0,
        }))
    }

    fn with_state(state: FilterState) -> Self {
        Self {
            state,
            pos: 0,
            buf: Vec::new(),
            filtered: 0,
            finished: false,
        }
    }

    /// Convert as much of `buf[filtered..]` as the filter can commit to;
    /// `end` means no more input follows, so everything is final.
    fn run(&mut self, end: bool) {
        let start = self.filtered;
        let now_pos = (self.pos + start as u64) as u32;
        let data = &mut self.buf[start..];
        let done = match &mut self.state {
            FilterState::Delta {
                distance,
                history,
                hist_pos,
            } => {
                let distance = *distance;
                for b in data.iter_mut() {
                    *b = b.wrapping_add(history[(distance + *hist_pos as usize) & 0xFF]);
                    history[*hist_pos as usize] = *b;
                    *hist_pos = hist_pos.wrapping_sub(1);
                }
                data.len()
            }
            FilterState::Bcj {
                arch,
                prev_mask,
                prev_pos,
            } => match arch {
                BcjArch::X86 => x86(data, now_pos, prev_mask, prev_pos),
                BcjArch::PowerPc => powerpc(data, now_pos),
                BcjArch::Ia64 => ia64(data, now_pos),
                BcjArch::Arm => arm(data, now_pos),
                BcjArch::ArmThumb => arm_thumb(data, now_pos),
                BcjArch::Sparc => sparc(data, now_pos),
                BcjArch::Arm64 => arm64(data, now_pos),
                BcjArch::RiscV => riscv(data, now_pos),
            },
        };
        self.filtered = if end { self.buf.len() } else { start + done };
    }

    fn emit(&mut self, output: &mut [u8]) -> usize {
        let n = self.filtered.min(output.len());
        output[..n].copy_from_slice(&self.buf[..n]);
        self.buf.drain(..n);
        self.filtered -= n;
        self.pos += n as u64;
        n
    }
}

impl Decompressor for FilterDecompressor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        let mut produced = self.emit(output);
        let mut consumed = 0;
        if produced < output.len() && !self.finished {
            if input.is_empty() {
                self.run(true);
                self.finished = true;
            } else {
                let take = input.len().min(CHUNK);
                self.buf.extend_from_slice(&input[..take]);
                consumed = take;
                self.run(false);
            }
            produced += self.emit(&mut output[produced..]);
        }
        Ok(DecompressResult {
            bytes_consumed: consumed,
            bytes_produced: produced,
            status: if self.finished && self.buf.is_empty() {
                DecompressStatus::StreamEnd
            } else {
                DecompressStatus::Continue
            },
        })
    }

    fn checkpoint(
        &self,
        compressed_offset: u64,
        uncompressed_offset: u64,
    ) -> Result<Option<Checkpoint>> {
        Ok(Some(Checkpoint {
            compressed_offset,
            bit_offset: 0,
            uncompressed_offset,
            state: CheckpointState::Filter(FilterCheckpointState {
                pos: self.pos,
                held: self.buf.clone(),
                filtered: self.filtered,
                extra: bincode::serialize(&self.state)
                    .map_err(|e| Error::CheckpointError(format!("serialize filter: {}", e)))?,
                finished: self.finished,
            }),
        }))
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        match &checkpoint.state {
            CheckpointState::Filter(s) => {
                if s.filtered > s.held.len() {
                    return Err(Error::CheckpointError(
                        "filter checkpoint inconsistent".into(),
                    ));
                }
                self.state = bincode::deserialize(&s.extra)
                    .map_err(|e| Error::CheckpointError(format!("deserialize filter: {}", e)))?;
                self.pos = s.pos;
                self.buf = s.held.clone();
                self.filtered = s.filtered;
                self.finished = s.finished;
                Ok(())
            }
            CheckpointState::None => {
                self.state = match &self.state {
                    FilterState::Bcj { arch, .. } => FilterState::Bcj {
                        arch: *arch,
                        prev_mask: 0,
                        prev_pos: 0u32.wrapping_sub(5),
                    },
                    FilterState::Delta { distance, .. } => FilterState::Delta {
                        distance: *distance,
                        history: vec![0; DELTA_HISTORY],
                        hist_pos: 0,
                    },
                };
                self.pos = 0;
                self.buf.clear();
                self.filtered = 0;
                self.finished = false;
                Ok(())
            }
            _ => Err(Error::CheckpointError(
                "expected filter checkpoint state".into(),
            )),
        }
    }
}

// ─── Converters ────────────────────────────────────────────────────
//
// Each returns how many leading bytes of `buf` are final. Positions are
// the low 32 bits of the stream offset, as in the reference code.

fn test86_msbyte(b: u8) -> bool {
    b == 0 || b == 0xFF
}

fn x86(buf: &mut [u8], now_pos: u32, prev_mask: &mut u32, prev_pos: &mut u32) -> usize {
    const MASK_TO_BIT_NUMBER: [u32; 5] = [0, 1, 2, 2, 3];
    if buf.len() < 5 {
        return 0;
    }
    if now_pos.wrapping_sub(*prev_pos) > 5 {
        *prev_pos = now_pos.wrapping_sub(5);
    }
    let limit = buf.len() - 5;
    let mut i = 0;
    while i <= limit {
        let b = buf[i];
        if b != 0xE8 && b != 0xE9 {
            i += 1;
            continue;
        }
        let here = now_pos.wrapping_add(i as u32);
        let offset = here.wrapping_sub(*prev_pos);
        *prev_pos = here;
        if offset > 5 {
            *prev_mask = 0;
        } else {
            for _ in 0..offset {
                *prev_mask &= 0x77;
                *prev_mask <<= 1;
            }
        }
        let mut b = buf[i + 4];
        if test86_msbyte(b) && (*prev_mask >> 1) <= 4 && (*prev_mask >> 1) != 3 {
            let mut src = (b as u32) << 24
                | (buf[i + 3] as u32) << 16
                | (buf[i + 2] as u32) << 8
                | buf[i + 1] as u32;
            let mut dest;
            loop {
                dest = src.wrapping_sub(here.wrapping_add(5));
                if *prev_mask == 0 {
                    break;
                }
                let idx = MASK_TO_BIT_NUMBER[(*prev_mask >> 1) as usize];
                b = (dest >> (24 - idx * 8)) as u8;
                if !test86_msbyte(b) {
                    break;
                }
                src = dest ^ ((1u32 << (32 - idx * 8)).wrapping_sub(1));
            }
            buf[i + 4] = (!(((dest >> 24) & 1).wrapping_sub(1))) as u8;
            buf[i + 3] = (dest >> 16) as u8;
            buf[i + 2] = (dest >> 8) as u8;
            buf[i + 1] = dest as u8;
            i += 5;
            *prev_mask = 0;
        } else {
            i += 1;
            *prev_mask |= 1;
            if test86_msbyte(b) {
                *prev_mask |= 0x10;
            }
        }
    }
    i
}

fn arm(buf: &mut [u8], now_pos: u32) -> usize {
    let size = buf.len() & !3;
    let mut i = 0;
    while i < size {
        if buf[i + 3] == 0xEB {
            let src = ((buf[i + 2] as u32) << 16 | (buf[i + 1] as u32) << 8 | buf[i] as u32) << 2;
            let dest = src.wrapping_sub(now_pos.wrapping_add(i as u32).wrapping_add(8)) >> 2;
            buf[i + 2] = (dest >> 16) as u8;
            buf[i + 1] = (dest >> 8) as u8;
            buf[i] = dest as u8;
        }
        i += 4;
    }
    i
}

fn arm_thumb(buf: &mut [u8], now_pos: u32) -> usize {
    if buf.len() < 4 {
        return 0;
    }
    let size = buf.len() - 4;
    let mut i = 0;
    while i <= size {
        if (buf[i + 1] & 0xF8) == 0xF0 && (buf[i + 3] & 0xF8) == 0xF8 {
            let src = (((buf[i + 1] as u32) & 7) << 19
                | (buf[i] as u32) << 11
                | ((buf[i + 3] as u32) & 7) << 8
                | buf[i + 2] as u32)
                << 1;
            let dest = src.wrapping_sub(now_pos.wrapping_add(i as u32).wrapping_add(4)) >> 1;
            buf[i + 1] = 0xF0 | ((dest >> 19) & 0x7) as u8;
            buf[i] = (dest >> 11) as u8;
            buf[i + 3] = 0xF8 | ((dest >> 8) & 0x7) as u8;
            buf[i + 2] = dest as u8;
            i += 2;
        }
        i += 2;
    }
    i
}

fn powerpc(buf: &mut [u8], now_pos: u32) -> usize {
    let size = buf.len() & !3;
    let mut i = 0;
    while i < size {
        if (buf[i] >> 2) == 0x12 && (buf[i + 3] & 3) == 1 {
            let src = ((buf[i] as u32) & 3) << 24
                | (buf[i + 1] as u32) << 16
                | (buf[i + 2] as u32) << 8
                | ((buf[i + 3] as u32) & !3);
            let dest = src.wrapping_sub(now_pos.wrapping_add(i as u32));
            buf[i] = 0x48 | ((dest >> 24) & 0x03) as u8;
            buf[i + 1] = (dest >> 16) as u8;
            buf[i + 2] = (dest >> 8) as u8;
            buf[i + 3] = (buf[i + 3] & 0x03) | dest as u8;
        }
        i += 4;
    }
    i
}

fn sparc(buf: &mut [u8], now_pos: u32) -> usize {
    let size = buf.len() & !3;
    let mut i = 0;
    while i < size {
        if (buf[i] == 0x40 && (buf[i + 1] & 0xC0) == 0x00)
            || (buf[i] == 0x7F && (buf[i + 1] & 0xC0) == 0xC0)
        {
            let src = ((buf[i] as u32) << 24
                | (buf[i + 1] as u32) << 16
                | (buf[i + 2] as u32) << 8
                | buf[i + 3] as u32)
                << 2;
            let mut dest = src.wrapping_sub(now_pos.wrapping_add(i as u32)) >> 2;
            dest = ((0u32.wrapping_sub((dest >> 22) & 1) << 22) & 0x3FFF_FFFF)
                | (dest & 0x3F_FFFF)
                | 0x4000_0000;
            buf[i] = (dest >> 24) as u8;
            buf[i + 1] = (dest >> 16) as u8;
            buf[i + 2] = (dest >> 8) as u8;
            buf[i + 3] = dest as u8;
        }
        i += 4;
    }
    i
}

fn ia64(buf: &mut [u8], now_pos: u32) -> usize {
    const BRANCH_TABLE: [u32; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4,
        0, 0,
    ];
    let size = buf.len() & !15;
    let mut i = 0;
    while i < size {
        let mask = BRANCH_TABLE[(buf[i] & 0x1F) as usize];
        let mut bit_pos = 5u32;
        for slot in 0..3 {
            if (mask >> slot) & 1 != 0 {
                let byte_pos = (bit_pos >> 3) as usize;
                let bit_res = bit_pos & 7;
                let mut instruction = 0u64;
                for j in 0..6 {
                    instruction |= (buf[i + j + byte_pos] as u64) << (8 * j);
                }
                let mut inst_norm = instruction >> bit_res;
                if (inst_norm >> 37) & 0xF == 0x5 && (inst_norm >> 9) & 0x7 == 0 {
                    let mut src = ((inst_norm >> 13) & 0xF_FFFF) as u32;
                    src |= (((inst_norm >> 36) & 1) as u32) << 20;
                    src <<= 4;
                    let dest = src.wrapping_sub(now_pos.wrapping_add(i as u32)) >> 4;
                    inst_norm &= !(0x8F_FFFFu64 << 13);
                    inst_norm |= ((dest & 0xF_FFFF) as u64) << 13;
                    inst_norm |= ((dest & 0x10_0000) as u64) << (36 - 20);
                    instruction &= (1u64 << bit_res) - 1;
                    instruction |= inst_norm << bit_res;
                    for j in 0..6 {
                        buf[i + j + byte_pos] = (instruction >> (8 * j)) as u8;
                    }
                }
            }
            bit_pos += 41;
        }
        i += 16;
    }
    i
}

fn arm64(buf: &mut [u8], now_pos: u32) -> usize {
    let size = buf.len() & !3;
    let mut i = 0;
    while i < size {
        let mut pc = now_pos.wrapping_add(i as u32);
        let mut instr = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        if instr >> 26 == 0x25 {
            let src = instr;
            instr = 0x9400_0000;
            pc >>= 2;
            pc = 0u32.wrapping_sub(pc);
            instr |= src.wrapping_add(pc) & 0x03FF_FFFF;
            buf[i..i + 4].copy_from_slice(&instr.to_le_bytes());
        } else if instr & 0x9F00_0000 == 0x9000_0000 {
            let src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001F_FFFC);
            if src.wrapping_add(0x0002_0000) & 0x001C_0000 != 0 {
                i += 4;
                continue;
            }
            instr &= 0x9000_001F;
            pc >>= 12;
            pc = 0u32.wrapping_sub(pc);
            let dest = src.wrapping_add(pc);
            instr |= (dest & 3) << 29;
            instr |= (dest & 0x0003_FFFC) << 3;
            instr |= 0u32.wrapping_sub(dest & 0x0002_0000) & 0x00E0_0000;
            buf[i..i + 4].copy_from_slice(&instr.to_le_bytes());
        }
        i += 4;
    }
    i
}

fn riscv(buf: &mut [u8], now_pos: u32) -> usize {
    fn read32le(b: &[u8]) -> u32 {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }
    fn read32be(b: &[u8]) -> u32 {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }
    fn not_auipc_pair(auipc: u32, inst2: u32) -> bool {
        ((auipc << 8) ^ inst2.wrapping_sub(3)) & 0xF8003 != 0
    }
    fn not_special_auipc(auipc: u32, inst2_rs1: u32) -> bool {
        auipc.wrapping_sub(0x3117) << 18 >= (inst2_rs1 & 0x1D)
    }
    if buf.len() < 8 {
        return 0;
    }
    let size = buf.len() - 8;
    let mut i = 0;
    while i <= size {
        let mut inst = buf[i] as u32;
        if inst == 0xEF {
            let b1 = buf[i + 1] as u32;
            if b1 & 0x0D != 0 {
                i += 2;
                continue;
            }
            let b2 = buf[i + 2] as u32;
            let b3 = buf[i + 3] as u32;
            let pc = now_pos.wrapping_add(i as u32);
            let addr = (((b1 & 0xF0) << 13) | (b2 << 9) | (b3 << 1)).wrapping_sub(pc);
            buf[i + 1] = ((b1 & 0x0F) | ((addr >> 8) & 0xF0)) as u8;
            buf[i + 2] =
                (((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)) as u8;
            buf[i + 3] = (((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)) as u8;
            i += 4;
        } else if inst & 0x7F == 0x17 {
            inst |= (buf[i + 1] as u32) << 8;
            inst |= (buf[i + 2] as u32) << 16;
            inst |= (buf[i + 3] as u32) << 24;
            let inst2;
            if inst & 0xE80 != 0 {
                let candidate = read32le(&buf[i + 4..]);
                if not_auipc_pair(inst, candidate) {
                    i += 6;
                    continue;
                }
                let addr = (inst & 0xFFFF_F000).wrapping_add(candidate >> 20);
                inst = 0x17 | (2 << 7) | (candidate << 12);
                inst2 = addr;
            } else {
                let inst2_rs1 = inst >> 27;
                if not_special_auipc(inst, inst2_rs1) {
                    i += 4;
                    continue;
                }
                let addr = read32be(&buf[i + 4..]).wrapping_sub(now_pos.wrapping_add(i as u32));
                inst2 = (inst >> 12) | (addr << 20);
                inst = 0x17 | (inst2_rs1 << 7) | (addr.wrapping_add(0x800) & 0xFFFF_F000);
            }
            buf[i..i + 4].copy_from_slice(&inst.to_le_bytes());
            buf[i + 4..i + 8].copy_from_slice(&inst2.to_le_bytes());
            i += 8;
        } else {
            i += 2;
        }
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference x86 encoder (the decoder above inverts it).
    fn x86_encode(buf: &mut [u8], now_pos: u32, prev_mask: &mut u32, prev_pos: &mut u32) -> usize {
        const MASK_TO_BIT_NUMBER: [u32; 5] = [0, 1, 2, 2, 3];
        if buf.len() < 5 {
            return 0;
        }
        if now_pos.wrapping_sub(*prev_pos) > 5 {
            *prev_pos = now_pos.wrapping_sub(5);
        }
        let limit = buf.len() - 5;
        let mut i = 0;
        while i <= limit {
            let b = buf[i];
            if b != 0xE8 && b != 0xE9 {
                i += 1;
                continue;
            }
            let here = now_pos.wrapping_add(i as u32);
            let offset = here.wrapping_sub(*prev_pos);
            *prev_pos = here;
            if offset > 5 {
                *prev_mask = 0;
            } else {
                for _ in 0..offset {
                    *prev_mask &= 0x77;
                    *prev_mask <<= 1;
                }
            }
            let mut b = buf[i + 4];
            if test86_msbyte(b) && (*prev_mask >> 1) <= 4 && (*prev_mask >> 1) != 3 {
                let mut src = (b as u32) << 24
                    | (buf[i + 3] as u32) << 16
                    | (buf[i + 2] as u32) << 8
                    | buf[i + 1] as u32;
                let mut dest;
                loop {
                    dest = src.wrapping_add(here.wrapping_add(5));
                    if *prev_mask == 0 {
                        break;
                    }
                    let idx = MASK_TO_BIT_NUMBER[(*prev_mask >> 1) as usize];
                    b = (dest >> (24 - idx * 8)) as u8;
                    if !test86_msbyte(b) {
                        break;
                    }
                    src = dest ^ ((1u32 << (32 - idx * 8)).wrapping_sub(1));
                }
                buf[i + 4] = (!(((dest >> 24) & 1).wrapping_sub(1))) as u8;
                buf[i + 3] = (dest >> 16) as u8;
                buf[i + 2] = (dest >> 8) as u8;
                buf[i + 1] = dest as u8;
                i += 5;
                *prev_mask = 0;
            } else {
                i += 1;
                *prev_mask |= 1;
                if test86_msbyte(b) {
                    *prev_mask |= 0x10;
                }
            }
        }
        i
    }

    fn code_like(seed: u64, len: usize) -> Vec<u8> {
        let mut s = seed;
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let r = (s >> 33) as u32;
            match r % 9 {
                0 => {
                    // x86 call with a small relative target
                    v.push(0xE8);
                    v.extend_from_slice(&((r >> 8) as i32 % 4096).to_le_bytes());
                }
                1 => v.extend_from_slice(&(0x9400_0000u32 | (r & 0x00FF_FFFF)).to_le_bytes()),
                2 => v.extend_from_slice(&(0xEB00_0000u32 | (r & 0x00FF_FFFF)).to_be_bytes()),
                3 => v.extend_from_slice(&(0x4800_0001u32 | (r & 0x03FF_FFFC)).to_be_bytes()),
                4 => v.extend_from_slice(&(0x4000_0000u32 | (r & 0x003F_FFFF)).to_be_bytes()),
                5 => v.extend_from_slice(&[
                    (r & 0xFF) as u8,
                    0xF0 | ((r >> 8) & 7) as u8,
                    (r >> 16) as u8,
                    0xF8,
                ]),
                6 => {
                    // An IA-64 bundle whose template has branch slots.
                    let mut bundle = [0u8; 16];
                    bundle[0] = 0x10 | (r & 0x0F) as u8;
                    for b in bundle.iter_mut().skip(1) {
                        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                        *b = (s >> 33) as u8;
                    }
                    v.extend_from_slice(&bundle);
                }
                _ => v.extend_from_slice(&r.to_le_bytes()),
            }
        }
        v.truncate(len);
        v
    }

    fn drive(dec: &mut FilterDecompressor, data: &[u8], chunk: usize, out_chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; out_chunk];
        let mut pos = 0;
        loop {
            let input = &data[pos..(pos + chunk).min(data.len())];
            let r = dec.decompress(input, &mut buf).unwrap();
            pos += r.bytes_consumed;
            out.extend_from_slice(&buf[..r.bytes_produced]);
            if r.status == DecompressStatus::StreamEnd {
                break;
            }
        }
        out
    }

    #[test]
    fn x86_round_trip_in_chunks() {
        let plain = code_like(1, 100_003);
        let mut encoded = plain.clone();
        let (mut m, mut p) = (0u32, 0u32.wrapping_sub(5));
        let done = x86_encode(&mut encoded, 0, &mut m, &mut p);
        assert!(done >= encoded.len() - 5);
        for (chunk, out_chunk) in [(7, 5), (4096, 64), (100_003, 65536), (1, 1)] {
            let mut dec = FilterDecompressor::bcj(BcjArch::X86);
            assert_eq!(drive(&mut dec, &encoded, chunk, out_chunk), plain);
        }
    }

    #[test]
    fn x86_checkpoint_restore_mid_stream() {
        let plain = code_like(2, 50_000);
        let mut encoded = plain.clone();
        let (mut m, mut p) = (0u32, 0u32.wrapping_sub(5));
        x86_encode(&mut encoded, 0, &mut m, &mut p);

        let mut dec = FilterDecompressor::bcj(BcjArch::X86);
        let mut out = vec![0u8; 777];
        let mut consumed = 0;
        let mut produced = Vec::new();
        for _ in 0..13 {
            let r = dec
                .decompress(&encoded[consumed..consumed + 1000], &mut out)
                .unwrap();
            consumed += r.bytes_consumed;
            produced.extend_from_slice(&out[..r.bytes_produced]);
        }
        let cp = dec
            .checkpoint(consumed as u64, produced.len() as u64)
            .unwrap()
            .unwrap();
        let mut fresh = FilterDecompressor::bcj(BcjArch::X86);
        fresh.restore(&cp).unwrap();
        let rest = drive(&mut fresh, &encoded[consumed..], 333, 100);
        produced.extend_from_slice(&rest);
        assert_eq!(produced, plain);
    }

    #[test]
    fn delta_round_trip() {
        let plain = code_like(3, 10_001);
        for distance in [1usize, 2, 4, 256] {
            // Encode: out[i] = in[i] - in[i - distance]
            let mut encoded = plain.clone();
            for i in (0..encoded.len()).rev() {
                if i >= distance {
                    encoded[i] = encoded[i].wrapping_sub(plain[i - distance]);
                }
            }
            let mut dec = FilterDecompressor::delta(distance).unwrap();
            assert_eq!(drive(&mut dec, &encoded, 1000, 64), plain);
        }
    }

    #[test]
    fn fixed_width_converters_round_trip_and_restore() {
        let plain = code_like(4, 40_000);
        for arch in [
            BcjArch::Arm,
            BcjArch::Arm64,
            BcjArch::PowerPc,
            BcjArch::Sparc,
            BcjArch::ArmThumb,
            BcjArch::Ia64,
        ] {
            let mut encoded = plain.clone();
            encode(arch, &mut encoded);
            assert_ne!(encoded, plain, "{:?} encoder changed nothing", arch);
            let mut dec = FilterDecompressor::bcj(arch);
            assert_eq!(drive(&mut dec, &encoded, 1234, 512), plain, "{:?}", arch);

            // Checkpoint mid-stream and finish from a fresh stage.
            let mut dec = FilterDecompressor::bcj(arch);
            let mut out = vec![0u8; 999];
            let mut consumed = 0;
            let mut produced = Vec::new();
            for _ in 0..7 {
                let r = dec
                    .decompress(&encoded[consumed..consumed + 1001], &mut out)
                    .unwrap();
                consumed += r.bytes_consumed;
                produced.extend_from_slice(&out[..r.bytes_produced]);
            }
            let cp = dec
                .checkpoint(consumed as u64, produced.len() as u64)
                .unwrap()
                .unwrap();
            let mut fresh = FilterDecompressor::bcj(arch);
            fresh.restore(&cp).unwrap();
            produced.extend_from_slice(&drive(&mut fresh, &encoded[consumed..], 500, 333));
            assert_eq!(produced, plain, "{:?} after restore", arch);
        }
    }

    #[test]
    fn riscv_round_trip() {
        let plain = riscv_like(5, 60_000);
        let mut encoded = plain.clone();
        riscv_encode(&mut encoded, 0);
        assert_ne!(encoded, plain);
        let mut dec = FilterDecompressor::bcj(BcjArch::RiscV);
        assert_eq!(drive(&mut dec, &encoded, 1234, 512), plain);
        let mut dec = FilterDecompressor::bcj(BcjArch::RiscV);
        assert_eq!(drive(&mut dec, &encoded, 3, 7), plain);
    }

    /// JAL to ra/t0, AUIPC pairs with both rd classes, and filler.
    fn riscv_like(seed: u64, len: usize) -> Vec<u8> {
        let mut s = seed;
        let mut v = Vec::with_capacity(len + 8);
        while v.len() < len {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let r = (s >> 33) as u32;
            match r % 5 {
                0 => {
                    // JAL rd=x1 with a small immediate
                    let imm = (r >> 8) & 0xFFFFE;
                    let inst = 0x6F | (1 << 7) | (imm << 12);
                    v.extend_from_slice(&inst.to_le_bytes());
                }
                1 => {
                    // AUIPC x10 + ADDI x10, x10, imm: a real pair
                    let auipc = 0x17 | (10 << 7) | (r & 0xFFFF_F000);
                    let addi = 0x13 | (10 << 7) | (10 << 15) | (((r >> 4) & 0xFFF) << 20);
                    v.extend_from_slice(&auipc.to_le_bytes());
                    v.extend_from_slice(&addi.to_le_bytes());
                }
                2 => v.extend_from_slice(&[(r & 0xFF) as u8 | 1, (r >> 8) as u8]),
                _ => v.extend_from_slice(&r.to_le_bytes()),
            }
        }
        v.truncate(len);
        v
    }

    /// The reference RISC-V encoder, for round trips only.
    fn riscv_encode(buf: &mut [u8], now_pos: u32) -> usize {
        fn read32le(b: &[u8]) -> u32 {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        }
        fn not_auipc_pair(auipc: u32, inst2: u32) -> bool {
            ((auipc << 8) ^ inst2.wrapping_sub(3)) & 0xF8003 != 0
        }
        fn not_special_auipc(auipc: u32, inst2_rs1: u32) -> bool {
            auipc.wrapping_sub(0x3117) << 18 >= (inst2_rs1 & 0x1D)
        }
        if buf.len() < 8 {
            return 0;
        }
        let size = buf.len() - 8;
        let mut i = 0;
        while i <= size {
            let mut inst = buf[i] as u32;
            if inst == 0xEF {
                let b1 = buf[i + 1] as u32;
                if b1 & 0x0D != 0 {
                    i += 2;
                    continue;
                }
                let b2 = buf[i + 2] as u32;
                let b3 = buf[i + 3] as u32;
                let pc = now_pos.wrapping_add(i as u32);
                let addr = (((b1 & 0xF0) << 8)
                    | ((b2 & 0x0F) << 16)
                    | ((b2 & 0x10) << 7)
                    | ((b2 & 0xE0) >> 4)
                    | ((b3 & 0x7F) << 4)
                    | ((b3 & 0x80) << 13))
                    .wrapping_add(pc);
                buf[i + 1] = ((b1 & 0x0F) | ((addr >> 13) & 0xF0)) as u8;
                buf[i + 2] = (addr >> 9) as u8;
                buf[i + 3] = (addr >> 1) as u8;
                i += 4;
            } else if inst & 0x7F == 0x17 {
                inst |= (buf[i + 1] as u32) << 8;
                inst |= (buf[i + 2] as u32) << 16;
                inst |= (buf[i + 3] as u32) << 24;
                if inst & 0xE80 != 0 {
                    let inst2 = read32le(&buf[i + 4..]);
                    if not_auipc_pair(inst, inst2) {
                        i += 6;
                        continue;
                    }
                    let addr = (inst & 0xFFFF_F000)
                        .wrapping_add((inst2 >> 20).wrapping_sub((inst2 >> 19) & 0x1000))
                        .wrapping_add(now_pos.wrapping_add(i as u32));
                    inst = 0x17 | (2 << 7) | (inst2 << 12);
                    buf[i..i + 4].copy_from_slice(&inst.to_le_bytes());
                    buf[i + 4..i + 8].copy_from_slice(&addr.to_be_bytes());
                } else {
                    let fake_rs1 = inst >> 27;
                    if not_special_auipc(inst, fake_rs1) {
                        i += 4;
                        continue;
                    }
                    let fake_addr = read32le(&buf[i + 4..]);
                    let fake_inst2 = (inst >> 12) | (fake_addr << 20);
                    inst = 0x17 | (fake_rs1 << 7) | (fake_addr & 0xFFFF_F000);
                    buf[i..i + 4].copy_from_slice(&inst.to_le_bytes());
                    buf[i + 4..i + 8].copy_from_slice(&fake_inst2.to_le_bytes());
                }
                i += 8;
            } else {
                i += 2;
            }
        }
        i
    }

    fn ia64_encode_bundle(b: &mut [u8], pc: u32) {
        const BRANCH_TABLE: [u32; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4,
            4, 0, 0,
        ];
        let mask = BRANCH_TABLE[(b[0] & 0x1F) as usize];
        let mut bit_pos = 5u32;
        for slot in 0..3 {
            if (mask >> slot) & 1 != 0 {
                let byte_pos = (bit_pos >> 3) as usize;
                let bit_res = bit_pos & 7;
                let mut instruction = 0u64;
                for j in 0..6 {
                    instruction |= (b[j + byte_pos] as u64) << (8 * j);
                }
                let mut inst_norm = instruction >> bit_res;
                if (inst_norm >> 37) & 0xF == 0x5 && (inst_norm >> 9) & 0x7 == 0 {
                    let mut src = ((inst_norm >> 13) & 0xF_FFFF) as u32;
                    src |= (((inst_norm >> 36) & 1) as u32) << 20;
                    src <<= 4;
                    let dest = pc.wrapping_add(src) >> 4;
                    inst_norm &= !(0x8F_FFFFu64 << 13);
                    inst_norm |= ((dest & 0xF_FFFF) as u64) << 13;
                    inst_norm |= ((dest & 0x10_0000) as u64) << (36 - 20);
                    instruction &= (1u64 << bit_res) - 1;
                    instruction |= inst_norm << bit_res;
                    for j in 0..6 {
                        b[j + byte_pos] = (instruction >> (8 * j)) as u8;
                    }
                }
            }
            bit_pos += 41;
        }
    }

    /// Encoders for the fixed-width converters, written independently of
    /// the decoders (add where they subtract).
    fn encode(arch: BcjArch, buf: &mut [u8]) {
        match arch {
            BcjArch::ArmThumb => {
                if buf.len() < 4 {
                    return;
                }
                let mut i = 0;
                while i <= buf.len() - 4 {
                    if (buf[i + 1] & 0xF8) == 0xF0 && (buf[i + 3] & 0xF8) == 0xF8 {
                        let src = (((buf[i + 1] as u32) & 7) << 19
                            | (buf[i] as u32) << 11
                            | ((buf[i + 3] as u32) & 7) << 8
                            | buf[i + 2] as u32)
                            << 1;
                        let dest = (i as u32).wrapping_add(4).wrapping_add(src) >> 1;
                        buf[i + 1] = 0xF0 | ((dest >> 19) & 0x7) as u8;
                        buf[i] = (dest >> 11) as u8;
                        buf[i + 3] = 0xF8 | ((dest >> 8) & 0x7) as u8;
                        buf[i + 2] = dest as u8;
                        i += 2;
                    }
                    i += 2;
                }
                return;
            }
            BcjArch::Ia64 => {
                let size = buf.len() & !15;
                let mut i = 0;
                while i < size {
                    ia64_encode_bundle(&mut buf[i..i + 16], i as u32);
                    i += 16;
                }
                return;
            }
            _ => {}
        }
        let size = buf.len() & !3;
        let mut i = 0;
        while i < size {
            let pc = i as u32;
            match arch {
                BcjArch::Arm => {
                    if buf[i + 3] == 0xEB {
                        let src =
                            ((buf[i + 2] as u32) << 16 | (buf[i + 1] as u32) << 8 | buf[i] as u32)
                                << 2;
                        let dest = pc.wrapping_add(8).wrapping_add(src) >> 2;
                        buf[i + 2] = (dest >> 16) as u8;
                        buf[i + 1] = (dest >> 8) as u8;
                        buf[i] = dest as u8;
                    }
                }
                BcjArch::Arm64 => {
                    let mut instr =
                        u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
                    if instr >> 26 == 0x25 {
                        let src = instr;
                        instr = 0x9400_0000 | (src.wrapping_add(pc >> 2) & 0x03FF_FFFF);
                        buf[i..i + 4].copy_from_slice(&instr.to_le_bytes());
                    } else if instr & 0x9F00_0000 == 0x9000_0000 {
                        let src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001F_FFFC);
                        if src.wrapping_add(0x0002_0000) & 0x001C_0000 == 0 {
                            instr &= 0x9000_001F;
                            let dest = src.wrapping_add(pc >> 12);
                            instr |= (dest & 3) << 29;
                            instr |= (dest & 0x0003_FFFC) << 3;
                            instr |= 0u32.wrapping_sub(dest & 0x0002_0000) & 0x00E0_0000;
                            buf[i..i + 4].copy_from_slice(&instr.to_le_bytes());
                        }
                    }
                }
                BcjArch::PowerPc => {
                    if (buf[i] >> 2) == 0x12 && (buf[i + 3] & 3) == 1 {
                        let src = ((buf[i] as u32) & 3) << 24
                            | (buf[i + 1] as u32) << 16
                            | (buf[i + 2] as u32) << 8
                            | ((buf[i + 3] as u32) & !3);
                        let dest = pc.wrapping_add(src);
                        buf[i] = 0x48 | ((dest >> 24) & 0x03) as u8;
                        buf[i + 1] = (dest >> 16) as u8;
                        buf[i + 2] = (dest >> 8) as u8;
                        buf[i + 3] = (buf[i + 3] & 0x03) | dest as u8;
                    }
                }
                BcjArch::Sparc => {
                    if (buf[i] == 0x40 && (buf[i + 1] & 0xC0) == 0x00)
                        || (buf[i] == 0x7F && (buf[i + 1] & 0xC0) == 0xC0)
                    {
                        let src = ((buf[i] as u32) << 24
                            | (buf[i + 1] as u32) << 16
                            | (buf[i + 2] as u32) << 8
                            | buf[i + 3] as u32)
                            << 2;
                        let mut dest = pc.wrapping_add(src) >> 2;
                        dest = ((0u32.wrapping_sub((dest >> 22) & 1) << 22) & 0x3FFF_FFFF)
                            | (dest & 0x3F_FFFF)
                            | 0x4000_0000;
                        buf[i..i + 4].copy_from_slice(&dest.to_be_bytes());
                    }
                }
                _ => unreachable!(),
            }
            i += 4;
        }
    }
}
