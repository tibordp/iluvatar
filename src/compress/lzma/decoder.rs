//! LZMA decoder core.
//!
//! Implements the LZMA decoding algorithm: probability tables, literal/match/rep
//! decoding, and the sliding window dictionary. This module handles a single
//! LZMA stream (as used within an LZMA2 chunk).
//!
//! All state is serializable for checkpointing.

use serde::{Deserialize, Serialize};

use super::range_coder::{RangeCoderStatus, RangeDecoder, PROB_INIT_VAL};

// ─── Constants ──────────────────────────────────────────────────────

const K_NUM_STATES: usize = 12;
const K_NUM_POS_BITS_MAX: usize = 4;
const K_NUM_POS_STATES_MAX: usize = 1 << K_NUM_POS_BITS_MAX;
const K_NUM_LEN_TO_POS_STATES: usize = 4;
const K_NUM_ALIGN_BITS: usize = 4;
const K_START_POS_MODEL_INDEX: usize = 4;
const K_END_POS_MODEL_INDEX: usize = 14;
const K_NUM_FULL_DISTANCES: usize = 1 << (K_END_POS_MODEL_INDEX >> 1);
const K_MATCH_MIN_LEN: usize = 2;
const K_LEN_NUM_LOW_BITS: usize = 3;
const K_LEN_NUM_LOW_SYMBOLS: usize = 1 << K_LEN_NUM_LOW_BITS;
const K_LEN_NUM_HIGH_BITS: usize = 8;
const K_LEN_NUM_HIGH_SYMBOLS: usize = 1 << K_LEN_NUM_HIGH_BITS;
const K_LEN_NUM_MID_BITS: usize = 3;
const K_LEN_NUM_MID_SYMBOLS: usize = 1 << K_LEN_NUM_MID_BITS;
const K_LZMA_LIT_SIZE: usize = 0x300;

/// Minimum dictionary size (4 KiB).
const K_DIC_MIN: u32 = 1 << 12;

// ─── Probability table layout ──────────────────────────────────────
// We use a single flat Vec<u16> for all probabilities except literals.
// This matches the spec's description of two arrays.

// Offsets into the main probs array:
const OFF_IS_MATCH: usize = 0;
const OFF_IS_REP: usize = OFF_IS_MATCH + K_NUM_STATES * K_NUM_POS_STATES_MAX; // 192
const OFF_IS_REP_G0: usize = OFF_IS_REP + K_NUM_STATES; // 204
const OFF_IS_REP_G1: usize = OFF_IS_REP_G0 + K_NUM_STATES; // 216
const OFF_IS_REP_G2: usize = OFF_IS_REP_G1 + K_NUM_STATES; // 228
const OFF_IS_REP0_LONG: usize = OFF_IS_REP_G2 + K_NUM_STATES; // 240
const OFF_LEN_CODER: usize = OFF_IS_REP0_LONG + K_NUM_STATES * K_NUM_POS_STATES_MAX; // 432
// LenDecoder: Choice(1) + Choice2(1) + LowCoder[16][8] + MidCoder[16][8] + HighCoder[256]
const K_LEN_DECODER_SIZE: usize =
    2 + K_NUM_POS_STATES_MAX * K_LEN_NUM_LOW_SYMBOLS + K_NUM_POS_STATES_MAX * K_LEN_NUM_MID_SYMBOLS + K_LEN_NUM_HIGH_SYMBOLS;
// = 2 + 128 + 128 + 256 = 514
const OFF_REP_LEN_CODER: usize = OFF_LEN_CODER + K_LEN_DECODER_SIZE; // 946
const OFF_POS_SLOT: usize = OFF_REP_LEN_CODER + K_LEN_DECODER_SIZE; // 1460
const OFF_POS_DECODERS: usize =
    OFF_POS_SLOT + K_NUM_LEN_TO_POS_STATES * (1 << 6); // 1460 + 256 = 1716
// PosDecoders: 1 + kNumFullDistances - kEndPosModelIndex = 1 + 128 - 14 = 115
const K_POS_DECODERS_SIZE: usize = 1 + K_NUM_FULL_DISTANCES - K_END_POS_MODEL_INDEX;
const OFF_ALIGN: usize = OFF_POS_DECODERS + K_POS_DECODERS_SIZE; // 1831
const K_ALIGN_TABLE_SIZE: usize = 1 << K_NUM_ALIGN_BITS;
const BASE_PROBS_SIZE: usize = OFF_ALIGN + K_ALIGN_TABLE_SIZE; // 1847

// Literals are stored separately: 0x300 * (1 << (lc + lp))

/// Compute total number of probability entries.
pub fn num_probs(lc: u8, lp: u8) -> usize {
    BASE_PROBS_SIZE + K_LZMA_LIT_SIZE * (1usize << (lc as usize + lp as usize))
}

// ─── State transition functions ─────────────────────────────────────

#[inline]
fn update_state_literal(state: u8) -> u8 {
    if state < 4 {
        0
    } else if state < 10 {
        state - 3
    } else {
        state - 6
    }
}

#[inline]
fn update_state_match(state: u8) -> u8 {
    if state < 7 { 7 } else { 10 }
}

#[inline]
fn update_state_rep(state: u8) -> u8 {
    if state < 7 { 8 } else { 11 }
}

#[inline]
fn update_state_short_rep(state: u8) -> u8 {
    if state < 7 { 9 } else { 11 }
}

// ─── LZMA Properties ───────────────────────────────────────────────

/// LZMA compression properties.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LzmaProperties {
    pub lc: u8,
    pub lp: u8,
    pub pb: u8,
}

impl LzmaProperties {
    /// Decode properties from a single byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        if b >= 9 * 5 * 5 {
            return None;
        }
        let lc = b % 9;
        let d = b / 9;
        let pb = d / 5;
        let lp = d % 5;
        Some(Self { lc, lp, pb })
    }
}

// ─── Sliding Window ─────────────────────────────────────────────────

/// Cyclic sliding window buffer for LZMA decoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlidingWindow {
    buf: Vec<u8>,
    pos: usize,
    size: usize,
    is_full: bool,
    pub total_pos: u64,
    /// How many output bytes are pending to be copied to the caller.
    pending_out: Vec<u8>,
}

impl SlidingWindow {
    pub fn new(dict_size: u32) -> Self {
        let size = dict_size.max(K_DIC_MIN) as usize;
        Self {
            buf: vec![0u8; size],
            pos: 0,
            size,
            is_full: false,
            total_pos: 0,
            pending_out: Vec::new(),
        }
    }

    #[inline]
    pub fn put_byte(&mut self, b: u8) {
        self.buf[self.pos] = b;
        self.pending_out.push(b);
        self.pos += 1;
        self.total_pos += 1;
        if self.pos == self.size {
            self.pos = 0;
            self.is_full = true;
        }
    }


    #[inline]
    pub fn get_byte(&self, dist: u32) -> u8 {
        let dist = dist as usize;
        if dist <= self.pos {
            self.buf[self.pos - dist]
        } else {
            self.buf[self.size - dist + self.pos]
        }
    }

    pub fn copy_match(&mut self, dist: u32, len: usize) {
        for _ in 0..len {
            let b = self.get_byte(dist);
            self.put_byte(b);
        }
    }

    pub fn check_distance(&self, dist: u32) -> bool {
        let d = dist as usize;
        if self.is_full { d < self.size } else { d < self.pos }
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0 && !self.is_full
    }

    /// Drain pending output bytes, copying to `output`.
    /// Returns how many bytes were written to `output`.
    pub fn drain_output(&mut self, output: &mut [u8]) -> usize {
        let n = self.pending_out.len().min(output.len());
        if n > 0 {
            output[..n].copy_from_slice(&self.pending_out[..n]);
            self.pending_out.drain(..n);
        }
        n
    }

    /// How many pending bytes are available.
    pub fn pending_len(&self) -> usize {
        self.pending_out.len()
    }

    /// Get the last `dict_size` bytes of the window for checkpointing.
    pub fn get_window_data(&self) -> Vec<u8> {
        if !self.is_full {
            self.buf[..self.pos].to_vec()
        } else {
            let mut data = Vec::with_capacity(self.size);
            data.extend_from_slice(&self.buf[self.pos..]);
            data.extend_from_slice(&self.buf[..self.pos]);
            data
        }
    }

    /// Restore window state from checkpoint data.
    pub fn restore_from_data(&mut self, data: &[u8], total_pos: u64) {
        let len = data.len().min(self.size);
        if len <= self.size {
            self.buf[..len].copy_from_slice(&data[data.len() - len..]);
            // Fill rest with zeros if data is shorter
            for i in len..self.size {
                self.buf[i] = 0;
            }
        }
        self.pos = len % self.size;
        self.is_full = len >= self.size;
        self.total_pos = total_pos;
        self.pending_out.clear();
    }
}

// ─── Decoder status ─────────────────────────────────────────────────

/// Status of the LZMA decoder after a decode step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LzmaDecodeStatus {
    /// More input/output may be needed.
    Continue,
    /// The LZMA end marker was found.
    FinishedWithMark,
    /// The specified unpack size was reached.
    FinishedWithoutMark,
    /// Need more input data.
    NeedInput,
}

/// Result of decoding.
#[derive(Debug)]
pub struct LzmaDecodeResult {
    pub bytes_consumed: usize,
    pub bytes_produced: usize,
    pub status: LzmaDecodeStatus,
}

// ─── Internal decode sub-step state ─────────────────────────────────
// When we run out of input mid-symbol, we need to know where to resume.
// We use a micro-state machine to track progress within a single LZMA symbol.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DecodePhase {
    /// Ready to start decoding a new symbol.
    NewSymbol,
    /// IsMatch=1 has been decoded; need to decode IsRep next.
    NeedIsRep { pos_state: usize },
    /// IsRep=1 decoded; need to decode IsRepG0.
    NeedRepG0 { pos_state: usize },
    /// IsRepG0=0 decoded; need to decode IsRep0Long.
    NeedRep0Long { pos_state: usize },
    /// IsRepG0=1 decoded; need to decode IsRepG1.
    NeedRepG1 { pos_state: usize },
    /// IsRepG1=1 decoded; need to decode IsRepG2.
    NeedRepG2 { pos_state: usize },
    /// In the middle of decoding a literal byte.
    Literal(LiteralState),
    /// Decoded match type, need to decode length.
    MatchLength(MatchType),
    /// Have length, need distance for simple match.
    MatchDistance { len: usize, len_state: usize },
    /// Have length and distance, copying match bytes.
    CopyMatch { dist: u32, remaining: usize },
    /// Finished (end marker or unpack limit).
    Finished(LzmaDecodeStatus),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LiteralState {
    symbol: u32,
    lit_state: usize,
    matched: bool,
    match_byte: u8,
    offs: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum MatchType {
    Simple,
    Rep0,
    Rep1,
    Rep2,
    Rep3,
}

// ─── The LZMA Decoder ──────────────────────────────────────────────

/// Core LZMA decoder. Handles a single LZMA stream.
///
/// All state is serializable for checkpointing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LzmaDecoder {
    // Properties
    pub props: LzmaProperties,
    pub dict_size: u32,

    // Range coder
    pub range_decoder: RangeDecoder,
    pub rc_initialized: bool,

    // LZMA state
    pub state: u8,
    pub reps: [u32; 4],

    // Probability tables
    pub probs: Vec<u16>,

    // Sliding window
    pub window: SlidingWindow,

    // Decode progress
    pub(crate) phase: DecodePhase,
    unpack_size: Option<u64>,
    pub(crate) decoded_size: u64,

    // Position tracking within LenDecoder decode (for mid-decode resume)
    pub(crate) len_decode_state: Option<LenDecodeState>,
    pub(crate) dist_decode_state: Option<DistDecodeState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LenDecodeState {
    is_rep: bool,
    pos_state: usize,
    phase: LenPhase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum LenPhase {
    Choice,
    Low { m: usize, bits_remaining: usize },
    Choice2,
    Mid { m: usize, bits_remaining: usize },
    High { m: usize, bits_remaining: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DistDecodeState {
    len_state: usize,
    phase: DistPhase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum DistPhase {
    PosSlot { m: usize, bits_remaining: usize },
    /// Direct bits: dist accumulates via (dist << 1) + bit, matching C code exactly.
    DirectBits { dist: u32, num_bits: usize },
    /// Reverse bit-tree decode for align bits. i tracks bit position (0..4).
    AlignBits { dist: u32, m: usize, symbol: u32, i: usize },
    /// Reverse bit-tree decode for spec pos (posSlot 4..13). i tracks bit position.
    SpecPosBits { dist: u32, probs_offset: usize, m: usize, symbol: u32, i: usize, num_bits: usize },
}

impl LzmaDecoder {
    /// Create a new LZMA decoder with the given properties and dictionary size.
    pub fn new(props: LzmaProperties, dict_size: u32) -> Self {
        let dict_size = dict_size.max(K_DIC_MIN);
        let n = num_probs(props.lc, props.lp);
        let probs = vec![PROB_INIT_VAL; n];

        Self {
            props,
            dict_size,
            range_decoder: RangeDecoder::new(),
            rc_initialized: false,
            state: 0,
            reps: [0; 4],
            probs,
            window: SlidingWindow::new(dict_size),
            phase: DecodePhase::NewSymbol,
            unpack_size: None,
            decoded_size: 0,
            len_decode_state: None,
            dist_decode_state: None,
        }
    }

    /// Set the expected uncompressed size. If None, decode until end marker.
    pub fn set_unpack_size(&mut self, size: Option<u64>) {
        self.unpack_size = size;
    }

    /// Reset the state machine (probabilities and reps) but keep the dictionary.
    pub fn reset_state(&mut self) {
        self.state = 0;
        self.reps = [0; 4];
        for p in self.probs.iter_mut() {
            *p = PROB_INIT_VAL;
        }
        self.rc_initialized = false;
        self.phase = DecodePhase::NewSymbol;
        self.decoded_size = 0;
        self.len_decode_state = None;
        self.dist_decode_state = None;
    }

    /// Reset state and set new properties.
    pub fn reset_state_and_props(&mut self, props: LzmaProperties) {
        self.props = props;
        let n = num_probs(props.lc, props.lp);
        self.probs.clear();
        self.probs.resize(n, PROB_INIT_VAL);
        self.state = 0;
        self.reps = [0; 4];
        self.rc_initialized = false;
        self.phase = DecodePhase::NewSymbol;
        self.decoded_size = 0;
        self.len_decode_state = None;
        self.dist_decode_state = None;
    }

    /// Reset the dictionary (window).
    pub fn reset_dict(&mut self) {
        self.window = SlidingWindow::new(self.dict_size);
    }

    /// Decode from input into the internal window. Returns status.
    ///
    /// After calling this, use `drain_output()` to get decompressed bytes.
    pub fn decode(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> LzmaDecodeResult {
        let mut in_pos = 0;
        let mut out_pos = 0;

        // First drain any pending output
        if self.window.pending_len() > 0 {
            let n = self.window.drain_output(&mut output[out_pos..]);
            out_pos += n;
            if self.window.pending_len() > 0 || out_pos >= output.len() {
                let final_status = match &self.phase {
                    DecodePhase::Finished(s) if self.window.pending_len() == 0 => *s,
                    _ => LzmaDecodeStatus::Continue,
                };
                return LzmaDecodeResult {
                    bytes_consumed: 0,
                    bytes_produced: out_pos,
                    status: final_status,
                };
            }
        }

        // Initialize range coder if needed
        if !self.rc_initialized {
            let (status, consumed) = self.range_decoder.init(&input[in_pos..]);
            if status == RangeCoderStatus::NeedInput {
                return LzmaDecodeResult {
                    bytes_consumed: in_pos,
                    bytes_produced: out_pos,
                    status: LzmaDecodeStatus::NeedInput,
                };
            }
            in_pos += consumed;
            self.rc_initialized = true;
        }

        loop {
            // Drain pending output first
            if self.window.pending_len() > 0 {
                let n = self.window.drain_output(&mut output[out_pos..]);
                out_pos += n;
                if self.window.pending_len() > 0 || out_pos >= output.len() {
                    return LzmaDecodeResult {
                        bytes_consumed: in_pos,
                        bytes_produced: out_pos,
                        status: LzmaDecodeStatus::Continue,
                    };
                }
            }

            match self.phase.clone() {
                DecodePhase::Finished(status) => {
                    return LzmaDecodeResult {
                        bytes_consumed: in_pos,
                        bytes_produced: out_pos,
                        status,
                    };
                }

                DecodePhase::CopyMatch { dist, remaining } => {
                    // Copy as many bytes as we can to output
                    let can_produce = output.len() - out_pos;
                    let to_copy = remaining.min(can_produce);
                    for _i in 0..to_copy {
                        let b = self.window.get_byte(dist + 1);
                        self.window.put_byte(b);
                    }
                    let n = self.window.drain_output(&mut output[out_pos..]);
                    out_pos += n;
                    self.decoded_size += to_copy as u64;
                    let new_remaining = remaining - to_copy;
                    if new_remaining > 0 {
                        self.phase = DecodePhase::CopyMatch {
                            dist,
                            remaining: new_remaining,
                        };
                        return LzmaDecodeResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: LzmaDecodeStatus::Continue,
                        };
                    }
                    self.phase = DecodePhase::NewSymbol;
                    continue;
                }

                DecodePhase::NewSymbol => {
                    // Check end conditions
                    if let Some(unpack) = self.unpack_size {
                        if self.decoded_size >= unpack {
                            self.phase = DecodePhase::Finished(LzmaDecodeStatus::FinishedWithoutMark);
                            continue;
                        }
                    }
                    let pos_state = (self.window.total_pos as usize) & ((1 << self.props.pb) - 1);
                    let state2 = (self.state as usize) * K_NUM_POS_STATES_MAX + pos_state;

                    // Decode IsMatch
                    let prob_idx = OFF_IS_MATCH + state2;
                    match self.range_decoder.decode_bit(
                        &mut self.probs[prob_idx],
                        input,
                        in_pos,
                    ) {
                        Err(_) => {
                            return LzmaDecodeResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: LzmaDecodeStatus::NeedInput,
                            };
                        }
                        Ok((bit, consumed)) => {
                            in_pos += consumed;
                            if bit == 0 {
                                // Literal
                                self.start_literal_decode(pos_state);
                                continue;
                            }
                            // Match
                            let prob_idx = OFF_IS_REP + self.state as usize;
                            match self.range_decoder.decode_bit(
                                &mut self.probs[prob_idx],
                                input,
                                in_pos,
                            ) {
                                Err(_) => {
                                    // IsMatch=1 decoded, but IsRep needs more input.
                                    // Save state to resume at IsRep decoding.
                                    self.phase = DecodePhase::NeedIsRep { pos_state };
                                    return LzmaDecodeResult {
                                        bytes_consumed: in_pos,
                                        bytes_produced: out_pos,
                                        status: LzmaDecodeStatus::NeedInput,
                                    };
                                }
                                Ok((is_rep, consumed)) => {
                                    in_pos += consumed;
                                    if is_rep == 0 {
                                        // Simple Match
                                        self.reps[3] = self.reps[2];
                                        self.reps[2] = self.reps[1];
                                        self.reps[1] = self.reps[0];
                                        self.state = update_state_match(self.state);
                                        self.phase = DecodePhase::MatchLength(MatchType::Simple);
                                        self.len_decode_state = Some(LenDecodeState {
                                            is_rep: false,
                                            pos_state,
                                            phase: LenPhase::Choice,
                                        });
                                        continue;
                                    }
                                    // Rep match - need to decode which rep
                                    let result = self.decode_rep_type(input, &mut in_pos, pos_state);
                                    match result {
                                        Ok(()) => continue,
                                        Err(_) => {
                                            return LzmaDecodeResult {
                                                bytes_consumed: in_pos,
                                                bytes_produced: out_pos,
                                                status: LzmaDecodeStatus::NeedInput,
                                            };
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                DecodePhase::NeedIsRep { pos_state } => {
                    // Resume: IsMatch=1 was decoded, now decode IsRep.
                    let prob_idx = OFF_IS_REP + self.state as usize;
                    match self.range_decoder.decode_bit(
                        &mut self.probs[prob_idx],
                        input,
                        in_pos,
                    ) {
                        Err(_) => {
                            // Still need input for IsRep
                            return LzmaDecodeResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: LzmaDecodeStatus::NeedInput,
                            };
                        }
                        Ok((is_rep, consumed)) => {
                            in_pos += consumed;
                            if is_rep == 0 {
                                // Simple Match
                                self.reps[3] = self.reps[2];
                                self.reps[2] = self.reps[1];
                                self.reps[1] = self.reps[0];
                                self.state = update_state_match(self.state);
                                self.phase = DecodePhase::MatchLength(MatchType::Simple);
                                self.len_decode_state = Some(LenDecodeState {
                                    is_rep: false,
                                    pos_state,
                                    phase: LenPhase::Choice,
                                });
                                continue;
                            }
                            // Rep match - need to decode which rep
                            let result = self.decode_rep_type(input, &mut in_pos, pos_state);
                            match result {
                                Ok(()) => continue,
                                Err(_) => {
                                    return LzmaDecodeResult {
                                        bytes_consumed: in_pos,
                                        bytes_produced: out_pos,
                                        status: LzmaDecodeStatus::NeedInput,
                                    };
                                }
                            }
                        }
                    }
                }

                DecodePhase::NeedRepG0 { pos_state } => {
                    // Resume: IsRep=1 decoded, need IsRepG0.
                    let result = self.decode_rep_type(input, &mut in_pos, pos_state);
                    match result {
                        Ok(()) => continue,
                        Err(_) => {
                            return LzmaDecodeResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: LzmaDecodeStatus::NeedInput,
                            };
                        }
                    }
                }

                DecodePhase::NeedRep0Long { pos_state } => {
                    // Resume: IsRepG0=0 decoded, need IsRep0Long.
                    let result = self.decode_rep0_long(input, &mut in_pos, pos_state);
                    match result {
                        Ok(()) => continue,
                        Err(_) => {
                            return LzmaDecodeResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: LzmaDecodeStatus::NeedInput,
                            };
                        }
                    }
                }

                DecodePhase::NeedRepG1 { pos_state } => {
                    // Resume: IsRepG0=1 decoded, need IsRepG1.
                    let result = self.decode_rep_g1(input, &mut in_pos, pos_state);
                    match result {
                        Ok(()) => continue,
                        Err(_) => {
                            return LzmaDecodeResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: LzmaDecodeStatus::NeedInput,
                            };
                        }
                    }
                }

                DecodePhase::NeedRepG2 { pos_state } => {
                    // Resume: IsRepG1=1 decoded, need IsRepG2.
                    let result = self.decode_rep_g2(input, &mut in_pos, pos_state);
                    match result {
                        Ok(()) => continue,
                        Err(_) => {
                            return LzmaDecodeResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: LzmaDecodeStatus::NeedInput,
                            };
                        }
                    }
                }

                DecodePhase::Literal(ref ls) => {
                    let ls = ls.clone();
                    let result = self.continue_literal_decode(input, &mut in_pos, &mut output[out_pos..], ls);
                    match result {
                        Ok(produced) => {
                            out_pos += produced;
                            continue;
                        }
                        Err(_) => {
                            return LzmaDecodeResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: LzmaDecodeStatus::NeedInput,
                            };
                        }
                    }
                }

                DecodePhase::MatchLength(match_type) => {
                    let result = self.decode_length(input, &mut in_pos);
                    match result {
                        Ok(len) => {
                            match match_type {
                                MatchType::Simple => {
                                    // Now decode distance
                                    let len_state = if len >= K_NUM_LEN_TO_POS_STATES {
                                        K_NUM_LEN_TO_POS_STATES - 1
                                    } else {
                                        len
                                    };
                                    self.phase = DecodePhase::MatchDistance {
                                        len: len + K_MATCH_MIN_LEN,
                                        len_state,
                                    };
                                    self.dist_decode_state = Some(DistDecodeState {
                                        len_state,
                                        phase: DistPhase::PosSlot {
                                            m: 1,
                                            bits_remaining: 6,
                                        },
                                    });
                                    continue;
                                }
                                _ => {
                                    // Rep match - length decoded, do copy
                                    let real_len = len + K_MATCH_MIN_LEN;
                                    self.start_copy_match(self.reps[0], real_len);
                                    continue;
                                }
                            }
                        }
                        Err(_) => {
                            return LzmaDecodeResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: LzmaDecodeStatus::NeedInput,
                            };
                        }
                    }
                }

                DecodePhase::MatchDistance { len, len_state: _ } => {
                    let result = self.decode_distance(input, &mut in_pos);
                    match result {
                        Ok(dist) => {
                            if dist == 0xFFFF_FFFF {
                                // End marker
                                self.phase = DecodePhase::Finished(
                                    if self.range_decoder.is_finished_ok() {
                                        LzmaDecodeStatus::FinishedWithMark
                                    } else {
                                        LzmaDecodeStatus::FinishedWithMark
                                    },
                                );
                                continue;
                            }
                            if dist >= self.dict_size || !self.window.check_distance(dist) {
                                self.phase = DecodePhase::Finished(LzmaDecodeStatus::FinishedWithMark);
                                continue;
                            }
                            self.reps[0] = dist;
                            self.start_copy_match(dist, len);
                            continue;
                        }
                        Err(_) => {
                            return LzmaDecodeResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: LzmaDecodeStatus::NeedInput,
                            };
                        }
                    }
                }
            }
        }
    }

    fn start_literal_decode(&mut self, _pos_state: usize) {
        let prev_byte = if !self.window.is_empty() {
            self.window.get_byte(1)
        } else {
            0
        };

        let lit_state = (((self.window.total_pos as usize) & ((1 << self.props.lp) - 1))
            << self.props.lc as usize)
            + ((prev_byte as usize) >> (8 - self.props.lc as usize));

        let matched = self.state >= 7;
        let match_byte = if matched {
            self.window.get_byte(self.reps[0] + 1)
        } else {
            0
        };

        self.phase = DecodePhase::Literal(LiteralState {
            symbol: 1,
            lit_state,
            matched,
            match_byte,
            offs: if matched { 0x100 } else { 0 },
        });
    }

    fn continue_literal_decode(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        mut ls: LiteralState,
    ) -> Result<usize, RangeCoderStatus> {
        let lit_probs_offset = BASE_PROBS_SIZE + K_LZMA_LIT_SIZE * ls.lit_state;

        if ls.matched && ls.symbol < 0x100 {
            // Matched literal decoding
            loop {
                if ls.symbol >= 0x100 {
                    break;
                }
                let match_bit = (ls.match_byte >> 7) & 1;

                let prob_idx =
                    lit_probs_offset + ((1 + match_bit as usize) << 8) + ls.symbol as usize;
                match self.range_decoder.decode_bit(
                    &mut self.probs[prob_idx],
                    input,
                    *in_pos,
                ) {
                    Err(_) => {
                        // Don't shift match_byte -- decode_bit didn't succeed
                        self.phase = DecodePhase::Literal(ls);
                        return Err(RangeCoderStatus::NeedInput);
                    }
                    Ok((bit, consumed)) => {
                        *in_pos += consumed;
                        // Shift match_byte AFTER successful decode
                        ls.match_byte <<= 1;
                        ls.symbol = (ls.symbol << 1) | bit;
                        if match_bit as u32 != bit {
                            // Switch to normal literal decoding
                            ls.matched = false;
                            break;
                        }
                    }
                }
            }
        }

        // Normal literal decoding (or continuation after matched diverged)
        while ls.symbol < 0x100 {
            let prob_idx = lit_probs_offset + ls.symbol as usize;
            match self.range_decoder.decode_bit(
                &mut self.probs[prob_idx],
                input,
                *in_pos,
            ) {
                Err(_) => {
                    ls.matched = false;
                    self.phase = DecodePhase::Literal(ls);
                    return Err(RangeCoderStatus::NeedInput);
                }
                Ok((bit, consumed)) => {
                    *in_pos += consumed;
                    ls.symbol = (ls.symbol << 1) | bit;
                }
            }
        }

        let byte = (ls.symbol - 0x100) as u8;
        self.window.put_byte(byte);
        self.state = update_state_literal(self.state);
        self.decoded_size += 1;

        // Drain to output
        let n = self.window.drain_output(output);
        self.phase = DecodePhase::NewSymbol;
        Ok(n)
    }

    fn decode_rep_type(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        pos_state: usize,
    ) -> Result<(), RangeCoderStatus> {
        // Check unpack size
        if let Some(unpack) = self.unpack_size {
            if self.decoded_size >= unpack {
                self.phase = DecodePhase::Finished(LzmaDecodeStatus::FinishedWithoutMark);
                return Ok(());
            }
        }
        if self.window.is_empty() {
            self.phase = DecodePhase::Finished(LzmaDecodeStatus::FinishedWithMark);
            return Ok(());
        }

        // IsRepG0
        let prob_idx = OFF_IS_REP_G0 + self.state as usize;
        let (is_rep_g0, consumed) = self.range_decoder.decode_bit(
            &mut self.probs[prob_idx],
            input,
            *in_pos,
        ).map_err(|_| {
            self.phase = DecodePhase::NeedRepG0 { pos_state };
            RangeCoderStatus::NeedInput
        })?;
        *in_pos += consumed;

        if is_rep_g0 == 0 {
            return self.decode_rep0_long(input, in_pos, pos_state);
        }

        // IsRepG1
        self.decode_rep_g1(input, in_pos, pos_state)
    }

    fn decode_rep0_long(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        pos_state: usize,
    ) -> Result<(), RangeCoderStatus> {
        // Distance is rep0; need to decode IsRep0Long
        let state2 = (self.state as usize) * K_NUM_POS_STATES_MAX + pos_state;
        let prob_idx = OFF_IS_REP0_LONG + state2;
        let (is_long, consumed) = self.range_decoder.decode_bit(
            &mut self.probs[prob_idx],
            input,
            *in_pos,
        ).map_err(|_| {
            self.phase = DecodePhase::NeedRep0Long { pos_state };
            RangeCoderStatus::NeedInput
        })?;
        *in_pos += consumed;

        if is_long == 0 {
            // Short rep match (single byte)
            self.state = update_state_short_rep(self.state);
            let b = self.window.get_byte(self.reps[0] + 1);
            self.window.put_byte(b);
            self.decoded_size += 1;
            self.phase = DecodePhase::NewSymbol;
            return Ok(());
        }
        // Rep0 with length
        self.state = update_state_rep(self.state);
        self.phase = DecodePhase::MatchLength(MatchType::Rep0);
        self.len_decode_state = Some(LenDecodeState {
            is_rep: true,
            pos_state,
            phase: LenPhase::Choice,
        });
        Ok(())
    }

    fn decode_rep_g1(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        pos_state: usize,
    ) -> Result<(), RangeCoderStatus> {
        let prob_idx = OFF_IS_REP_G1 + self.state as usize;
        let (is_rep_g1, consumed) = self.range_decoder.decode_bit(
            &mut self.probs[prob_idx],
            input,
            *in_pos,
        ).map_err(|_| {
            self.phase = DecodePhase::NeedRepG1 { pos_state };
            RangeCoderStatus::NeedInput
        })?;
        *in_pos += consumed;

        if is_rep_g1 == 0 {
            // Rep1
            let dist = self.reps[1];
            self.reps[1] = self.reps[0];
            self.reps[0] = dist;
            self.state = update_state_rep(self.state);
            self.phase = DecodePhase::MatchLength(MatchType::Rep1);
            self.len_decode_state = Some(LenDecodeState {
                is_rep: true,
                pos_state,
                phase: LenPhase::Choice,
            });
            return Ok(());
        }

        // IsRepG2
        self.decode_rep_g2(input, in_pos, pos_state)
    }

    fn decode_rep_g2(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        pos_state: usize,
    ) -> Result<(), RangeCoderStatus> {
        let prob_idx = OFF_IS_REP_G2 + self.state as usize;
        let (is_rep_g2, consumed) = self.range_decoder.decode_bit(
            &mut self.probs[prob_idx],
            input,
            *in_pos,
        ).map_err(|_| {
            self.phase = DecodePhase::NeedRepG2 { pos_state };
            RangeCoderStatus::NeedInput
        })?;
        *in_pos += consumed;

        if is_rep_g2 == 0 {
            // Rep2
            let dist = self.reps[2];
            self.reps[2] = self.reps[1];
            self.reps[1] = self.reps[0];
            self.reps[0] = dist;
        } else {
            // Rep3
            let dist = self.reps[3];
            self.reps[3] = self.reps[2];
            self.reps[2] = self.reps[1];
            self.reps[1] = self.reps[0];
            self.reps[0] = dist;
        }
        self.state = update_state_rep(self.state);
        self.phase = DecodePhase::MatchLength(if is_rep_g2 == 0 {
            MatchType::Rep2
        } else {
            MatchType::Rep3
        });
        self.len_decode_state = Some(LenDecodeState {
            is_rep: true,
            pos_state,
            phase: LenPhase::Choice,
        });
        Ok(())
    }

    fn decode_length(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
    ) -> Result<usize, RangeCoderStatus> {
        let lds = self.len_decode_state.take().unwrap_or(LenDecodeState {
            is_rep: false,
            pos_state: 0,
            phase: LenPhase::Choice,
        });

        let base_offset = if lds.is_rep {
            OFF_REP_LEN_CODER
        } else {
            OFF_LEN_CODER
        };

        // LenDecoder layout within the probs:
        // [0]: Choice
        // [1]: Choice2
        // [2 .. 2 + 16*8]: LowCoder[posState][8]
        // [2 + 128 .. 2 + 128 + 16*8]: MidCoder[posState][8]
        // [2 + 256 .. 2 + 256 + 256]: HighCoder[256]

        let choice_idx = base_offset;
        let choice2_idx = base_offset + 1;
        let low_base = base_offset + 2;
        let mid_base = low_base + K_NUM_POS_STATES_MAX * K_LEN_NUM_LOW_SYMBOLS;
        let high_base = mid_base + K_NUM_POS_STATES_MAX * K_LEN_NUM_MID_SYMBOLS;

        match lds.phase {
            LenPhase::Choice => {
                let (choice, consumed) = self.range_decoder.decode_bit(
                    &mut self.probs[choice_idx],
                    input,
                    *in_pos,
                ).map_err(|_| {
                    self.len_decode_state = Some(LenDecodeState {
                        is_rep: lds.is_rep,
                        pos_state: lds.pos_state,
                        phase: LenPhase::Choice,
                    });
                    RangeCoderStatus::NeedInput
                })?;
                *in_pos += consumed;

                if choice == 0 {
                    // Low coder
                    self.len_decode_state = Some(LenDecodeState {
                        is_rep: lds.is_rep,
                        pos_state: lds.pos_state,
                        phase: LenPhase::Low {
                            m: 1,
                            bits_remaining: K_LEN_NUM_LOW_BITS,
                        },
                    });
                    return self.decode_length(input, in_pos);
                }
                // Choice2
                self.len_decode_state = Some(LenDecodeState {
                    is_rep: lds.is_rep,
                    pos_state: lds.pos_state,
                    phase: LenPhase::Choice2,
                });
                return self.decode_length(input, in_pos);
            }

            LenPhase::Low { mut m, mut bits_remaining } => {
                let probs_base = low_base + lds.pos_state * K_LEN_NUM_LOW_SYMBOLS;
                while bits_remaining > 0 {
                    let (bit, consumed) = self.range_decoder.decode_bit(
                        &mut self.probs[probs_base + m],
                        input,
                        *in_pos,
                    ).map_err(|_| {
                        self.len_decode_state = Some(LenDecodeState {
                            is_rep: lds.is_rep,
                            pos_state: lds.pos_state,
                            phase: LenPhase::Low { m, bits_remaining },
                        });
                        RangeCoderStatus::NeedInput
                    })?;
                    *in_pos += consumed;
                    m = (m << 1) + bit as usize;
                    bits_remaining -= 1;
                }
                Ok(m - K_LEN_NUM_LOW_SYMBOLS)
            }

            LenPhase::Choice2 => {
                let (choice2, consumed) = self.range_decoder.decode_bit(
                    &mut self.probs[choice2_idx],
                    input,
                    *in_pos,
                ).map_err(|_| {
                    self.len_decode_state = Some(LenDecodeState {
                        is_rep: lds.is_rep,
                        pos_state: lds.pos_state,
                        phase: LenPhase::Choice2,
                    });
                    RangeCoderStatus::NeedInput
                })?;
                *in_pos += consumed;

                if choice2 == 0 {
                    // Mid coder
                    self.len_decode_state = Some(LenDecodeState {
                        is_rep: lds.is_rep,
                        pos_state: lds.pos_state,
                        phase: LenPhase::Mid {
                            m: 1,
                            bits_remaining: K_LEN_NUM_MID_BITS,
                        },
                    });
                    return self.decode_length(input, in_pos);
                }
                // High coder
                self.len_decode_state = Some(LenDecodeState {
                    is_rep: lds.is_rep,
                    pos_state: lds.pos_state,
                    phase: LenPhase::High {
                        m: 1,
                        bits_remaining: K_LEN_NUM_HIGH_BITS,
                    },
                });
                return self.decode_length(input, in_pos);
            }

            LenPhase::Mid { mut m, mut bits_remaining } => {
                let probs_base = mid_base + lds.pos_state * K_LEN_NUM_MID_SYMBOLS;
                while bits_remaining > 0 {
                    let (bit, consumed) = self.range_decoder.decode_bit(
                        &mut self.probs[probs_base + m],
                        input,
                        *in_pos,
                    ).map_err(|_| {
                        self.len_decode_state = Some(LenDecodeState {
                            is_rep: lds.is_rep,
                            pos_state: lds.pos_state,
                            phase: LenPhase::Mid { m, bits_remaining },
                        });
                        RangeCoderStatus::NeedInput
                    })?;
                    *in_pos += consumed;
                    m = (m << 1) + bit as usize;
                    bits_remaining -= 1;
                }
                Ok(m - K_LEN_NUM_MID_SYMBOLS + K_LEN_NUM_LOW_SYMBOLS)
            }

            LenPhase::High { mut m, mut bits_remaining } => {
                while bits_remaining > 0 {
                    let (bit, consumed) = self.range_decoder.decode_bit(
                        &mut self.probs[high_base + m],
                        input,
                        *in_pos,
                    ).map_err(|_| {
                        self.len_decode_state = Some(LenDecodeState {
                            is_rep: lds.is_rep,
                            pos_state: lds.pos_state,
                            phase: LenPhase::High { m, bits_remaining },
                        });
                        RangeCoderStatus::NeedInput
                    })?;
                    *in_pos += consumed;
                    m = (m << 1) + bit as usize;
                    bits_remaining -= 1;
                }
                Ok(m - K_LEN_NUM_HIGH_SYMBOLS + K_LEN_NUM_LOW_SYMBOLS + K_LEN_NUM_MID_SYMBOLS)
            }
        }
    }

    fn decode_distance(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
    ) -> Result<u32, RangeCoderStatus> {
        let dds = self.dist_decode_state.take().unwrap();

        match dds.phase {
            DistPhase::PosSlot { mut m, mut bits_remaining } => {
                let probs_base = OFF_POS_SLOT + dds.len_state * (1 << 6);
                while bits_remaining > 0 {
                    let (bit, consumed) = self.range_decoder.decode_bit(
                        &mut self.probs[probs_base + m],
                        input,
                        *in_pos,
                    ).map_err(|_| {
                        self.dist_decode_state = Some(DistDecodeState {
                            len_state: dds.len_state,
                            phase: DistPhase::PosSlot { m, bits_remaining },
                        });
                        RangeCoderStatus::NeedInput
                    })?;
                    *in_pos += consumed;
                    m = (m << 1) + bit as usize;
                    bits_remaining -= 1;
                }
                let pos_slot = m - (1 << 6);

                if pos_slot < K_START_POS_MODEL_INDEX {
                    return Ok(pos_slot as u32);
                }

                let num_direct_bits = (pos_slot >> 1) - 1;
                // dist starts as (2 | (posSlot & 1)), will be shifted bit-by-bit
                let dist_initial = (2 | (pos_slot & 1)) as u32;

                if pos_slot < K_END_POS_MODEL_INDEX {
                    // Reverse bit tree decode using PosDecoders
                    // The probs offset: PosDecoders + dist_base - posSlot
                    // where dist_base = dist_initial << num_direct_bits
                    let dist_base = dist_initial << num_direct_bits;
                    let probs_offset = OFF_POS_DECODERS + (dist_base as usize) - pos_slot;
                    self.dist_decode_state = Some(DistDecodeState {
                        len_state: dds.len_state,
                        phase: DistPhase::SpecPosBits {
                            dist: dist_base,
                            probs_offset,
                            m: 1,
                            symbol: 0,
                            i: 0,
                            num_bits: num_direct_bits,
                        },
                    });
                    return self.decode_distance(input, in_pos);
                }

                // posSlot >= kEndPosModelIndex: direct bits + align
                // Start with dist = (2 | (posSlot & 1))
                // Will shift bit-by-bit for (numDirectBits - kNumAlignBits) direct bits
                let direct_bits_count = num_direct_bits - K_NUM_ALIGN_BITS;
                self.dist_decode_state = Some(DistDecodeState {
                    len_state: dds.len_state,
                    phase: DistPhase::DirectBits {
                        dist: dist_initial,
                        num_bits: direct_bits_count,
                    },
                });
                return self.decode_distance(input, in_pos);
            }

            DistPhase::DirectBits { mut dist, mut num_bits } => {
                // Each direct bit: dist = (dist << 1) + bit
                while num_bits > 0 {
                    let (bit, consumed) = self.range_decoder.decode_direct_bit(
                        input,
                        *in_pos,
                    ).map_err(|_| {
                        self.dist_decode_state = Some(DistDecodeState {
                            len_state: dds.len_state,
                            phase: DistPhase::DirectBits { dist, num_bits },
                        });
                        RangeCoderStatus::NeedInput
                    })?;
                    *in_pos += consumed;
                    dist = (dist << 1) + bit;
                    num_bits -= 1;
                }
                // Now shift left by kNumAlignBits and decode align bits
                dist <<= K_NUM_ALIGN_BITS as u32;
                self.dist_decode_state = Some(DistDecodeState {
                    len_state: dds.len_state,
                    phase: DistPhase::AlignBits {
                        dist,
                        m: 1,
                        symbol: 0,
                        i: 0,
                    },
                });
                return self.decode_distance(input, in_pos);
            }

            DistPhase::AlignBits {
                mut dist,
                mut m,
                mut symbol,
                mut i,
            } => {
                // Reverse bit tree decode: 4 bits using AlignDecoder
                while i < K_NUM_ALIGN_BITS {
                    let (bit, consumed) = self.range_decoder.decode_bit(
                        &mut self.probs[OFF_ALIGN + m],
                        input,
                        *in_pos,
                    ).map_err(|_| {
                        self.dist_decode_state = Some(DistDecodeState {
                            len_state: dds.len_state,
                            phase: DistPhase::AlignBits { dist, m, symbol, i },
                        });
                        RangeCoderStatus::NeedInput
                    })?;
                    *in_pos += consumed;
                    m = (m << 1) + bit as usize;
                    symbol |= bit << i;
                    i += 1;
                }
                dist |= symbol;
                return Ok(dist);
            }

            DistPhase::SpecPosBits {
                dist,
                probs_offset,
                mut m,
                mut symbol,
                mut i,
                num_bits,
            } => {
                // Reverse bit tree decode using PosDecoders
                while i < num_bits {
                    let (bit, consumed) = self.range_decoder.decode_bit(
                        &mut self.probs[probs_offset + m],
                        input,
                        *in_pos,
                    ).map_err(|_| {
                        self.dist_decode_state = Some(DistDecodeState {
                            len_state: dds.len_state,
                            phase: DistPhase::SpecPosBits {
                                dist,
                                probs_offset,
                                m,
                                symbol,
                                i,
                                num_bits,
                            },
                        });
                        RangeCoderStatus::NeedInput
                    })?;
                    *in_pos += consumed;
                    m = (m << 1) + bit as usize;
                    symbol |= bit << i;
                    i += 1;
                }
                return Ok(dist + symbol);
            }
        }
    }

    fn start_copy_match(&mut self, dist: u32, len: usize) {
        let actual_len = if let Some(unpack) = self.unpack_size {
            let remaining = (unpack - self.decoded_size) as usize;
            len.min(remaining)
        } else {
            len
        };
        self.phase = DecodePhase::CopyMatch {
            dist,
            remaining: actual_len,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_properties_decode() {
        let props = LzmaProperties::from_byte(0).unwrap();
        assert_eq!(props.lc, 0);
        assert_eq!(props.lp, 0);
        assert_eq!(props.pb, 0);

        // Default LZMA: lc=3, lp=0, pb=2
        // byte = (2 * 5 + 0) * 9 + 3 = 93
        let props = LzmaProperties::from_byte(93).unwrap();
        assert_eq!(props.lc, 3);
        assert_eq!(props.lp, 0);
        assert_eq!(props.pb, 2);

        assert!(LzmaProperties::from_byte(225).is_none());
    }

    #[test]
    fn test_num_probs() {
        // lc=3, lp=0: 1847 + 768 * 8 = 1847 + 6144 = 7991
        // Actually: BASE_PROBS_SIZE + 0x300 * (1 << 3) = 1847 + 768 * 8 = 1847 + 6144 = 7991
        let n = num_probs(3, 0);
        assert_eq!(n, BASE_PROBS_SIZE + 0x300 * 8);
    }

    #[test]
    fn test_state_transitions() {
        assert_eq!(update_state_literal(0), 0);
        assert_eq!(update_state_literal(3), 0);
        assert_eq!(update_state_literal(4), 1);
        assert_eq!(update_state_literal(10), 4);

        assert_eq!(update_state_match(0), 7);
        assert_eq!(update_state_match(7), 10);

        assert_eq!(update_state_rep(0), 8);
        assert_eq!(update_state_rep(7), 11);

        assert_eq!(update_state_short_rep(0), 9);
        assert_eq!(update_state_short_rep(7), 11);
    }

    #[test]
    fn test_sliding_window_basic() {
        let mut w = SlidingWindow::new(8);
        assert!(w.is_empty());

        w.put_byte(b'A');
        assert!(!w.is_empty());
        assert_eq!(w.get_byte(1), b'A');

        w.put_byte(b'B');
        assert_eq!(w.get_byte(1), b'B');
        assert_eq!(w.get_byte(2), b'A');
    }

    #[test]
    fn test_sliding_window_wrap() {
        let mut w = SlidingWindow::new(K_DIC_MIN); // minimum 4096
        for i in 0..8192u32 {
            w.put_byte((i & 0xFF) as u8);
            let _ = w.drain_output(&mut [0u8; 1]);
        }
        // After 8192 bytes, window should be full and wrapped
        assert!(w.is_full);
        assert_eq!(w.get_byte(1), 0xFF); // last byte written: 8191 & 0xFF = 0xFF
    }

    #[test]
    fn test_sliding_window_checkpoint() {
        let mut w = SlidingWindow::new(K_DIC_MIN);
        for i in 0..100u32 {
            w.put_byte(i as u8);
        }
        let data = w.get_window_data();
        assert_eq!(data.len(), 100);
        assert_eq!(data[0], 0);
        assert_eq!(data[99], 99);
    }
}
