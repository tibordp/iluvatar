//! LZMA2 chunk framing decoder.
//!
//! LZMA2 wraps LZMA data in a series of chunks, each with a control byte
//! that indicates the chunk type. This module handles the framing protocol
//! and delegates actual LZMA decoding to the `LzmaDecoder`.
//!
//! All state is serializable for checkpointing.

use serde::{Deserialize, Serialize};

use super::decoder::{LzmaDecodeStatus, LzmaDecoder, LzmaProperties};

// ─── LZMA2 state machine ───────────────────────────────────────────

/// LZMA2 chunk parsing state.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Lzma2State {
    /// Expecting the control byte.
    Control,
    /// Reading unpack size byte 0.
    Unpack0,
    /// Reading unpack size byte 1.
    Unpack1,
    /// Reading pack size byte 0 (compressed chunks only).
    Pack0,
    /// Reading pack size byte 1.
    Pack1,
    /// Reading properties byte (when control indicates new properties).
    Prop,
    /// Processing chunk data (uncompressed or LZMA compressed).
    Data,
    /// Finished (control byte 0x00 seen).
    Finished,
    /// Error state.
    Error,
}

/// LZMA2 decode status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lzma2DecodeStatus {
    Continue,
    Finished,
    NeedInput,
}

/// Result of an LZMA2 decode step.
#[derive(Debug)]
pub struct Lzma2DecodeResult {
    pub bytes_consumed: usize,
    pub bytes_produced: usize,
    pub status: Lzma2DecodeStatus,
}

/// LZMA2 decoder. Wraps the LZMA decoder and handles chunk framing.
///
/// All state is serializable for checkpointing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lzma2Decoder {
    state: Lzma2State,
    control: u8,
    unpack_size: u32,
    pack_size: u32,
    decoder: LzmaDecoder,
    dict_size: u32,
    /// Whether state has been initialized at least once.
    state_initialized: bool,
    /// Whether properties have been set.
    props_set: bool,
    /// Track compressed bytes consumed in current chunk.
    chunk_in_consumed: u32,
    /// Track uncompressed bytes produced in current chunk.
    chunk_out_produced: u32,
}

impl Lzma2Decoder {
    /// Create a new LZMA2 decoder with the given dictionary size.
    pub fn new(dict_size: u32) -> Self {
        let dict_size = dict_size.max(1 << 12);
        // Start with default properties; they'll be set by the first chunk
        let props = LzmaProperties { lc: 0, lp: 0, pb: 0 };
        Self {
            state: Lzma2State::Control,
            control: 0,
            unpack_size: 0,
            pack_size: 0,
            decoder: LzmaDecoder::new(props, dict_size),
            dict_size,
            state_initialized: false,
            props_set: false,
            chunk_in_consumed: 0,
            chunk_out_produced: 0,
        }
    }

    /// Create from the LZMA2 dictionary size property byte.
    pub fn from_prop_byte(prop: u8) -> Option<Self> {
        if prop > 40 {
            return None;
        }
        let dict_size = if prop == 40 {
            0xFFFF_FFFF
        } else {
            (2u32 | ((prop as u32) & 1)) << ((prop as u32) / 2 + 11)
        };
        Some(Self::new(dict_size))
    }

    /// Get a reference to the inner LZMA decoder (for checkpointing).
    pub fn inner_decoder(&self) -> &LzmaDecoder {
        &self.decoder
    }

    /// Is the decoder in a finished state?
    pub fn is_finished(&self) -> bool {
        matches!(self.state, Lzma2State::Finished)
    }

    /// Decode from input, writing decompressed data to output.
    pub fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Lzma2DecodeResult {
        let mut in_pos = 0;
        let mut out_pos = 0;

        // First, drain any pending output from the LZMA decoder
        if self.decoder.window.pending_len() > 0 {
            let n = self.decoder.window.drain_output(&mut output[out_pos..]);
            out_pos += n;
            if self.decoder.window.pending_len() > 0 || out_pos >= output.len() {
                return Lzma2DecodeResult {
                    bytes_consumed: 0,
                    bytes_produced: out_pos,
                    status: if matches!(self.state, Lzma2State::Finished) {
                        Lzma2DecodeStatus::Finished
                    } else {
                        Lzma2DecodeStatus::Continue
                    },
                };
            }
        }

        loop {
            match self.state {
                Lzma2State::Finished => {
                    return Lzma2DecodeResult {
                        bytes_consumed: in_pos,
                        bytes_produced: out_pos,
                        status: Lzma2DecodeStatus::Finished,
                    };
                }
                Lzma2State::Error => {
                    return Lzma2DecodeResult {
                        bytes_consumed: in_pos,
                        bytes_produced: out_pos,
                        status: Lzma2DecodeStatus::Finished,
                    };
                }
                Lzma2State::Control => {
                    if in_pos >= input.len() {
                        return Lzma2DecodeResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Lzma2DecodeStatus::NeedInput,
                        };
                    }
                    self.control = input[in_pos];
                    in_pos += 1;

                    if self.control == 0x00 {
                        self.state = Lzma2State::Finished;
                        continue;
                    }

                    if self.control < 0x80 {
                        // Uncompressed
                        if self.control == 0x01 {
                            // Reset dict
                            self.decoder.reset_dict();
                            self.state_initialized = false;
                        } else if self.control == 0x02 {
                            // No reset
                            if !self.state_initialized {
                                self.state = Lzma2State::Error;
                                continue;
                            }
                        } else {
                            self.state = Lzma2State::Error;
                            continue;
                        }
                        self.unpack_size = 0;
                        self.state = Lzma2State::Unpack0;
                    } else {
                        // LZMA compressed
                        let need_init_level = if self.control >= 0xE0 {
                            // Reset state + props + dict
                            4
                        } else if self.control >= 0xC0 {
                            // Reset state + props
                            3
                        } else if self.control >= 0xA0 {
                            // Reset state
                            2
                        } else {
                            // No reset
                            1
                        };

                        if need_init_level >= 4 {
                            self.decoder.reset_dict();
                        }

                        // Validate: if state hasn't been initialized yet, we need level >= 2
                        // and props need to be set
                        if !self.state_initialized && need_init_level < 3 {
                            self.state = Lzma2State::Error;
                            continue;
                        }

                        self.unpack_size = ((self.control & 0x1F) as u32) << 16;
                        self.state = Lzma2State::Unpack0;
                    }
                }

                Lzma2State::Unpack0 => {
                    if in_pos >= input.len() {
                        return Lzma2DecodeResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Lzma2DecodeStatus::NeedInput,
                        };
                    }
                    self.unpack_size |= (input[in_pos] as u32) << 8;
                    in_pos += 1;
                    self.state = Lzma2State::Unpack1;
                }

                Lzma2State::Unpack1 => {
                    if in_pos >= input.len() {
                        return Lzma2DecodeResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Lzma2DecodeStatus::NeedInput,
                        };
                    }
                    self.unpack_size |= input[in_pos] as u32;
                    self.unpack_size += 1;
                    in_pos += 1;

                    if self.control < 0x80 {
                        // Uncompressed chunk - go to data directly
                        self.chunk_out_produced = 0;
                        self.state = Lzma2State::Data;
                    } else {
                        self.state = Lzma2State::Pack0;
                    }
                }

                Lzma2State::Pack0 => {
                    if in_pos >= input.len() {
                        return Lzma2DecodeResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Lzma2DecodeStatus::NeedInput,
                        };
                    }
                    self.pack_size = (input[in_pos] as u32) << 8;
                    in_pos += 1;
                    self.state = Lzma2State::Pack1;
                }

                Lzma2State::Pack1 => {
                    if in_pos >= input.len() {
                        return Lzma2DecodeResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Lzma2DecodeStatus::NeedInput,
                        };
                    }
                    self.pack_size |= input[in_pos] as u32;
                    self.pack_size += 1;
                    in_pos += 1;

                    if self.control & 0x40 != 0 {
                        // Has properties
                        self.state = Lzma2State::Prop;
                    } else {
                        // No new properties
                        if !self.props_set {
                            self.state = Lzma2State::Error;
                            continue;
                        }
                        self.prepare_lzma_chunk(false);
                        self.state = Lzma2State::Data;
                    }
                }

                Lzma2State::Prop => {
                    if in_pos >= input.len() {
                        return Lzma2DecodeResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Lzma2DecodeStatus::NeedInput,
                        };
                    }
                    let prop_byte = input[in_pos];
                    in_pos += 1;

                    if let Some(props) = LzmaProperties::from_byte(prop_byte) {
                        if props.lc + props.lp > 4 {
                            self.state = Lzma2State::Error;
                            continue;
                        }
                        self.decoder.reset_state_and_props(props);
                        self.props_set = true;
                        self.state_initialized = true;
                        self.prepare_lzma_chunk(true);
                        self.state = Lzma2State::Data;
                    } else {
                        self.state = Lzma2State::Error;
                    }
                }

                Lzma2State::Data => {
                    if self.control < 0x80 {
                        // Uncompressed data: copy input directly to window and output
                        let remaining_unpack = self.unpack_size - self.chunk_out_produced;
                        if remaining_unpack == 0 {
                            self.state = Lzma2State::Control;
                            continue;
                        }
                        let available_in = input.len() - in_pos;
                        let available_out = output.len() - out_pos;
                        if available_in == 0 {
                            return Lzma2DecodeResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: Lzma2DecodeStatus::NeedInput,
                            };
                        }
                        let to_copy = (remaining_unpack as usize)
                            .min(available_in)
                            .min(available_out);
                        if to_copy == 0 {
                            // Output full
                            return Lzma2DecodeResult {
                                bytes_consumed: in_pos,
                                bytes_produced: out_pos,
                                status: Lzma2DecodeStatus::Continue,
                            };
                        }
                        // Copy to window and output
                        for i in 0..to_copy {
                            self.decoder.window.put_byte(input[in_pos + i]);
                        }
                        let n = self.decoder.window.drain_output(&mut output[out_pos..]);
                        in_pos += to_copy;
                        out_pos += n;
                        self.chunk_out_produced += to_copy as u32;
                        if self.chunk_out_produced >= self.unpack_size {
                            self.state = Lzma2State::Control;
                            self.state_initialized = true;
                        }
                        continue;
                    }

                    // LZMA compressed data
                    let remaining_pack = self.pack_size - self.chunk_in_consumed;
                    let remaining_unpack = self.unpack_size - self.chunk_out_produced;

                    if remaining_unpack == 0 {
                        // All output produced; skip any remaining packed bytes
                        // that the LZMA range coder didn't consume.
                        if remaining_pack > 0 {
                            let can_skip = (input.len() - in_pos).min(remaining_pack as usize);
                            in_pos += can_skip;
                            self.chunk_in_consumed += can_skip as u32;
                            if self.chunk_in_consumed < self.pack_size {
                                return Lzma2DecodeResult {
                                    bytes_consumed: in_pos,
                                    bytes_produced: out_pos,
                                    status: Lzma2DecodeStatus::NeedInput,
                                };
                            }
                        }
                        self.state = Lzma2State::Control;
                        continue;
                    }

                    // Feed available input to LZMA decoder
                    let available_in = (input.len() - in_pos).min(remaining_pack as usize);
                    let lzma_input = &input[in_pos..in_pos + available_in];
                    let available_out = (output.len() - out_pos).min(remaining_unpack as usize);

                    if available_out == 0 {
                        // Output buffer full, need to return
                        return Lzma2DecodeResult {
                            bytes_consumed: in_pos,
                            bytes_produced: out_pos,
                            status: Lzma2DecodeStatus::Continue,
                        };
                    }

                    let result = self.decoder.decode(lzma_input, &mut output[out_pos..out_pos + available_out]);
                    in_pos += result.bytes_consumed;
                    out_pos += result.bytes_produced;
                    self.chunk_in_consumed += result.bytes_consumed as u32;
                    self.chunk_out_produced += result.bytes_produced as u32;

                    match result.status {
                        LzmaDecodeStatus::NeedInput => {
                            if self.chunk_in_consumed >= self.pack_size {
                                // All packed data consumed
                                if self.chunk_out_produced >= self.unpack_size {
                                    self.state = Lzma2State::Control;
                                } else {
                                    // Data error: packed data exhausted before unpack complete
                                    self.state = Lzma2State::Error;
                                }
                            } else if available_in == 0 {
                                return Lzma2DecodeResult {
                                    bytes_consumed: in_pos,
                                    bytes_produced: out_pos,
                                    status: Lzma2DecodeStatus::NeedInput,
                                };
                            }
                            // Otherwise loop to feed more
                            continue;
                        }
                        LzmaDecodeStatus::Continue => {
                            if result.bytes_consumed == 0 && result.bytes_produced == 0 {
                                if self.chunk_in_consumed >= self.pack_size
                                    && self.chunk_out_produced >= self.unpack_size
                                {
                                    self.state = Lzma2State::Control;
                                    continue;
                                }
                                // Need either more input or more output space
                                if available_in == 0 {
                                    return Lzma2DecodeResult {
                                        bytes_consumed: in_pos,
                                        bytes_produced: out_pos,
                                        status: Lzma2DecodeStatus::NeedInput,
                                    };
                                }
                                return Lzma2DecodeResult {
                                    bytes_consumed: in_pos,
                                    bytes_produced: out_pos,
                                    status: Lzma2DecodeStatus::Continue,
                                };
                            }
                            // Loop back; the top-of-Data check handles the
                            // case where unpack is done but packed bytes remain.
                            continue;
                        }
                        LzmaDecodeStatus::FinishedWithMark | LzmaDecodeStatus::FinishedWithoutMark => {
                            // LZMA decoder finished (produced all unpack_size bytes
                            // or hit an end marker). Skip any remaining packed bytes
                            // that the LZMA range coder didn't consume — the range
                            // coder can leave trailing bytes because it only reads
                            // ahead as needed.
                            let remaining_pack = self.pack_size - self.chunk_in_consumed;
                            if remaining_pack > 0 {
                                let can_skip = (input.len() - in_pos).min(remaining_pack as usize);
                                in_pos += can_skip;
                                self.chunk_in_consumed += can_skip as u32;
                                if self.chunk_in_consumed < self.pack_size {
                                    // Still have packed bytes to skip but input
                                    // is exhausted; stay in Data state and come
                                    // back when more input is available.
                                    return Lzma2DecodeResult {
                                        bytes_consumed: in_pos,
                                        bytes_produced: out_pos,
                                        status: Lzma2DecodeStatus::NeedInput,
                                    };
                                }
                            }
                            self.state = Lzma2State::Control;
                            continue;
                        }
                    }
                }
            }
        }
    }

    fn prepare_lzma_chunk(&mut self, props_reset: bool) {
        // For LZMA chunks, set up the decoder
        let need_state_reset = self.control >= 0xA0;
        if need_state_reset && !props_reset {
            self.decoder.reset_state();
        }
        self.state_initialized = true;
        // Set unpack size for the LZMA decoder and reset per-chunk counters
        self.decoder.set_unpack_size(Some(self.unpack_size as u64));
        self.decoder.decoded_size = 0;
        self.decoder.rc_initialized = false;
        // Reset the decode phase to start fresh for this chunk
        self.decoder.phase = super::decoder::DecodePhase::NewSymbol;
        self.decoder.len_decode_state = None;
        self.decoder.dist_decode_state = None;
        self.chunk_in_consumed = 0;
        self.chunk_out_produced = 0;

    }

    /// Get checkpoint state (all serializable state).
    pub fn get_state(&self) -> Lzma2DecoderState {
        Lzma2DecoderState {
            state: match &self.state {
                Lzma2State::Control => 0,
                Lzma2State::Unpack0 => 1,
                Lzma2State::Unpack1 => 2,
                Lzma2State::Pack0 => 3,
                Lzma2State::Pack1 => 4,
                Lzma2State::Prop => 5,
                Lzma2State::Data => 6,
                Lzma2State::Finished => 7,
                Lzma2State::Error => 8,
            },
            control: self.control,
            unpack_size: self.unpack_size,
            pack_size: self.pack_size,
            decoder: self.decoder.clone(),
            dict_size: self.dict_size,
            state_initialized: self.state_initialized,
            props_set: self.props_set,
            chunk_in_consumed: self.chunk_in_consumed,
            chunk_out_produced: self.chunk_out_produced,
        }
    }

    /// Restore from checkpoint state.
    pub fn restore_state(&mut self, state: &Lzma2DecoderState) {
        self.state = match state.state {
            0 => Lzma2State::Control,
            1 => Lzma2State::Unpack0,
            2 => Lzma2State::Unpack1,
            3 => Lzma2State::Pack0,
            4 => Lzma2State::Pack1,
            5 => Lzma2State::Prop,
            6 => Lzma2State::Data,
            7 => Lzma2State::Finished,
            _ => Lzma2State::Error,
        };
        self.control = state.control;
        self.unpack_size = state.unpack_size;
        self.pack_size = state.pack_size;
        self.decoder = state.decoder.clone();
        self.dict_size = state.dict_size;
        self.state_initialized = state.state_initialized;
        self.props_set = state.props_set;
        self.chunk_in_consumed = state.chunk_in_consumed;
        self.chunk_out_produced = state.chunk_out_produced;
    }
}

/// Serializable LZMA2 decoder state for checkpointing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lzma2DecoderState {
    pub state: u8,
    pub control: u8,
    pub unpack_size: u32,
    pub pack_size: u32,
    pub decoder: LzmaDecoder,
    pub dict_size: u32,
    pub state_initialized: bool,
    pub props_set: bool,
    pub chunk_in_consumed: u32,
    pub chunk_out_produced: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_prop_byte() {
        let dec = Lzma2Decoder::from_prop_byte(0).unwrap();
        assert_eq!(dec.dict_size, 2 << 11); // 4096

        let dec = Lzma2Decoder::from_prop_byte(40).unwrap();
        assert_eq!(dec.dict_size, 0xFFFF_FFFF);

        assert!(Lzma2Decoder::from_prop_byte(41).is_none());
    }

    #[test]
    fn test_end_marker() {
        // A minimal LZMA2 stream: just the end marker (0x00)
        let mut dec = Lzma2Decoder::new(1 << 16);
        let input = [0x00u8];
        let mut output = [0u8; 64];
        let result = dec.decode(&input, &mut output);
        assert_eq!(result.bytes_consumed, 1);
        assert_eq!(result.bytes_produced, 0);
        assert_eq!(result.status, Lzma2DecodeStatus::Finished);
    }

    #[test]
    fn test_state_serialization() {
        let dec = Lzma2Decoder::new(1 << 16);
        let state = dec.get_state();
        let serialized = bincode::serialize(&state).unwrap();
        let state2: Lzma2DecoderState = bincode::deserialize(&serialized).unwrap();
        assert_eq!(state2.dict_size, 1 << 16);
    }
}
