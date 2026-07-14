//! Sequence decoding and execution for zstd.
//!
//! Each compressed block contains a sequences section that describes how to
//! reconstruct the output from literals and back-references. Each sequence
//! is a triplet (literal_length, offset, match_length).

use super::bits::SeqBitReader;
use super::block::BlockDecoderState;
use super::fse::{
    build_fse_table, build_rle_fse_table, read_ncount, FseTable, LL_BASE, LL_BITS, LL_FSE_LOG,
    MAX_LL, MAX_ML, MAX_OFF, ML_BASE, ML_BITS, ML_FSE_LOG, OFF_FSE_LOG, OF_BASE, OF_BITS,
};

/// Compression mode for symbol types in the sequences section.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum SymbolCompressionMode {
    Predefined = 0,
    Rle = 1,
    FseCompressed = 2,
    Repeat = 3,
}

impl SymbolCompressionMode {
    pub fn from_u8(val: u8) -> Result<Self, String> {
        match val {
            0 => Ok(SymbolCompressionMode::Predefined),
            1 => Ok(SymbolCompressionMode::Rle),
            2 => Ok(SymbolCompressionMode::FseCompressed),
            3 => Ok(SymbolCompressionMode::Repeat),
            _ => Err(format!("invalid symbol compression mode: {}", val)),
        }
    }
}

/// Parse the sequences section header, updating the FSE tables stored in
/// `state` in place. Returns `(num_sequences, bytes_consumed)`.
///
/// When the block declares zero sequences the header stops after the count
/// byte and the previously-used tables in `state` are left untouched.
pub(crate) fn parse_sequences_header(
    data: &[u8],
    state: &mut BlockDecoderState,
) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("empty sequences section".into());
    }

    let mut pos = 0;

    // Number of sequences
    let first_byte = data[pos] as usize;
    pos += 1;
    let num_sequences;
    if first_byte == 0 {
        return Ok((0, pos));
    } else if first_byte < 128 {
        num_sequences = first_byte;
    } else if first_byte == 255 {
        if pos + 2 > data.len() {
            return Err("sequences header truncated".into());
        }
        num_sequences = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize + 0x7F00;
        pos += 2;
    } else {
        // 128..254
        if pos >= data.len() {
            return Err("sequences header truncated".into());
        }
        num_sequences = ((first_byte - 128) << 8) + data[pos] as usize;
        pos += 1;
    }

    if num_sequences == 0 {
        return Ok((0, pos));
    }

    // Symbol compression modes byte
    if pos >= data.len() {
        return Err("sequences header truncated at modes byte".into());
    }
    let modes_byte = data[pos];
    pos += 1;

    // The spec says the bottom 2 bits must be zero (Reserved)
    if modes_byte & 3 != 0 {
        return Err("reserved bits in sequence modes byte are not zero".into());
    }

    let ll_mode = SymbolCompressionMode::from_u8((modes_byte >> 6) & 3)?;
    let of_mode = SymbolCompressionMode::from_u8((modes_byte >> 4) & 3)?;
    let ml_mode = SymbolCompressionMode::from_u8((modes_byte >> 2) & 3)?;

    build_seq_table(
        ll_mode,
        data,
        MAX_LL,
        LL_FSE_LOG,
        &LL_BASE,
        &LL_BITS,
        super::block::default_ll_table(),
        &mut state.ll_table,
        &mut pos,
    )?;

    build_seq_table(
        of_mode,
        data,
        MAX_OFF,
        OFF_FSE_LOG,
        &OF_BASE,
        &OF_BITS,
        super::block::default_of_table(),
        &mut state.of_table,
        &mut pos,
    )?;

    build_seq_table(
        ml_mode,
        data,
        MAX_ML,
        ML_FSE_LOG,
        &ML_BASE,
        &ML_BITS,
        super::block::default_ml_table(),
        &mut state.ml_table,
        &mut pos,
    )?;

    Ok((num_sequences, pos))
}

/// Set `table` according to the block's compression mode for one symbol type.
/// `pos` indexes into `data` and is advanced past any table description bytes.
#[allow(clippy::too_many_arguments)]
fn build_seq_table(
    mode: SymbolCompressionMode,
    data: &[u8],
    max_symbol: u32,
    max_log: u32,
    base_values: &[u32],
    nb_add_bits: &[u8],
    default_table: &FseTable,
    table: &mut Option<FseTable>,
    pos: &mut usize,
) -> Result<(), String> {
    let data = &data[*pos..];
    match mode {
        SymbolCompressionMode::Predefined => {
            *table = Some(default_table.clone());
            Ok(())
        }
        SymbolCompressionMode::Rle => {
            if data.is_empty() {
                return Err("RLE mode but no data for symbol".into());
            }
            let symbol = data[0];
            if symbol as u32 > max_symbol {
                return Err(format!("RLE symbol {} exceeds max {}", symbol, max_symbol));
            }
            *pos += 1;
            *table = Some(build_rle_fse_table(
                symbol,
                Some(base_values),
                Some(nb_add_bits),
            ));
            Ok(())
        }
        SymbolCompressionMode::FseCompressed => {
            let (norm, actual_max, table_log, header_size) = read_ncount(data, max_symbol)?;
            if table_log > max_log {
                return Err(format!(
                    "FSE table log {} exceeds max {}",
                    table_log, max_log
                ));
            }
            *table = Some(build_fse_table(
                &norm,
                actual_max,
                table_log,
                Some(base_values),
                Some(nb_add_bits),
            )?);
            *pos += header_size;
            Ok(())
        }
        SymbolCompressionMode::Repeat => {
            if table.is_none() {
                return Err("Repeat mode but no previous table".into());
            }
            Ok(())
        }
    }
}

/// Decode all sequences from the bitstream data and execute them, appending
/// the reconstructed block output to `output`.
///
/// `output` holds the decoding history: bytes before `output.len()` at entry
/// are the window from previous blocks. `max_back` limits how far before the
/// block start a match may reference (i.e. `min(history_len, window_size)`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn decode_and_execute_sequences(
    data: &[u8],
    num_sequences: usize,
    ll_table: &FseTable,
    of_table: &FseTable,
    ml_table: &FseTable,
    rep_offsets: &mut [u32; 3],
    literals: &[u8],
    output: &mut Vec<u8>,
    max_back: usize,
) -> Result<(), String> {
    if num_sequences == 0 {
        output.extend_from_slice(literals);
        return Ok(());
    }
    if data.is_empty() {
        return Err("empty sequence bitstream data".into());
    }

    let block_start = output.len();
    debug_assert!(max_back <= block_start);
    let mut lit_pos = 0usize;

    // A zstd block regenerates at most 128 KiB; reserving upfront keeps the
    // copy fast paths below from triggering reallocation checks mid-loop.
    output.reserve(128 * 1024 + 32);

    let mut reader = SeqBitReader::new(data)?;

    // Initialize FSE states
    let mut ll_state = reader
        .read(ll_table.table_log as usize)
        .map_err(|_| "init LL state: not enough bits".to_string())?;
    let mut of_state = reader
        .read(of_table.table_log as usize)
        .map_err(|_| "init OF state: not enough bits".to_string())?;
    let mut ml_state = reader
        .read(ml_table.table_log as usize)
        .map_err(|_| "init ML state: not enough bits".to_string())?;

    let ll_entries = &ll_table.entries[..];
    let of_entries = &of_table.entries[..];
    let ml_entries = &ml_table.entries[..];

    for i in 0..num_sequences {
        let is_last = i == num_sequences - 1;

        // Read values from current states
        let of_entry = of_entries[of_state];
        let ll_entry = ll_entries[ll_state];
        let ml_entry = ml_entries[ml_state];

        // Compute Offset_Value per RFC 8878 Section 3.1.1.3.2.1.1:
        //   if (code > 0) Offset_Value = (1 << code) + readNBits(code)
        //   else          Offset_Value = 1
        let of_code = of_entry.symbol as u32;
        let offset_value = if of_code == 0 {
            1usize
        } else {
            let extra = reader
                .read(of_code as usize)
                .map_err(|_| "offset extra bits: not enough bits".to_string())?;
            (1usize << of_code) + extra
        };

        // Read match length extra bits (MSB-first from backward bitstream)
        let match_length = ml_entry.base_value as usize
            + reader
                .read(ml_entry.nb_additional_bits as usize)
                .map_err(|_| "ML extra bits: not enough bits".to_string())?;

        // Read literal length extra bits (MSB-first from backward bitstream)
        let literal_length = ll_entry.base_value as usize
            + reader
                .read(ll_entry.nb_additional_bits as usize)
                .map_err(|_| "LL extra bits: not enough bits".to_string())?;

        // Resolve offset (handle repeat offsets per RFC 8878 Section 3.1.1.5)
        let offset = resolve_offset(offset_value, literal_length, rep_offsets)?;

        // Execute: copy literals
        if literal_length > 0 {
            if lit_pos + literal_length > literals.len() {
                return Err(format!(
                    "sequence {} literal length {} exceeds available literals (at {}, have {})",
                    i,
                    literal_length,
                    lit_pos,
                    literals.len()
                ));
            }
            // Short literal runs dominate; a fixed-size 16-byte copy compiles
            // to two load/store pairs instead of a memmove call.
            if literal_length <= 16 && lit_pos + 16 <= literals.len() {
                let chunk: [u8; 16] = literals[lit_pos..lit_pos + 16].try_into().unwrap();
                let keep = output.len() + literal_length;
                output.extend_from_slice(&chunk);
                output.truncate(keep);
            } else {
                output.extend_from_slice(&literals[lit_pos..lit_pos + literal_length]);
            }
            lit_pos += literal_length;
        }

        // Execute: copy match
        if match_length > 0 {
            let out_len = output.len();
            // History available: bytes produced in this block plus up to
            // max_back bytes of window before the block start.
            if offset > (out_len - block_start) + max_back {
                return Err(format!(
                    "sequence {} offset {} exceeds available history ({} output + {} window)",
                    i,
                    offset,
                    out_len - block_start,
                    max_back
                ));
            }
            // Fast path for short non-overlapping matches (same trick).
            if match_length <= 16 && offset >= 16 {
                let start = out_len - offset;
                let chunk: [u8; 16] = output[start..start + 16].try_into().unwrap();
                output.extend_from_slice(&chunk);
                output.truncate(out_len + match_length);
            } else {
                copy_match(output, offset, match_length);
            }
        }

        // Update FSE states (but not for the last sequence)
        if !is_last {
            let ll_new_bits = reader
                .read(ll_entry.nb_bits as usize)
                .map_err(|_| "LL state bits: not enough bits".to_string())?;
            ll_state = ll_entry.next_state as usize + ll_new_bits;

            let ml_new_bits = reader
                .read(ml_entry.nb_bits as usize)
                .map_err(|_| "ML state bits: not enough bits".to_string())?;
            ml_state = ml_entry.next_state as usize + ml_new_bits;

            let of_new_bits = reader
                .read(of_entry.nb_bits as usize)
                .map_err(|_| "OF state bits: not enough bits".to_string())?;
            of_state = of_entry.next_state as usize + of_new_bits;
        }
    }

    // Remaining literals after all sequences
    if lit_pos < literals.len() {
        output.extend_from_slice(&literals[lit_pos..]);
    }

    Ok(())
}

/// Append `match_length` bytes copied from `offset` bytes back in `output`.
/// Handles overlapping copies (offset < match_length) with the standard
/// pattern-replication approach; callers must ensure `offset <= output.len()`.
#[inline]
fn copy_match(output: &mut Vec<u8>, offset: usize, match_length: usize) {
    let start = output.len() - offset;
    if offset >= match_length {
        // Non-overlapping: single memcpy.
        output.extend_from_within(start..start + match_length);
    } else if offset == 1 {
        // Run of a single byte.
        let b = output[start];
        output.resize(output.len() + match_length, b);
    } else {
        // Overlapping: repeatedly copy the (growing) region starting at
        // `start`; each pass at least doubles the copied span.
        let mut copied = 0;
        while copied < match_length {
            let chunk = (output.len() - start).min(match_length - copied);
            output.extend_from_within(start..start + chunk);
            copied += chunk;
        }
    }
}

/// Resolve the offset value, handling repeat offsets.
fn resolve_offset(
    offset_raw: usize,
    literal_length: usize,
    rep_offsets: &mut [u32; 3],
) -> Result<usize, String> {
    // Offset values 1, 2, 3 are repeat offsets (adjusted by ll==0)
    // Offset > 3 is a real offset (value - 3)
    if offset_raw > 3 {
        // New offset
        let offset = offset_raw - 3;
        // Shift repeat offsets
        rep_offsets[2] = rep_offsets[1];
        rep_offsets[1] = rep_offsets[0];
        rep_offsets[0] = offset as u32;
        Ok(offset)
    } else if offset_raw == 0 {
        // Should not happen with valid encoding
        Err("offset code 0 is invalid".into())
    } else {
        // Repeat offset
        let ll0 = literal_length == 0;
        let actual_offset = if !ll0 {
            // Normal repeat offset behavior
            match offset_raw {
                1 => {
                    // rep_offsets[0] unchanged
                    rep_offsets[0] as usize
                }
                2 => {
                    rep_offsets.swap(0, 1);
                    rep_offsets[0] as usize
                }
                3 => {
                    let off = rep_offsets[2];
                    rep_offsets[2] = rep_offsets[1];
                    rep_offsets[1] = rep_offsets[0];
                    rep_offsets[0] = off;
                    off as usize
                }
                _ => unreachable!(),
            }
        } else {
            // When literal_length == 0, offset codes shift by 1
            match offset_raw {
                1 => {
                    // Use rep_offsets[1] (which becomes new rep_offsets[0])
                    rep_offsets.swap(0, 1);
                    rep_offsets[0] as usize
                }
                2 => {
                    let off = rep_offsets[2];
                    rep_offsets[2] = rep_offsets[1];
                    rep_offsets[1] = rep_offsets[0];
                    rep_offsets[0] = off;
                    off as usize
                }
                3 => {
                    // rep_offsets[0] - 1
                    let off = rep_offsets[0].saturating_sub(1);
                    if off == 0 {
                        return Err("repeat offset - 1 would be 0".into());
                    }
                    rep_offsets[2] = rep_offsets[1];
                    rep_offsets[1] = rep_offsets[0];
                    rep_offsets[0] = off;
                    off as usize
                }
                _ => unreachable!(),
            }
        };

        if actual_offset == 0 {
            return Err("resolved offset is 0".into());
        }
        Ok(actual_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_offset_new() {
        let mut rep = [1u32, 4, 8];
        let off = resolve_offset(100, 5, &mut rep).unwrap();
        assert_eq!(off, 97); // 100 - 3
        assert_eq!(rep[0], 97);
        assert_eq!(rep[1], 1);
        assert_eq!(rep[2], 4);
    }

    #[test]
    fn test_resolve_offset_repeat1() {
        let mut rep = [10u32, 4, 8];
        let off = resolve_offset(1, 5, &mut rep).unwrap(); // ll > 0
        assert_eq!(off, 10); // rep[0]
        assert_eq!(rep[0], 10);
    }

    #[test]
    fn test_resolve_offset_repeat2() {
        let mut rep = [10u32, 20, 8];
        let off = resolve_offset(2, 5, &mut rep).unwrap();
        assert_eq!(off, 20); // rep[1]
        assert_eq!(rep[0], 20);
        assert_eq!(rep[1], 10);
    }

    #[test]
    fn test_resolve_offset_repeat1_ll0() {
        let mut rep = [10u32, 20, 30];
        let off = resolve_offset(1, 0, &mut rep).unwrap(); // ll == 0
        assert_eq!(off, 20); // rep[1] when ll==0
        assert_eq!(rep[0], 20);
        assert_eq!(rep[1], 10);
    }

    #[test]
    fn test_copy_match_simple() {
        // "abcd", copy 3 bytes from offset 4 -> "abcdabc"
        let mut output = b"abcd".to_vec();
        copy_match(&mut output, 4, 3);
        assert_eq!(output, b"abcdabc");
    }

    #[test]
    fn test_copy_match_overlapping() {
        // "a", copy 4 bytes from offset 1 -> "aaaaa"
        let mut output = b"a".to_vec();
        copy_match(&mut output, 1, 4);
        assert_eq!(output, b"aaaaa");
    }

    #[test]
    fn test_copy_match_overlapping_pattern() {
        // "ab", copy 7 bytes from offset 2 -> "ababababa"
        let mut output = b"ab".to_vec();
        copy_match(&mut output, 2, 7);
        assert_eq!(output, b"ababababa");

        // Period-3 pattern with a long replication.
        let mut output = b"xyz".to_vec();
        copy_match(&mut output, 3, 100);
        for (i, &b) in output.iter().enumerate() {
            assert_eq!(b, b"xyz"[i % 3]);
        }
    }
}
