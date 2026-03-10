//! Sequence decoding and execution for zstd.
//!
//! Each compressed block contains a sequences section that describes how to
//! reconstruct the output from literals and back-references. Each sequence
//! is a triplet (literal_length, offset, match_length).

use super::bits::BackwardBitReader;
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

/// A decoded sequence (literal_length, offset, match_length).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sequence {
    pub literal_length: usize,
    pub offset: usize,
    pub match_length: usize,
}

/// Parsed sequences header: number of sequences and the three FSE tables.
pub(crate) struct SequencesHeader {
    pub num_sequences: usize,
    pub ll_table: FseTable,
    pub of_table: FseTable,
    pub ml_table: FseTable,
    pub bytes_consumed: usize,
}

/// Parse the sequences section header and build FSE tables.
/// `prev_ll`, `prev_of`, `prev_ml` are previously used tables (for Repeat mode).
pub(crate) fn parse_sequences_header(
    data: &[u8],
    prev_ll: Option<&FseTable>,
    prev_of: Option<&FseTable>,
    prev_ml: Option<&FseTable>,
    default_ll: &FseTable,
    default_of: &FseTable,
    default_ml: &FseTable,
) -> Result<SequencesHeader, String> {
    if data.is_empty() {
        return Err("empty sequences section".into());
    }

    let mut pos = 0;

    // Number of sequences
    let first_byte = data[pos] as usize;
    pos += 1;
    let num_sequences;
    if first_byte == 0 {
        return Ok(SequencesHeader {
            num_sequences: 0,
            ll_table: default_ll.clone(),
            of_table: default_of.clone(),
            ml_table: default_ml.clone(),
            bytes_consumed: pos,
        });
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
        return Ok(SequencesHeader {
            num_sequences: 0,
            ll_table: default_ll.clone(),
            of_table: default_of.clone(),
            ml_table: default_ml.clone(),
            bytes_consumed: pos,
        });
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

    // Build LL table
    let ll_table = build_seq_table(
        ll_mode,
        &data[pos..],
        MAX_LL,
        LL_FSE_LOG,
        &LL_BASE,
        &LL_BITS,
        default_ll,
        prev_ll,
        &mut pos,
    )?;

    // Build OF table
    let of_table = build_seq_table(
        of_mode,
        &data[pos..],
        MAX_OFF,
        OFF_FSE_LOG,
        &OF_BASE,
        &OF_BITS,
        default_of,
        prev_of,
        &mut pos,
    )?;

    // Build ML table
    let ml_table = build_seq_table(
        ml_mode,
        &data[pos..],
        MAX_ML,
        ML_FSE_LOG,
        &ML_BASE,
        &ML_BITS,
        default_ml,
        prev_ml,
        &mut pos,
    )?;

    Ok(SequencesHeader {
        num_sequences,
        ll_table,
        of_table,
        ml_table,
        bytes_consumed: pos,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_seq_table(
    mode: SymbolCompressionMode,
    data: &[u8],
    max_symbol: u32,
    max_log: u32,
    base_values: &[u32],
    nb_add_bits: &[u8],
    default_table: &FseTable,
    prev_table: Option<&FseTable>,
    pos: &mut usize,
) -> Result<FseTable, String> {
    match mode {
        SymbolCompressionMode::Predefined => Ok(default_table.clone()),
        SymbolCompressionMode::Rle => {
            if data.is_empty() {
                return Err("RLE mode but no data for symbol".into());
            }
            let symbol = data[0];
            if symbol as u32 > max_symbol {
                return Err(format!("RLE symbol {} exceeds max {}", symbol, max_symbol));
            }
            *pos += 1;
            Ok(build_rle_fse_table(
                symbol,
                Some(base_values),
                Some(nb_add_bits),
            ))
        }
        SymbolCompressionMode::FseCompressed => {
            let (norm, actual_max, table_log, header_size) = read_ncount(data, max_symbol)?;
            if table_log > max_log {
                return Err(format!(
                    "FSE table log {} exceeds max {}",
                    table_log, max_log
                ));
            }
            let table = build_fse_table(
                &norm,
                actual_max,
                table_log,
                Some(base_values),
                Some(nb_add_bits),
            )?;
            *pos += header_size;
            Ok(table)
        }
        SymbolCompressionMode::Repeat => prev_table
            .cloned()
            .ok_or_else(|| "Repeat mode but no previous table".into()),
    }
}

/// Decode all sequences from the bitstream data.
pub(crate) fn decode_sequences(
    data: &[u8],
    num_sequences: usize,
    ll_table: &FseTable,
    of_table: &FseTable,
    ml_table: &FseTable,
    rep_offsets: &mut [u32; 3],
) -> Result<Vec<Sequence>, String> {
    if num_sequences == 0 {
        return Ok(Vec::new());
    }
    if data.is_empty() {
        return Err("empty sequence bitstream data".into());
    }

    let mut reader = BackwardBitReader::new(data)?;

    // Initialize FSE states
    let mut ll_state = reader
        .read_bits(ll_table.table_log)
        .map_err(|e| format!("init LL state: {}", e))?;
    let mut of_state = reader
        .read_bits(of_table.table_log)
        .map_err(|e| format!("init OF state: {}", e))?;
    let mut ml_state = reader
        .read_bits(ml_table.table_log)
        .map_err(|e| format!("init ML state: {}", e))?;

    let mut sequences = Vec::with_capacity(num_sequences);

    for i in 0..num_sequences {
        let is_last = i == num_sequences - 1;

        // Read values from current states
        let of_entry = of_table.decode(of_state);
        let ll_entry = ll_table.decode(ll_state);
        let ml_entry = ml_table.decode(ml_state);

        // Compute Offset_Value per RFC 8878 Section 3.1.1.3.2.1.1:
        //   if (code > 0) Offset_Value = (1 << code) + readNBits(code)
        //   else          Offset_Value = 1
        let of_code = of_entry.symbol as u32;
        let offset_value = if of_code == 0 {
            1usize
        } else {
            let extra = reader
                .read_bits(of_code)
                .map_err(|e| format!("offset extra bits: {}", e))?;
            (1usize << of_code) + extra
        };

        // Read match length extra bits (MSB-first from backward bitstream)
        let ml_bits = ml_entry.nb_additional_bits;
        let match_length = if ml_bits > 0 {
            let extra = reader
                .read_bits(ml_bits as u32)
                .map_err(|e| format!("ML extra bits: {}", e))?;
            ml_entry.base_value as usize + extra
        } else {
            ml_entry.base_value as usize
        };

        // Read literal length extra bits (MSB-first from backward bitstream)
        let ll_bits = ll_entry.nb_additional_bits;
        let literal_length = if ll_bits > 0 {
            let extra = reader
                .read_bits(ll_bits as u32)
                .map_err(|e| format!("LL extra bits: {}", e))?;
            ll_entry.base_value as usize + extra
        } else {
            ll_entry.base_value as usize
        };

        // Resolve offset (handle repeat offsets per RFC 8878 Section 3.1.1.5)
        let offset = resolve_offset(offset_value, literal_length, rep_offsets)?;

        sequences.push(Sequence {
            literal_length,
            offset,
            match_length,
        });

        // Update FSE states (but not for the last sequence)
        if !is_last {
            let ll_nb = ll_entry.nb_bits;
            let ml_nb = ml_entry.nb_bits;
            let of_nb = of_entry.nb_bits;

            let ll_new_bits = reader
                .read_bits(ll_nb as u32)
                .map_err(|e| format!("LL state bits: {}", e))?;
            ll_state = ll_entry.next_state as usize + ll_new_bits;

            let ml_new_bits = reader
                .read_bits(ml_nb as u32)
                .map_err(|e| format!("ML state bits: {}", e))?;
            ml_state = ml_entry.next_state as usize + ml_new_bits;

            let of_new_bits = reader
                .read_bits(of_nb as u32)
                .map_err(|e| format!("OF state bits: {}", e))?;
            of_state = of_entry.next_state as usize + of_new_bits;
        }
    }

    Ok(sequences)
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

/// Execute sequences: copy literals and back-references to produce output.
pub(crate) fn execute_sequences(
    sequences: &[Sequence],
    literals: &[u8],
    window: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), String> {
    let mut lit_pos = 0;

    for (i, seq) in sequences.iter().enumerate() {
        // Copy literal_length bytes from literals
        if seq.literal_length > 0 {
            if lit_pos + seq.literal_length > literals.len() {
                return Err(format!(
                    "sequence {} literal length {} exceeds available literals (at {}, have {})",
                    i,
                    seq.literal_length,
                    lit_pos,
                    literals.len()
                ));
            }
            output.extend_from_slice(&literals[lit_pos..lit_pos + seq.literal_length]);
            lit_pos += seq.literal_length;
        }

        // Copy match_length bytes from offset back in the output/window
        if seq.match_length > 0 {
            let output_len = output.len();
            if seq.offset > output_len + window.len() {
                return Err(format!(
                    "sequence {} offset {} exceeds available history ({} output + {} window)",
                    i,
                    seq.offset,
                    output_len,
                    window.len()
                ));
            }

            let mut remaining = seq.match_length;
            output.reserve(remaining);

            // Phase 1: Copy from window if offset reaches into history
            if seq.offset > output_len {
                let window_bytes = seq.offset - output_len;
                let window_start = window.len() - window_bytes;
                let from_window = remaining.min(window_bytes);
                output.extend_from_slice(&window[window_start..window_start + from_window]);
                remaining -= from_window;
            }

            // Phase 2: Copy from output using bulk operations
            if remaining > 0 {
                if seq.offset >= remaining {
                    // Non-overlapping: single bulk copy
                    let start = output.len() - seq.offset;
                    output.extend_from_within(start..start + remaining);
                } else {
                    // Overlapping: copy in expanding chunks (doubling strategy)
                    let start = output.len() - seq.offset;
                    let initial = remaining.min(seq.offset);
                    output.extend_from_within(start..start + initial);
                    remaining -= initial;

                    let mut copied = initial;
                    while remaining > 0 {
                        let chunk = remaining.min(copied);
                        let start = output.len() - copied;
                        output.extend_from_within(start..start + chunk);
                        remaining -= chunk;
                        copied += chunk;
                    }
                }
            }
        }
    }

    // Remaining literals after all sequences
    if lit_pos < literals.len() {
        output.extend_from_slice(&literals[lit_pos..]);
    }

    Ok(())
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
    fn test_execute_simple() {
        let sequences = vec![Sequence {
            literal_length: 3,
            offset: 0,
            match_length: 0,
        }];
        let literals = b"abc";
        let mut output = Vec::new();
        // offset 0, match_length 0 is fine (no match copy)
        execute_sequences(&sequences, literals, &[], &mut output).unwrap();
        assert_eq!(output, b"abc");
    }

    #[test]
    fn test_execute_with_match() {
        // First write "abcd", then copy 3 bytes from offset 4 (= "abc")
        let sequences = vec![
            Sequence {
                literal_length: 4,
                offset: 0,
                match_length: 0,
            },
            Sequence {
                literal_length: 0,
                offset: 4,
                match_length: 3,
            },
        ];
        let literals = b"abcd";
        let mut output = Vec::new();
        execute_sequences(&sequences, literals, &[], &mut output).unwrap();
        assert_eq!(output, b"abcdabc");
    }

    #[test]
    fn test_execute_overlapping_match() {
        // Write "a", then copy 4 bytes from offset 1 -> "aaaa"
        let sequences = vec![Sequence {
            literal_length: 1,
            offset: 1,
            match_length: 4,
        }];
        let literals = b"a";
        let mut output = Vec::new();
        execute_sequences(&sequences, literals, &[], &mut output).unwrap();
        assert_eq!(output, b"aaaaa");
    }
}
