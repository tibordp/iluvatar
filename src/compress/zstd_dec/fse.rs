//! FSE (Finite State Entropy) table decoding for zstd.
//!
//! FSE is the entropy coding system used by zstd for sequence headers
//! (literal lengths, match lengths, and offsets). This module handles:
//! - Reading normalized count distributions from compressed headers
//! - Building FSE decoding tables from distributions
//! - The predefined (default) FSE tables for LL, ML, and OF

use serde::{Deserialize, Serialize};

use super::bits::{highest_bit, ForwardBitReader};

/// Maximum FSE accuracy log values per symbol type.
pub(crate) const LL_FSE_LOG: u32 = 9;
pub(crate) const ML_FSE_LOG: u32 = 9;
pub(crate) const OFF_FSE_LOG: u32 = 8;
pub(crate) const MAX_FSE_LOG: u32 = 9; // max of the above

/// Maximum symbol values.
pub(crate) const MAX_LL: u32 = 35;
pub(crate) const MAX_ML: u32 = 52;
pub(crate) const MAX_OFF: u32 = 31;

/// Minimum FSE table log (from spec).
pub(crate) const FSE_MIN_TABLE_LOG: u32 = 5;

/// An entry in an FSE decoding table.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub(crate) struct FseEntry {
    /// Symbol this entry decodes to.
    pub symbol: u8,
    /// Number of bits to read for next state transition.
    pub nb_bits: u8,
    /// Base value for next state computation.
    pub next_state: u16,
    /// Number of additional bits to read for value.
    pub nb_additional_bits: u8,
    /// Base value for the decoded value.
    pub base_value: u32,
}

/// A complete FSE decoding table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FseTable {
    pub table_log: u32,
    pub entries: Vec<FseEntry>,
}

impl FseTable {
    /// Decode: given current state, return the entry and produce the symbol.
    pub fn decode(&self, state: usize) -> &FseEntry {
        &self.entries[state]
    }
}

/// Read an FSE normalized count distribution from a bitstream.
/// Returns (normalized_counts, max_symbol_value, table_log, bytes_consumed).
pub(crate) fn read_ncount(
    data: &[u8],
    max_symbol: u32,
) -> Result<(Vec<i16>, u32, u32, usize), String> {
    if data.len() < 4 {
        // Pad to at least 8 bytes for safe reading
        let mut padded = vec![0u8; 8];
        padded[..data.len()].copy_from_slice(data);
        return read_ncount_inner(&padded, max_symbol, data.len());
    }
    read_ncount_inner(data, max_symbol, data.len())
}

fn read_ncount_inner(
    data: &[u8],
    max_symbol: u32,
    actual_len: usize,
) -> Result<(Vec<i16>, u32, u32, usize), String> {
    let mut reader = ForwardBitReader::new(data);

    // Read table log: bottom 4 bits + FSE_MIN_TABLE_LOG
    let raw = reader
        .read_bits(4)
        .map_err(|e| format!("reading table log: {}", e))?;
    let table_log = raw + FSE_MIN_TABLE_LOG;
    if table_log > MAX_FSE_LOG {
        return Err(format!(
            "table log {} exceeds max {}",
            table_log, MAX_FSE_LOG
        ));
    }

    let max_sv1 = max_symbol + 1;
    let mut normalized = vec![0i16; max_sv1 as usize];

    let mut remaining = (1i32 << table_log) + 1;
    let mut threshold = 1i32 << table_log;
    let mut nb_bits = table_log + 1;
    let mut charnum: u32 = 0;
    let mut previous0 = false;

    loop {
        if previous0 {
            // Count runs of zero-probability symbols using 2-bit codes.
            // Each 0b11 means 3 more zeros, terminated by 0b00/0b01/0b10.
            loop {
                let bits = reader
                    .read_bits(2)
                    .map_err(|e| format!("reading zero run: {}", e))?;
                if bits == 3 {
                    charnum += 3;
                    if charnum >= max_sv1 {
                        break;
                    }
                } else {
                    charnum += bits;
                    break;
                }
            }
            if charnum >= max_sv1 {
                break;
            }
        }

        // Read the count value
        let max_val = (2 * threshold - 1) - remaining;

        let bits_avail = nb_bits - 1;
        let low = reader
            .read_bits(bits_avail)
            .map_err(|e| format!("reading count: {}", e))? as i32;

        let count;
        if low < max_val {
            count = low;
            // nb_bits - 1 bits consumed (already read)
        } else {
            // Need one more bit
            let extra = reader
                .read_bits(1)
                .map_err(|e| format!("reading extra count bit: {}", e))?
                as i32;
            let value = low + (extra << bits_avail as i32);
            if value >= threshold {
                count = value - max_val;
            } else {
                count = value;
            }
        }

        let count = count - 1; // extra accuracy

        if count >= 0 {
            remaining -= count;
        } else {
            // count == -1: "less than 1" probability
            remaining += count; // remaining -= 1 (since count == -1)
        }

        if charnum < max_sv1 {
            normalized[charnum as usize] = count as i16;
        }
        charnum += 1;
        previous0 = count == 0;

        if remaining <= 1 {
            break;
        }
        if remaining < threshold {
            nb_bits = highest_bit(remaining as u32) + 1;
            threshold = 1 << (nb_bits - 1);
        }
        if charnum >= max_sv1 {
            break;
        }
    }

    if remaining != 1 {
        return Err(format!(
            "FSE NCount corruption: remaining={} (expected 1)",
            remaining
        ));
    }
    if charnum > max_sv1 {
        return Err(format!(
            "FSE NCount: charnum {} exceeds max {}",
            charnum, max_sv1
        ));
    }

    let bytes_consumed = reader.bytes_consumed();
    if bytes_consumed > actual_len {
        return Err("FSE NCount extends beyond available data".into());
    }

    let actual_max_symbol = if charnum > 0 { charnum - 1 } else { 0 };

    Ok((normalized, actual_max_symbol, table_log, bytes_consumed))
}

/// Build an FSE decoding table from normalized counts.
///
/// For sequence tables (LL/ML/OF), each entry also stores base_value and
/// nb_additional_bits. For plain FSE tables (used in Huffman weight decoding),
/// these are zero.
pub(crate) fn build_fse_table(
    normalized: &[i16],
    max_symbol: u32,
    table_log: u32,
    base_values: Option<&[u32]>,
    nb_add_bits: Option<&[u8]>,
) -> Result<FseTable, String> {
    let table_size = 1u32 << table_log;
    let mut entries = vec![FseEntry::default(); table_size as usize];
    let max_sv1 = max_symbol as usize + 1;

    // Phase 1: Place low-probability (-1) symbols at the high end
    let mut high_threshold = table_size as usize - 1;
    let mut symbol_next = vec![0u16; max_sv1];

    for s in 0..max_sv1 {
        if normalized[s] == -1 {
            entries[high_threshold].symbol = s as u8;
            high_threshold = high_threshold.wrapping_sub(1);
            symbol_next[s] = 1;
        } else {
            debug_assert!(normalized[s] >= 0);
            symbol_next[s] = normalized[s] as u16;
        }
    }

    // Phase 2: Spread symbols across the table
    let table_mask = table_size - 1;
    let step = (table_size >> 1) + (table_size >> 3) + 3; // FSE_TABLESTEP

    let mut position: u32 = 0;
    for (s, &count) in normalized.iter().enumerate().take(max_sv1) {
        for _ in 0..count.max(0) {
            entries[position as usize].symbol = s as u8;
            position = (position + step) & table_mask;
            while position > high_threshold as u32 {
                position = (position + step) & table_mask;
            }
        }
    }
    if position != 0 {
        return Err("FSE table building error: position should reach 0".into());
    }

    // Phase 3: Build decoding entries (nbBits, nextState, baseValue, nbAdditionalBits)
    for entry in entries.iter_mut().take(table_size as usize) {
        let symbol = entry.symbol as usize;
        let next_state = symbol_next[symbol] as u32;
        symbol_next[symbol] += 1;
        let nb_bits = table_log - highest_bit(next_state);
        entry.nb_bits = nb_bits as u8;
        entry.next_state = ((next_state << nb_bits) - table_size) as u16;
        if let Some(bv) = base_values {
            if symbol < bv.len() {
                entry.base_value = bv[symbol];
            }
        }
        if let Some(nb) = nb_add_bits {
            if symbol < nb.len() {
                entry.nb_additional_bits = nb[symbol];
            }
        }
    }

    Ok(FseTable { table_log, entries })
}

/// Build a single-entry (RLE) FSE table for a given symbol.
pub(crate) fn build_rle_fse_table(
    symbol: u8,
    base_values: Option<&[u32]>,
    nb_add_bits: Option<&[u8]>,
) -> FseTable {
    let base_value = base_values
        .and_then(|bv| bv.get(symbol as usize).copied())
        .unwrap_or(0);
    let nb_additional_bits = nb_add_bits
        .and_then(|nb| nb.get(symbol as usize).copied())
        .unwrap_or(0);
    FseTable {
        table_log: 0,
        entries: vec![FseEntry {
            symbol,
            nb_bits: 0,
            next_state: 0,
            nb_additional_bits,
            base_value,
        }],
    }
}

// ============================================================================
// Predefined (default) FSE tables
// ============================================================================

/// Literal Length baseline values.
pub(crate) const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];

/// Literal Length extra bits.
pub(crate) const LL_BITS: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];

/// Match Length baseline values.
pub(crate) const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];

/// Match Length extra bits.
pub(crate) const ML_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

/// Offset baseline values: OF_base[n] = (1 << n) - 1 for n >= 1, OF_base[0] = 0.
pub(crate) const OF_BASE: [u32; 32] = [
    0, 1, 1, 5, 0xD, 0x1D, 0x3D, 0x7D, 0xFD, 0x1FD, 0x3FD, 0x7FD, 0xFFD, 0x1FFD, 0x3FFD, 0x7FFD,
    0xFFFD, 0x1FFFD, 0x3FFFD, 0x7FFFD, 0xFFFFD, 0x1FFFFD, 0x3FFFFD, 0x7FFFFD, 0xFFFFFD, 0x1FFFFFD,
    0x3FFFFFD, 0x7FFFFFD, 0xFFFFFFD, 0x1FFFFFFD, 0x3FFFFFFD, 0x7FFFFFFD,
];

/// Offset extra bits: OF_bits[n] = n.
pub(crate) const OF_BITS: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

// Default normalized distributions (from zstd_internal.h).

const LL_DEFAULT_NORM: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
const LL_DEFAULT_LOG: u32 = 6;

const ML_DEFAULT_NORM: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const ML_DEFAULT_LOG: u32 = 6;

const OF_DEFAULT_NORM: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
const OF_DEFAULT_LOG: u32 = 5;

/// Build the default (predefined) Literal Length FSE table.
pub(crate) fn build_default_ll_table() -> FseTable {
    build_fse_table(
        &LL_DEFAULT_NORM,
        MAX_LL,
        LL_DEFAULT_LOG,
        Some(&LL_BASE),
        Some(&LL_BITS),
    )
    .expect("default LL table should always build")
}

/// Build the default (predefined) Match Length FSE table.
pub(crate) fn build_default_ml_table() -> FseTable {
    build_fse_table(
        &ML_DEFAULT_NORM,
        MAX_ML,
        ML_DEFAULT_LOG,
        Some(&ML_BASE),
        Some(&ML_BITS),
    )
    .expect("default ML table should always build")
}

/// Build the default (predefined) Offset FSE table.
pub(crate) fn build_default_of_table() -> FseTable {
    build_fse_table(
        &OF_DEFAULT_NORM,
        (OF_DEFAULT_NORM.len() as u32) - 1, // max symbol = 28
        OF_DEFAULT_LOG,
        Some(&OF_BASE),
        Some(&OF_BITS),
    )
    .expect("default OF table should always build")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_default_ll_table() {
        let table = build_default_ll_table();
        assert_eq!(table.table_log, 6);
        assert_eq!(table.entries.len(), 64);
        // Verify some known entries from the reference
        // Entry 0: symbol for state 0
        // We just verify it builds without error and has correct size
    }

    #[test]
    fn test_build_default_ml_table() {
        let table = build_default_ml_table();
        assert_eq!(table.table_log, 6);
        assert_eq!(table.entries.len(), 64);
    }

    #[test]
    fn test_build_default_of_table() {
        let table = build_default_of_table();
        assert_eq!(table.table_log, 5);
        assert_eq!(table.entries.len(), 32);
    }

    #[test]
    fn test_build_rle_table() {
        let table = build_rle_fse_table(5, Some(&LL_BASE), Some(&LL_BITS));
        assert_eq!(table.table_log, 0);
        assert_eq!(table.entries.len(), 1);
        assert_eq!(table.entries[0].symbol, 5);
        assert_eq!(table.entries[0].base_value, LL_BASE[5]);
        assert_eq!(table.entries[0].nb_additional_bits, LL_BITS[5]);
    }

    #[test]
    fn test_default_ll_table_matches_reference() {
        // Verify the default LL table matches the reference C implementation
        let table = build_default_ll_table();

        // From the reference: entry at state 0 should have next_state=0, nbAddBits=0, nbBits=4, baseVal=0
        // The reference table is: { 0, 0, 4, 0 } for state 0
        let e0 = &table.entries[0];
        assert_eq!(e0.nb_bits, 4);
        assert_eq!(e0.base_value, 0);
        assert_eq!(e0.nb_additional_bits, 0);

        // State 1: { 16, 0, 4, 0 } -> next_state=16, nbAddBits=0, nbBits=4, baseVal=0
        let e1 = &table.entries[1];
        assert_eq!(e1.nb_bits, 4);
        assert_eq!(e1.base_value, 0);
        assert_eq!(e1.next_state, 16);
    }

    #[test]
    fn test_default_of_table_matches_reference() {
        let table = build_default_of_table();

        // From the reference: state 0: {0, 0, 5, 0}
        let e0 = &table.entries[0];
        assert_eq!(e0.nb_bits, 5);
        assert_eq!(e0.base_value, 0);
        assert_eq!(e0.nb_additional_bits, 0);
    }

    #[test]
    fn test_default_ml_table_matches_reference() {
        let table = build_default_ml_table();

        // From reference: state 0: {0, 0, 6, 3}
        let e0 = &table.entries[0];
        assert_eq!(e0.nb_bits, 6);
        assert_eq!(e0.base_value, 3);
        assert_eq!(e0.nb_additional_bits, 0);
    }
}
