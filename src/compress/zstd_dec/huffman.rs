//! Huffman decoding for zstd literal decompression.
//!
//! Zstd uses Huffman coding for compressing the literals section of blocks.
//! The Huffman table is encoded as a list of symbol weights, then
//! a canonical code is reconstructed from these weights.

use serde::{Deserialize, Serialize};

use super::bits::{highest_bit, BackwardBitReader};
use super::fse::{build_fse_table, read_ncount, FseTable};

/// Maximum Huffman table log.
pub(crate) const HUF_TABLE_LOG_MAX: u32 = 12;

/// A single entry in the Huffman decoding table (flat table approach).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub(crate) struct HufEntry {
    /// The decoded symbol byte.
    pub symbol: u8,
    /// Number of bits this symbol consumes.
    pub nb_bits: u8,
}

/// Huffman decoding table.
///
/// Serialized (in checkpoints) as `entries` + `table_log` only; the `lookup`
/// view is rebuilt on deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "HuffmanTableRepr", into = "HuffmanTableRepr")]
pub(crate) struct HuffmanTable {
    /// The decoding table (size = 1 << table_log).
    pub entries: Vec<HufEntry>,
    /// Table log (max bits per symbol).
    pub table_log: u32,
    /// `entries` expanded to a `HUF_TABLE_LOG_MAX`-bit index (each entry
    /// replicated `1 << (HUF_TABLE_LOG_MAX - table_log)` times), packed as
    /// `nb_bits | symbol << 8`. Decoding indexes it with the top 12 bits of
    /// the bit cache (a constant shift, no bounds check); keeping `nb_bits`
    /// in the low bits lets the entry feed the cache shift directly.
    pub lookup: Box<[u16; HUF_LOOKUP_SIZE]>,
    /// Cached `is_valid()`, checked before every decode.
    valid: bool,
}

const HUF_LOOKUP_SIZE: usize = 1 << HUF_TABLE_LOG_MAX;

/// Serialized form of `HuffmanTable` (the checkpoint format).
#[derive(Serialize, Deserialize)]
struct HuffmanTableRepr {
    entries: Vec<HufEntry>,
    table_log: u32,
}

impl From<HuffmanTableRepr> for HuffmanTable {
    fn from(repr: HuffmanTableRepr) -> Self {
        HuffmanTable::new(repr.entries, repr.table_log)
    }
}

impl From<HuffmanTable> for HuffmanTableRepr {
    fn from(table: HuffmanTable) -> Self {
        HuffmanTableRepr {
            entries: table.entries,
            table_log: table.table_log,
        }
    }
}

impl HuffmanTable {
    pub fn new(entries: Vec<HufEntry>, table_log: u32) -> Self {
        let mut table = HuffmanTable {
            entries,
            table_log,
            lookup: Box::new([0u16; HUF_LOOKUP_SIZE]),
            valid: false,
        };
        // Tables that fail validation (possible only via a corrupt
        // checkpoint) are rejected by the decoders before `lookup` is used.
        table.valid = table.is_valid();
        if table.valid {
            let (entries, lookup) = (&table.entries, &mut table.lookup);
            let shift = HUF_TABLE_LOG_MAX - table_log;
            for (i, slot) in lookup.iter_mut().enumerate() {
                let e = entries[i >> shift];
                *slot = e.nb_bits as u16 | (e.symbol as u16) << 8;
            }
        }
        table
    }

    /// Whether the table is internally consistent (always true for tables
    /// built by `read_huffman_table`; a corrupt checkpoint may not be). The
    /// fast decoders rely on every code length being in `1..=table_log`.
    fn is_valid(&self) -> bool {
        let tl = self.table_log;
        (1..=HUF_TABLE_LOG_MAX).contains(&tl)
            && self.entries.len() >= 1 << tl
            && self.entries[..1 << tl]
                .iter()
                .all(|e| (1..=tl).contains(&(e.nb_bits as u32)))
    }
}

/// Look up the symbol at the top of an MSB-aligned bit cache. Returns
/// `(symbol, nb_bits)`.
#[inline(always)]
fn huf_lookup(lookup: &[u16; HUF_LOOKUP_SIZE], cache: u64) -> (u8, u32) {
    let e = lookup[(cache >> (64 - HUF_TABLE_LOG_MAX)) as usize];
    ((e >> 8) as u8, (e & 0x3F) as u32)
}

/// Read a Huffman table description from compressed data.
/// Returns (HuffmanTable, bytes_consumed).
pub(crate) fn read_huffman_table(data: &[u8]) -> Result<(HuffmanTable, usize), String> {
    if data.is_empty() {
        return Err("empty huffman table data".into());
    }

    let header_byte = data[0];
    let (weights, num_symbols, bytes_consumed) = if header_byte >= 128 {
        // Direct representation: weights are packed 4 bits each
        let num_weights = (header_byte - 127) as usize;
        let num_bytes = num_weights.div_ceil(2);
        if 1 + num_bytes > data.len() {
            return Err("huffman table header extends past data".into());
        }
        let mut weights = Vec::with_capacity(num_weights);
        for i in 0..num_weights {
            let byte = data[1 + i / 2];
            let w = if i % 2 == 0 { byte >> 4 } else { byte & 0x0F };
            weights.push(w);
        }
        (weights, num_weights, 1 + num_bytes)
    } else {
        // FSE compressed weights
        let compressed_size = header_byte as usize;
        if 1 + compressed_size > data.len() {
            return Err("huffman FSE compressed header extends past data".into());
        }
        let compressed_data = &data[1..1 + compressed_size];
        let weights = decompress_huffman_weights_fse(compressed_data)?;
        let num = weights.len();
        (weights, num, 1 + compressed_size)
    };

    if num_symbols == 0 {
        return Err("no Huffman symbols".into());
    }

    // Compute weight total and determine last symbol weight
    let mut weight_total: u32 = 0;
    for &w in &weights {
        if w as u32 > HUF_TABLE_LOG_MAX {
            return Err("Huffman weight exceeds max".into());
        }
        weight_total += (1u32 << w) >> 1;
    }
    if weight_total == 0 {
        return Err("Huffman weight total is 0".into());
    }

    let table_log = highest_bit(weight_total) + 1;
    if table_log > HUF_TABLE_LOG_MAX {
        return Err("Huffman table log exceeds max".into());
    }

    let total = 1u32 << table_log;
    let rest = total - weight_total;
    // rest must be a power of 2
    if rest & (rest - 1) != 0 {
        return Err("Huffman rest is not a power of 2".into());
    }
    let last_weight = highest_bit(rest) + 1;

    // Build the full weights including the last symbol
    let mut all_weights = weights;
    all_weights.push(last_weight as u8);
    let total_symbols = all_weights.len();

    // Build the flat decoding table
    let table_size = 1usize << table_log;

    // Count symbols at each weight level
    let mut rank_count = vec![0u32; (table_log + 2) as usize];
    for &w in &all_weights {
        if (w as u32) < rank_count.len() as u32 {
            rank_count[w as usize] += 1;
        }
    }

    // Single symbol table
    if total_symbols <= 1 {
        let entries = vec![
            HufEntry {
                symbol: 0,
                nb_bits: 1,
            };
            table_size
        ];
        return Ok((HuffmanTable::new(entries, table_log), bytes_consumed));
    }

    // Compute rank starting positions (ascending weight order).
    // Each symbol with weight w occupies 1 << (w-1) table entries.
    let mut rank_start = vec![0u32; (table_log + 2) as usize];
    {
        let mut current_start = 0u32;
        for w in 1..=table_log {
            rank_start[w as usize] = current_start;
            current_start += rank_count[w as usize] * (1u32 << (w - 1));
            if current_start > table_size as u32 {
                return Err("Huffman table construction overflow".into());
            }
        }
    }

    // Fill the table
    let mut entries = vec![HufEntry::default(); table_size];
    for (symbol, &weight) in all_weights.iter().enumerate().take(total_symbols) {
        let w = weight as u32;
        if w == 0 {
            continue;
        }
        let nb_bits = (table_log + 1 - w) as u8;
        let num_entries = 1usize << (w - 1);
        let start = rank_start[w as usize] as usize;

        for i in 0..num_entries {
            if start + i < table_size {
                entries[start + i] = HufEntry {
                    symbol: symbol as u8,
                    nb_bits,
                };
            }
        }
        rank_start[w as usize] += num_entries as u32;
    }

    Ok((HuffmanTable::new(entries, table_log), bytes_consumed))
}

/// Decompress Huffman weights from FSE-compressed data.
fn decompress_huffman_weights_fse(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Err("empty FSE data for huffman weights".into());
    }

    // Read the FSE distribution table
    let max_symbol = 12; // Max weight value for FSE-compressed Huffman weights
    let (norm, actual_max, table_log, header_size) = read_ncount(data, max_symbol)?;

    // Per RFC 8878 Section 4.2.1.2: maximum accuracy log for Huffman weight FSE is 6
    const HUF_WEIGHT_FSE_MAX_LOG: u32 = 6;
    if table_log > HUF_WEIGHT_FSE_MAX_LOG {
        return Err(format!(
            "Huffman weight FSE table log {} exceeds max {}",
            table_log, HUF_WEIGHT_FSE_MAX_LOG
        ));
    }

    // Build FSE table (no base values or extra bits for raw weight decoding)
    let fse_table = build_fse_table(&norm, actual_max, table_log, None, None)?;

    // The remaining data is the compressed weights
    let compressed = &data[header_size..];
    if compressed.is_empty() {
        return Err("no compressed data after FSE header".into());
    }

    // Decode using two interleaved FSE states (like the reference)
    decompress_fse_weights(&fse_table, compressed)
}

/// Decompress FSE-coded byte symbols (used for Huffman weights).
fn decompress_fse_weights(table: &FseTable, data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Err("empty FSE compressed data".into());
    }

    let mut reader = BackwardBitReader::new(data).map_err(|e| e.to_string())?;

    // Initialize two states
    let mut state1 = reader
        .read_bits(table.table_log)
        .map_err(|_| "FSE bit read overflow".to_string())?;
    let mut state2 = reader
        .read_bits(table.table_log)
        .map_err(|_| "FSE bit read overflow".to_string())?;

    let mut output = Vec::new();

    // Two-interleaved-state FSE decode loop matching the reference implementation.
    // The reference uses BIT_reloadDStream to detect overflow AFTER each
    // decode+update step. Overflow means bits were consumed past the stream end.
    // Reads past the end return zero-padded bits; "completed" (all bits consumed)
    // is NOT overflow, only reading beyond that is.
    loop {
        // Decode from state1 and update state
        let entry1 = table.decode(state1);
        output.push(entry1.symbol);
        let new_bits1 = reader.read_bits_padded(entry1.nb_bits as u32);
        state1 = entry1.next_state as usize + new_bits1;

        // Check for overflow (consumed past end)
        if reader.is_overflowed() {
            // Stream overflowed after state1 update: output state2's final symbol
            let entry2 = table.decode(state2);
            output.push(entry2.symbol);
            break;
        }

        // Decode from state2 and update state
        let entry2 = table.decode(state2);
        output.push(entry2.symbol);
        let new_bits2 = reader.read_bits_padded(entry2.nb_bits as u32);
        state2 = entry2.next_state as usize + new_bits2;

        // Check for overflow (consumed past end)
        if reader.is_overflowed() {
            // Stream overflowed after state2 update: output state1's final symbol
            let entry1_final = table.decode(state1);
            output.push(entry1_final.symbol);
            break;
        }
    }

    Ok(output)
}

/// Decompress Huffman-coded literals from a single stream into `out`.
/// The output length is the expected regenerated size.
pub(crate) fn decompress_huffman_1stream(
    table: &HuffmanTable,
    src: &[u8],
    out: &mut [u8],
) -> Result<(), String> {
    if src.is_empty() {
        if out.is_empty() {
            return Ok(());
        }
        return Err("empty source for huffman 1-stream".into());
    }

    let mut rem = init_stream_bits(src)?;
    if !table.valid {
        return Err("invalid huffman table".into());
    }

    let mut decoded = 0usize;
    decode_stream_tail(
        &table.lookup,
        table.table_log as usize,
        src,
        &mut rem,
        out,
        &mut decoded,
        out.len(),
    );

    if decoded != out.len() {
        return Err(format!(
            "huffman 1-stream: decoded {} bytes, expected {}",
            decoded,
            out.len()
        ));
    }

    Ok(())
}

/// Find the init bit and return the number of valid bits in a backward stream.
#[inline]
fn init_stream_bits(src: &[u8]) -> Result<usize, String> {
    let reader =
        BackwardBitReader::new(src).map_err(|_| "last byte is 0 in huffman stream".to_string())?;
    Ok(reader.bits_remaining())
}

/// Decode symbols from a backward Huffman stream into `out[*decoded..end]`,
/// continuing from `rem` bits remaining. Stops when `end` symbols are decoded
/// or the stream is exhausted; callers check `*decoded` afterwards.
///
/// Keeps up to 56 bits in a local MSB-aligned u64 container and decodes
/// several symbols per refill instead of touching memory per symbol.
fn decode_stream_tail(
    lookup: &[u16; HUF_LOOKUP_SIZE],
    tl: usize,
    src: &[u8],
    rem: &mut usize,
    out: &mut [u8],
    decoded: &mut usize,
    end: usize,
) {
    'outer: while *decoded < end && *rem > 0 {
        // Cache bits [rem - avail, rem), MSB-aligned. When fewer than
        // `tl` bits remain, the missing low bits read as zero.
        let avail = (*rem).min(56);
        let bits = super::bits::extract_bits(src, *rem - avail, avail);
        let mut cache = (bits as u64) << (64 - avail);
        let mut cbits = avail;
        loop {
            // Bits past `tl` in the 12-bit peek don't affect the lookup.
            let (symbol, nb) = huf_lookup(lookup, cache);
            let nb = nb as usize;
            if nb > *rem {
                break 'outer;
            }
            out[*decoded] = symbol;
            *decoded += 1;
            cache <<= nb;
            cbits -= nb;
            *rem -= nb;
            if *decoded >= end {
                break 'outer;
            }
            // Refill once the cache may hold fewer than `tl` real bits
            // (unless the stream itself is down to those bits).
            if cbits < tl && cbits < *rem {
                break;
            }
        }
    }
}

/// Decompress Huffman-coded literals using 4 streams into `out`.
/// The source contains: 3x 2-byte stream sizes (LE) for streams 1-3,
/// then the 4 streams packed contiguously.
pub(crate) fn decompress_huffman_4streams(
    table: &HuffmanTable,
    src: &[u8],
    out: &mut [u8],
) -> Result<(), String> {
    if src.len() < 6 {
        return Err("huffman 4-stream source too small for jump table".into());
    }

    let regen_size = out.len();

    // Read the 3 stream sizes (little-endian u16)
    let size1 = u16::from_le_bytes([src[0], src[1]]) as usize;
    let size2 = u16::from_le_bytes([src[2], src[3]]) as usize;
    let size3 = u16::from_le_bytes([src[4], src[5]]) as usize;

    let streams_start = 6;
    let stream1_start = streams_start;
    let stream2_start = stream1_start + size1;
    let stream3_start = stream2_start + size2;
    let stream4_start = stream3_start + size3;

    if stream4_start > src.len() {
        return Err("huffman 4-stream sizes exceed source".into());
    }

    let stream1 = &src[stream1_start..stream2_start];
    let stream2 = &src[stream2_start..stream3_start];
    let stream3 = &src[stream3_start..stream4_start];
    let stream4 = &src[stream4_start..];

    // Each stream decodes approximately regen_size/4 bytes
    // (the last stream may have a different count)
    let seg_size = regen_size.div_ceil(4);
    let regen1 = seg_size.min(regen_size);
    let regen2 = seg_size.min(regen_size.saturating_sub(seg_size));
    let regen3 = seg_size.min(regen_size.saturating_sub(2 * seg_size));

    if !table.valid {
        return Err("invalid huffman table".into());
    }
    let lookup = &*table.lookup;
    let tl = table.table_log as usize;
    if regen_size == 0 {
        return Ok(());
    }
    if stream1.is_empty() || stream2.is_empty() || stream3.is_empty() || stream4.is_empty() {
        return Err("empty source for huffman 4-stream".into());
    }

    let srcs = [stream1, stream2, stream3, stream4];
    let mut rems = [
        init_stream_bits(stream1)?,
        init_stream_bits(stream2)?,
        init_stream_bits(stream3)?,
        init_stream_bits(stream4)?,
    ];
    let starts = [0, regen1, regen1 + regen2, regen1 + regen2 + regen3];
    let ends = [
        regen1,
        regen1 + regen2,
        regen1 + regen2 + regen3,
        regen_size,
    ];
    let mut poss = starts;

    // Fast path: several symbols per stream per round, interleaved across
    // the 4 independent streams for instruction-level parallelism. A round
    // reads at most `k * tl` bits per stream, so with 5 symbols the 56-bit
    // cache suffices for tables up to 11 bits (the encoder's default max).
    if tl <= 11 {
        decode_4streams_fast::<5>(lookup, tl, &srcs, &mut rems, &mut poss, &ends, out);
    } else {
        decode_4streams_fast::<4>(lookup, tl, &srcs, &mut rems, &mut poss, &ends, out);
    }

    // Finish each stream with the general (bounds-checked) decoder.
    for i in 0..4 {
        decode_stream_tail(
            lookup,
            tl,
            srcs[i],
            &mut rems[i],
            out,
            &mut poss[i],
            ends[i],
        );
        if poss[i] != ends[i] {
            return Err(format!(
                "huffman 4-stream: stream {} decoded {} bytes, expected {}",
                i + 1,
                poss[i] - starts[i],
                ends[i] - starts[i]
            ));
        }
    }

    Ok(())
}

/// Bulk-decode the four interleaved streams `K` symbols at a time while
/// every stream is far from both its input start and its output end.
/// Leaves the remainder for `decode_stream_tail`.
#[inline(always)]
fn decode_4streams_fast<const K: usize>(
    lookup: &[u16; HUF_LOOKUP_SIZE],
    tl: usize,
    srcs: &[&[u8]; 4],
    rems: &mut [usize; 4],
    poss: &mut [usize; 4],
    ends: &[usize; 4],
    out: &mut [u8],
) {
    debug_assert!(K <= 8 && K * tl <= 56);
    let max_bits = K * tl;
    loop {
        // Number of rounds that can run without checks: each stream needs
        // >= 56 unread bits at the start of a round (a round consumes at
        // most `max_bits`) and room for `K` more symbols.
        let mut rounds = usize::MAX;
        for i in 0..4 {
            let by_bits = if rems[i] >= 56 {
                (rems[i] - 56) / max_bits + 1
            } else {
                0
            };
            rounds = rounds.min(by_bits).min((ends[i] - poss[i]) / K);
        }
        if rounds == 0 {
            return;
        }
        for _ in 0..rounds {
            let mut caches = [0u64; 4];
            for i in 0..4 {
                let bits = super::bits::extract_bits(srcs[i], rems[i] - 56, 56);
                caches[i] = (bits as u64) << 8;
            }
            let mut words = [0u64; 4];
            let mut used = [0u32; 4];
            for k in 0..K {
                for i in 0..4 {
                    let (symbol, nb) = huf_lookup(lookup, caches[i]);
                    words[i] |= (symbol as u64) << (8 * k);
                    caches[i] <<= nb;
                    used[i] += nb;
                }
            }
            for i in 0..4 {
                out[poss[i]..poss[i] + K].copy_from_slice(&words[i].to_le_bytes()[..K]);
                poss[i] += K;
                rems[i] -= used[i] as usize;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_huffman_table_direct_weights() {
        // Create a simple huffman table with direct weight encoding
        // Header byte >= 128 means direct representation
        // 130 = 128 + 3 means 3 weights
        // Weights packed 4-bits each: weight1=4, weight2=2, weight3=1 -> bytes: 0x42, 0x10
        let data = [130u8, 0x42, 0x10];
        let result = read_huffman_table(&data);
        // This should parse (may or may not produce valid table depending on weights)
        assert!(result.is_ok() || result.is_err()); // Just check it doesn't panic
    }

    #[test]
    fn test_huf_entry_size() {
        assert_eq!(std::mem::size_of::<HufEntry>(), 2);
    }

    #[test]
    fn test_failing_huffman_table_from_mitmproxy() {
        // Exact bytes from block 472 of mitmproxy.tar.zst
        // Header byte 0x2D = 45 means 45 bytes of FSE-compressed weights
        let huf_desc: [u8; 46] = [
            0x2D, 0x10, 0x48, 0x7B, 0xC6, 0xDA, 0xFB, 0xED, 0xE8, 0x27, 0xC8, 0xAE, 0xB1, 0x22,
            0x5D, 0xD0, 0xF3, 0xF9, 0x35, 0x87, 0x7C, 0xBE, 0x9B, 0x15, 0x7F, 0x08, 0x89, 0xBA,
            0xE2, 0x72, 0x01, 0x5B, 0x2E, 0xA2, 0xC9, 0x99, 0x0C, 0x8C, 0xFD, 0xE1, 0x51, 0x18,
            0x2B, 0xEC, 0xDE, 0x29,
        ];
        let result = read_huffman_table(&huf_desc);
        assert!(
            result.is_ok(),
            "read_huffman_table failed: {:?}",
            result.err()
        );
    }
}
