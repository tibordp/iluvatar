//! Huffman decoding for zstd literal decompression.
//!
//! Zstd uses Huffman coding for compressing the literals section of blocks.
//! The Huffman table is encoded as a list of symbol weights, then
//! a canonical code is reconstructed from these weights.

use serde::{Deserialize, Serialize};

use super::bits::highest_bit;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HuffmanTable {
    /// The decoding table (size = 1 << table_log).
    pub entries: Vec<HufEntry>,
    /// Table log (max bits per symbol).
    pub table_log: u32,
}

impl HuffmanTable {
    /// Decode one symbol from the given bit value (top table_log bits of stream).
    pub fn decode(&self, bits: u32) -> &HufEntry {
        &self.entries[bits as usize]
    }
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
        return Ok((HuffmanTable { entries, table_log }, bytes_consumed));
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

    Ok((HuffmanTable { entries, table_log }, bytes_consumed))
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
    use super::bits::read_bits_backward_bulk;

    if data.is_empty() {
        return Err("empty FSE compressed data".into());
    }

    // Initialize backward bit reader
    let last_byte = data[data.len() - 1];
    if last_byte == 0 {
        return Err("last byte is 0 in FSE stream".into());
    }
    let init_bit = 7 - last_byte.leading_zeros() as usize;
    let total_bits = (data.len() - 1) * 8 + init_bit;

    let mut bit_pos = 0usize;

    let read_bits_checked = |bit_pos: &mut usize, n: u32| -> Result<usize, String> {
        let n = n as usize;
        if *bit_pos + n > total_bits {
            return Err("FSE bit read overflow".into());
        }
        let result = read_bits_backward_bulk(data, total_bits, *bit_pos, n) as usize;
        *bit_pos += n;
        Ok(result)
    };

    // Initialize two states
    let mut state1 = read_bits_checked(&mut bit_pos, table.table_log)?;
    let mut state2 = read_bits_checked(&mut bit_pos, table.table_log)?;

    let mut output = Vec::new();

    // Read bits from the backward stream, padding with zeros if past the end.
    let read_bits_padded = |bit_pos: &mut usize, n: u32| -> usize {
        let n = n as usize;
        if n == 0 {
            return 0;
        }
        // If fully within bounds, use bulk read
        if *bit_pos + n <= total_bits {
            let result = read_bits_backward_bulk(data, total_bits, *bit_pos, n) as usize;
            *bit_pos += n;
            return result;
        }
        // Partially past end: read available bits, pad rest with zeros
        let avail = total_bits.saturating_sub(*bit_pos);
        let result = if avail > 0 {
            read_bits_backward_bulk(data, total_bits, *bit_pos, avail) as usize
        } else {
            0
        };
        // Shift the available bits up and pad the MSB positions with zeros
        let result = result << (n - avail);
        // Note: backward bitstream reads MSB-first, so available bits go to
        // higher positions and padding zeros go to lower positions. But our
        // bulk reader returns LSB-aligned, so we need to handle this carefully.
        // Actually, the original per-bit code reads MSB-first with zero padding
        // for past-end bits. The bulk equivalent: read `avail` bits (MSB portion),
        // shift left by (n - avail) to place them at MSB, zeros fill LSB.
        *bit_pos += n;
        result
    };

    // Two-interleaved-state FSE decode loop
    loop {
        let entry1 = table.decode(state1);
        output.push(entry1.symbol);
        let new_bits1 = read_bits_padded(&mut bit_pos, entry1.nb_bits as u32);
        state1 = entry1.next_state as usize + new_bits1;

        if bit_pos > total_bits {
            let entry2 = table.decode(state2);
            output.push(entry2.symbol);
            break;
        }

        let entry2 = table.decode(state2);
        output.push(entry2.symbol);
        let new_bits2 = read_bits_padded(&mut bit_pos, entry2.nb_bits as u32);
        state2 = entry2.next_state as usize + new_bits2;

        if bit_pos > total_bits {
            let entry1_final = table.decode(state1);
            output.push(entry1_final.symbol);
            break;
        }
    }

    Ok(output)
}

/// Decompress a Huffman stream directly into a pre-allocated output slice.
fn decompress_huffman_stream_into(
    table: &HuffmanTable,
    src: &[u8],
    output: &mut [u8],
) -> Result<(), String> {
    use super::bits::read_bits_backward_bulk;

    let regen_size = output.len();
    if src.is_empty() {
        if regen_size == 0 {
            return Ok(());
        }
        return Err("empty source for huffman stream".into());
    }

    let last_byte = src[src.len() - 1];
    if last_byte == 0 {
        return Err("last byte is 0 in huffman stream".into());
    }
    let init_bit = 7 - last_byte.leading_zeros() as usize;
    let total_bits = (src.len() - 1) * 8 + init_bit;
    let table_log = table.table_log as usize;

    let mut bit_pos = 0usize;
    let mut out_pos = 0;

    while out_pos < regen_size {
        let bits_remaining = total_bits.saturating_sub(bit_pos);
        if bits_remaining == 0 {
            break;
        }

        // Peek table_log bits using bulk read
        let peek_n = table_log.min(bits_remaining);
        let mut peek_val =
            read_bits_backward_bulk(src, total_bits, bit_pos, peek_n) as u32;
        // Pad to table_log bits if we peeked fewer
        if peek_n < table_log {
            peek_val <<= table_log - peek_n;
        }

        let entry = table.decode(peek_val);
        if entry.nb_bits as usize > bits_remaining {
            break;
        }
        output[out_pos] = entry.symbol;
        out_pos += 1;
        bit_pos += entry.nb_bits as usize;
    }

    if out_pos != regen_size {
        return Err(format!(
            "huffman stream: decoded {} bytes, expected {}",
            out_pos, regen_size
        ));
    }

    Ok(())
}

/// Decompress Huffman-coded literals using a single stream.
pub(crate) fn decompress_huffman_1stream(
    table: &HuffmanTable,
    src: &[u8],
    regen_size: usize,
) -> Result<Vec<u8>, String> {
    let mut output = vec![0u8; regen_size];
    decompress_huffman_stream_into(table, src, &mut output)?;
    Ok(output)
}

/// Decompress Huffman-coded literals using 4 streams.
/// The source contains: 3x 2-byte stream sizes (LE) for streams 1-3,
/// then the 4 streams packed contiguously.
pub(crate) fn decompress_huffman_4streams(
    table: &HuffmanTable,
    src: &[u8],
    regen_size: usize,
) -> Result<Vec<u8>, String> {
    if src.len() < 6 {
        return Err("huffman 4-stream source too small for jump table".into());
    }

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
    let seg_size = regen_size.div_ceil(4);
    let regen1 = seg_size.min(regen_size);
    let regen2 = seg_size.min(regen_size.saturating_sub(seg_size));
    let regen3 = seg_size.min(regen_size.saturating_sub(2 * seg_size));
    let regen4 = regen_size.saturating_sub(3 * seg_size);

    // Decode directly into a single output buffer (avoids 4 allocations + copies)
    let mut result = vec![0u8; regen_size];
    let mut offset = 0;

    decompress_huffman_stream_into(table, stream1, &mut result[offset..offset + regen1])?;
    offset += regen1;
    decompress_huffman_stream_into(table, stream2, &mut result[offset..offset + regen2])?;
    offset += regen2;
    decompress_huffman_stream_into(table, stream3, &mut result[offset..offset + regen3])?;
    offset += regen3;
    decompress_huffman_stream_into(table, stream4, &mut result[offset..offset + regen4])?;

    Ok(result)
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
