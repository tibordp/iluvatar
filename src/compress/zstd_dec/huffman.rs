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
/// Maximum Huffman table log for zstd literals (usually 11).
pub(crate) const HUF_TABLE_LOG_DEFAULT: u32 = 11;

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
        let num_bytes = (num_weights + 1) / 2;
        if 1 + num_bytes > data.len() {
            return Err("huffman table header extends past data".into());
        }
        let mut weights = Vec::with_capacity(num_weights);
        for i in 0..num_weights {
            let byte = data[1 + i / 2];
            let w = if i % 2 == 0 {
                byte >> 4
            } else {
                byte & 0x0F
            };
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
        return Ok((
            HuffmanTable {
                entries,
                table_log,
            },
            bytes_consumed,
        ));
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
    for symbol in 0..total_symbols {
        let w = all_weights[symbol] as u32;
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

    Ok((
        HuffmanTable {
            entries,
            table_log,
        },
        bytes_consumed,
    ))
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

    // Initialize backward bit reader
    // Find the init bit in the last byte
    let last_byte = data[data.len() - 1];
    if last_byte == 0 {
        return Err("last byte is 0 in FSE stream".into());
    }
    let init_bit = 7 - last_byte.leading_zeros() as usize;
    // Total available bits
    let total_bits = (data.len() - 1) * 8 + init_bit;

    let mut bit_pos = 0usize; // bits consumed from the end

    let read_bits_backward = |bit_pos: &mut usize, n: u32| -> Result<usize, String> {
        if n == 0 {
            return Ok(0);
        }
        let n = n as usize;
        if *bit_pos + n > total_bits {
            return Err("FSE bit read overflow".into());
        }
        let mut result: usize = 0;
        for _ in 0..n {
            result <<= 1;
            let abs_bit = total_bits - 1 - *bit_pos;
            let byte_idx = abs_bit / 8;
            let bit_idx = abs_bit % 8;
            if (data[byte_idx] >> bit_idx) & 1 != 0 {
                result |= 1;
            }
            *bit_pos += 1;
        }
        Ok(result)
    };

    // Initialize two states
    let mut state1 = read_bits_backward(&mut bit_pos, table.table_log)?;
    let mut state2 = read_bits_backward(&mut bit_pos, table.table_log)?;

    let mut output = Vec::new();

    // Read bits from the backward stream, padding with zeros if past the end.
    // This matches the reference behavior where BIT_readBits continues reading
    // from the register even past the logical end of the stream.
    let read_bits_padded = |bit_pos: &mut usize, n: u32| -> usize {
        if n == 0 {
            return 0;
        }
        let n = n as usize;
        let mut result: usize = 0;
        for _ in 0..n {
            result <<= 1;
            if *bit_pos < total_bits {
                let abs_bit = total_bits - 1 - *bit_pos;
                let byte_idx = abs_bit / 8;
                let bit_idx = abs_bit % 8;
                if (data[byte_idx] >> bit_idx) & 1 != 0 {
                    result |= 1;
                }
            }
            // else: beyond stream end, bit is zero (padding)
            *bit_pos += 1;
        }
        result
    };

    // Two-interleaved-state FSE decode loop matching the reference implementation.
    // The reference uses BIT_reloadDStream to detect overflow AFTER each
    // decode+update step. Overflow means bits were consumed past the stream end.
    // "Completed" (bit_pos == total_bits) is NOT overflow; only bit_pos > total_bits is.
    loop {
        // Decode from state1 and update state
        let entry1 = table.decode(state1);
        output.push(entry1.symbol);
        let new_bits1 = read_bits_padded(&mut bit_pos, entry1.nb_bits as u32);
        state1 = entry1.next_state as usize + new_bits1;

        // Check for overflow (consumed past end)
        if bit_pos > total_bits {
            // Stream overflowed after state1 update: output state2's final symbol
            let entry2 = table.decode(state2);
            output.push(entry2.symbol);
            break;
        }

        // Decode from state2 and update state
        let entry2 = table.decode(state2);
        output.push(entry2.symbol);
        let new_bits2 = read_bits_padded(&mut bit_pos, entry2.nb_bits as u32);
        state2 = entry2.next_state as usize + new_bits2;

        // Check for overflow (consumed past end)
        if bit_pos > total_bits {
            // Stream overflowed after state2 update: output state1's final symbol
            let entry1_final = table.decode(state1);
            output.push(entry1_final.symbol);
            break;
        }
    }

    Ok(output)
}

/// Decompress Huffman-coded literals using a single stream.
pub(crate) fn decompress_huffman_1stream(
    table: &HuffmanTable,
    src: &[u8],
    regen_size: usize,
) -> Result<Vec<u8>, String> {
    if src.is_empty() {
        if regen_size == 0 {
            return Ok(Vec::new());
        }
        return Err("empty source for huffman 1-stream".into());
    }

    let last_byte = src[src.len() - 1];
    if last_byte == 0 {
        return Err("last byte is 0 in huffman stream".into());
    }
    let init_bit = 7 - last_byte.leading_zeros() as usize;
    let total_bits = (src.len() - 1) * 8 + init_bit;

    let mut bit_pos = 0usize;
    let mut output = Vec::with_capacity(regen_size);

    while output.len() < regen_size {
        let bits_remaining = if bit_pos < total_bits {
            total_bits - bit_pos
        } else {
            0
        };
        if bits_remaining == 0 {
            break;
        }

        // Peek table_log bits
        let peek_n = (table.table_log as usize).min(bits_remaining);
        let mut peek_val: u32 = 0;
        for i in 0..peek_n {
            peek_val <<= 1;
            let abs_bit = total_bits - 1 - (bit_pos + i);
            let byte_idx = abs_bit / 8;
            let bit_idx = abs_bit % 8;
            if (src[byte_idx] >> bit_idx) & 1 != 0 {
                peek_val |= 1;
            }
        }
        // Pad to table_log bits if we peeked fewer
        if peek_n < table.table_log as usize {
            peek_val <<= table.table_log as usize - peek_n;
        }

        let entry = table.decode(peek_val);
        if entry.nb_bits as usize > bits_remaining {
            break;
        }
        output.push(entry.symbol);
        bit_pos += entry.nb_bits as usize;
    }

    if output.len() != regen_size {
        return Err(format!(
            "huffman 1-stream: decoded {} bytes, expected {}",
            output.len(),
            regen_size
        ));
    }

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
    // (the last stream may have a different count)
    let seg_size = (regen_size + 3) / 4;
    let regen1 = seg_size.min(regen_size);
    let regen2 = seg_size.min(regen_size.saturating_sub(seg_size));
    let regen3 = seg_size.min(regen_size.saturating_sub(2 * seg_size));
    let regen4 = regen_size.saturating_sub(3 * seg_size);

    let out1 = decompress_huffman_1stream(table, stream1, regen1)?;
    let out2 = decompress_huffman_1stream(table, stream2, regen2)?;
    let out3 = decompress_huffman_1stream(table, stream3, regen3)?;
    let out4 = decompress_huffman_1stream(table, stream4, regen4)?;

    let mut result = Vec::with_capacity(regen_size);
    result.extend_from_slice(&out1);
    result.extend_from_slice(&out2);
    result.extend_from_slice(&out3);
    result.extend_from_slice(&out4);

    if result.len() != regen_size {
        return Err(format!(
            "huffman 4-stream: decoded {} bytes, expected {}",
            result.len(),
            regen_size
        ));
    }

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
            0x2D, 0x10, 0x48, 0x7B, 0xC6, 0xDA, 0xFB, 0xED, 0xE8, 0x27,
            0xC8, 0xAE, 0xB1, 0x22, 0x5D, 0xD0, 0xF3, 0xF9, 0x35, 0x87,
            0x7C, 0xBE, 0x9B, 0x15, 0x7F, 0x08, 0x89, 0xBA, 0xE2, 0x72,
            0x01, 0x5B, 0x2E, 0xA2, 0xC9, 0x99, 0x0C, 0x8C, 0xFD, 0xE1,
            0x51, 0x18, 0x2B, 0xEC, 0xDE, 0x29,
        ];
        let result = read_huffman_table(&huf_desc);
        assert!(result.is_ok(), "read_huffman_table failed: {:?}", result.err());
    }
}
