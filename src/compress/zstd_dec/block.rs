//! Block-level decompression for zstd.
//!
//! A zstd frame consists of one or more blocks, each preceded by a 3-byte
//! block header. Block types: Raw (0), RLE (1), Compressed (2), Reserved (3).
//!
//! Compressed blocks contain a literals section followed by a sequences section.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::fse::{self, FseTable};
use super::huffman::{self, decompress_huffman_1stream, decompress_huffman_4streams, HuffmanTable};
use super::sequences::{decode_and_execute_sequences, parse_sequences_header};

/// Predefined (default) FSE tables, built once and shared.
pub(crate) fn default_ll_table() -> &'static FseTable {
    static TABLE: OnceLock<FseTable> = OnceLock::new();
    TABLE.get_or_init(fse::build_default_ll_table)
}

pub(crate) fn default_of_table() -> &'static FseTable {
    static TABLE: OnceLock<FseTable> = OnceLock::new();
    TABLE.get_or_init(fse::build_default_of_table)
}

pub(crate) fn default_ml_table() -> &'static FseTable {
    static TABLE: OnceLock<FseTable> = OnceLock::new();
    TABLE.get_or_init(fse::build_default_ml_table)
}

/// Block types as specified in the zstd format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockType {
    Raw = 0,
    Rle = 1,
    Compressed = 2,
    Reserved = 3,
}

/// Parsed block header.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockHeader {
    pub is_last: bool,
    pub block_type: BlockType,
    pub block_size: usize,
}

/// Parse a 3-byte block header.
pub(crate) fn parse_block_header(data: &[u8]) -> Result<BlockHeader, String> {
    if data.len() < 3 {
        return Err("block header needs 3 bytes".into());
    }

    let raw = (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16);

    let is_last = (raw & 1) != 0;
    let block_type_val = (raw >> 1) & 3;
    let block_size = (raw >> 3) as usize;

    let block_type = match block_type_val {
        0 => BlockType::Raw,
        1 => BlockType::Rle,
        2 => BlockType::Compressed,
        3 => BlockType::Reserved,
        _ => unreachable!(),
    };

    if block_type == BlockType::Reserved {
        return Err("reserved block type".into());
    }

    Ok(BlockHeader {
        is_last,
        block_type,
        block_size,
    })
}

/// The compressed size of the block (how many bytes to read from input).
pub(crate) fn block_compressed_size(header: &BlockHeader) -> usize {
    match header.block_type {
        BlockType::Raw => header.block_size,
        BlockType::Rle => 1, // Only 1 byte to read
        BlockType::Compressed => header.block_size,
        BlockType::Reserved => 0,
    }
}

/// State that persists across blocks within a frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BlockDecoderState {
    /// Huffman table for literals (persists across blocks).
    pub huffman_table: Option<HuffmanTable>,
    /// FSE table for literal lengths.
    pub ll_table: Option<FseTable>,
    /// FSE table for offsets.
    pub of_table: Option<FseTable>,
    /// FSE table for match lengths.
    pub ml_table: Option<FseTable>,
    /// Repeat offsets.
    pub rep_offsets: [u32; 3],
    /// Scratch buffer for decoded literals, reused across blocks.
    /// Not part of checkpoint state.
    #[serde(skip)]
    pub literals_buf: Vec<u8>,
}

impl BlockDecoderState {
    pub fn new() -> Self {
        Self {
            huffman_table: None,
            ll_table: None,
            of_table: None,
            ml_table: None,
            rep_offsets: [1, 4, 8], // Default repeat offsets per spec
            literals_buf: Vec::new(),
        }
    }
}

/// Decompress a single block, appending its output to `output`.
///
/// `output` also serves as the decoding history: its existing contents are
/// the window from previous blocks. `max_back` limits how far before the
/// block start a match may reference (`min(history_len, window_size)`).
/// Updates the `state` with any new tables (Huffman, FSE) learned from this block.
pub(crate) fn decompress_block(
    header: &BlockHeader,
    block_data: &[u8],
    state: &mut BlockDecoderState,
    output: &mut Vec<u8>,
    max_back: usize,
) -> Result<(), String> {
    match header.block_type {
        BlockType::Raw => {
            if block_data.len() < header.block_size {
                return Err("raw block data too short".into());
            }
            output.extend_from_slice(&block_data[..header.block_size]);
            Ok(())
        }
        BlockType::Rle => {
            if block_data.is_empty() {
                return Err("RLE block needs at least 1 byte".into());
            }
            let byte = block_data[0];
            output.resize(output.len() + header.block_size, byte);
            Ok(())
        }
        BlockType::Compressed => {
            decompress_compressed_block(block_data, header.block_size, state, output, max_back)
        }
        BlockType::Reserved => Err("cannot decompress reserved block".into()),
    }
}

/// Decompress a compressed block.
fn decompress_compressed_block(
    data: &[u8],
    block_size: usize,
    state: &mut BlockDecoderState,
    output: &mut Vec<u8>,
    max_back: usize,
) -> Result<(), String> {
    if data.len() < block_size {
        return Err(format!(
            "compressed block data ({} bytes) shorter than block_size ({})",
            data.len(),
            block_size
        ));
    }
    let block_data = &data[..block_size];

    // 1. Decode literals section into the reusable scratch buffer.
    // Take the buffer out of `state` so the literals can be borrowed while
    // `state` is used mutably below.
    let mut literals = std::mem::take(&mut state.literals_buf);
    literals.clear();
    let lit_consumed = decode_literals_section(block_data, state, &mut literals)?;

    // 2. Parse the sequences section header, updating the FSE tables in `state`.
    let seq_data = &block_data[lit_consumed..];
    let (num_sequences, header_consumed) = parse_sequences_header(seq_data, state)?;

    // 3. Decode and execute sequences.
    let result = if num_sequences == 0 {
        // No sequences: output is just the literals
        output.extend_from_slice(&literals);
        Ok(())
    } else {
        // The remaining bytes after the sequences header are the compressed
        // sequences bitstream.
        let bitstream_data = &seq_data[header_consumed..];
        let BlockDecoderState {
            ll_table,
            of_table,
            ml_table,
            rep_offsets,
            ..
        } = state;
        decode_and_execute_sequences(
            bitstream_data,
            num_sequences,
            ll_table.as_ref().expect("LL table set by header parse"),
            of_table.as_ref().expect("OF table set by header parse"),
            ml_table.as_ref().expect("ML table set by header parse"),
            rep_offsets,
            &literals,
            output,
            max_back,
        )
    };

    // Return the scratch buffer for reuse.
    state.literals_buf = literals;
    result
}

/// Decode the literals section of a compressed block into `literals`.
/// Returns the number of bytes consumed from the block.
fn decode_literals_section(
    data: &[u8],
    state: &mut BlockDecoderState,
    literals: &mut Vec<u8>,
) -> Result<usize, String> {
    if data.is_empty() {
        return Err("empty literals section".into());
    }

    let first_byte = data[0];
    let lit_block_type = first_byte & 3;

    match lit_block_type {
        0 => decode_raw_literals(data, literals),
        1 => decode_rle_literals(data, literals),
        2 => decode_compressed_literals(data, state, false, literals),
        3 => decode_compressed_literals(data, state, true, literals), // Treeless (repeat Huffman)
        _ => unreachable!(),
    }
}

/// Decode raw literals (type 0).
fn decode_raw_literals(data: &[u8], literals: &mut Vec<u8>) -> Result<usize, String> {
    let first_byte = data[0];
    let size_format = (first_byte >> 2) & 3;

    let (header_size, lit_size) = match size_format {
        0 | 2 => {
            // 1 byte header, size in bits 3..7
            let size = (first_byte >> 3) as usize;
            (1, size)
        }
        1 => {
            // 2 byte header
            if data.len() < 2 {
                return Err("raw literals header truncated".into());
            }
            let size = (u16::from_le_bytes([data[0], data[1]]) >> 4) as usize;
            (2, size)
        }
        3 => {
            // 3 byte header
            if data.len() < 3 {
                return Err("raw literals header truncated".into());
            }
            let val = (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16);
            let size = (val >> 4) as usize;
            (3, size)
        }
        _ => unreachable!(),
    };

    if header_size + lit_size > data.len() {
        return Err("raw literals extend past block".into());
    }

    literals.extend_from_slice(&data[header_size..header_size + lit_size]);
    Ok(header_size + lit_size)
}

/// Decode RLE literals (type 1).
fn decode_rle_literals(data: &[u8], literals: &mut Vec<u8>) -> Result<usize, String> {
    let first_byte = data[0];
    let size_format = (first_byte >> 2) & 3;

    let (header_size, lit_size) = match size_format {
        0 | 2 => {
            let size = (first_byte >> 3) as usize;
            (1, size)
        }
        1 => {
            if data.len() < 2 {
                return Err("RLE literals header truncated".into());
            }
            let size = (u16::from_le_bytes([data[0], data[1]]) >> 4) as usize;
            (2, size)
        }
        3 => {
            if data.len() < 3 {
                return Err("RLE literals header truncated".into());
            }
            let val = (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16);
            let size = (val >> 4) as usize;
            (3, size)
        }
        _ => unreachable!(),
    };

    if header_size >= data.len() {
        return Err("RLE literals missing byte value".into());
    }

    let byte = data[header_size];
    literals.resize(lit_size, byte);
    Ok(header_size + 1)
}

/// Decode compressed or treeless literals (types 2 and 3).
fn decode_compressed_literals(
    data: &[u8],
    state: &mut BlockDecoderState,
    treeless: bool,
    literals: &mut Vec<u8>,
) -> Result<usize, String> {
    if data.len() < 3 {
        return Err("compressed literals header too short".into());
    }

    let first_byte = data[0];
    let size_format = (first_byte >> 2) & 3;

    let (header_size, regen_size, compressed_size, single_stream) = match size_format {
        0 | 1 => {
            // 3-byte header: 2-2-10-10
            let single = size_format == 0;
            let lhc = (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16);
            let regen = ((lhc >> 4) & 0x3FF) as usize;
            let compressed = ((lhc >> 14) & 0x3FF) as usize;
            (3, regen, compressed, single)
        }
        2 => {
            // 4-byte header: 2-2-14-14
            if data.len() < 4 {
                return Err("compressed literals header truncated (4-byte)".into());
            }
            let lhc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let regen = ((lhc >> 4) & 0x3FFF) as usize;
            let compressed = (lhc >> 18) as usize;
            (4, regen, compressed, false)
        }
        3 => {
            // 5-byte header: 2-2-18-18
            if data.len() < 5 {
                return Err("compressed literals header truncated (5-byte)".into());
            }
            let lhc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let regen = ((lhc >> 4) & 0x3FFFF) as usize;
            let compressed = ((lhc >> 22) as usize) + ((data[4] as usize) << 10);
            (5, regen, compressed, false)
        }
        _ => unreachable!(),
    };

    if header_size + compressed_size > data.len() {
        return Err("compressed literals extend past block".into());
    }

    let compressed_data = &data[header_size..header_size + compressed_size];

    // Get or build Huffman table (stored in state for treeless reuse)
    let huf_consumed = if treeless {
        if state.huffman_table.is_none() {
            return Err("treeless literals but no previous Huffman table".into());
        }
        0
    } else {
        // Read new Huffman table from compressed data
        let (table, consumed) = huffman::read_huffman_table(compressed_data)?;
        state.huffman_table = Some(table);
        consumed
    };
    let huf_table = state.huffman_table.as_ref().expect("huffman table present");

    let huf_stream = &compressed_data[huf_consumed..];

    // Decompress using Huffman coding
    literals.resize(regen_size, 0);
    if single_stream {
        decompress_huffman_1stream(huf_table, huf_stream, literals)?;
    } else {
        decompress_huffman_4streams(huf_table, huf_stream, literals)?;
    }

    Ok(header_size + compressed_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_block_header() {
        // last=0, type=Raw(00), size=5 -> bits: size(5)=000000000000000000101, type=00, last=0
        // 24-bit: 000000000000000000101_00_0 = 0x000028
        let data = [0x28, 0x00, 0x00];
        let header = parse_block_header(&data).unwrap();
        assert!(!header.is_last);
        assert_eq!(header.block_type, BlockType::Raw);
        assert_eq!(header.block_size, 5);
    }

    #[test]
    fn test_parse_block_header_rle() {
        // last=1, type=RLE(01), size=100 -> bits: 100=0...01100100, type=01, last=1
        // = 0...01100100_01_1 = 0x000323
        let val: u32 = 1 | (1 << 1) | (100 << 3);
        let data = val.to_le_bytes();
        let header = parse_block_header(&data[..3]).unwrap();
        assert!(header.is_last);
        assert_eq!(header.block_type, BlockType::Rle);
        assert_eq!(header.block_size, 100);
    }

    #[test]
    fn test_parse_block_header_compressed() {
        // last=0, type=Compressed(10), size=256
        let val: u32 = (2 << 1) | (256 << 3);
        let data = val.to_le_bytes();
        let header = parse_block_header(&data[..3]).unwrap();
        assert!(!header.is_last);
        assert_eq!(header.block_type, BlockType::Compressed);
        assert_eq!(header.block_size, 256);
    }

    #[test]
    fn test_block_compressed_size() {
        let raw_header = BlockHeader {
            is_last: false,
            block_type: BlockType::Raw,
            block_size: 42,
        };
        assert_eq!(block_compressed_size(&raw_header), 42);

        let rle_header = BlockHeader {
            is_last: false,
            block_type: BlockType::Rle,
            block_size: 1000,
        };
        assert_eq!(block_compressed_size(&rle_header), 1);
    }

    #[test]
    fn test_decompress_raw_block() {
        let header = BlockHeader {
            is_last: true,
            block_type: BlockType::Raw,
            block_size: 5,
        };
        let data = b"hello world";
        let mut state = BlockDecoderState::new();
        let mut output = Vec::new();
        decompress_block(&header, data, &mut state, &mut output, 0).unwrap();
        assert_eq!(&output, b"hello");
    }

    #[test]
    fn test_decompress_rle_block() {
        let header = BlockHeader {
            is_last: true,
            block_type: BlockType::Rle,
            block_size: 10,
        };
        let data = [0x41]; // 'A'
        let mut state = BlockDecoderState::new();
        let mut output = Vec::new();
        decompress_block(&header, &data, &mut state, &mut output, 0).unwrap();
        assert_eq!(output, vec![0x41; 10]);
    }
}
