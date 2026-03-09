//! Zstd frame header parsing.
//!
//! A zstd frame starts with a 4-byte magic number (0xFD2FB528), followed by
//! a frame header descriptor, optional window descriptor, optional dictionary ID,
//! and optional frame content size.

use serde::{Deserialize, Serialize};

/// Zstd magic number (little-endian).
pub(crate) const ZSTD_MAGIC: u32 = 0xFD2FB528;

/// Skippable frame magic range: 0x184D2A50 to 0x184D2A5F.
pub(crate) const SKIPPABLE_MAGIC_LOW: u32 = 0x184D2A50;
pub(crate) const SKIPPABLE_MAGIC_HIGH: u32 = 0x184D2A5F;

/// Maximum window size we'll support (128 MiB).
pub(crate) const MAX_WINDOW_SIZE: usize = 128 * 1024 * 1024;

/// Minimum window size (1 KB).
pub(crate) const MIN_WINDOW_LOG: u32 = 10;

/// Parsed frame header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FrameHeader {
    /// Whether a content checksum (XXH64) is present at end of frame.
    pub checksum_flag: bool,
    /// Whether single_segment flag is set (no window descriptor, content size known).
    pub single_segment: bool,
    /// Window size in bytes.
    pub window_size: usize,
    /// Dictionary ID (0 if none).
    pub dictionary_id: u32,
    /// Frame content size (None if not specified).
    pub content_size: Option<u64>,
    /// Total header size in bytes (including magic number).
    pub header_size: usize,
}

/// Parse a zstd frame header from the given data.
/// Returns the frame header or an error.
pub(crate) fn parse_frame_header(data: &[u8]) -> Result<FrameHeader, String> {
    if data.len() < 5 {
        return Err("frame header too short".into());
    }

    // Check magic number
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != ZSTD_MAGIC {
        return Err(format!("invalid zstd magic: 0x{:08X}", magic));
    }

    let descriptor = data[4];
    let checksum_flag = (descriptor & 0x04) != 0;
    let single_segment = (descriptor & 0x20) != 0;
    let content_size_flag = (descriptor >> 6) & 3;
    let dict_id_flag = descriptor & 3;
    let _reserved = (descriptor >> 3) & 3;

    let mut pos = 5;

    // Window descriptor (absent if single_segment)
    let window_size;
    if !single_segment {
        if pos >= data.len() {
            return Err("frame header truncated at window descriptor".into());
        }
        let win_byte = data[pos];
        pos += 1;
        let exponent = (win_byte >> 3) as u32;
        let mantissa = (win_byte & 7) as u64;
        let base = 1u64 << (MIN_WINDOW_LOG + exponent);
        window_size = (base + (mantissa * (base >> 3))) as usize;
    } else {
        // Will be set from content_size below
        window_size = 0;
    }

    // Dictionary ID
    let dict_id_size = match dict_id_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        _ => unreachable!(),
    };
    if pos + dict_id_size > data.len() {
        return Err("frame header truncated at dictionary ID".into());
    }
    let dictionary_id = match dict_id_size {
        0 => 0,
        1 => data[pos] as u32,
        2 => u16::from_le_bytes([data[pos], data[pos + 1]]) as u32,
        4 => u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]),
        _ => unreachable!(),
    };
    pos += dict_id_size;

    // Frame content size
    let fcs_size = match content_size_flag {
        0 => {
            if single_segment {
                1
            } else {
                0
            }
        }
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    if pos + fcs_size > data.len() {
        return Err("frame header truncated at content size".into());
    }

    let content_size = if fcs_size == 0 {
        None
    } else {
        let val = match fcs_size {
            1 => data[pos] as u64,
            2 => u16::from_le_bytes([data[pos], data[pos + 1]]) as u64 + 256,
            4 => u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                as u64,
            8 => u64::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]),
            _ => unreachable!(),
        };
        Some(val)
    };
    pos += fcs_size;

    // Adjust window_size for single_segment frames
    let final_window_size = if single_segment {
        content_size.unwrap_or(0) as usize
    } else {
        window_size
    };

    // Clamp window size
    let clamped_window_size = if final_window_size > MAX_WINDOW_SIZE {
        MAX_WINDOW_SIZE
    } else if final_window_size == 0 {
        // Minimum window
        1 << MIN_WINDOW_LOG
    } else {
        final_window_size
    };

    Ok(FrameHeader {
        checksum_flag,
        single_segment,
        window_size: clamped_window_size,
        dictionary_id,
        content_size,
        header_size: pos,
    })
}

/// Check if data starts with a skippable frame magic.
/// Returns Some(frame_size_including_header) or None.
pub(crate) fn check_skippable_frame(data: &[u8]) -> Option<usize> {
    if data.len() < 8 {
        return None;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic >= SKIPPABLE_MAGIC_LOW && magic <= SKIPPABLE_MAGIC_HIGH {
        let frame_size =
            u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        Some(8 + frame_size)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_number() {
        let magic_bytes = ZSTD_MAGIC.to_le_bytes();
        assert_eq!(magic_bytes, [0x28, 0xB5, 0x2F, 0xFD]);
    }

    #[test]
    fn test_parse_minimal_header() {
        // Magic + descriptor (single_segment, no dict, FCS=1 byte)
        // descriptor: single_segment=1 (bit5), content_size_flag=0 (bits 6-7), dict_id_flag=0 (bits 0-1)
        // = 0b00100000 = 0x20
        // single_segment with content_size_flag=0 means 1 byte FCS
        let mut data = vec![0x28, 0xB5, 0x2F, 0xFD]; // magic
        data.push(0x20); // descriptor: single_segment=1
        data.push(42); // FCS = 42 bytes

        let header = parse_frame_header(&data).unwrap();
        assert!(!header.checksum_flag);
        assert!(header.single_segment);
        assert_eq!(header.content_size, Some(42));
        assert_eq!(header.window_size, 42);
        assert_eq!(header.dictionary_id, 0);
        assert_eq!(header.header_size, 6);
    }

    #[test]
    fn test_parse_header_with_window() {
        // descriptor: not single_segment, checksum=0, FCS=0, dict=0
        // = 0x00
        let mut data = vec![0x28, 0xB5, 0x2F, 0xFD]; // magic
        data.push(0x00); // descriptor
        data.push(0x00); // window descriptor: exponent=0, mantissa=0 -> 1<<10 = 1024

        let header = parse_frame_header(&data).unwrap();
        assert!(!header.single_segment);
        assert_eq!(header.window_size, 1024);
        assert_eq!(header.content_size, None);
        assert_eq!(header.header_size, 6);
    }

    #[test]
    fn test_parse_header_with_checksum() {
        let mut data = vec![0x28, 0xB5, 0x2F, 0xFD];
        data.push(0x24); // single_segment + checksum
        data.push(100); // FCS = 100

        let header = parse_frame_header(&data).unwrap();
        assert!(header.checksum_flag);
        assert!(header.single_segment);
        assert_eq!(header.content_size, Some(100));
    }

    #[test]
    fn test_invalid_magic() {
        let data = vec![0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(parse_frame_header(&data).is_err());
    }

    #[test]
    fn test_skippable_frame() {
        let mut data = vec![0x50, 0x2A, 0x4D, 0x18]; // skippable magic 0x184D2A50
        data.extend_from_slice(&10u32.to_le_bytes()); // frame size = 10
        data.extend_from_slice(&[0u8; 10]); // frame content

        let result = check_skippable_frame(&data);
        assert_eq!(result, Some(18)); // 8 header + 10 content
    }

    #[test]
    fn test_window_size_calculation() {
        // window byte = 0x18: exponent=3, mantissa=0
        // window = 1 << (10+3) = 8192
        let mut data = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x18];
        let header = parse_frame_header(&data).unwrap();
        assert_eq!(header.window_size, 8192);

        // window byte = 0x1F: exponent=3, mantissa=7
        // base = 1 << 13 = 8192, window = 8192 + 7 * (8192 >> 3) = 8192 + 7*1024 = 15360
        data[5] = 0x1F;
        let header = parse_frame_header(&data).unwrap();
        assert_eq!(header.window_size, 15360);
    }
}
