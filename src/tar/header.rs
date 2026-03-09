use crate::error::{Result, Error};
use crate::tar::entry::{TarEntry, TarEntryType};

/// Size of a tar header/block.
pub const BLOCK_SIZE: usize = 512;

/// Parse an octal string from a tar header field.
/// Handles both traditional octal and GNU binary extension.
pub fn parse_octal(field: &[u8]) -> Result<u64> {
    // GNU binary extension: if the high bit is set, treat as big-endian binary
    if !field.is_empty() && field[0] & 0x80 != 0 {
        let mut value: u64 = 0;
        for &b in &field[1..] {
            value = value << 8 | b as u64;
        }
        return Ok(value);
    }

    // Traditional: octal string, null/space terminated
    let s = field
        .iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .copied()
        .collect::<Vec<u8>>();

    if s.is_empty() {
        return Ok(0);
    }

    let s = std::str::from_utf8(&s)
        .map_err(|_| Error::InvalidTarHeader("invalid octal field".into()))?;

    u64::from_str_radix(s, 8)
        .map_err(|_| Error::InvalidTarHeader(format!("invalid octal: {:?}", s)))
}

/// Extract a null-terminated string from a tar header field.
pub fn parse_string(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Check if a block is all zeros (end-of-archive marker).
pub fn is_zero_block(block: &[u8; BLOCK_SIZE]) -> bool {
    block.iter().all(|&b| b == 0)
}

/// Validate the tar header checksum.
pub fn validate_checksum(header: &[u8; BLOCK_SIZE]) -> bool {
    // The checksum field is at bytes 148-155
    // For checksum calculation, the checksum field is treated as spaces
    let stored = match parse_octal(&header[148..156]) {
        Ok(v) => v as u32,
        Err(_) => return false,
    };

    let mut unsigned_sum: u32 = 0;
    let mut signed_sum: i32 = 0;
    for (i, &byte) in header.iter().enumerate() {
        if (148..156).contains(&i) {
            unsigned_sum += b' ' as u32;
            signed_sum += b' ' as i32;
        } else {
            unsigned_sum += byte as u32;
            signed_sum += (byte as i8) as i32;
        }
    }

    stored == unsigned_sum || stored == signed_sum as u32
}

/// Parse a tar header block into a TarEntry.
/// `data_offset` is the byte position in the uncompressed stream
/// where the file data starts (immediately after this header block).
pub fn parse_header(header: &[u8; BLOCK_SIZE], data_offset: u64) -> Result<TarEntry> {
    if !validate_checksum(header) {
        return Err(Error::InvalidTarHeader(
            "checksum mismatch".into(),
        ));
    }

    let name = parse_string(&header[0..100]);
    let mode = parse_octal(&header[100..108])? as u32;
    let uid = parse_octal(&header[108..116])?;
    let gid = parse_octal(&header[116..124])?;
    let size = parse_octal(&header[124..136])?;
    let mtime = parse_octal(&header[136..148])?;
    let typeflag = header[156];
    let linkname = parse_string(&header[157..257]);

    let entry_type = TarEntryType::from_byte(typeflag);

    // Check for ustar magic
    let is_ustar = &header[257..262] == b"ustar";

    let (full_path, uname, gname) = if is_ustar {
        let prefix = parse_string(&header[345..500]);
        let uname = parse_string(&header[265..297]);
        let gname = parse_string(&header[297..329]);

        let full_path = if prefix.is_empty() {
            name
        } else {
            format!("{}/{}", prefix, name)
        };

        let uname = if uname.is_empty() {
            None
        } else {
            Some(uname)
        };
        let gname = if gname.is_empty() {
            None
        } else {
            Some(gname)
        };

        (full_path, uname, gname)
    } else {
        (name, None, None)
    };

    let link_target = if linkname.is_empty() {
        None
    } else {
        Some(linkname)
    };

    Ok(TarEntry {
        path: full_path,
        size,
        entry_type,
        mode,
        uid,
        gid,
        mtime,
        uname,
        gname,
        link_target,
        data_offset,
    })
}

/// Calculate the number of 512-byte blocks needed for `size` bytes of data,
/// including padding to block boundary.
pub fn blocks_for_size(size: u64) -> u64 {
    size.div_ceil(BLOCK_SIZE as u64)
}

/// Calculate padded size (rounded up to 512-byte block boundary).
pub fn padded_size(size: u64) -> u64 {
    blocks_for_size(size) * BLOCK_SIZE as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_octal() {
        assert_eq!(parse_octal(b"000755\0 ").unwrap(), 0o755);
        assert_eq!(parse_octal(b"0001750\0").unwrap(), 0o1750);
        assert_eq!(parse_octal(b"00000000000\0").unwrap(), 0);
        assert_eq!(parse_octal(b"00000000144\0").unwrap(), 100);
        assert_eq!(parse_octal(b"\0").unwrap(), 0);
        assert_eq!(parse_octal(b"").unwrap(), 0);
    }

    #[test]
    fn test_parse_octal_gnu_binary() {
        // GNU binary extension: high bit set
        let mut field = [0u8; 12];
        field[0] = 0x80;
        field[11] = 42;
        assert_eq!(parse_octal(&field).unwrap(), 42);
    }

    #[test]
    fn test_parse_string() {
        assert_eq!(parse_string(b"hello\0world"), "hello");
        assert_eq!(parse_string(b"hello"), "hello");
        assert_eq!(parse_string(b"\0"), "");
        assert_eq!(parse_string(b""), "");
    }

    #[test]
    fn test_is_zero_block() {
        let zero = [0u8; BLOCK_SIZE];
        assert!(is_zero_block(&zero));

        let mut nonzero = [0u8; BLOCK_SIZE];
        nonzero[0] = 1;
        assert!(!is_zero_block(&nonzero));
    }

    #[test]
    fn test_entry_type_from_byte() {
        assert_eq!(TarEntryType::from_byte(b'0'), TarEntryType::Regular);
        assert_eq!(TarEntryType::from_byte(0), TarEntryType::Regular);
        assert_eq!(TarEntryType::from_byte(b'5'), TarEntryType::Directory);
        assert_eq!(TarEntryType::from_byte(b'2'), TarEntryType::SymLink);
        assert_eq!(TarEntryType::from_byte(b'L'), TarEntryType::GnuLongName);
        assert_eq!(TarEntryType::from_byte(b'x'), TarEntryType::PaxExtended);
    }

    #[test]
    fn test_blocks_for_size() {
        assert_eq!(blocks_for_size(0), 0);
        assert_eq!(blocks_for_size(1), 1);
        assert_eq!(blocks_for_size(512), 1);
        assert_eq!(blocks_for_size(513), 2);
        assert_eq!(blocks_for_size(1024), 2);
    }

    #[test]
    fn test_padded_size() {
        assert_eq!(padded_size(0), 0);
        assert_eq!(padded_size(1), 512);
        assert_eq!(padded_size(512), 512);
        assert_eq!(padded_size(513), 1024);
    }
}
