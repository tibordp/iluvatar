use crate::archive::EntryType;
use crate::error::{Result, SupertarError};

/// Size of a newc/crc format header (fixed).
pub const NEWC_HEADER_SIZE: usize = 110;

/// Magic bytes for newc format.
pub const NEWC_MAGIC: &[u8; 6] = b"070701";

/// Magic bytes for newc with CRC.
pub const NEWC_CRC_MAGIC: &[u8; 6] = b"070702";

/// Magic bytes for odc (POSIX.1) format.
pub const ODC_MAGIC: &[u8; 6] = b"070707";

/// Size of an odc format header (fixed).
pub const ODC_HEADER_SIZE: usize = 76;

/// End-of-archive marker filename.
pub const TRAILER_NAME: &str = "TRAILER!!!";

/// Detected cpio sub-format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpioSubFormat {
    /// SVR4 / "newc" format (most common).
    Newc,
    /// SVR4 with CRC.
    NewcCrc,
    /// POSIX.1 / "odc" portable format.
    Odc,
}

/// Parsed cpio header fields (format-independent).
#[derive(Debug, Clone)]
pub struct CpioHeader {
    pub ino: u64,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub nlink: u32,
    pub mtime: u64,
    pub filesize: u64,
    pub devmajor: u32,
    pub devminor: u32,
    pub rdevmajor: u32,
    pub rdevminor: u32,
    pub namesize: u32,
}

/// Parse an 8-character hex field from a newc header.
fn parse_hex8(data: &[u8]) -> Result<u64> {
    let s = std::str::from_utf8(data)
        .map_err(|_| SupertarError::InvalidCpioHeader("invalid UTF-8 in hex field".into()))?;
    u64::from_str_radix(s, 16)
        .map_err(|_| SupertarError::InvalidCpioHeader(format!("invalid hex field: {:?}", s)))
}

/// Parse a 6- or 11-character octal field from an odc header.
fn parse_octal(data: &[u8]) -> Result<u64> {
    let s = std::str::from_utf8(data)
        .map_err(|_| SupertarError::InvalidCpioHeader("invalid UTF-8 in octal field".into()))?;
    u64::from_str_radix(s, 8)
        .map_err(|_| SupertarError::InvalidCpioHeader(format!("invalid octal field: {:?}", s)))
}

/// Parse a newc-format cpio header (110 bytes).
pub fn parse_newc_header(data: &[u8]) -> Result<CpioHeader> {
    if data.len() < NEWC_HEADER_SIZE {
        return Err(SupertarError::InvalidCpioHeader("header too short".into()));
    }
    // Offsets: magic(0,6) ino(6,8) mode(14,8) uid(22,8) gid(30,8)
    //          nlink(38,8) mtime(46,8) filesize(54,8) devmajor(62,8) devminor(70,8)
    //          rdevmajor(78,8) rdevminor(86,8) namesize(94,8) check(102,8)
    Ok(CpioHeader {
        ino: parse_hex8(&data[6..14])?,
        mode: parse_hex8(&data[14..22])? as u32,
        uid: parse_hex8(&data[22..30])?,
        gid: parse_hex8(&data[30..38])?,
        nlink: parse_hex8(&data[38..46])? as u32,
        mtime: parse_hex8(&data[46..54])?,
        filesize: parse_hex8(&data[54..62])?,
        devmajor: parse_hex8(&data[62..70])? as u32,
        devminor: parse_hex8(&data[70..78])? as u32,
        rdevmajor: parse_hex8(&data[78..86])? as u32,
        rdevminor: parse_hex8(&data[86..94])? as u32,
        namesize: parse_hex8(&data[94..102])? as u32,
    })
}

/// Parse an odc-format cpio header (76 bytes).
pub fn parse_odc_header(data: &[u8]) -> Result<CpioHeader> {
    if data.len() < ODC_HEADER_SIZE {
        return Err(SupertarError::InvalidCpioHeader("odc header too short".into()));
    }
    // Offsets: magic(0,6) dev(6,6) ino(12,6) mode(18,6) uid(24,6) gid(30,6)
    //          nlink(36,6) rdev(42,6) mtime(48,11) namesize(59,6) filesize(65,11)
    let dev = parse_octal(&data[6..12])? as u32;
    let rdev = parse_octal(&data[42..48])? as u32;
    Ok(CpioHeader {
        ino: parse_octal(&data[12..18])?,
        mode: parse_octal(&data[18..24])? as u32,
        uid: parse_octal(&data[24..30])?,
        gid: parse_octal(&data[30..36])?,
        nlink: parse_octal(&data[36..42])? as u32,
        mtime: parse_octal(&data[48..59])?,
        filesize: parse_octal(&data[65..76])?,
        devmajor: dev >> 8,
        devminor: dev & 0xFF,
        rdevmajor: rdev >> 8,
        rdevminor: rdev & 0xFF,
        namesize: parse_octal(&data[59..65])? as u32,
    })
}

/// Derive the entry type from Unix mode bits.
pub fn entry_type_from_mode(mode: u32) -> EntryType {
    match mode & 0o170000 {
        0o100000 => EntryType::Regular,
        0o040000 => EntryType::Directory,
        0o120000 => EntryType::SymLink,
        0o020000 => EntryType::CharDevice,
        0o060000 => EntryType::BlockDevice,
        0o010000 => EntryType::Fifo,
        0o140000 => EntryType::Socket,
        _ => EntryType::Other((mode >> 12) as u8),
    }
}

/// Alignment for newc format: pad to 4-byte boundary.
pub fn align4(offset: usize) -> usize {
    (offset + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_type_from_mode() {
        assert_eq!(entry_type_from_mode(0o100644), EntryType::Regular);
        assert_eq!(entry_type_from_mode(0o040755), EntryType::Directory);
        assert_eq!(entry_type_from_mode(0o120777), EntryType::SymLink);
        assert_eq!(entry_type_from_mode(0o020660), EntryType::CharDevice);
        assert_eq!(entry_type_from_mode(0o060660), EntryType::BlockDevice);
        assert_eq!(entry_type_from_mode(0o010644), EntryType::Fifo);
        assert_eq!(entry_type_from_mode(0o140755), EntryType::Socket);
    }

    #[test]
    fn test_align4() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(110), 112);
    }

    #[test]
    fn test_parse_hex8() {
        assert_eq!(parse_hex8(b"00000000").unwrap(), 0);
        assert_eq!(parse_hex8(b"000000FF").unwrap(), 255);
        assert_eq!(parse_hex8(b"00000064").unwrap(), 100);
    }

    #[test]
    fn test_parse_newc_header() {
        // Build a minimal valid newc header
        let mut header = [b'0'; NEWC_HEADER_SIZE];
        header[0..6].copy_from_slice(b"070701");
        // mode = 0o100644 = 0x81A4
        header[14..22].copy_from_slice(b"000081A4");
        // filesize = 13
        header[54..62].copy_from_slice(b"0000000D");
        // namesize = 6 ("hello\0")
        header[94..102].copy_from_slice(b"00000006");

        let h = parse_newc_header(&header).unwrap();
        assert_eq!(h.mode, 0o100644);
        assert_eq!(h.filesize, 13);
        assert_eq!(h.namesize, 6);
    }
}
