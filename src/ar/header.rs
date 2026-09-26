use crate::error::{Error, Result};

/// Global header that opens every (non-thin) ar archive.
pub const AR_MAGIC: &[u8; 8] = b"!<arch>\n";

/// Global header of a GNU thin archive, whose members live outside it.
pub const THIN_MAGIC: &[u8; 8] = b"!<thin>\n";

/// Size of a member header (fixed).
pub const HEADER_SIZE: usize = 60;

/// Terminator of every member header.
const FMAG: &[u8; 2] = b"`\n";

/// Parsed ar member header. The name is the raw field with trailing spaces
/// removed; the GNU and BSD name conventions are resolved by the parser.
#[derive(Debug, Clone)]
pub struct ArHeader {
    pub name: Vec<u8>,
    pub mtime: u64,
    pub uid: u64,
    pub gid: u64,
    pub mode: u32,
    pub size: u64,
}

/// Parse a space-padded numeric field. A blank field reads as zero:
/// Windows import libraries and some symbol tables leave fields empty.
fn parse_field(data: &[u8], radix: u32, what: &str) -> Result<u64> {
    let s = std::str::from_utf8(data)
        .map_err(|_| Error::InvalidArHeader(format!("invalid UTF-8 in {} field", what)))?
        .trim_end_matches(' ');
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, radix)
        .map_err(|_| Error::InvalidArHeader(format!("invalid {} field: {:?}", what, s)))
}

/// Parse a member header (60 bytes).
pub fn parse_header(data: &[u8]) -> Result<ArHeader> {
    if data.len() < HEADER_SIZE {
        return Err(Error::InvalidArHeader("header too short".into()));
    }
    // Offsets: name(0,16) mtime(16,12) uid(28,6) gid(34,6) mode(40,8)
    //          size(48,10) fmag(58,2)
    if &data[58..60] != FMAG {
        return Err(Error::InvalidArHeader(format!(
            "bad header terminator: {:?}",
            &data[58..60]
        )));
    }
    let name_end = data[..16]
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |i| i + 1);
    Ok(ArHeader {
        name: data[..name_end].to_vec(),
        mtime: parse_field(&data[16..28], 10, "mtime")?,
        uid: parse_field(&data[28..34], 10, "uid")?,
        gid: parse_field(&data[34..40], 10, "gid")?,
        mode: parse_field(&data[40..48], 8, "mode")? as u32,
        size: parse_field(&data[48..58], 10, "size")?,
    })
}

/// Parse a decimal number embedded in a member name (`/123`, `#1/20`).
pub fn parse_name_number(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(digits).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, size: &str, mode: &str) -> Vec<u8> {
        format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            name, "1700000000", "1000", "1000", mode, size
        )
        .into_bytes()
    }

    #[test]
    fn test_parse_header() {
        let h = parse_header(&header("hello.o/", "42", "100644")).unwrap();
        assert_eq!(h.name, b"hello.o/");
        assert_eq!(h.mtime, 1700000000);
        assert_eq!(h.uid, 1000);
        assert_eq!(h.gid, 1000);
        assert_eq!(h.mode, 0o100644);
        assert_eq!(h.size, 42);
    }

    #[test]
    fn test_blank_fields_read_as_zero() {
        let data = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            "//", "", "", "", "", "8"
        );
        let h = parse_header(data.as_bytes()).unwrap();
        assert_eq!(h.name, b"//");
        assert_eq!((h.mtime, h.uid, h.gid, h.mode), (0, 0, 0, 0));
        assert_eq!(h.size, 8);
    }

    #[test]
    fn test_bad_terminator_rejected() {
        let mut data = header("a/", "1", "644");
        data[59] = b'x';
        assert!(parse_header(&data).is_err());
    }

    #[test]
    fn test_bad_size_rejected() {
        assert!(parse_header(&header("a/", "12x", "644")).is_err());
    }

    #[test]
    fn test_parse_name_number() {
        assert_eq!(parse_name_number(b"123"), Some(123));
        assert_eq!(parse_name_number(b""), None);
        assert_eq!(parse_name_number(b"12 "), None);
        assert_eq!(parse_name_number(b"SYM64/"), None);
    }
}
