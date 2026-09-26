use crate::ar::header::{self, ArHeader, AR_MAGIC, HEADER_SIZE, THIN_MAGIC};
use crate::archive::entry::{ArchiveEntry, EntryType};
use crate::archive::parser::{ArchiveEvent, ArchiveParser};
use crate::error::{Error, Result};

/// Maximum accepted BSD inline member name. Names are never anywhere near
/// this; the limit keeps a crafted header from forcing a huge allocation.
const MAX_NAME_SIZE: usize = 1 << 16;

/// Maximum accepted GNU long-name table (`//` member). It holds only the
/// names longer than 15 bytes, so even huge static libraries stay far
/// below this.
const MAX_NAME_TABLE_SIZE: u64 = 64 << 20;

/// Internal parser state.
enum ArState {
    /// Reading the 8-byte global header.
    ReadingMagic,
    /// Reading a fixed-size member header.
    ReadingHeader,
    /// Reading the GNU long-name table (`//` member).
    ReadingNameTable {
        remaining: usize,
        /// Padding byte to skip after the table.
        pad: u64,
        buf: Vec<u8>,
    },
    /// Reading a BSD inline name (`#1/<len>`) from the start of member data.
    ReadingBsdName {
        header: ArHeader,
        remaining: usize,
        buf: Vec<u8>,
    },
    /// Skipping member data and its padding.
    SkippingData {
        remaining: u64,
        /// How many of the `remaining` bytes are the trailing pad byte.
        pad: u64,
    },
}

/// How a member header is to be handled.
enum Member {
    /// A symbol table or other special member with no user-visible file.
    Skip,
    /// The GNU long-name table.
    NameTable,
    /// A BSD member whose name is the first `len` bytes of its data.
    BsdName(usize),
    /// A regular member with its resolved name.
    Named(String),
}

/// Incremental, sans-I/O ar parser.
///
/// Supports the common (GNU/SysV) variant with its `//` long-name table,
/// the BSD variant with `#1/<len>` inline names, and Windows `.lib`
/// archives, which follow the GNU layout. Symbol tables (`/`, `/SYM64/`,
/// `__.SYMDEF`) are skipped. Every member is reported as a regular file.
///
/// ar has no end-of-archive marker; the archive simply ends with the
/// stream.
pub struct ArParser {
    state: ArState,
    /// Buffer for accumulating the global header or a member header.
    header_buf: Vec<u8>,
    /// Current position in the uncompressed stream.
    stream_pos: u64,
    /// GNU long-name table, once seen.
    name_table: Option<Vec<u8>>,
}

impl ArParser {
    pub fn new() -> Self {
        Self {
            state: ArState::ReadingMagic,
            header_buf: Vec::with_capacity(HEADER_SIZE),
            stream_pos: 0,
            name_table: None,
        }
    }

    /// Accumulate up to `size` bytes into `header_buf`. Returns the number
    /// of bytes taken and whether the buffer is now full.
    fn fill_header_buf(&mut self, data: &[u8], size: usize) -> (usize, bool) {
        let take = data.len().min(size - self.header_buf.len());
        self.header_buf.extend_from_slice(&data[..take]);
        self.stream_pos += take as u64;
        (take, self.header_buf.len() == size)
    }

    fn feed_magic(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        let (take, full) = self.fill_header_buf(data, AR_MAGIC.len());
        if !full {
            return Ok((take, ArchiveEvent::NeedData));
        }
        if self.header_buf == THIN_MAGIC {
            return Err(Error::InvalidArHeader(
                "thin archives are not supported (member data is stored outside the archive)"
                    .into(),
            ));
        }
        if self.header_buf != AR_MAGIC {
            return Err(Error::InvalidArHeader(format!(
                "unrecognized ar magic: {:?}",
                self.header_buf
            )));
        }
        self.header_buf.clear();
        self.state = ArState::ReadingHeader;
        Ok((take, ArchiveEvent::NeedData))
    }

    fn feed_header(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        let (take, full) = self.fill_header_buf(data, HEADER_SIZE);
        if !full {
            return Ok((take, ArchiveEvent::NeedData));
        }
        let hdr = header::parse_header(&self.header_buf)?;
        self.header_buf.clear();

        // Member data is padded to an even offset.
        let pad = hdr.size & 1;
        let event = match self.classify(&hdr)? {
            Member::Skip => {
                self.skip(hdr.size, pad);
                ArchiveEvent::NeedData
            }
            Member::NameTable => {
                if hdr.size > MAX_NAME_TABLE_SIZE {
                    return Err(Error::InvalidArHeader(format!(
                        "implausible long-name table size {}",
                        hdr.size
                    )));
                }
                self.state = ArState::ReadingNameTable {
                    remaining: hdr.size as usize,
                    pad,
                    buf: Vec::with_capacity(hdr.size as usize),
                };
                ArchiveEvent::NeedData
            }
            Member::BsdName(len) => {
                self.state = ArState::ReadingBsdName {
                    header: hdr,
                    remaining: len,
                    buf: Vec::with_capacity(len),
                };
                ArchiveEvent::NeedData
            }
            Member::Named(path) => {
                let entry = self.entry(path, &hdr, hdr.size);
                self.skip(hdr.size, pad);
                ArchiveEvent::Entry(entry)
            }
        };
        Ok((take, event))
    }

    /// Decide what a member is from its header name.
    fn classify(&self, hdr: &ArHeader) -> Result<Member> {
        let name = hdr.name.as_slice();
        if name == b"//" {
            return Ok(Member::NameTable);
        }
        if let Some(rest) = name.strip_prefix(b"/") {
            // `/<offset>` names a member via the long-name table; any other
            // `/`-prefixed name (`/`, `/SYM64/`, `/<ECSYMBOLS>/`) is special.
            return match header::parse_name_number(rest) {
                Some(offset) => self.lookup_long_name(offset).map(Member::Named),
                None => Ok(Member::Skip),
            };
        }
        if let Some(rest) = name.strip_prefix(b"#1/") {
            let len = header::parse_name_number(rest)
                .filter(|&len| len as usize <= MAX_NAME_SIZE && len <= hdr.size)
                .ok_or_else(|| {
                    Error::InvalidArHeader(format!(
                        "invalid BSD name length {:?} for member of size {}",
                        String::from_utf8_lossy(rest),
                        hdr.size
                    ))
                })?;
            return Ok(Member::BsdName(len as usize));
        }
        if name.starts_with(b"__.SYMDEF") {
            return Ok(Member::Skip);
        }
        // GNU terminates short names with '/'; BSD pads them with spaces
        // (already trimmed).
        let name = name.strip_suffix(b"/").unwrap_or(name);
        if name.is_empty() {
            return Err(Error::InvalidArHeader("empty member name".into()));
        }
        Ok(Member::Named(String::from_utf8_lossy(name).into_owned()))
    }

    /// Resolve a GNU `/<offset>` name. Entries in the table end with `/\n`
    /// (GNU) or NUL (Windows).
    fn lookup_long_name(&self, offset: u64) -> Result<String> {
        let table = self.name_table.as_deref().ok_or_else(|| {
            Error::InvalidArHeader("long name reference without a long-name table".into())
        })?;
        let tail = usize::try_from(offset)
            .ok()
            .and_then(|o| table.get(o..))
            .ok_or_else(|| {
                Error::InvalidArHeader(format!("long name offset {} out of range", offset))
            })?;
        let end = tail
            .iter()
            .position(|&b| b == b'\n' || b == 0)
            .unwrap_or(tail.len());
        let name = &tail[..end];
        let name = name.strip_suffix(b"/").unwrap_or(name);
        if name.is_empty() {
            return Err(Error::InvalidArHeader("empty member name".into()));
        }
        Ok(String::from_utf8_lossy(name).into_owned())
    }

    /// Build the entry for a member whose data starts at the current position.
    fn entry(&self, path: String, hdr: &ArHeader, size: u64) -> ArchiveEntry {
        ArchiveEntry {
            path,
            size,
            entry_type: EntryType::Regular,
            mode: hdr.mode & 0o7777,
            uid: hdr.uid,
            gid: hdr.gid,
            mtime: hdr.mtime,
            link_target: None,
            data_offset: self.stream_pos,
        }
    }

    /// Skip `data` member bytes followed by `pad` padding bytes.
    fn skip(&mut self, data: u64, pad: u64) {
        let remaining = data + pad;
        self.state = if remaining == 0 {
            ArState::ReadingHeader
        } else {
            ArState::SkippingData { remaining, pad }
        };
    }

    fn feed_name_table(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        let (remaining, buf) = match &mut self.state {
            ArState::ReadingNameTable { remaining, buf, .. } => (remaining, buf),
            _ => unreachable!(),
        };
        let take = data.len().min(*remaining);
        buf.extend_from_slice(&data[..take]);
        *remaining -= take;
        self.stream_pos += take as u64;
        if *remaining > 0 {
            return Ok((take, ArchiveEvent::NeedData));
        }

        let (buf, pad) = match std::mem::replace(&mut self.state, ArState::ReadingHeader) {
            ArState::ReadingNameTable { buf, pad, .. } => (buf, pad),
            _ => unreachable!(),
        };
        self.name_table = Some(buf);
        self.skip(0, pad);
        Ok((take, ArchiveEvent::NeedData))
    }

    fn feed_bsd_name(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        let (remaining, buf) = match &mut self.state {
            ArState::ReadingBsdName { remaining, buf, .. } => (remaining, buf),
            _ => unreachable!(),
        };
        let take = data.len().min(*remaining);
        buf.extend_from_slice(&data[..take]);
        *remaining -= take;
        self.stream_pos += take as u64;
        if *remaining > 0 {
            return Ok((take, ArchiveEvent::NeedData));
        }

        let (hdr, buf) = match std::mem::replace(&mut self.state, ArState::ReadingHeader) {
            ArState::ReadingBsdName { header, buf, .. } => (header, buf),
            _ => unreachable!(),
        };
        // The name is NUL-padded; the member size includes it.
        let name_end = buf.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        let name = &buf[..name_end];
        let data_size = hdr.size - buf.len() as u64;
        let pad = hdr.size & 1;

        if name.starts_with(b"__.SYMDEF") {
            self.skip(data_size, pad);
            return Ok((take, ArchiveEvent::NeedData));
        }
        if name.is_empty() {
            return Err(Error::InvalidArHeader("empty member name".into()));
        }
        let path = String::from_utf8_lossy(name).into_owned();
        let entry = self.entry(path, &hdr, data_size);
        self.skip(data_size, pad);
        Ok((take, ArchiveEvent::Entry(entry)))
    }

    fn feed_skip_data(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        let (remaining, pad) = match &mut self.state {
            ArState::SkippingData { remaining, pad } => (remaining, pad),
            _ => unreachable!(),
        };
        let skip = (data.len() as u64).min(*remaining) as usize;
        *remaining -= skip as u64;
        *pad = (*pad).min(*remaining);
        self.stream_pos += skip as u64;
        if *remaining == 0 {
            self.state = ArState::ReadingHeader;
        }
        Ok((skip, ArchiveEvent::NeedData))
    }
}

impl Default for ArParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveParser for ArParser {
    fn feed(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        if data.is_empty() {
            return Ok((0, ArchiveEvent::NeedData));
        }
        match &self.state {
            ArState::ReadingMagic => self.feed_magic(data),
            ArState::ReadingHeader => self.feed_header(data),
            ArState::ReadingNameTable { .. } => self.feed_name_table(data),
            ArState::ReadingBsdName { .. } => self.feed_bsd_name(data),
            ArState::SkippingData { .. } => self.feed_skip_data(data),
        }
    }

    fn stream_pos(&self) -> u64 {
        self.stream_pos
    }

    fn end_of_stream(&self) -> Result<()> {
        // ar has no trailer: the archive may end at any member boundary.
        let problem = match &self.state {
            ArState::ReadingHeader if self.header_buf.is_empty() => return Ok(()),
            // Some writers omit the pad byte after an odd-sized last member.
            ArState::SkippingData { remaining, pad } if remaining <= pad => return Ok(()),
            ArState::ReadingMagic => "stream ended inside the global header".to_string(),
            ArState::ReadingHeader => "stream ended inside a member header".to_string(),
            ArState::ReadingNameTable { .. } => {
                "stream ended inside the long-name table".to_string()
            }
            ArState::ReadingBsdName { .. } => "stream ended inside a member name".to_string(),
            ArState::SkippingData { remaining, pad } => format!(
                "stream ended {} bytes before the end of a member",
                remaining - pad
            ),
        };
        Err(Error::TruncatedArchive(problem))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member_header(name: &str, size: usize) -> Vec<u8> {
        format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            name, "1700000000", "1000", "1001", "100644", size
        )
        .into_bytes()
    }

    fn push_member(out: &mut Vec<u8>, name: &str, data: &[u8]) {
        out.extend_from_slice(&member_header(name, data.len()));
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
    }

    /// GNU-style archive: symbol table, long-name table, `name/` short names.
    fn gnu_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = AR_MAGIC.to_vec();
        push_member(&mut out, "/", b"\0\0\0\0");
        let mut table = Vec::new();
        let mut names = Vec::new();
        for (path, _) in files {
            if path.len() > 15 {
                names.push(format!("/{}", table.len()));
                table.extend_from_slice(path.as_bytes());
                table.extend_from_slice(b"/\n");
            } else {
                names.push(format!("{}/", path));
            }
        }
        if !table.is_empty() {
            push_member(&mut out, "//", &table);
        }
        for (name, (_, data)) in names.iter().zip(files) {
            push_member(&mut out, name, data);
        }
        out
    }

    /// BSD-style archive: `__.SYMDEF` and `#1/<len>` inline names.
    fn bsd_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = AR_MAGIC.to_vec();
        let mut symdef = b"__.SYMDEF SORTED\0\0\0\0".to_vec();
        symdef.extend_from_slice(&[0; 8]);
        push_member(&mut out, "#1/20", &symdef);
        for (path, data) in files {
            // Pad the name with NULs as Apple's ar does.
            let mut name = path.as_bytes().to_vec();
            name.resize((name.len() + 4) & !3, 0);
            let mut body = name.clone();
            body.extend_from_slice(data);
            push_member(&mut out, &format!("#1/{}", name.len()), &body);
        }
        out
    }

    /// Feed `data` in chunks of `chunk` bytes and collect the entries.
    fn parse_chunked(data: &[u8], chunk: usize) -> Result<Vec<ArchiveEntry>> {
        let mut parser = ArParser::new();
        let mut entries = Vec::new();
        for piece in data.chunks(chunk) {
            let mut offset = 0;
            while offset < piece.len() {
                let (consumed, event) = parser.feed(&piece[offset..])?;
                offset += consumed;
                match event {
                    ArchiveEvent::Entry(e) => entries.push(e),
                    ArchiveEvent::NeedData => {}
                    ArchiveEvent::EndOfArchive => unreachable!(),
                }
            }
        }
        assert_eq!(parser.stream_pos(), data.len() as u64);
        Ok(entries)
    }

    fn assert_entries(data: &[u8], files: &[(&str, &[u8])]) {
        for chunk in [1, 7, data.len()] {
            let entries = parse_chunked(data, chunk).unwrap();
            assert_eq!(entries.len(), files.len(), "chunk size {}", chunk);
            for (e, (path, content)) in entries.iter().zip(files) {
                assert_eq!(e.path, *path);
                assert_eq!(e.size, content.len() as u64);
                let start = e.data_offset as usize;
                assert_eq!(&data[start..start + content.len()], *content);
                assert_eq!(e.entry_type, EntryType::Regular);
                assert_eq!(e.mode, 0o644);
                assert_eq!((e.uid, e.gid, e.mtime), (1000, 1001, 1700000000));
            }
        }
    }

    const FILES: &[(&str, &[u8])] = &[
        ("a.o", b"odd"),
        ("a_rather_long_member_name.o", b"even"),
        ("empty.o", b""),
        ("another_long_member_name.o", b"x"),
        ("sub/dir.o", b"path"),
    ];

    #[test]
    fn test_gnu_archive() {
        assert_entries(&gnu_archive(FILES), FILES);
    }

    #[test]
    fn test_bsd_archive() {
        assert_entries(&bsd_archive(FILES), FILES);
    }

    #[test]
    fn test_bsd_short_names() {
        let mut data = AR_MAGIC.to_vec();
        push_member(&mut data, "short.o", b"abc");
        assert_entries(&data, &[("short.o", b"abc")]);
    }

    #[test]
    fn test_windows_nul_terminated_long_names() {
        let mut data = AR_MAGIC.to_vec();
        push_member(&mut data, "/", b"\0\0\0\0");
        push_member(&mut data, "/", b"\0\0\0\0");
        push_member(&mut data, "//", b"a_very_long_import_name.dll\0");
        push_member(&mut data, "/0", b"obj");
        assert_entries(&data, &[("a_very_long_import_name.dll", b"obj")]);
    }

    #[test]
    fn test_empty_archive() {
        assert!(parse_chunked(AR_MAGIC, 1).unwrap().is_empty());
    }

    #[test]
    fn test_thin_archive_rejected() {
        let err = parse_chunked(THIN_MAGIC, 8).unwrap_err();
        assert!(err.to_string().contains("thin"), "{}", err);
    }

    #[test]
    fn test_long_name_without_table_rejected() {
        let mut data = AR_MAGIC.to_vec();
        push_member(&mut data, "/0", b"x");
        assert!(parse_chunked(&data, 60).is_err());
    }

    #[test]
    fn test_long_name_offset_out_of_range_rejected() {
        let mut data = AR_MAGIC.to_vec();
        push_member(&mut data, "//", b"name/\n");
        push_member(&mut data, "/99", b"x");
        assert!(parse_chunked(&data, 60).is_err());
    }

    #[test]
    fn test_bsd_name_longer_than_member_rejected() {
        let mut data = AR_MAGIC.to_vec();
        push_member(&mut data, "#1/10", b"abc");
        assert!(parse_chunked(&data, 60).is_err());
    }

    #[test]
    fn test_implausible_name_table_rejected() {
        let mut data = AR_MAGIC.to_vec();
        data.extend_from_slice(&member_header("//", 1 << 30));
        assert!(parse_chunked(&data, 68).is_err());
    }
}
