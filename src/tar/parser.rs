use crate::archive::{ArchiveEvent, ArchiveParser};
use crate::error::Result;
use crate::tar::entry::{TarEntry, TarEntryType};
use crate::tar::header::{self, BLOCK_SIZE};

/// Events emitted by the incremental tar parser.
#[derive(Debug)]
pub enum TarEvent {
    /// A complete entry (file, directory, symlink, etc.) has been parsed.
    Entry(TarEntry),
    /// The parser needs more data.
    NeedData,
    /// End of archive detected.
    EndOfArchive,
}

/// Internal parser state.
#[derive(Debug)]
enum ParserState {
    /// Expecting a 512-byte header block.
    ReadingHeader,
    /// Skipping file data (during indexing, we don't need contents).
    SkippingData { remaining: u64 },
    /// Reading PAX extended header data.
    ReadingPaxData { remaining: u64, buf: Vec<u8> },
    /// Reading GNU long name/link data.
    ReadingGnuLong {
        remaining: u64,
        buf: Vec<u8>,
        is_link: bool,
    },
    /// We saw one zero block, looking for the second.
    OneZeroBlock,
    /// End of archive.
    End,
}

/// Incremental, sans-I/O tar parser.
///
/// Feed decompressed bytes in chunks. The parser processes them and
/// emits events (entries found, need more data, end of archive).
pub struct TarParser {
    state: ParserState,
    /// Buffer for accumulating a complete 512-byte header block.
    header_buf: [u8; BLOCK_SIZE],
    header_pos: usize,
    /// Current position in the uncompressed stream.
    stream_pos: u64,
    /// Pending PAX attributes for the next entry.
    pax_path: Option<String>,
    pax_linkpath: Option<String>,
    pax_size: Option<u64>,
    /// Pending GNU long name/link for the next entry.
    gnu_long_name: Option<String>,
    gnu_long_link: Option<String>,
}

impl TarParser {
    pub fn new() -> Self {
        Self {
            state: ParserState::ReadingHeader,
            header_buf: [0u8; BLOCK_SIZE],
            header_pos: 0,
            stream_pos: 0,
            pax_path: None,
            pax_linkpath: None,
            pax_size: None,
            gnu_long_name: None,
            gnu_long_link: None,
        }
    }

    /// Current position in the uncompressed stream.
    #[allow(dead_code)]
    pub fn stream_pos(&self) -> u64 {
        self.stream_pos
    }

    /// Feed decompressed data to the parser (tar-specific interface).
    ///
    /// Returns `(bytes_consumed, event)`. The caller should advance their
    /// buffer by `bytes_consumed` and call again if `NeedData` is returned
    /// and more data is available.
    pub fn feed_tar(&mut self, data: &[u8]) -> Result<(usize, TarEvent)> {
        match &mut self.state {
            ParserState::ReadingHeader => self.feed_header(data),
            ParserState::SkippingData { .. } => self.feed_skip(data),
            ParserState::ReadingPaxData { .. } => self.feed_pax(data),
            ParserState::ReadingGnuLong { .. } => self.feed_gnu_long(data),
            ParserState::OneZeroBlock => self.feed_second_zero(data),
            ParserState::End => Ok((0, TarEvent::EndOfArchive)),
        }
    }

    fn feed_header(&mut self, data: &[u8]) -> Result<(usize, TarEvent)> {
        if data.is_empty() {
            return Ok((0, TarEvent::NeedData));
        }

        let needed = BLOCK_SIZE - self.header_pos;
        let available = data.len().min(needed);
        self.header_buf[self.header_pos..self.header_pos + available]
            .copy_from_slice(&data[..available]);
        self.header_pos += available;
        self.stream_pos += available as u64;

        if self.header_pos < BLOCK_SIZE {
            return Ok((available, TarEvent::NeedData));
        }

        // We have a complete header block
        self.header_pos = 0;

        if header::is_zero_block(&self.header_buf) {
            self.state = ParserState::OneZeroBlock;
            return Ok((available, TarEvent::NeedData));
        }

        let data_offset = self.stream_pos;
        let mut entry = header::parse_header(&self.header_buf, data_offset)?;

        match entry.entry_type {
            TarEntryType::PaxExtended => {
                // Read PAX extended header data
                let padded = header::padded_size(entry.size);
                self.state = ParserState::ReadingPaxData {
                    remaining: padded,
                    buf: Vec::with_capacity(entry.size as usize),
                };
                return Ok((available, TarEvent::NeedData));
            }
            TarEntryType::PaxGlobal => {
                // Skip global PAX headers for now
                let padded = header::padded_size(entry.size);
                self.state = ParserState::SkippingData { remaining: padded };
                return Ok((available, TarEvent::NeedData));
            }
            TarEntryType::GnuLongName => {
                let padded = header::padded_size(entry.size);
                self.state = ParserState::ReadingGnuLong {
                    remaining: padded,
                    buf: Vec::with_capacity(entry.size as usize),
                    is_link: false,
                };
                return Ok((available, TarEvent::NeedData));
            }
            TarEntryType::GnuLongLink => {
                let padded = header::padded_size(entry.size);
                self.state = ParserState::ReadingGnuLong {
                    remaining: padded,
                    buf: Vec::with_capacity(entry.size as usize),
                    is_link: true,
                };
                return Ok((available, TarEvent::NeedData));
            }
            _ => {}
        }

        // Apply pending PAX/GNU attributes
        if let Some(path) = self.pax_path.take() {
            entry.path = path;
        }
        if let Some(linkpath) = self.pax_linkpath.take() {
            entry.link_target = Some(linkpath);
        }
        if let Some(size) = self.pax_size.take() {
            entry.size = size;
        }
        if let Some(name) = self.gnu_long_name.take() {
            entry.path = name;
        }
        if let Some(link) = self.gnu_long_link.take() {
            entry.link_target = Some(link);
        }

        // Set up to skip file data
        let padded = header::padded_size(entry.size);
        if padded > 0 {
            self.state = ParserState::SkippingData { remaining: padded };
        } else {
            self.state = ParserState::ReadingHeader;
        }

        Ok((available, TarEvent::Entry(entry)))
    }

    fn feed_skip(&mut self, data: &[u8]) -> Result<(usize, TarEvent)> {
        if data.is_empty() {
            return Ok((0, TarEvent::NeedData));
        }

        if let ParserState::SkippingData { remaining } = &mut self.state {
            let skip = (data.len() as u64).min(*remaining) as usize;
            *remaining -= skip as u64;
            self.stream_pos += skip as u64;

            if *remaining == 0 {
                self.state = ParserState::ReadingHeader;
            }

            Ok((skip, TarEvent::NeedData))
        } else {
            unreachable!()
        }
    }

    fn feed_pax(&mut self, data: &[u8]) -> Result<(usize, TarEvent)> {
        if data.is_empty() {
            return Ok((0, TarEvent::NeedData));
        }

        if let ParserState::ReadingPaxData { remaining, buf } = &mut self.state {
            let take = (data.len() as u64).min(*remaining) as usize;
            // Only accumulate non-padding bytes
            let useful = take.min(buf.capacity() - buf.len());
            if useful > 0 {
                buf.extend_from_slice(&data[..useful]);
            }
            *remaining -= take as u64;
            self.stream_pos += take as u64;

            if *remaining == 0 {
                // Parse the PAX data
                let pax_data = std::mem::take(buf);
                self.parse_pax_data(&pax_data);
                self.state = ParserState::ReadingHeader;
            }

            Ok((take, TarEvent::NeedData))
        } else {
            unreachable!()
        }
    }

    fn feed_gnu_long(&mut self, data: &[u8]) -> Result<(usize, TarEvent)> {
        if data.is_empty() {
            return Ok((0, TarEvent::NeedData));
        }

        if let ParserState::ReadingGnuLong {
            remaining,
            buf,
            is_link,
        } = &mut self.state
        {
            let take = (data.len() as u64).min(*remaining) as usize;
            let useful = take.min(buf.capacity() - buf.len());
            if useful > 0 {
                buf.extend_from_slice(&data[..useful]);
            }
            *remaining -= take as u64;
            self.stream_pos += take as u64;

            if *remaining == 0 {
                let long_data = std::mem::take(buf);
                let is_link_val = *is_link;
                let name = String::from_utf8_lossy(&long_data)
                    .trim_end_matches('\0')
                    .to_string();

                if is_link_val {
                    self.gnu_long_link = Some(name);
                } else {
                    self.gnu_long_name = Some(name);
                }
                self.state = ParserState::ReadingHeader;
            }

            Ok((take, TarEvent::NeedData))
        } else {
            unreachable!()
        }
    }

    fn feed_second_zero(&mut self, data: &[u8]) -> Result<(usize, TarEvent)> {
        if data.is_empty() {
            return Ok((0, TarEvent::NeedData));
        }

        let needed = BLOCK_SIZE - self.header_pos;
        let available = data.len().min(needed);
        self.header_buf[self.header_pos..self.header_pos + available]
            .copy_from_slice(&data[..available]);
        self.header_pos += available;
        self.stream_pos += available as u64;

        if self.header_pos < BLOCK_SIZE {
            return Ok((available, TarEvent::NeedData));
        }

        self.header_pos = 0;

        if header::is_zero_block(&self.header_buf) {
            self.state = ParserState::End;
            Ok((available, TarEvent::EndOfArchive))
        } else {
            // Not actually end of archive — this was a valid header after a zero block
            // (unusual but technically possible)
            let data_offset = self.stream_pos;
            let entry = header::parse_header(&self.header_buf, data_offset)?;
            let padded = header::padded_size(entry.size);
            if padded > 0 {
                self.state = ParserState::SkippingData { remaining: padded };
            } else {
                self.state = ParserState::ReadingHeader;
            }
            Ok((available, TarEvent::Entry(entry)))
        }
    }

    /// Parse PAX extended header data (key=value pairs).
    fn parse_pax_data(&mut self, data: &[u8]) {
        let text = String::from_utf8_lossy(data);
        for line in text.split('\n') {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Format: "len key=value\n"
            if let Some(space_pos) = line.find(' ') {
                let rest = &line[space_pos + 1..];
                if let Some(eq_pos) = rest.find('=') {
                    let key = &rest[..eq_pos];
                    let value = &rest[eq_pos + 1..];
                    match key {
                        "path" => self.pax_path = Some(value.to_string()),
                        "linkpath" => self.pax_linkpath = Some(value.to_string()),
                        "size" => {
                            if let Ok(size) = value.parse::<u64>() {
                                self.pax_size = Some(size);
                            }
                        }
                        _ => {} // Ignore other PAX attributes
                    }
                }
            }
        }
    }
}

impl Default for TarParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveParser for TarParser {
    fn feed(&mut self, data: &[u8]) -> Result<(usize, ArchiveEvent)> {
        let (consumed, event) = self.feed_tar(data)?;
        let archive_event = match event {
            TarEvent::Entry(entry) => ArchiveEvent::Entry(entry.into()),
            TarEvent::NeedData => ArchiveEvent::NeedData,
            TarEvent::EndOfArchive => ArchiveEvent::EndOfArchive,
        };
        Ok((consumed, archive_event))
    }

    fn stream_pos(&self) -> u64 {
        self.stream_pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal valid tar archive with one file.
    fn create_test_tar(filename: &str, content: &[u8]) -> Vec<u8> {
        let mut archive = Vec::new();

        // Build header
        let mut header = [0u8; 512];

        // Name (0-99)
        let name_bytes = filename.as_bytes();
        header[..name_bytes.len()].copy_from_slice(name_bytes);

        // Mode (100-107): "0000644\0"
        header[100..108].copy_from_slice(b"0000644\0");

        // UID (108-115): "0001000\0"
        header[108..116].copy_from_slice(b"0001000\0");

        // GID (116-123): "0001000\0"
        header[116..124].copy_from_slice(b"0001000\0");

        // Size (124-135): octal
        let size_str = format!("{:011o}\0", content.len());
        header[124..136].copy_from_slice(size_str.as_bytes());

        // Mtime (136-147)
        header[136..148].copy_from_slice(b"14267657570\0");

        // Typeflag (156): '0' for regular file
        header[156] = b'0';

        // Magic (257-262): "ustar"
        header[257..262].copy_from_slice(b"ustar");

        // Version (263-264): "00"
        header[263..265].copy_from_slice(b"00");

        // Calculate checksum
        // First fill checksum field with spaces
        header[148..156].copy_from_slice(b"        ");
        let checksum: u32 = header.iter().map(|&b| b as u32).sum();
        let checksum_str = format!("{:06o}\0 ", checksum);
        header[148..156].copy_from_slice(checksum_str.as_bytes());

        archive.extend_from_slice(&header);

        // File content (padded to 512-byte boundary)
        archive.extend_from_slice(content);
        let padding = (512 - (content.len() % 512)) % 512;
        archive.extend(std::iter::repeat(0u8).take(padding));

        // Two zero blocks for end-of-archive
        archive.extend(std::iter::repeat(0u8).take(1024));

        archive
    }

    #[test]
    fn test_parse_single_file() {
        let tar_data = create_test_tar("hello.txt", b"Hello, world!");
        let mut parser = TarParser::new();

        let mut offset = 0;
        let mut entries = Vec::new();

        loop {
            let (consumed, event) = parser.feed_tar(&tar_data[offset..]).unwrap();
            offset += consumed;
            match event {
                TarEvent::Entry(entry) => entries.push(entry),
                TarEvent::NeedData => {
                    if offset >= tar_data.len() {
                        break;
                    }
                }
                TarEvent::EndOfArchive => break,
            }
        }

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "hello.txt");
        assert_eq!(entries[0].size, 13);
        assert_eq!(entries[0].entry_type, TarEntryType::Regular);
    }

    #[test]
    fn test_parse_byte_by_byte() {
        let tar_data = create_test_tar("test.txt", b"test");
        let mut parser = TarParser::new();

        let mut offset = 0;
        let mut entries = Vec::new();

        while offset < tar_data.len() {
            let (consumed, event) = parser.feed_tar(&tar_data[offset..offset + 1]).unwrap();
            offset += consumed;
            match event {
                TarEvent::Entry(entry) => entries.push(entry),
                TarEvent::NeedData => {}
                TarEvent::EndOfArchive => break,
            }
        }

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "test.txt");
    }

    #[test]
    fn test_parse_empty_archive() {
        // An archive with just two zero blocks
        let tar_data = vec![0u8; 1024];
        let mut parser = TarParser::new();

        let (consumed, _event) = parser.feed(&tar_data).unwrap();
        assert!(consumed > 0);

        let mut offset = consumed;
        loop {
            let (consumed, event) = parser.feed_tar(&tar_data[offset..]).unwrap();
            offset += consumed;
            match event {
                TarEvent::EndOfArchive => break,
                TarEvent::NeedData => {
                    if offset >= tar_data.len() {
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_parse_multiple_files() {
        let mut archive = Vec::new();

        // First file
        let tar1 = create_test_tar("file1.txt", b"content1");
        // Take only the header + data (skip the two end-of-archive zero blocks)
        let data_end = 512 + 512; // header + one data block
        archive.extend_from_slice(&tar1[..data_end]);

        // Second file
        let tar2 = create_test_tar("file2.txt", b"content2content2");
        archive.extend_from_slice(&tar2[..512 + 512]); // header + one data block

        // End of archive
        archive.extend(std::iter::repeat(0u8).take(1024));

        let mut parser = TarParser::new();
        let mut offset = 0;
        let mut entries = Vec::new();

        loop {
            let (consumed, event) = parser.feed_tar(&archive[offset..]).unwrap();
            offset += consumed;
            match event {
                TarEvent::Entry(entry) => entries.push(entry),
                TarEvent::NeedData => {
                    if offset >= archive.len() {
                        break;
                    }
                }
                TarEvent::EndOfArchive => break,
            }
        }

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "file1.txt");
        assert_eq!(entries[0].size, 8);
        assert_eq!(entries[1].path, "file2.txt");
        assert_eq!(entries[1].size, 16);
    }

    #[test]
    fn test_data_offset_tracking() {
        let tar_data = create_test_tar("data.bin", b"0123456789");
        let mut parser = TarParser::new();

        let mut offset = 0;
        let mut entries = Vec::new();

        loop {
            let (consumed, event) = parser.feed_tar(&tar_data[offset..]).unwrap();
            offset += consumed;
            match event {
                TarEvent::Entry(entry) => entries.push(entry),
                TarEvent::NeedData => {
                    if offset >= tar_data.len() {
                        break;
                    }
                }
                TarEvent::EndOfArchive => break,
            }
        }

        assert_eq!(entries.len(), 1);
        // Data offset should be right after the 512-byte header
        assert_eq!(entries[0].data_offset, 512);
    }
}
