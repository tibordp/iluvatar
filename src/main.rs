use clap::{Parser, Subcommand};
use std::fs::{self, File};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use supertar::sync::Archive;
use supertar::{ArchiveIndex, EntryType, DEFAULT_CHECKPOINT_INTERVAL};

#[derive(Parser)]
#[command(name = "supertar", version, about = "Random-access compressed archive tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build a persistent index for fast random access
    Index {
        /// Archive file
        archive: PathBuf,
        /// Checkpoint interval in bytes
        #[arg(short, long, default_value_t = DEFAULT_CHECKPOINT_INTERVAL)]
        interval: u64,
    },
    /// List archive contents
    Ls {
        /// Archive file
        archive: PathBuf,
        /// Path prefix to filter
        path: Option<String>,
        /// Long listing format
        #[arg(short, long)]
        long: bool,
    },
    /// Print file contents to stdout
    Cat {
        /// Archive file
        archive: PathBuf,
        /// Path within the archive
        path: String,
        /// Start byte offset within the file
        #[arg(long)]
        offset: Option<u64>,
        /// Number of bytes to read
        #[arg(long)]
        length: Option<u64>,
    },
    /// Extract a file from the archive
    Cp {
        /// Archive file
        archive: PathBuf,
        /// Path within the archive
        path: String,
        /// Destination path (file or directory)
        dest: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("\x1b[1;31merror\x1b[0m: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Index { archive, interval } => cmd_index(&archive, interval),
        Command::Ls { archive, path, long } => cmd_ls(&archive, path.as_deref(), long),
        Command::Cat {
            archive,
            path,
            offset,
            length,
        } => cmd_cat(&archive, &path, offset, length),
        Command::Cp {
            archive,
            path,
            dest,
        } => cmd_cp(&archive, &path, &dest),
    }
}

// ─── Index path convention: archive.tar.gz → archive.tar.gz.stidx ───

fn index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_owned();
    s.push(".stidx");
    PathBuf::from(s)
}

// ─── Index management ───

fn load_index(archive: &Path) -> Result<Option<ArchiveIndex>, Box<dyn std::error::Error>> {
    let p = index_path(archive);
    if !p.exists() {
        return Ok(None);
    }
    let data = fs::read(&p)?;
    Ok(Some(ArchiveIndex::from_bytes(&data)?))
}

fn build_index(
    archive: &Path,
    interval: u64,
) -> Result<ArchiveIndex, Box<dyn std::error::Error>> {
    let mut file = File::open(archive)?;
    let size = file.metadata()?.len();
    let tty = io::stderr().is_terminal();
    let mut last_pct = 255u8;

    let index = Archive::build_index_with_progress(&mut file, size, interval, |p| {
        if !tty {
            return true;
        }
        let pct = p.fraction().map(|f| (f * 100.0) as u8).unwrap_or(0);
        if pct != last_pct {
            last_pct = pct;
            let frac = p.fraction().unwrap_or(0.0);
            let bar_w = 30;
            let filled = (frac * bar_w as f64) as usize;
            eprint!(
                "\r\x1b[2Kindexing  {pct:>3}% \x1b[32m{}\x1b[0m{} {:>9}  {} entries",
                "\u{2588}".repeat(filled),
                "\u{2591}".repeat(bar_w - filled),
                human_size(p.compressed_bytes_processed),
                p.entries_found,
            );
        }
        true
    })?;

    if tty {
        eprintln!(
            "\r\x1b[2K\x1b[1;32m done\x1b[0m  {} entries, {} checkpoints, {} compressed",
            index.entries.len(),
            index.checkpoints.len(),
            human_size(size),
        );
    }

    Ok(index)
}

fn require_index(archive: &Path) -> Result<ArchiveIndex, Box<dyn std::error::Error>> {
    if let Some(idx) = load_index(archive)? {
        return Ok(idx);
    }
    if io::stderr().is_terminal() {
        eprintln!("\x1b[33mno index found, building on-the-fly...\x1b[0m");
    }
    build_index(archive, DEFAULT_CHECKPOINT_INTERVAL)
}

fn open_archive(archive: &Path) -> Result<Archive<File>, Box<dyn std::error::Error>> {
    let index = require_index(archive)?;
    let file = File::open(archive)?;
    Ok(Archive::from_parts(file, index))
}

// ─── Commands ───

fn cmd_index(archive: &Path, interval: u64) -> Result<(), Box<dyn std::error::Error>> {
    let index = build_index(archive, interval)?;
    let p = index_path(archive);
    let data = index.to_bytes()?;
    fs::write(&p, &data)?;
    eprintln!(
        "\x1b[1;32msaved\x1b[0m  {} ({})",
        p.display(),
        human_size(data.len() as u64),
    );
    Ok(())
}

fn cmd_ls(
    archive: &Path,
    path: Option<&str>,
    long: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let index = require_index(archive)?;
    let mut entries: Vec<_> = index.list(path).into_iter().cloned().collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let out = io::stdout();
    let color = out.is_terminal();
    let mut out = io::BufWriter::new(out.lock());

    if long {
        let size_w = entries
            .iter()
            .map(|e| digit_count(e.size))
            .max()
            .unwrap_or(1)
            .max(4);

        for e in &entries {
            let mode = format_mode(e.mode, &e.entry_type);
            let date = format_mtime(e.mtime);
            let name = format_name(
                &e.path,
                &e.entry_type,
                e.mode,
                e.link_target.as_deref(),
                color,
            );
            writeln!(
                out,
                "{mode} {s:>w$}  {date}  {name}",
                s = e.size,
                w = size_w
            )?;
        }
    } else {
        for e in &entries {
            writeln!(
                out,
                "{}",
                format_name(&e.path, &e.entry_type, e.mode, None, color)
            )?;
        }
    }

    Ok(())
}

fn cmd_cat(
    archive: &Path,
    path: &str,
    offset: Option<u64>,
    length: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ar = open_archive(archive)?;

    let (is_dir, file_size) = {
        let entry = ar
            .index()
            .get(path)
            .ok_or_else(|| format!("not found: {path}"))?;
        (entry.entry_type.is_directory(), entry.size)
    };

    if is_dir {
        return Err(format!("{path}: is a directory").into());
    }

    let data = if offset.is_some() || length.is_some() {
        let off = offset.unwrap_or(0);
        let len = length.unwrap_or(file_size.saturating_sub(off));
        ar.read_file_range(path, off, len)?
    } else {
        ar.read_file(path)?
    };

    if io::stdout().is_terminal() && is_binary(&data) {
        eprintln!("\x1b[33mwarning\x1b[0m: binary data, consider redirecting to a file");
    }

    let mut out = io::stdout().lock();
    match out.write_all(&data) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn cmd_cp(
    archive: &Path,
    path: &str,
    dest: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ar = open_archive(archive)?;

    let (is_dir, file_size) = {
        let entry = ar
            .index()
            .get(path)
            .ok_or_else(|| format!("not found: {path}"))?;
        (entry.entry_type.is_directory(), entry.size)
    };

    if is_dir {
        return Err(format!("{path}: is a directory").into());
    }

    let data = ar.read_file(path)?;

    let dest = if dest.is_dir() {
        let name = Path::new(path)
            .file_name()
            .ok_or_else(|| format!("no filename in archive path: {path}"))?;
        dest.join(name)
    } else {
        dest.to_path_buf()
    };

    fs::write(&dest, &data)?;

    if io::stderr().is_terminal() {
        eprintln!(
            "\x1b[1;32mextracted\x1b[0m  {} ({})",
            dest.display(),
            human_size(file_size),
        );
    }

    Ok(())
}

// ─── Formatting helpers ───

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    for &unit in UNITS {
        if size < 1024.0 {
            return if unit == "B" {
                format!("{size:.0} {unit}")
            } else {
                format!("{size:.1} {unit}")
            };
        }
        size /= 1024.0;
    }
    format!("{size:.1} PiB")
}

fn digit_count(n: u64) -> usize {
    if n == 0 {
        return 1;
    }
    (n as f64).log10() as usize + 1
}

fn format_mode(mode: u32, et: &EntryType) -> String {
    let t = match et {
        EntryType::Directory => 'd',
        EntryType::SymLink => 'l',
        EntryType::CharDevice => 'c',
        EntryType::BlockDevice => 'b',
        EntryType::Fifo => 'p',
        EntryType::Socket => 's',
        EntryType::HardLink => 'h',
        _ => '-',
    };
    let bits = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    let perms: String = bits
        .iter()
        .map(|&(bit, ch)| if mode & bit != 0 { ch } else { '-' })
        .collect();
    format!("{t}{perms}")
}

fn format_mtime(ts: u64) -> String {
    let (y, m, d, h, min) = epoch_to_civil(ts);
    format!("{y}-{m:02}-{d:02} {h:02}:{min:02}")
}

/// Convert unix timestamp to (year, month, day, hour, minute).
/// Uses Howard Hinnant's civil_from_days algorithm.
fn epoch_to_civil(ts: u64) -> (i64, u32, u32, u32, u32) {
    let ts = ts as i64;
    let days = ts.div_euclid(86400);
    let secs = ts.rem_euclid(86400);
    let h = (secs / 3600) as u32;
    let min = ((secs % 3600) / 60) as u32;

    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, min)
}

fn format_name(
    path: &str,
    et: &EntryType,
    mode: u32,
    link: Option<&str>,
    color: bool,
) -> String {
    if !color {
        return match (et, link) {
            (EntryType::SymLink, Some(t)) => format!("{path} -> {t}"),
            (EntryType::HardLink, Some(t)) => format!("{path} => {t}"),
            _ => path.to_string(),
        };
    }
    match et {
        EntryType::Directory => format!("\x1b[1;34m{path}\x1b[0m"),
        EntryType::SymLink => match link {
            Some(t) => format!("\x1b[1;36m{path}\x1b[0m -> {t}"),
            None => format!("\x1b[1;36m{path}\x1b[0m"),
        },
        EntryType::HardLink => match link {
            Some(t) => format!("{path} => {t}"),
            None => path.to_string(),
        },
        _ if mode & 0o111 != 0 => format!("\x1b[1;32m{path}\x1b[0m"),
        _ => path.to_string(),
    }
}

fn is_binary(data: &[u8]) -> bool {
    let check_len = data.len().min(8192);
    data[..check_len].contains(&0)
}
