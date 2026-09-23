//! End-to-end benchmarks: the library used the way it's meant to be used.
//!
//! Where `throughput` measures raw decoder speed, these cover the whole
//! path: indexing an archive (with checkpointing), saving and loading the
//! index, random file and range reads through restored checkpoints, full
//! extraction, bare compressed streams, and taking/restoring individual
//! checkpoints. Every scenario runs for gzip, bzip2, xz and zstd.
//!
//! ```text
//! cargo bench --bench e2e                           # everything (~8 min)
//! cargo bench --bench e2e -- 'read/.*zstd'          # regex filter on ids
//! cargo bench --bench e2e -- --save-baseline before # record a baseline...
//! cargo bench --bench e2e -- --baseline before      # ...and compare to it
//! ```
//!
//! Benchmark ids are `<group>/<scenario>/<codec>[-<strategy>]`. Strategies:
//! `default` is the format's default checkpoint interval (a single
//! checkpoint for xz/zstd at this corpus size, so reads decode from the
//! start); `1mib` checkpoints every MiB, the setting random access wants.
//!
//! The corpus is a deterministic ~19 MiB tar (source-like text files, JSON
//! logs, one large log, one incompressible blob). Fixture sizes (compressed
//! size, checkpoint count, index size) are printed on first use.

use std::hint::black_box;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::sync::OnceLock;
use std::time::Duration;

use criterion::measurement::WallTime;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion, Throughput};

use iluvatar::compress::decompressor::{DecompressStatus, Decompressor};
use iluvatar::sync::{Archive, Stream};
use iluvatar::{
    ArchiveIndex, Checkpoint, CodecSpec, CompressionFormat, EngineRequest, EntryType,
    FixedInterval, IndexEntry, StreamReader,
};

/// Checkpoint interval of the dense (`1mib`) strategy.
const DENSE_INTERVAL: u64 = 1 << 20;
/// The large member used for range reads and as the bare stream.
const BIG_FILE: &str = "logs/big.log";

// ─── Corpus ──────────────────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Source-like text: identifiers from a shared vocabulary, so there are
/// both near matches (within a file) and far ones (across files).
fn source_text(rng: &mut Rng, size: usize) -> Vec<u8> {
    const WORDS: &str = "let fn match return self impl pub struct if else for while mut usize \
        Result Option Some None Ok Err buffer offset decoder state index checkpoint window len \
        data input";
    let words: Vec<&str> = WORDS.split_whitespace().collect();
    let mut out = Vec::with_capacity(size + 80);
    while out.len() < size {
        let indent = rng.below(4) as usize * 4;
        out.resize(out.len() + indent, b' ');
        for _ in 0..rng.below(8) + 2 {
            out.extend_from_slice(words[rng.below(words.len() as u64) as usize].as_bytes());
            out.push(if rng.below(5) == 0 { b'_' } else { b' ' });
        }
        if rng.below(3) == 0 {
            out.extend_from_slice(format!("{}", rng.next() % 100_000).as_bytes());
        }
        out.extend_from_slice(b";\n");
    }
    out.truncate(size);
    out
}

/// JSON-ish log lines: repetitive keys, random values.
fn log_lines(rng: &mut Rng, size: usize) -> Vec<u8> {
    const LEVELS: &[&str] = &["debug", "info", "info", "info", "warn", "error"];
    let mut out = Vec::with_capacity(size + 160);
    let mut ts = 1_700_000_000_000u64;
    while out.len() < size {
        ts += rng.below(5000);
        out.extend_from_slice(
            format!(
                "{{\"ts\":{},\"level\":\"{}\",\"req\":\"{:016x}\",\"latency_ms\":{},\"path\":\"/api/v{}/items/{}\"}}\n",
                ts,
                LEVELS[rng.below(LEVELS.len() as u64) as usize],
                rng.next() ^ (rng.next() << 31),
                rng.below(2000),
                rng.below(3) + 1,
                rng.below(50_000),
            )
            .as_bytes(),
        );
    }
    out.truncate(size);
    out
}

struct Corpus {
    tar: Vec<u8>,
    /// Regular-file paths in a fixed pseudo-random order (for random reads).
    shuffled_paths: Vec<String>,
    big_file_len: u64,
}

fn corpus() -> &'static Corpus {
    static CORPUS: OnceLock<Corpus> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let mut rng = Rng(0x5eed);
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        for i in 0..400 {
            let size = 1024 + rng.below(31 * 1024) as usize;
            files.push((
                format!("src/mod{}/file{i}.rs", i % 20),
                source_text(&mut rng, size),
            ));
        }
        for i in 0..20 {
            let size = 128 * 1024 + rng.below(384 * 1024) as usize;
            files.push((format!("logs/service{i}.jsonl"), log_lines(&mut rng, size)));
        }
        files.push((BIG_FILE.to_string(), log_lines(&mut rng, 6 << 20)));
        files.push((
            "assets/blob.bin".to_string(),
            (0..1 << 20).map(|_| rng.next() as u8).collect(),
        ));
        let big_file_len = files.iter().find(|(p, _)| p == BIG_FILE).unwrap().1.len() as u64;

        let mut builder = tar::Builder::new(Vec::new());
        for (path, data) in &files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            builder
                .append_data(&mut header, path, data.as_slice())
                .unwrap();
        }
        let tar = builder.into_inner().unwrap();

        let mut shuffled_paths: Vec<String> = files.into_iter().map(|(p, _)| p).collect();
        for i in (1..shuffled_paths.len()).rev() {
            let j = rng.below(i as u64 + 1) as usize;
            shuffled_paths.swap(i, j);
        }
        Corpus {
            tar,
            shuffled_paths,
            big_file_len,
        }
    })
}

// ─── Fixtures ────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Format {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

const FORMATS: [Format; 4] = [Format::Gzip, Format::Bzip2, Format::Xz, Format::Zstd];

impl Format {
    fn name(self) -> &'static str {
        match self {
            Format::Gzip => "gzip",
            Format::Bzip2 => "bzip2",
            Format::Xz => "xz",
            Format::Zstd => "zstd",
        }
    }

    fn compression(self) -> CompressionFormat {
        match self {
            Format::Gzip => CompressionFormat::Gzip,
            Format::Bzip2 => CompressionFormat::Bzip2,
            Format::Xz => CompressionFormat::Xz,
            Format::Zstd => CompressionFormat::Zstd,
        }
    }

    /// Compress with the reference encoder at its common default level.
    fn compress(self, data: &[u8]) -> Vec<u8> {
        match self {
            Format::Gzip => {
                let mut e =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            Format::Bzip2 => {
                let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            Format::Xz => {
                let mut e = xz2::write::XzEncoder::new(Vec::new(), 6);
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            Format::Zstd => zstd::encode_all(data, 3).unwrap(),
        }
    }
}

struct Fixture {
    /// The corpus tar, compressed.
    archive: Vec<u8>,
    /// Index built with the format's default strategy.
    index_default: ArchiveIndex,
    /// Index built with a checkpoint every `DENSE_INTERVAL`.
    index_dense: ArchiveIndex,
    /// `BIG_FILE` alone, compressed (a bare stream).
    stream: Vec<u8>,
}

fn fixture(format: Format) -> &'static Fixture {
    static FIXTURES: [OnceLock<Fixture>; 4] = [
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
    ];
    FIXTURES[format as usize].get_or_init(|| {
        let corpus = corpus();
        let archive = format.compress(&corpus.tar);
        let index_default = Archive::new(Cursor::new(archive.as_slice()))
            .unwrap()
            .into_parts()
            .1;
        let index_dense = Archive::with_strategy(
            Cursor::new(archive.as_slice()),
            FixedInterval::new(DENSE_INTERVAL),
        )
        .unwrap()
        .into_parts()
        .1;
        let big = Archive::from_parts(Cursor::new(archive.as_slice()), index_dense.clone())
            .read_file(BIG_FILE)
            .unwrap();
        let stream = format.compress(&big);

        let index_bytes = |index: &ArchiveIndex| index.to_bytes().unwrap().len();
        println!(
            "[fixture {:>5}] tar {:.1} MiB -> {:.2} MiB; checkpoints: default {} ({} B index), \
             1mib {} ({} B index)",
            format.name(),
            corpus.tar.len() as f64 / (1 << 20) as f64,
            archive.len() as f64 / (1 << 20) as f64,
            index_default.checkpoints().len(),
            index_bytes(&index_default),
            index_dense.checkpoints().len(),
            index_bytes(&index_dense),
        );
        Fixture {
            archive,
            index_default,
            index_dense,
            stream,
        }
    })
}

/// (id suffix, index) for both strategies.
fn strategies(f: &Fixture) -> [(&'static str, &ArchiveIndex); 2] {
    [("default", &f.index_default), ("1mib", &f.index_dense)]
}

fn configure(group: &mut BenchmarkGroup<'_, WallTime>, sample_size: usize, secs: u64) {
    group
        .sample_size(sample_size)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(secs));
}

// ─── Indexing ────────────────────────────────────────────────────────────

/// Full indexing pass (decode everything, parse tar headers, checkpoint).
fn bench_index_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("index/build");
    configure(&mut group, 10, 8);
    group.throughput(Throughput::Bytes(corpus().tar.len() as u64));
    for format in FORMATS {
        let f = fixture(format);
        group.bench_function(format!("{}-default", format.name()), |b| {
            b.iter(|| Archive::new(Cursor::new(f.archive.as_slice())).unwrap())
        });
        group.bench_function(format!("{}-1mib", format.name()), |b| {
            b.iter(|| {
                Archive::with_strategy(
                    Cursor::new(f.archive.as_slice()),
                    FixedInterval::new(DENSE_INTERVAL),
                )
                .unwrap()
            })
        });
    }
    group.finish();
}

/// Saving and loading an index (the dense one, where checkpoints dominate).
fn bench_index_serde(c: &mut Criterion) {
    let mut group = c.benchmark_group("index");
    configure(&mut group, 10, 3);
    for format in FORMATS {
        let index = &fixture(format).index_dense;
        let bytes = index.to_bytes().unwrap();
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function(format!("to_bytes/{}-1mib", format.name()), |b| {
            b.iter(|| index.to_bytes().unwrap())
        });
        group.bench_function(format!("from_bytes/{}-1mib", format.name()), |b| {
            b.iter(|| ArchiveIndex::from_bytes(black_box(&bytes)).unwrap())
        });
    }
    group.finish();
}

// ─── Reads through an index ──────────────────────────────────────────────

/// Whole files in random order: restore the nearest checkpoint, decode
/// forward to the file, read it.
fn bench_read_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("read/file_random");
    configure(&mut group, 20, 5);
    group.throughput(Throughput::Elements(1));
    let paths = &corpus().shuffled_paths;
    for format in FORMATS {
        let f = fixture(format);
        for (strategy, index) in strategies(f) {
            let mut archive = Archive::from_parts(Cursor::new(f.archive.as_slice()), index.clone());
            let mut i = 0;
            group.bench_function(format!("{}-{strategy}", format.name()), |b| {
                b.iter(|| {
                    let path = &paths[i % paths.len()];
                    i += 1;
                    archive.read_file(path).unwrap()
                })
            });
        }
    }
    group.finish();
}

/// 4 KiB reads at random offsets inside one large member: the range read
/// picks the checkpoint nearest the offset, not the file's start.
fn bench_read_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("read/range_4k");
    configure(&mut group, 20, 4);
    group.throughput(Throughput::Elements(1));
    let big_len = corpus().big_file_len;
    for format in FORMATS {
        let f = fixture(format);
        for (strategy, index) in strategies(f) {
            let mut archive = Archive::from_parts(Cursor::new(f.archive.as_slice()), index.clone());
            let mut rng = Rng(42);
            group.bench_function(format!("{}-{strategy}", format.name()), |b| {
                b.iter(|| {
                    let offset = rng.below(big_len - 4096);
                    archive.read_file_range(BIG_FILE, offset, 4096).unwrap()
                })
            });
        }
    }
    group.finish();
}

/// Extracting files one after another in archive order. `read_file`
/// restores a checkpoint and decodes forward for every file; a live
/// `StreamReader` makes it one pass. The `read_file` loop is limited to
/// the first `EXTRACT_FILES` files to keep bzip2/xz runs short.
fn bench_extract_sequential(c: &mut Criterion) {
    const EXTRACT_FILES: usize = 60;
    let mut group = c.benchmark_group("read/extract_sequential");
    configure(&mut group, 10, 6);
    for format in FORMATS {
        let f = fixture(format);
        let mut archive =
            Archive::from_parts(Cursor::new(f.archive.as_slice()), f.index_dense.clone());
        let files: Vec<(String, u64)> = archive
            .list()
            .into_iter()
            .filter(|e| e.entry_type == EntryType::Regular)
            .take(EXTRACT_FILES)
            .map(|e| (e.path.clone(), e.size))
            .collect();
        group.throughput(Throughput::Bytes(files.iter().map(|(_, size)| size).sum()));
        group.bench_function(format!("read_file/{}-1mib", format.name()), |b| {
            b.iter(|| {
                for (path, _) in &files {
                    black_box(archive.read_file(path).unwrap());
                }
            })
        });

        // The same files through one live reader (the pattern documented
        // on `StreamReader`), then the whole archive that way.
        let index = &f.index_dense;
        let entries: Vec<&IndexEntry> = regular_entries(index)
            .into_iter()
            .take(EXTRACT_FILES)
            .collect();
        let mut cursor = Cursor::new(f.archive.as_slice());
        group.bench_function(format!("live_reader/{}-1mib", format.name()), |b| {
            b.iter(|| extract_live(&mut cursor, index, &entries))
        });
        let all = regular_entries(index);
        group.throughput(Throughput::Bytes(all.iter().map(|e| e.size).sum()));
        group.bench_function(format!("live_reader_all/{}-1mib", format.name()), |b| {
            b.iter(|| extract_live(&mut cursor, index, &all))
        });
    }
    group.finish();
}

/// Regular files in archive order.
fn regular_entries(index: &ArchiveIndex) -> Vec<&IndexEntry> {
    let mut entries: Vec<&IndexEntry> = index
        .list(None)
        .into_iter()
        .filter(|e| e.entry_type == EntryType::Regular)
        .collect();
    entries.sort_by_key(|e| e.uncompressed_offset);
    entries
}

/// Read `entries` (in archive order) with one `StreamReader` moved along
/// with `seek_forward`, as in the `StreamReader` docs.
fn extract_live(file: &mut Cursor<&[u8]>, index: &ArchiveIndex, entries: &[&IndexEntry]) {
    let mut live: Option<StreamReader> = None;
    let mut input = vec![0u8; 64 * 1024];
    let mut output = vec![0u8; 64 * 1024];
    for entry in entries {
        match live.as_mut() {
            Some(reader) => reader
                .seek_forward(entry.uncompressed_offset, entry.size)
                .unwrap(),
            None => {
                live = Some(
                    StreamReader::new(&index.stream, entry.uncompressed_offset, entry.size)
                        .unwrap(),
                )
            }
        }
        let reader = live.as_mut().unwrap();
        let mut data = Vec::with_capacity(entry.size as usize);
        loop {
            match reader.step() {
                EngineRequest::NeedInput | EngineRequest::SeekAndRead { .. } => {
                    file.seek(SeekFrom::Start(reader.compressed_position()))
                        .unwrap();
                    let n = file.read(&mut input).unwrap();
                    if n == 0 {
                        reader.signal_eof();
                    } else {
                        reader.provide_data(&input[..n]);
                    }
                }
                EngineRequest::OutputReady => loop {
                    let n = reader.read_output(&mut output);
                    if n == 0 {
                        break;
                    }
                    data.extend_from_slice(&output[..n]);
                },
                EngineRequest::Done => break,
                EngineRequest::Error(e) => panic!("{e}"),
            }
        }
        black_box(data);
    }
}

// ─── Bare streams ────────────────────────────────────────────────────────

/// A bare compressed file (no container): index it, then read ranges.
fn bench_stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream");
    configure(&mut group, 10, 6);
    let big_len = corpus().big_file_len;
    for format in FORMATS {
        let f = fixture(format);
        let name = format.name();

        group.throughput(Throughput::Bytes(big_len));
        group.bench_function(format!("index/{name}-1mib"), |b| {
            b.iter(|| {
                Stream::with_strategy(
                    Cursor::new(f.stream.as_slice()),
                    FixedInterval::new(DENSE_INTERVAL),
                )
                .unwrap()
            })
        });

        let stream = Stream::with_strategy(
            Cursor::new(f.stream.as_slice()),
            FixedInterval::new(DENSE_INTERVAL),
        )
        .unwrap();
        let (_, index) = stream.into_parts();

        // The whole stream as consecutive 256 KiB range reads, each one
        // independent (restore + decode forward).
        let mut stream = Stream::from_parts(Cursor::new(f.stream.as_slice()), index.clone());
        group.bench_function(format!("sequential_256k/{name}-1mib"), |b| {
            b.iter(|| {
                let mut offset = 0;
                while offset < big_len {
                    black_box(stream.read_range(offset, 256 * 1024).unwrap());
                    offset += 256 * 1024;
                }
            })
        });

        group.throughput(Throughput::Elements(1));
        let mut stream = Stream::from_parts(Cursor::new(f.stream.as_slice()), index);
        let mut rng = Rng(7);
        group.bench_function(format!("range_64k/{name}-1mib"), |b| {
            b.iter(|| {
                let offset = rng.below(big_len - 65536);
                stream.read_range(offset, 65536).unwrap()
            })
        });
    }
    group.finish();
}

// ─── Individual checkpoints ──────────────────────────────────────────────

/// Decode `compressed` until at least `target` bytes are out and the
/// decompressor can checkpoint there (deflate and bzip2 only can at block
/// boundaries). Returns the decompressor and its checkpoint.
fn decompressor_at(
    format: Format,
    compressed: &[u8],
    target: u64,
) -> (Box<dyn Decompressor>, Checkpoint) {
    let mut dec = CodecSpec::from(format.compression()).create().unwrap();
    let mut out = vec![0u8; 256 * 1024];
    let (mut consumed, mut produced) = (0usize, 0u64);
    loop {
        let end = (consumed + 64 * 1024).min(compressed.len());
        let r = dec
            .decompress(&compressed[consumed..end], &mut out)
            .unwrap();
        consumed += r.bytes_consumed;
        produced += r.bytes_produced as u64;
        if produced >= target {
            if let Some(cp) = dec.checkpoint(consumed as u64, produced).unwrap() {
                return (dec, cp);
            }
        }
        assert!(
            r.status != DecompressStatus::StreamEnd,
            "no checkpoint after {target} bytes"
        );
    }
}

/// Taking a checkpoint mid-stream (what indexing pays per checkpoint) and
/// restoring one into a fresh decompressor (what every read pays).
fn bench_checkpoint(c: &mut Criterion) {
    let mut group = c.benchmark_group("checkpoint");
    configure(&mut group, 20, 4);
    for format in FORMATS {
        let f = fixture(format);
        let (dec, cp) = decompressor_at(format, &f.archive, corpus().tar.len() as u64 / 2);
        println!(
            "[checkpoint {:>5}] at {:.1} MiB: ~{} B",
            format.name(),
            cp.uncompressed_offset as f64 / (1 << 20) as f64,
            cp.estimated_size()
        );
        group.bench_function(format!("take/{}", format.name()), |b| {
            b.iter(|| {
                dec.checkpoint(cp.compressed_offset, cp.uncompressed_offset)
                    .unwrap()
            })
        });
        let spec = CodecSpec::from(format.compression());
        group.bench_function(format!("create_and_restore/{}", format.name()), |b| {
            b.iter(|| {
                let mut dec = spec.create().unwrap();
                dec.restore(black_box(&cp)).unwrap();
                dec
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_index_build,
    bench_index_serde,
    bench_read_file,
    bench_read_range,
    bench_extract_sequential,
    bench_stream,
    bench_checkpoint
);
criterion_main!(benches);
