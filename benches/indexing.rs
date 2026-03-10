use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::io::{self, Cursor, Write};
use std::sync::OnceLock;

const TAR_SIZE_TARGET: usize = 100 * 1024 * 1024; // 100 MB uncompressed
const FILE_COUNT: usize = 100;
const FILE_SIZE: usize = TAR_SIZE_TARGET / FILE_COUNT; // ~1 MB each

/// Deterministic content generator producing moderately compressible data.
///
/// Repeats a 1 KB pseudo-random base block with periodic mutations,
/// yielding roughly 3–5:1 compression ratios (similar to source code).
fn generate_content(seed: u64, size: usize) -> Vec<u8> {
    let block_size = 1024;
    let mut base = vec![0u8; block_size];
    let mut state = seed;
    for b in base.iter_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(seed ^ 0xdeadbeef);
        *b = (state >> 33) as u8;
    }
    let mut data = Vec::with_capacity(size);
    let mut round = 0u64;
    while data.len() < size {
        for (i, &b) in base.iter().enumerate() {
            if data.len() >= size {
                break;
            }
            if (i as u64 + round) % 7 == 0 {
                data.push(b.wrapping_add(round as u8));
            } else {
                data.push(b);
            }
        }
        round += 1;
    }
    data.truncate(size);
    data
}

fn tar_data() -> &'static Vec<u8> {
    static DATA: OnceLock<Vec<u8>> = OnceLock::new();
    DATA.get_or_init(|| {
        eprintln!("Generating {FILE_COUNT} × {:.1} MB tar archive...", FILE_SIZE as f64 / 1e6);
        let mut builder = tar::Builder::new(Vec::new());
        for i in 0..FILE_COUNT {
            let content = generate_content(i as u64, FILE_SIZE);
            let path = format!("dir{:02}/file{:04}.dat", i / 10, i);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_uid(1000);
            header.set_gid(1000);
            header.set_mtime(1700000000);
            header.set_cksum();
            builder
                .append_data(&mut header, &path, &content[..])
                .unwrap();
        }
        builder.finish().unwrap();
        builder.into_inner().unwrap()
    })
}

fn compressed_gz() -> &'static Vec<u8> {
    static DATA: OnceLock<Vec<u8>> = OnceLock::new();
    DATA.get_or_init(|| {
        eprintln!("  compressing with gzip...");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
        enc.write_all(tar_data()).unwrap();
        enc.finish().unwrap()
    })
}

fn compressed_bz2() -> &'static Vec<u8> {
    static DATA: OnceLock<Vec<u8>> = OnceLock::new();
    DATA.get_or_init(|| {
        eprintln!("  compressing with bzip2...");
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(9));
        enc.write_all(tar_data()).unwrap();
        enc.finish().unwrap()
    })
}

fn compressed_xz() -> &'static Vec<u8> {
    static DATA: OnceLock<Vec<u8>> = OnceLock::new();
    DATA.get_or_init(|| {
        eprintln!("  compressing with xz...");
        let mut enc = xz2::write::XzEncoder::new(Vec::new(), 6);
        enc.write_all(tar_data()).unwrap();
        enc.finish().unwrap()
    })
}

fn compressed_zst() -> &'static Vec<u8> {
    static DATA: OnceLock<Vec<u8>> = OnceLock::new();
    DATA.get_or_init(|| {
        eprintln!("  compressing with zstd...");
        zstd::encode_all(Cursor::new(tar_data()), 3).unwrap()
    })
}

fn bench_indexing(c: &mut Criterion) {
    let uncompressed_size = tar_data().len() as u64;

    // Pre-generate all compressed variants (one-time cost).
    let gz = compressed_gz();
    let bz2 = compressed_bz2();
    let xz = compressed_xz();
    let zst = compressed_zst();

    eprintln!(
        "Sizes: tar={:.1}MB  gz={:.1}MB  bz2={:.1}MB  xz={:.1}MB  zst={:.1}MB",
        tar_data().len() as f64 / 1e6,
        gz.len() as f64 / 1e6,
        bz2.len() as f64 / 1e6,
        xz.len() as f64 / 1e6,
        zst.len() as f64 / 1e6,
    );

    let mut group = c.benchmark_group("indexing");
    group.throughput(Throughput::Bytes(uncompressed_size));
    group.sample_size(10);

    // ── Gzip ──────────────────────────────────────────────────────────

    group.bench_function("gzip/upstream_decompress", |b| {
        b.iter(|| {
            let mut dec = flate2::read::GzDecoder::new(Cursor::new(gz.as_slice()));
            io::copy(&mut dec, &mut io::sink()).unwrap()
        })
    });

    group.bench_function("gzip/upstream_tar_list", |b| {
        b.iter(|| {
            let dec = flate2::read::GzDecoder::new(Cursor::new(gz.as_slice()));
            let mut archive = tar::Archive::new(dec);
            archive.entries().unwrap().count()
        })
    });

    group.bench_function("gzip/iluvatar_index", |b| {
        b.iter(|| {
            let archive =
                iluvatar::sync::Archive::new(Cursor::new(gz.as_slice())).unwrap();
            archive.list().len()
        })
    });

    // ── Bzip2 ─────────────────────────────────────────────────────────

    group.bench_function("bzip2/upstream_decompress", |b| {
        b.iter(|| {
            let mut dec = bzip2::read::BzDecoder::new(Cursor::new(bz2.as_slice()));
            io::copy(&mut dec, &mut io::sink()).unwrap()
        })
    });

    group.bench_function("bzip2/upstream_tar_list", |b| {
        b.iter(|| {
            let dec = bzip2::read::BzDecoder::new(Cursor::new(bz2.as_slice()));
            let mut archive = tar::Archive::new(dec);
            archive.entries().unwrap().count()
        })
    });

    group.bench_function("bzip2/iluvatar_index", |b| {
        b.iter(|| {
            let archive =
                iluvatar::sync::Archive::new(Cursor::new(bz2.as_slice())).unwrap();
            archive.list().len()
        })
    });

    // ── XZ ────────────────────────────────────────────────────────────

    group.bench_function("xz/upstream_decompress", |b| {
        b.iter(|| {
            let mut dec = xz2::read::XzDecoder::new(Cursor::new(xz.as_slice()));
            io::copy(&mut dec, &mut io::sink()).unwrap()
        })
    });

    group.bench_function("xz/upstream_tar_list", |b| {
        b.iter(|| {
            let dec = xz2::read::XzDecoder::new(Cursor::new(xz.as_slice()));
            let mut archive = tar::Archive::new(dec);
            archive.entries().unwrap().count()
        })
    });

    group.bench_function("xz/iluvatar_index", |b| {
        b.iter(|| {
            let archive =
                iluvatar::sync::Archive::new(Cursor::new(xz.as_slice())).unwrap();
            archive.list().len()
        })
    });

    // ── Zstd ──────────────────────────────────────────────────────────

    group.bench_function("zstd/upstream_decompress", |b| {
        b.iter(|| {
            let mut dec = zstd::Decoder::new(Cursor::new(zst.as_slice())).unwrap();
            io::copy(&mut dec, &mut io::sink()).unwrap()
        })
    });

    group.bench_function("zstd/upstream_tar_list", |b| {
        b.iter(|| {
            let dec = zstd::Decoder::new(Cursor::new(zst.as_slice())).unwrap();
            let mut archive = tar::Archive::new(dec);
            archive.entries().unwrap().count()
        })
    });

    group.bench_function("zstd/iluvatar_index", |b| {
        b.iter(|| {
            let archive =
                iluvatar::sync::Archive::new(Cursor::new(zst.as_slice())).unwrap();
            archive.list().len()
        })
    });

    group.finish();
}

criterion_group!(benches, bench_indexing);
criterion_main!(benches);
