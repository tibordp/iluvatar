//! Decompression throughput benchmark for the pure-Rust zstd and xz decoders.
//!
//! Run with: cargo bench --bench throughput
//!
//! Builds a mixed corpus (text-like, binary, repetitive), compresses it with
//! the reference encoders at several levels, then measures how fast the
//! iluvatar decompressors decode it through the `Decompressor` trait.

use std::io::Write;
use std::time::Instant;

use iluvatar::compress::decompressor::{DecompressStatus, Decompressor};
use iluvatar::compress::xz::XzDecompressor;
use iluvatar::compress::zstd_dec::ZstdDecompressor;

/// Simple deterministic PRNG.
fn prng_data(seed: u64, size: usize) -> Vec<u8> {
    let mut state = seed;
    (0..size)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

/// Text-like data resembling structured logs/source: a large synthetic
/// vocabulary plus random identifiers and numbers, so both the match-copy
/// and literal/Huffman paths get exercised.
fn text_data(seed: u64, size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size + 64);
    let mut state = seed;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state >> 33
    };
    // 4096 distinct pseudo-words, zipf-ish reuse
    let vocab: Vec<String> = (0..4096)
        .map(|i| format!("sym{:x}_{}", i * 2654435761u64 % 65536, i % 97))
        .collect();
    while out.len() < size {
        let r = next();
        match r % 10 {
            0..=5 => {
                // common structured line
                let w1 = &vocab[(next() as usize) % 256];
                let w2 = &vocab[(next() as usize) % 4096];
                out.extend_from_slice(
                    format!("{} = {}({}, 0x{:08x});\n", w1, w2, next() % 100000, next()).as_bytes(),
                );
            }
            6..=8 => {
                // json-ish record with random values
                out.extend_from_slice(
                    format!(
                        "{{\"ts\":{},\"id\":\"{:016x}\",\"level\":\"info\",\"msg\":\"{}\"}}\n",
                        next(),
                        next() ^ (next() << 31),
                        vocab[(next() as usize) % 4096]
                    )
                    .as_bytes(),
                );
            }
            _ => {
                // base64-ish blob (literal-heavy)
                const B64: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                for _ in 0..12 {
                    let v = next();
                    out.push(B64[(v & 63) as usize]);
                    out.push(B64[((v >> 6) & 63) as usize]);
                    out.push(B64[((v >> 12) & 63) as usize]);
                    out.push(B64[((v >> 18) & 63) as usize]);
                }
                out.push(b'\n');
            }
        }
    }
    out.truncate(size);
    out
}

fn build_corpus() -> Vec<u8> {
    let mut corpus = Vec::new();
    corpus.extend_from_slice(&text_data(1, 12 << 20)); // 12 MiB text-like
    corpus.extend_from_slice(&prng_data(2, 2 << 20)); // 2 MiB incompressible
    corpus.extend_from_slice(&vec![0u8; 2 << 20]); // 2 MiB zeros
    let pattern = prng_data(3, 4096);
    for _ in 0..512 {
        corpus.extend_from_slice(&pattern); // 2 MiB repetitive
    }
    corpus
}

/// Decompress `compressed` fully, feeding input in 64 KiB chunks, and verify
/// the output matches `expected`. Returns elapsed seconds.
fn run_decompress(mut dec: Box<dyn Decompressor>, compressed: &[u8], expected: &[u8]) -> f64 {
    let mut output = vec![0u8; 256 * 1024];
    let mut produced_total = 0usize;
    let mut offset = 0usize;
    let mut hasher = 0u64;
    let mut ok = true;

    let start = Instant::now();
    loop {
        let end = (offset + 64 * 1024).min(compressed.len());
        let input = &compressed[offset..end];
        let result = dec.decompress(input, &mut output).unwrap();
        offset += result.bytes_consumed;
        if result.bytes_produced > 0 {
            // Cheap correctness check without holding the full output.
            let chunk = &output[..result.bytes_produced];
            if chunk != &expected[produced_total..produced_total + chunk.len()] {
                ok = false;
            }
            for &b in chunk.iter().step_by(4093) {
                hasher = hasher.wrapping_mul(31).wrapping_add(b as u64);
            }
            produced_total += result.bytes_produced;
        }
        if result.status == DecompressStatus::StreamEnd {
            break;
        }
        if result.bytes_consumed == 0 && result.bytes_produced == 0 && offset >= compressed.len() {
            break;
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    std::hint::black_box(hasher);
    assert!(ok, "output mismatch");
    assert_eq!(produced_total, expected.len(), "length mismatch");
    elapsed
}

fn bench(name: &str, compressed: &[u8], expected: &[u8], make: impl Fn() -> Box<dyn Decompressor>) {
    // Warmup + best-of-3
    let mut best = f64::INFINITY;
    for _ in 0..3 {
        let t = run_decompress(make(), compressed, expected);
        best = best.min(t);
    }
    let mbps = expected.len() as f64 / best / 1e6;
    println!(
        "{name:<28} {:>8.1} MB/s  ({:.3}s, {} -> {} bytes)",
        mbps,
        best,
        compressed.len(),
        expected.len()
    );
}

/// Reference decode speed using the C libraries, for context.
fn bench_reference_zstd(compressed: &[u8], expected: &[u8]) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..3 {
        let start = Instant::now();
        let out = zstd::decode_all(std::io::Cursor::new(compressed)).unwrap();
        best = best.min(start.elapsed().as_secs_f64());
        assert_eq!(out.len(), expected.len());
    }
    expected.len() as f64 / best / 1e6
}

fn bench_reference_xz(compressed: &[u8], expected: &[u8]) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..3 {
        let mut out = Vec::new();
        let start = Instant::now();
        let mut r = xz2::read::XzDecoder::new(std::io::Cursor::new(compressed));
        std::io::Read::read_to_end(&mut r, &mut out).unwrap();
        best = best.min(start.elapsed().as_secs_f64());
        assert_eq!(out.len(), expected.len());
    }
    expected.len() as f64 / best / 1e6
}

fn main() {
    let corpus = build_corpus();
    println!("corpus: {} bytes", corpus.len());

    // Profiling mode: loop one decoder forever so a sampling profiler can attach.
    if let Ok(which) = std::env::var("PROFILE_LOOP") {
        match which.as_str() {
            "zstd" => {
                let compressed = zstd::encode_all(std::io::Cursor::new(&corpus), 3).unwrap();
                loop {
                    run_decompress(Box::new(ZstdDecompressor::new()), &compressed, &corpus);
                }
            }
            _ => {
                let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
                encoder.write_all(&corpus).unwrap();
                let compressed = encoder.finish().unwrap();
                loop {
                    run_decompress(Box::new(XzDecompressor::new()), &compressed, &corpus);
                }
            }
        }
    }

    for level in [1, 3, 9, 19] {
        let compressed = zstd::encode_all(std::io::Cursor::new(&corpus), level).unwrap();
        let ref_mbps = bench_reference_zstd(&compressed, &corpus);
        println!("  [reference C zstd: {:.0} MB/s]", ref_mbps);
        bench(&format!("zstd level {level}"), &compressed, &corpus, || {
            Box::new(ZstdDecompressor::new())
        });
    }

    for preset in [0, 6, 9] {
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), preset);
        encoder.write_all(&corpus).unwrap();
        let compressed = encoder.finish().unwrap();
        let ref_mbps = bench_reference_xz(&compressed, &corpus);
        println!("  [reference C xz: {:.0} MB/s]", ref_mbps);
        bench(&format!("xz preset {preset}"), &compressed, &corpus, || {
            Box::new(XzDecompressor::new())
        });
    }
}
