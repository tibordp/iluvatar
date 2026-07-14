//! Randomized (but deterministic) stress tests for the zstd and xz decoders.
//!
//! Feeds compressed streams in pseudo-random chunk sizes with pseudo-random
//! output buffer sizes, and exercises checkpoint/restore at arbitrary points
//! mid-stream. Complements the structured conformance tests with coverage of
//! buffer-boundary conditions (the decoders switch between fast and resumable
//! paths near boundaries).

#![cfg(any(feature = "zstandard", feature = "xz"))]

#[cfg(feature = "xz")]
use std::io::Write;

use iluvatar::compress::decompressor::{DecompressStatus, Decompressor};
#[cfg(feature = "xz")]
use iluvatar::compress::xz::XzDecompressor;
#[cfg(feature = "zstandard")]
use iluvatar::compress::zstd_dec::ZstdDecompressor;

/// Simple deterministic PRNG (splitmix-ish LCG).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next() as usize) % (hi - lo)
    }
}

/// Mixed-content test data: text-ish runs, random bytes, zeros, repeats.
fn build_data(seed: u64, size: usize) -> Vec<u8> {
    let mut rng = Rng(seed);
    let mut out = Vec::with_capacity(size + 64);
    while out.len() < size {
        match rng.next() % 4 {
            0 => {
                // compressible text-ish
                let word = format!("token{:03} ", rng.next() % 300);
                for _ in 0..rng.range(4, 64) {
                    out.extend_from_slice(word.as_bytes());
                }
            }
            1 => {
                // incompressible
                for _ in 0..rng.range(16, 2048) {
                    out.push(rng.next() as u8);
                }
            }
            2 => {
                // zeros
                let n = rng.range(16, 4096);
                out.resize(out.len() + n, 0);
            }
            _ => {
                // short-period repeats (exercises small match offsets)
                let period = rng.range(1, 9);
                let pattern: Vec<u8> = (0..period).map(|_| rng.next() as u8).collect();
                for i in 0..rng.range(32, 1024) {
                    out.push(pattern[i % period]);
                }
            }
        }
    }
    out.truncate(size);
    out
}

/// Decompress with pseudo-random input chunk and output buffer sizes,
/// checkpointing at every opportunity once `checkpoint_after` bytes have been
/// produced. Returns (output, first checkpoint at/after the threshold).
fn decompress_random_chunks(
    dec: &mut dyn Decompressor,
    compressed: &[u8],
    rng: &mut Rng,
    checkpoint_after: Option<u64>,
) -> (Vec<u8>, Option<iluvatar::compress::checkpoint::Checkpoint>) {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut pending: &[u8] = &[];
    let mut checkpoint = None;

    loop {
        if pending.is_empty() && offset < compressed.len() {
            let n = rng.range(1, 4096).min(compressed.len() - offset);
            pending = &compressed[offset..offset + n];
            offset += n;
        }
        let mut buf = vec![0u8; rng.range(1, 16384)];
        let result = dec.decompress(pending, &mut buf).unwrap();
        pending = &pending[result.bytes_consumed..];
        out.extend_from_slice(&buf[..result.bytes_produced]);

        // Take a checkpoint only between decompress calls with no undelivered
        // input chunk (the engine checkpoints at exact consumption points).
        if let Some(threshold) = checkpoint_after {
            if checkpoint.is_none() && pending.is_empty() && out.len() as u64 >= threshold {
                let consumed = (offset - pending.len()) as u64;
                checkpoint = Some(dec.checkpoint(consumed, out.len() as u64).unwrap());
            }
        }

        if result.status == DecompressStatus::StreamEnd {
            break;
        }
        if result.bytes_consumed == 0
            && result.bytes_produced == 0
            && pending.is_empty()
            && offset >= compressed.len()
        {
            break;
        }
    }
    (out, checkpoint)
}

fn stress_roundtrip(
    compressed: &[u8],
    original: &[u8],
    make: &dyn Fn() -> Box<dyn Decompressor>,
    seed: u64,
) {
    let mut rng = Rng(seed);

    // Plain randomized-chunk decompression.
    let mut dec = make();
    let (out, _) = decompress_random_chunks(dec.as_mut(), compressed, &mut rng, None);
    assert_eq!(out.len(), original.len(), "length mismatch (seed {seed})");
    assert!(out == original, "content mismatch (seed {seed})");

    // Checkpoint mid-stream, restore into a fresh decoder, continue.
    let threshold = (original.len() / 3) as u64;
    let mut dec = make();
    let (full, cp) = decompress_random_chunks(dec.as_mut(), compressed, &mut rng, Some(threshold));
    assert!(
        full == original,
        "content mismatch pre-restore (seed {seed})"
    );
    let cp = cp.expect("checkpoint should have been taken");

    let mut dec2 = make();
    dec2.restore(&cp).unwrap();
    let resume_at = cp.compressed_offset as usize;
    let (tail, _) =
        decompress_random_chunks(dec2.as_mut(), &compressed[resume_at..], &mut rng, None);
    let expected_tail = &original[cp.uncompressed_offset as usize..];
    assert_eq!(
        tail.len(),
        expected_tail.len(),
        "restored tail length mismatch (seed {seed})"
    );
    assert!(
        tail == expected_tail,
        "restored tail content mismatch (seed {seed})"
    );
}

#[cfg(feature = "zstandard")]
#[test]
fn test_zstd_randomized_chunks_and_checkpoints() {
    for seed in 1..=3u64 {
        let original = build_data(seed * 7919, 1_500_000);
        for level in [1, 3, 19] {
            let compressed = zstd::encode_all(std::io::Cursor::new(&original), level).unwrap();
            stress_roundtrip(
                &compressed,
                &original,
                &|| Box::new(ZstdDecompressor::new()),
                seed * 31 + level as u64,
            );
        }
    }
}

#[cfg(feature = "xz")]
#[test]
fn test_xz_randomized_chunks_and_checkpoints() {
    for seed in 1..=3u64 {
        let original = build_data(seed * 104729, 1_000_000);
        for preset in [0, 6] {
            let mut encoder = xz2::write::XzEncoder::new(Vec::new(), preset);
            encoder.write_all(&original).unwrap();
            let compressed = encoder.finish().unwrap();
            stress_roundtrip(
                &compressed,
                &original,
                &|| Box::new(XzDecompressor::new()),
                seed * 37 + preset as u64,
            );
        }
    }
}

#[cfg(feature = "xz")]
#[test]
fn test_xz_checkpoint_size_is_proportional_to_decoded_data() {
    // The LZMA dictionary buffer is allocated at full dict_size up front
    // (64 MiB at preset 9). Checkpoints must serialize only the live window,
    // not the zero-filled tail — otherwise every checkpoint costs dict_size
    // bytes and frequent checkpointing becomes impractical.
    let original = build_data(4242, 200_000);
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 9);
    encoder.write_all(&original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut dec = XzDecompressor::new();
    let mut out = vec![0u8; 64 * 1024];
    let mut offset = 0;
    let mut produced = 0u64;
    // Decode roughly half the stream.
    while produced < 100_000 {
        let end = (offset + 4096).min(compressed.len());
        let result = dec.decompress(&compressed[offset..end], &mut out).unwrap();
        offset = end.min(offset + result.bytes_consumed.max(1));
        produced += result.bytes_produced as u64;
        if result.status == DecompressStatus::StreamEnd {
            break;
        }
    }

    let cp = dec.checkpoint(offset as u64, produced).unwrap();
    let size = cp.estimated_size();
    // The window can hold at most `produced` bytes plus decoder tables
    // (~16 KiB of probabilities) and small buffers. With the full 64 MiB
    // dictionary serialized this would be > 64_000_000.
    assert!(
        size < 1_000_000,
        "checkpoint unexpectedly large: {} bytes for {} decoded",
        size,
        produced
    );

    // And the checkpoint must actually work: restore + finish the stream.
    let mut dec2 = XzDecompressor::new();
    dec2.restore(&cp).unwrap();
    let mut rng = Rng(1);
    let (tail, _) = decompress_random_chunks(&mut dec2, &compressed[offset..], &mut rng, None);
    assert_eq!(
        &tail[..],
        &original[produced as usize..],
        "restored tail mismatch"
    );
}
