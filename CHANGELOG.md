# Changelog

## Unreleased

### Changed

- **zstd decoder: ~5x faster decompression.** Bit reading now uses unaligned
  64-bit loads with a register-resident cache instead of per-bit loops; the
  four Huffman literal streams decode interleaved for instruction-level
  parallelism; sequence decoding and execution are fused with memcpy-based
  match copies (with fixed-size fast paths for short copies); blocks decode
  directly into the shared history buffer, eliminating the staged-output
  copy and per-block window trimming; predefined FSE tables are built once
  and entropy tables are no longer cloned per block.
- **xz/LZMA decoder: ~1.3x faster decompression.** Added a fast path that
  decodes whole LZMA symbols with the range coder held in local registers
  while generous input/output margins remain (the resumable state machine
  still handles buffer boundaries and checkpoint resume); match copies and
  uncompressed LZMA2 chunks now use chunked slice copies through the
  dictionary instead of per-byte pushes through a pending-output queue; the
  XZ layer reuses its LZMA2 scratch buffer across calls.
- **Index format version bumped to 3** (XZ checkpoint state gained a field;
  see below). Indexes built by earlier versions are rejected on load and
  must be rebuilt.

### Fixed

- **xz: checkpoint/restore lost decoded-but-undelivered output.** A
  checkpoint taken while the XZ decompressor still held staged output that
  the caller had not yet read would silently drop those bytes on restore,
  corrupting reads that resumed from such a checkpoint. This could occur
  through the engine as well, since checkpoints are taken right after a
  decompress step and highly compressible data can stage more output than
  one step delivers. The staged output is now included in the checkpoint
  state. Found by new randomized stress tests (`tests/decoder_stress.rs`).

## 0.1.1 — 2026-03-10

### Fixed

- **bzip2: checkpoint offsets drift due to RLE1 byte count mismatch.**
  The bzip2 checkpoint `uncompressed_offset` was computed from a formula
  (`block_index * block_capacity`) that assumed each block holds exactly
  `blockSize100k * 100000 - 19` original bytes. This is wrong because
  bzip2's initial RLE1 step changes the byte count per block, causing
  cumulative drift. Files read via checkpoint restore returned corrupted
  data or content from the wrong offset. Fixed by tracking the
  decompressor's actual output at each block boundary, using a pre-scan
  to split decompression at boundary positions for precise tracking
  without per-byte overhead.

## 0.1.0 — 2026-03-09

Initial release.
