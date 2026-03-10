# Changelog

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
