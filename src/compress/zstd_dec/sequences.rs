//! Sequence decoding and execution for zstd.
//!
//! Each compressed block contains a sequences section that describes how to
//! reconstruct the output from literals and back-references. Each sequence
//! is a triplet (literal_length, offset, match_length).

use super::bits::SeqBitReader;
use super::block::BlockDecoderState;
use super::fse::{
    build_fse_table, build_rle_fse_table, read_ncount, FseTable, SeqEntry, LL_BASE, LL_BITS,
    LL_FSE_LOG, MAX_LL, MAX_ML, MAX_OFF, ML_BASE, ML_BITS, ML_FSE_LOG, OFF_FSE_LOG, OF_BASE,
    OF_BITS, SEQ_TABLE_SLOTS,
};

/// Compression mode for symbol types in the sequences section.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum SymbolCompressionMode {
    Predefined = 0,
    Rle = 1,
    FseCompressed = 2,
    Repeat = 3,
}

impl SymbolCompressionMode {
    pub fn from_u8(val: u8) -> Result<Self, String> {
        match val {
            0 => Ok(SymbolCompressionMode::Predefined),
            1 => Ok(SymbolCompressionMode::Rle),
            2 => Ok(SymbolCompressionMode::FseCompressed),
            3 => Ok(SymbolCompressionMode::Repeat),
            _ => Err(format!("invalid symbol compression mode: {}", val)),
        }
    }
}

/// Parse the sequences section header, updating the FSE tables stored in
/// `state` in place. Returns `(num_sequences, bytes_consumed)`.
///
/// When the block declares zero sequences the header stops after the count
/// byte and the previously-used tables in `state` are left untouched.
pub(crate) fn parse_sequences_header(
    data: &[u8],
    state: &mut BlockDecoderState,
) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("empty sequences section".into());
    }

    let mut pos = 0;

    // Number of sequences
    let first_byte = data[pos] as usize;
    pos += 1;
    let num_sequences;
    if first_byte == 0 {
        return Ok((0, pos));
    } else if first_byte < 128 {
        num_sequences = first_byte;
    } else if first_byte == 255 {
        if pos + 2 > data.len() {
            return Err("sequences header truncated".into());
        }
        num_sequences = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize + 0x7F00;
        pos += 2;
    } else {
        // 128..254
        if pos >= data.len() {
            return Err("sequences header truncated".into());
        }
        num_sequences = ((first_byte - 128) << 8) + data[pos] as usize;
        pos += 1;
    }

    if num_sequences == 0 {
        return Ok((0, pos));
    }

    // Symbol compression modes byte
    if pos >= data.len() {
        return Err("sequences header truncated at modes byte".into());
    }
    let modes_byte = data[pos];
    pos += 1;

    // The spec says the bottom 2 bits must be zero (Reserved)
    if modes_byte & 3 != 0 {
        return Err("reserved bits in sequence modes byte are not zero".into());
    }

    let ll_mode = SymbolCompressionMode::from_u8((modes_byte >> 6) & 3)?;
    let of_mode = SymbolCompressionMode::from_u8((modes_byte >> 4) & 3)?;
    let ml_mode = SymbolCompressionMode::from_u8((modes_byte >> 2) & 3)?;

    build_seq_table(
        ll_mode,
        data,
        MAX_LL,
        LL_FSE_LOG,
        &LL_BASE,
        &LL_BITS,
        super::block::default_ll_table(),
        &mut state.ll_table,
        &mut pos,
    )?;

    build_seq_table(
        of_mode,
        data,
        MAX_OFF,
        OFF_FSE_LOG,
        &OF_BASE,
        &OF_BITS,
        super::block::default_of_table(),
        &mut state.of_table,
        &mut pos,
    )?;

    build_seq_table(
        ml_mode,
        data,
        MAX_ML,
        ML_FSE_LOG,
        &ML_BASE,
        &ML_BITS,
        super::block::default_ml_table(),
        &mut state.ml_table,
        &mut pos,
    )?;

    Ok((num_sequences, pos))
}

/// Set `table` according to the block's compression mode for one symbol type.
/// `pos` indexes into `data` and is advanced past any table description bytes.
#[allow(clippy::too_many_arguments)]
fn build_seq_table(
    mode: SymbolCompressionMode,
    data: &[u8],
    max_symbol: u32,
    max_log: u32,
    base_values: &[u32],
    nb_add_bits: &[u8],
    default_table: &FseTable,
    table: &mut Option<FseTable>,
    pos: &mut usize,
) -> Result<(), String> {
    let data = &data[*pos..];
    match mode {
        SymbolCompressionMode::Predefined => {
            *table = Some(default_table.clone());
            Ok(())
        }
        SymbolCompressionMode::Rle => {
            if data.is_empty() {
                return Err("RLE mode but no data for symbol".into());
            }
            let symbol = data[0];
            if symbol as u32 > max_symbol {
                return Err(format!("RLE symbol {} exceeds max {}", symbol, max_symbol));
            }
            *pos += 1;
            *table = Some(build_rle_fse_table(
                symbol,
                Some(base_values),
                Some(nb_add_bits),
            ));
            Ok(())
        }
        SymbolCompressionMode::FseCompressed => {
            let (norm, actual_max, table_log, header_size) = read_ncount(data, max_symbol)?;
            if table_log > max_log {
                return Err(format!(
                    "FSE table log {} exceeds max {}",
                    table_log, max_log
                ));
            }
            *table = Some(build_fse_table(
                &norm,
                actual_max,
                table_log,
                Some(base_values),
                Some(nb_add_bits),
            )?);
            *pos += header_size;
            Ok(())
        }
        SymbolCompressionMode::Repeat => {
            if table.is_none() {
                return Err("Repeat mode but no previous table".into());
            }
            Ok(())
        }
    }
}

/// Largest output a single block may regenerate (Block_Maximum_Size).
const MAX_BLOCK_SIZE: usize = 128 * 1024;

/// Scratch space kept past the block's output limit so literal and match
/// copies can move whole 8/16-byte chunks and overshoot the true end; the
/// overshoot is overwritten by later copies or truncated away.
const WILDCOPY_SLACK: usize = 32;

/// Decode all sequences from the bitstream data and execute them, appending
/// the reconstructed block output to `output`.
///
/// `output` holds the decoding history: bytes before `output.len()` at entry
/// are the window from previous blocks. `max_back` limits how far before the
/// block start a match may reference (i.e. `min(history_len, window_size)`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn decode_and_execute_sequences(
    data: &[u8],
    num_sequences: usize,
    ll_table: &FseTable,
    of_table: &FseTable,
    ml_table: &FseTable,
    rep_offsets: &mut [u32; 3],
    literals: &[u8],
    output: &mut Vec<u8>,
    max_back: usize,
) -> Result<(), String> {
    if num_sequences == 0 {
        output.extend_from_slice(literals);
        return Ok(());
    }
    if data.is_empty() {
        return Err("empty sequence bitstream data".into());
    }
    // The decode loop's bit budget (56 bits per refill) assumes in-spec
    // tables; reject any that aren't (only possible via a corrupt
    // checkpoint).
    let fits = |t: &FseTable, max: u8| t.seq_max_additional_bits.is_some_and(|m| m <= max);
    if !(fits(ll_table, LL_BITS[MAX_LL as usize])
        && fits(ml_table, ML_BITS[MAX_ML as usize])
        && fits(of_table, MAX_OFF as u8))
    {
        return Err("malformed sequence decoding table".into());
    }

    let block_start = output.len();
    debug_assert!(max_back <= block_start);

    // Size the buffer for the largest possible block plus copy slack, then
    // write through a plain slice with a cursor; the true length is
    // restored at the end.
    let limit = block_start + MAX_BLOCK_SIZE;
    output.resize(limit + WILDCOPY_SLACK, 0);
    let result = execute_sequences(
        data,
        num_sequences,
        ll_table,
        of_table,
        ml_table,
        rep_offsets,
        literals,
        output,
        block_start,
        limit,
        max_back,
    );
    match result {
        Ok(end) => {
            output.truncate(end);
            Ok(())
        }
        Err(e) => {
            output.truncate(block_start);
            Err(e)
        }
    }
}

/// Sequences are decoded in batches of this many into a small on-stack
/// buffer, then executed. Splitting the two phases keeps each loop's live
/// state small enough to stay in registers.
const SEQ_BATCH: usize = 64;

/// A decoded sequence with its offset already resolved against the repeat
/// offsets. `offset == 0` marks an invalid (zero) repeat offset.
#[derive(Clone, Copy, Default)]
struct Sequence {
    literal_length: u32,
    match_length: u32,
    offset: u32,
}

/// Body of `decode_and_execute_sequences`: decodes into `out[block_start..]`
/// (which has `WILDCOPY_SLACK` bytes of room past `limit`) and returns the
/// end of the block's output.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn execute_sequences(
    data: &[u8],
    num_sequences: usize,
    ll_table: &FseTable,
    of_table: &FseTable,
    ml_table: &FseTable,
    rep_offsets: &mut [u32; 3],
    literals: &[u8],
    out: &mut [u8],
    block_start: usize,
    limit: usize,
    max_back: usize,
) -> Result<usize, String> {
    debug_assert!(out.len() >= limit + WILDCOPY_SLACK);
    let mut op = block_start;
    let mut lit_pos = 0usize;

    let mut reader = SeqBitReader::new(data)?;

    // Initialize FSE states (at most 9 + 8 + 9 bits).
    let mut states = SeqStates {
        ll: reader.read(ll_table.table_log),
        of: reader.read(of_table.table_log),
        ml: reader.read(ml_table.table_log),
    };
    let tables = SeqTables {
        ll: &ll_table.seq_entries,
        of: &of_table.seq_entries,
        ml: &ml_table.seq_entries,
    };

    let mut batch = [Sequence::default(); SEQ_BATCH];
    let mut done = 0usize;
    while done < num_sequences {
        let n = (num_sequences - done).min(SEQ_BATCH);
        let last_batch = done + n == num_sequences;
        decode_batch(
            &mut reader,
            &tables,
            &mut states,
            rep_offsets,
            &mut batch[..n],
            last_batch,
        );

        touch_match_sources(out, op, &batch[..n]);

        for (j, seq) in batch[..n].iter().enumerate() {
            let literal_length = seq.literal_length as usize;
            let match_length = seq.match_length as usize;
            let offset = seq.offset as usize;

            // Execute: copy literals
            if literal_length > literals.len() - lit_pos || literal_length > limit - op {
                return Err(literal_error(
                    done + j,
                    literal_length,
                    lit_pos,
                    literals.len(),
                ));
            }
            // Short literal runs dominate; fixed-size 16-byte copies compile
            // to load/store pairs instead of a memcpy call. They may
            // overshoot into the slack past `limit`.
            if literal_length <= 32 && lit_pos + 32 <= literals.len() {
                let chunk: [u8; 16] = literals[lit_pos..lit_pos + 16].try_into().unwrap();
                out[op..op + 16].copy_from_slice(&chunk);
                if literal_length > 16 {
                    let chunk: [u8; 16] = literals[lit_pos + 16..lit_pos + 32].try_into().unwrap();
                    out[op + 16..op + 32].copy_from_slice(&chunk);
                }
            } else {
                out[op..op + literal_length]
                    .copy_from_slice(&literals[lit_pos..lit_pos + literal_length]);
            }
            lit_pos += literal_length;
            op += literal_length;

            // Execute: copy match. History available: bytes produced in this
            // block plus up to max_back bytes of window before the block.
            if offset == 0 || offset > (op - block_start) + max_back || match_length > limit - op {
                return Err(match_error(done + j, offset, op - block_start, max_back));
            }
            copy_match(out, op, offset, match_length);
            op += match_length;
        }
        done += n;
    }

    if reader.is_overflowed() {
        return Err("sequence bitstream overread".into());
    }

    // Remaining literals after all sequences
    let rest = literals.len() - lit_pos;
    if rest > limit - op {
        return Err("trailing literals overflow the maximum block size".into());
    }
    out[op..op + rest].copy_from_slice(&literals[lit_pos..]);
    op += rest;

    Ok(op)
}

/// Load the first byte of each match source in `batch` (which starts at
/// output position `op`), acting as a software prefetch: the loads are
/// independent, so the core overlaps their cache misses instead of taking
/// them one at a time during the copies. Stable Rust has no portable
/// prefetch intrinsic; a plain load has the same effect here.
#[inline(always)]
fn touch_match_sources(out: &[u8], mut op: usize, batch: &[Sequence]) {
    let mut acc = 0u8;
    for seq in batch {
        op = op.wrapping_add(seq.literal_length as usize);
        let src = op.wrapping_sub(seq.offset as usize);
        // Invalid sequences are rejected later; just skip them here.
        if let Some(&b) = out.get(src) {
            acc ^= b;
        }
        op = op.wrapping_add(seq.match_length as usize);
    }
    std::hint::black_box(acc);
}

struct SeqStates {
    ll: usize,
    of: usize,
    ml: usize,
}

struct SeqTables<'a> {
    ll: &'a [SeqEntry; SEQ_TABLE_SLOTS],
    of: &'a [SeqEntry; SEQ_TABLE_SLOTS],
    ml: &'a [SeqEntry; SEQ_TABLE_SLOTS],
}

/// Decode `batch.len()` sequences, resolving offsets against `reps`. When
/// `last_batch` is set, the final sequence skips the FSE state update.
///
/// Kept out of line so its register allocation is independent of the
/// execute loop's; inlined, the decode state gets spilled.
#[inline(never)]
fn decode_batch(
    reader: &mut SeqBitReader<'_>,
    tables: &SeqTables<'_>,
    states: &mut SeqStates,
    reps: &mut [u32; 3],
    batch: &mut [Sequence],
    last_batch: bool,
) {
    // Work on local copies and write back once: state behind `&mut` would
    // otherwise be stored to memory on every iteration.
    let mut r = reader.clone();
    let mut local_reps = *reps;
    let (mut ll_state, mut of_state, mut ml_state) = (states.ll, states.of, states.ml);
    const MASK: usize = SEQ_TABLE_SLOTS - 1;
    let n = batch.len();
    for (j, seq) in batch.iter_mut().enumerate() {
        // Valid states are always below the table size; masking just lets
        // the compiler drop the bounds checks.
        let of_entry = tables.of[of_state & MASK];
        let ll_entry = tables.ll[ll_state & MASK];
        let ml_entry = tables.ml[ml_state & MASK];

        let of_bits = of_entry.nb_additional_bits();
        let ml_bits = ml_entry.nb_additional_bits();
        let ll_bits = ll_entry.nb_additional_bits();
        let (ll_nb, ml_nb, of_nb) = (ll_entry.nb_bits(), ml_entry.nb_bits(), of_entry.nb_bits());

        // Each field is peeked at a precomputed offset rather than read in
        // sequence, so the extractions don't serialize on the cache shift.
        // A refill provides 56 bits.
        //
        // First group: offset (<= 31 bits) and match length (<= 16) extra
        // bits.
        r.refill();
        // Offset_Value per RFC 8878 Section 3.1.1.3.2.1.1:
        //   if (code > 0) Offset_Value = (1 << code) + readNBits(code)
        //   else          Offset_Value = 1
        // (code 0 reads zero bits, so the formula covers both cases).
        let offset_value = (1u32 << of_bits).wrapping_add(r.peek_at(0, of_bits) as u32);
        let match_length = ml_entry.base_value() + r.peek_at(of_bits, ml_bits) as u32;
        r.consume(of_bits + ml_bits);

        // Second group: literal length extra bits (<= 16) and the state
        // updates (<= 9 + 9 + 8 = 26 bits). Refilling sits on the critical
        // path of the state chain, so skip it when the cache still holds
        // enough bits (the common case: offsets are rarely long). Making
        // the first refill conditional as well measured slower (the branch
        // mispredicts too often).
        let need = ll_bits + ll_nb + ml_nb + of_nb;
        if need > r.available() {
            r.refill();
        }
        let literal_length = ll_entry.base_value() + r.peek_at(0, ll_bits) as u32;

        let offset = resolve_offset(offset_value, literal_length, &mut local_reps);

        *seq = Sequence {
            literal_length,
            match_length,
            offset,
        };

        // Update FSE states (the last sequence has no state update).
        if !(last_batch && j + 1 == n) {
            ll_state = ll_entry.next_state() + r.peek_at(ll_bits, ll_nb);
            ml_state = ml_entry.next_state() + r.peek_at(ll_bits + ll_nb, ml_nb);
            of_state = of_entry.next_state() + r.peek_at(ll_bits + ll_nb + ml_nb, of_nb);
            r.consume(need);
        } else {
            r.consume(ll_bits);
        }
    }
    *reader = r;
    *reps = local_reps;
    *states = SeqStates {
        ll: ll_state,
        of: of_state,
        ml: ml_state,
    };
}

#[cold]
#[inline(never)]
fn literal_error(seq: usize, literal_length: usize, lit_pos: usize, available: usize) -> String {
    if literal_length > available - lit_pos {
        format!(
            "sequence {} literal length {} exceeds available literals (at {}, have {})",
            seq, literal_length, lit_pos, available
        )
    } else {
        format!("sequence {} overflows the maximum block size", seq)
    }
}

#[cold]
#[inline(never)]
fn match_error(seq: usize, offset: usize, produced: usize, max_back: usize) -> String {
    if offset == 0 {
        format!("sequence {} has a zero repeat offset", seq)
    } else if offset > produced + max_back {
        format!(
            "sequence {} offset {} exceeds available history ({} output + {} window)",
            seq, offset, produced, max_back
        )
    } else {
        format!("sequence {} overflows the maximum block size", seq)
    }
}

/// Write `len` bytes at `out[op..]`, copied from `offset` bytes back
/// (LZ77 semantics: overlapping copies replicate the pattern).
///
/// Requires `1 <= offset <= op` and `WILDCOPY_SLACK` bytes of writable room
/// past `op + len`: copies proceed in whole 8/16-byte chunks and may
/// overwrite up to 15 bytes past the end.
#[inline(always)]
fn copy_match(out: &mut [u8], op: usize, offset: usize, len: usize) {
    debug_assert!(offset >= 1 && offset <= op);
    let src = op - offset;
    if offset >= 16 {
        // Chunks never overlap their own source.
        let mut k = 0;
        loop {
            let chunk: [u8; 16] = out[src + k..src + k + 16].try_into().unwrap();
            out[op + k..op + k + 16].copy_from_slice(&chunk);
            k += 16;
            if k >= len {
                break;
            }
        }
    } else if offset == 1 {
        let b = out[src];
        out[op..op + len].fill(b);
    } else {
        // Replicate with a period that is a multiple of `offset` and >= 8,
        // so 8-byte chunks read only bytes already written. When `offset`
        // is below 8, lay down one full period byte by byte first.
        let (dist, mut k) = if offset >= 8 {
            (offset, 0)
        } else {
            let dist = offset * 8usize.div_ceil(offset);
            for j in 0..dist.min(len) {
                out[op + j] = out[src + j];
            }
            (dist, dist)
        };
        while k < len {
            let s = op + k - dist;
            let chunk: [u8; 8] = out[s..s + 8].try_into().unwrap();
            out[op + k..op + k + 8].copy_from_slice(&chunk);
            k += 8;
        }
    }
}

/// Resolve the offset value, handling repeat offsets (RFC 8878 Section
/// 3.1.1.5). Offset values above 3 are new offsets (value - 3); 1..=3 select
/// a repeat offset, shifted by one when the literal length is zero.
///
/// Returns 0 for an invalid offset (Offset_Value 0, or repeat offset
/// `rep[0] - 1` with `rep[0] == 1`); the caller rejects it. Only constant
/// indices touch `reps`, so it can live in registers.
#[inline(always)]
fn resolve_offset(offset_value: u32, literal_length: u32, reps: &mut [u32; 3]) -> u32 {
    if offset_value > 3 {
        let offset = offset_value - 3;
        reps[2] = reps[1];
        reps[1] = reps[0];
        reps[0] = offset;
        return offset;
    }
    // 0 => rep0, 1 => rep1, 2 => rep2, 3 => rep0 - 1.
    let idx = offset_value.wrapping_sub(1) + (literal_length == 0) as u32;
    let offset = match idx {
        0 => return reps[0],
        1 => reps[1],
        2 => reps[2],
        3 => reps[0].wrapping_sub(1),
        _ => return 0,
    };
    // idx 1 swaps rep0 and rep1; idx 2 and 3 shift everything down.
    if idx != 1 {
        reps[2] = reps[1];
    }
    reps[1] = reps[0];
    reps[0] = offset;
    offset
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_offset_new() {
        let mut rep = [1u32, 4, 8];
        let off = resolve_offset(100, 5, &mut rep);
        assert_eq!(off, 97); // 100 - 3
        assert_eq!(rep[0], 97);
        assert_eq!(rep[1], 1);
        assert_eq!(rep[2], 4);
    }

    #[test]
    fn test_resolve_offset_repeat1() {
        let mut rep = [10u32, 4, 8];
        let off = resolve_offset(1, 5, &mut rep); // ll > 0
        assert_eq!(off, 10); // rep[0]
        assert_eq!(rep[0], 10);
    }

    #[test]
    fn test_resolve_offset_repeat2() {
        let mut rep = [10u32, 20, 8];
        let off = resolve_offset(2, 5, &mut rep);
        assert_eq!(off, 20); // rep[1]
        assert_eq!(rep[0], 20);
        assert_eq!(rep[1], 10);
    }

    #[test]
    fn test_resolve_offset_repeat1_ll0() {
        let mut rep = [10u32, 20, 30];
        let off = resolve_offset(1, 0, &mut rep); // ll == 0
        assert_eq!(off, 20); // rep[1] when ll==0
        assert_eq!(rep[0], 20);
        assert_eq!(rep[1], 10);
    }

    #[test]
    fn test_resolve_offset_remaining_repeat_cases() {
        // ll > 0, value 3 -> rep[2], rotated to the front.
        let mut rep = [10u32, 20, 30];
        assert_eq!(resolve_offset(3, 5, &mut rep), 30);
        assert_eq!(rep, [30, 10, 20]);

        // ll == 0, value 2 -> rep[2].
        let mut rep = [10u32, 20, 30];
        assert_eq!(resolve_offset(2, 0, &mut rep), 30);
        assert_eq!(rep, [30, 10, 20]);

        // ll == 0, value 3 -> rep[0] - 1.
        let mut rep = [10u32, 20, 30];
        assert_eq!(resolve_offset(3, 0, &mut rep), 9);
        assert_eq!(rep, [9, 10, 20]);

        // rep[0] - 1 == 0 is invalid.
        let mut rep = [1u32, 20, 30];
        assert_eq!(resolve_offset(3, 0, &mut rep), 0);

        // Offset_Value 0 is invalid.
        let mut rep = [10u32, 20, 30];
        assert_eq!(resolve_offset(0, 5, &mut rep), 0);
        assert_eq!(rep, [10, 20, 30]);
    }

    /// Run `copy_match` on `history` followed by slack and return the
    /// logical result.
    fn run_copy(history: &[u8], offset: usize, len: usize) -> Vec<u8> {
        let mut out = history.to_vec();
        out.resize(history.len() + len + WILDCOPY_SLACK, 0xEE);
        copy_match(&mut out, history.len(), offset, len);
        out.truncate(history.len() + len);
        out
    }

    #[test]
    fn test_copy_match_simple() {
        // "abcd", copy 3 bytes from offset 4 -> "abcdabc"
        assert_eq!(run_copy(b"abcd", 4, 3), b"abcdabc");
    }

    #[test]
    fn test_copy_match_overlapping() {
        // "a", copy 4 bytes from offset 1 -> "aaaaa"
        assert_eq!(run_copy(b"a", 1, 4), b"aaaaa");
    }

    #[test]
    fn test_copy_match_overlapping_pattern() {
        // "ab", copy 7 bytes from offset 2 -> "ababababa"
        assert_eq!(run_copy(b"ab", 2, 7), b"ababababa");
    }

    #[test]
    fn test_copy_match_all_offsets_and_lengths() {
        let history: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(37) ^ 0x5A).collect();
        for offset in 1..=40 {
            for len in 0..=80 {
                let mut expected = history.clone();
                for _ in 0..len {
                    expected.push(expected[expected.len() - offset]);
                }
                assert_eq!(
                    run_copy(&history, offset, len),
                    expected,
                    "offset {offset} len {len}"
                );
            }
        }
    }
}
