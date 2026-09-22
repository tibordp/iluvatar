//! AES-256-CBC decryption as a stage on the packed side of a chain. Key
//! derivation belongs to the container (7z hashes the password its own
//! way); this stage takes the finished key and IV.

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;

use crate::compress::checkpoint::{AesCheckpointState, Checkpoint, CheckpointState};
use crate::compress::decompressor::{DecompressResult, DecompressStatus, Decompressor};
use crate::error::{Error, Result};

const BLOCK: usize = 16;

pub struct AesCbcDecryptor {
    cipher: Aes256,
    iv: [u8; 16],
    prev: [u8; 16],
    carry: Vec<u8>,
    staged: Vec<u8>,
    produced: u64,
    /// Plaintext length; the last block's padding is cut here. `None`
    /// emits every decrypted byte.
    len: Option<u64>,
    finished: bool,
}

impl AesCbcDecryptor {
    pub fn new(key: &[u8; 32], iv: [u8; 16], len: Option<u64>) -> Self {
        Self {
            cipher: Aes256::new(key.into()),
            iv,
            prev: iv,
            carry: Vec::new(),
            staged: Vec::new(),
            produced: 0,
            len,
            finished: false,
        }
    }

    fn remaining(&self) -> u64 {
        self.len
            .map_or(u64::MAX, |l| l.saturating_sub(self.produced))
    }

    fn emit(&mut self, output: &mut [u8]) -> usize {
        let n = self
            .staged
            .len()
            .min(output.len())
            .min(self.remaining().min(usize::MAX as u64) as usize);
        output[..n].copy_from_slice(&self.staged[..n]);
        self.staged.drain(..n);
        self.produced += n as u64;
        if self.remaining() == 0 {
            self.finished = true;
            self.staged.clear();
        }
        n
    }

    fn decrypt_block(&mut self, block: &[u8]) {
        let mut b = [0u8; BLOCK];
        b.copy_from_slice(block);
        let mut out = b;
        self.cipher.decrypt_block((&mut out).into());
        for (o, p) in out.iter_mut().zip(self.prev.iter()) {
            *o ^= p;
        }
        self.prev = b;
        self.staged.extend_from_slice(&out);
    }
}

impl Decompressor for AesCbcDecryptor {
    fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<DecompressResult> {
        let mut produced = self.emit(output);
        let mut consumed = 0;
        if self.finished {
            return Ok(DecompressResult {
                bytes_consumed: 0,
                bytes_produced: produced,
                status: DecompressStatus::StreamEnd,
            });
        }
        if input.is_empty() {
            if !self.carry.is_empty() {
                return Err(Error::DecompressionError(
                    "encrypted stream ends mid-block".into(),
                ));
            }
            if self.staged.is_empty() {
                self.finished = true;
            }
        } else if produced < output.len() && self.staged.is_empty() {
            // Decrypt no more than the output can take, so a checkpoint
            // rarely has to carry staged plaintext.
            let want_blocks = ((output.len() - produced) / BLOCK).max(1);
            let mut pos = 0;
            if !self.carry.is_empty() {
                let need = BLOCK - self.carry.len();
                let take = need.min(input.len());
                self.carry.extend_from_slice(&input[..take]);
                pos = take;
                if self.carry.len() == BLOCK {
                    let block = std::mem::take(&mut self.carry);
                    self.decrypt_block(&block);
                }
            }
            let mut blocks = usize::from(self.staged.len() >= BLOCK);
            while blocks < want_blocks && input.len() - pos >= BLOCK {
                self.decrypt_block(&input[pos..pos + BLOCK]);
                pos += BLOCK;
                blocks += 1;
            }
            if blocks < want_blocks && pos < input.len() {
                self.carry.extend_from_slice(&input[pos..]);
                pos = input.len();
            }
            consumed = pos;
            produced += self.emit(&mut output[produced..]);
        }
        Ok(DecompressResult {
            bytes_consumed: consumed,
            bytes_produced: produced,
            status: if self.finished {
                DecompressStatus::StreamEnd
            } else {
                DecompressStatus::Continue
            },
        })
    }

    fn checkpoint(
        &self,
        compressed_offset: u64,
        uncompressed_offset: u64,
    ) -> Result<Option<Checkpoint>> {
        Ok(Some(Checkpoint {
            compressed_offset,
            bit_offset: 0,
            uncompressed_offset,
            state: CheckpointState::Aes(AesCheckpointState {
                prev: self.prev,
                carry: self.carry.clone(),
                staged: self.staged.clone(),
                produced: self.produced,
                finished: self.finished,
            }),
        }))
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<()> {
        match &checkpoint.state {
            CheckpointState::Aes(s) => {
                self.prev = s.prev;
                self.carry = s.carry.clone();
                self.staged = s.staged.clone();
                self.produced = s.produced;
                self.finished = s.finished;
                Ok(())
            }
            CheckpointState::None => {
                self.prev = self.iv;
                self.carry.clear();
                self.staged.clear();
                self.produced = 0;
                self.finished = false;
                Ok(())
            }
            _ => Err(Error::CheckpointError(
                "expected AES checkpoint state".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncrypt;

    fn encrypt(key: &[u8; 32], iv: [u8; 16], plain: &[u8]) -> Vec<u8> {
        let cipher = Aes256::new(key.into());
        let mut prev = iv;
        let mut out = Vec::new();
        let mut padded = plain.to_vec();
        padded.resize(plain.len().div_ceil(BLOCK) * BLOCK, 0);
        for chunk in padded.chunks(BLOCK) {
            let mut b = [0u8; BLOCK];
            for (i, (c, p)) in chunk.iter().zip(prev.iter()).enumerate() {
                b[i] = c ^ p;
            }
            cipher.encrypt_block((&mut b).into());
            out.extend_from_slice(&b);
            prev = b;
        }
        out
    }

    #[test]
    fn round_trip_with_odd_chunking_and_restore() {
        let key = [7u8; 32];
        let iv = [3u8; 16];
        let plain: Vec<u8> = (0..10_007u32).map(|i| (i * 31 % 251) as u8).collect();
        let cipher_text = encrypt(&key, iv, &plain);

        let mut dec = AesCbcDecryptor::new(&key, iv, Some(plain.len() as u64));
        let mut out = vec![0u8; 100];
        let mut got = Vec::new();
        let mut pos = 0;
        let mut cp = None;
        for step in 0.. {
            let input = &cipher_text[pos..(pos + 37).min(cipher_text.len())];
            let r = dec.decompress(input, &mut out).unwrap();
            pos += r.bytes_consumed;
            got.extend_from_slice(&out[..r.bytes_produced]);
            if step == 50 {
                cp = Some((
                    dec.checkpoint(pos as u64, got.len() as u64)
                        .unwrap()
                        .unwrap(),
                    pos,
                    got.len(),
                ));
            }
            if r.status == DecompressStatus::StreamEnd {
                break;
            }
        }
        assert_eq!(got, plain);

        let (cp, cp_pos, cp_out) = cp.unwrap();
        let mut fresh = AesCbcDecryptor::new(&key, iv, Some(plain.len() as u64));
        fresh.restore(&cp).unwrap();
        let mut got2 = plain[..cp_out].to_vec();
        let mut pos = cp_pos;
        loop {
            let input = &cipher_text[pos..(pos + 1000).min(cipher_text.len())];
            let r = fresh.decompress(input, &mut out).unwrap();
            pos += r.bytes_consumed;
            got2.extend_from_slice(&out[..r.bytes_produced]);
            if r.status == DecompressStatus::StreamEnd {
                break;
            }
        }
        assert_eq!(got2, plain);
    }
}
