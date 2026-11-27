//! Random numbers for the key exchanges, from what the board offers:
//! no generator in silicon, so a pool that everything uncertain is
//! stirred into (analogue noise, the moments frames arrive, their
//! contents and signal strength, the jitter of the main loop), and
//! output drawn from it through SHA-256.
//!
//! What it is not: a source of entropy. On the rabbit the inputs are a
//! volume wheel's ADC readings, the jitter of a busy loop against the
//! millisecond tick, and what the radio hears, much of which an
//! onlooker hears too. The firmware counts what went in (`mixes`) and
//! draws nothing for a key exchange before enough has (see the board's
//! `Radio::random`); it cannot measure how unpredictable it was.

use crate::sha256::{Sha256, sha256};

pub struct Pool {
    state: [u8; 32],
    counter: u64,
    /// Cheap mixing of frequent events, hashed in at the next draw.
    acc: [u32; 8],
    at: usize,
    mixes: u32,
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl Pool {
    pub const fn new() -> Pool {
        Pool {
            state: [0; 32],
            counter: 0,
            acc: [0; 8],
            at: 0,
            mixes: 0,
        }
    }

    /// Mix something in.
    pub fn stir(&mut self, parts: &[&[u8]]) {
        let mut h = Sha256::new();
        h.update(&self.state);
        for p in parts {
            h.update(p);
        }
        self.state = h.finish();
        self.mixes = self.mixes.saturating_add(1);
    }

    /// How many things were mixed or stirred in so far.
    pub fn mixes(&self) -> u32 {
        self.mixes
    }

    /// Mix a word in, at the cost of a few instructions: for events
    /// too frequent to hash each time.
    pub fn mix(&mut self, x: u32) {
        let a = &mut self.acc[self.at];
        *a = a.rotate_left(7) ^ x.wrapping_mul(0x9E37_79B1);
        self.at = (self.at + 1) & 7;
        self.mixes = self.mixes.saturating_add(1);
    }

    /// Fill `out`; the pool moves on, so that what came out cannot be
    /// found again from the pool's later state.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut acc = [0u8; 32];
        for (chunk, w) in acc.as_chunks_mut::<4>().0.iter_mut().zip(self.acc) {
            *chunk = w.to_le_bytes();
        }
        self.stir(&[&acc]);
        for chunk in out.chunks_mut(32) {
            self.counter += 1;
            let block = sha256(&[&self.state, b"out", &self.counter.to_le_bytes()]);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        self.state = sha256(&[&self.state, b"next", &self.counter.to_le_bytes()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outputs_differ_and_depend_on_what_was_stirred() {
        let mut a = Pool::new();
        let mut b = Pool::new();
        a.stir(&[b"one"]);
        b.stir(&[b"two"]);
        let (mut x, mut y, mut z) = ([0u8; 40], [0u8; 40], [0u8; 40]);
        a.fill(&mut x);
        a.fill(&mut y);
        b.fill(&mut z);
        assert_ne!(x, y);
        assert_ne!(x, z);
        assert_ne!(x[..32], x[8..]);
    }

    #[test]
    fn what_went_in_is_counted() {
        let mut a = Pool::new();
        assert_eq!(a.mixes(), 0);
        a.mix(1);
        a.stir(&[b"x"]);
        assert_eq!(a.mixes(), 2);
    }
}
