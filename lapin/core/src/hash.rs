//! What MD5, SHA-1 and SHA-256 share: the 64-byte blocks, the padding
//! with the length at the end, and HMAC. Each hash brings its initial
//! state, its block function and its byte order; the rest is one copy.

/// A hash's block function, over a state of up to eight words.
pub(crate) type Compress = fn(&mut [u32; 8], &[u8; 64]);

#[derive(Clone)]
pub(crate) struct Engine {
    state: [u32; 8],
    block: [u8; 64],
    filled: usize,
    length: u64,
    compress: Compress,
    /// SHA's byte order; MD5's is little-endian.
    big_endian: bool,
}

impl Engine {
    pub(crate) const fn new(state: [u32; 8], compress: Compress, big_endian: bool) -> Engine {
        Engine {
            state,
            block: [0; 64],
            filled: 0,
            length: 0,
            compress,
            big_endian,
        }
    }

    #[inline(never)]
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.length += data.len() as u64;
        for &byte in data {
            self.block[self.filled] = byte;
            self.filled += 1;
            if self.filled == 64 {
                (self.compress)(&mut self.state, &self.block);
                self.filled = 0;
            }
        }
    }

    /// Pad, and write the first `out.len() / 4` words of the state.
    #[inline(never)]
    pub(crate) fn finish(&mut self, out: &mut [u8]) {
        let bits = self.length * 8;
        self.block[self.filled] = 0x80;
        self.block[self.filled + 1..].fill(0);
        if self.filled >= 56 {
            (self.compress)(&mut self.state, &self.block);
            self.block = [0; 64];
        }
        let swap = if self.big_endian { 0 } else { 7 };
        for (i, byte) in self.block[56..].iter_mut().enumerate() {
            *byte = (bits >> (8 * ((7 - i) ^ swap))) as u8;
        }
        (self.compress)(&mut self.state, &self.block);
        let swap = swap & 3;
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (self.state[i / 4] >> (8 * ((3 - i % 4) ^ swap))) as u8;
        }
    }
}

/// The two hash states an HMAC key leads to, computed once for the
/// many messages PBKDF2 signs with the same key.
#[derive(Clone)]
pub(crate) struct Keyed {
    inner: Engine,
    outer: Engine,
    /// The digest's length.
    size: usize,
}

impl Keyed {
    /// `fresh` is the hash at its start, `size` its digest's length.
    #[inline(never)]
    pub(crate) fn new(fresh: &Engine, size: usize, key: &[u8]) -> Keyed {
        let mut block = [0u8; 64];
        if key.len() > 64 {
            let mut h = fresh.clone();
            h.update(key);
            h.finish(&mut block[..size]);
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut inner = fresh.clone();
        for b in block.iter_mut() {
            *b ^= 0x36;
        }
        inner.update(&block);
        let mut outer = fresh.clone();
        for b in block.iter_mut() {
            *b ^= 0x36 ^ 0x5C;
        }
        outer.update(&block);
        Keyed { inner, outer, size }
    }

    /// The code of the concatenation of `parts`, into `out` (the
    /// digest's length).
    #[inline(never)]
    pub(crate) fn sign(&self, parts: &[&[u8]], out: &mut [u8]) {
        let mut inner = self.inner.clone();
        for p in parts {
            inner.update(p);
        }
        let mut digest = [0u8; 32];
        let digest = &mut digest[..self.size];
        inner.finish(digest);
        let mut outer = self.outer.clone();
        outer.update(digest);
        outer.finish(out);
    }
}
