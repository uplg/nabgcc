//! SHA-256 and what is built on it: HMAC, the 802.11 key derivation
//! function, HKDF-Expand. Small rather than fast.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    filled: usize,
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            filled: 0,
            length: 0,
        }
    }

    fn compress(&mut self) {
        let mut w = [0u32; 64];
        for (slot, word) in w.iter_mut().zip(self.block.as_chunks::<4>().0) {
            *slot = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = self.state;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            v.copy_within(0..7, 1);
            v[4] = v[4].wrapping_add(t1);
            v[0] = t1.wrapping_add(s0).wrapping_add(maj);
        }
        for (s, x) in self.state.iter_mut().zip(v) {
            *s = s.wrapping_add(x);
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.length += data.len() as u64;
        for &byte in data {
            self.block[self.filled] = byte;
            self.filled += 1;
            if self.filled == 64 {
                self.compress();
                self.filled = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.length * 8;
        self.update(&[0x80]);
        while self.filled != 56 {
            self.update(&[0]);
        }
        self.block[56..].copy_from_slice(&bits.to_be_bytes());
        self.compress();
        let mut out = [0u8; 32];
        for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *chunk = word.to_be_bytes();
        }
        out
    }
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finish()
}

pub fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256(&[key]));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(&block.map(|b| b ^ 0x36));
    for p in parts {
        inner.update(p);
    }
    let mut outer = Sha256::new();
    outer.update(&block.map(|b| b ^ 0x5C));
    outer.update(&inner.finish());
    outer.finish()
}

/// The 802.11 key derivation function: fills `out` from a key, a label
/// and a context. The length that goes into the hash is `out`'s, in bits.
pub fn kdf(key: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    let bits = (out.len() as u16 * 8).to_le_bytes();
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let block = hmac(key, &[&(i as u16 + 1).to_le_bytes(), label, context, &bits]);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

/// HKDF-Expand (RFC 5869).
pub fn hkdf_expand(key: &[u8], info: &[u8], out: &mut [u8]) {
    let mut previous = [0u8; 32];
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let before: &[u8] = if i == 0 { &[] } else { &previous };
        previous = hmac(key, &[before, info, &[i as u8 + 1]]);
        chunk.copy_from_slice(&previous[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn digests_match_the_published_ones() {
        assert_eq!(
            sha256(&[b"abc"]).to_vec(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            sha256(&[]).to_vec(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        // Longer than a block, and split across updates.
        let long = [b'a'; 200];
        assert_eq!(sha256(&[&long[..63], &long[63..]]), sha256(&[&long]));
        assert_eq!(
            sha256(&[b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"]).to_vec(),
            hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
    }

    #[test]
    fn hmac_and_hkdf_match_their_rfcs() {
        assert_eq!(
            hmac(b"Jefe", &[b"what do ya want ", b"for nothing?"]).to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        // RFC 4231, test case 6: a key longer than a block.
        assert_eq!(
            hmac(
                &[0xaa; 131],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )
            .to_vec(),
            hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
        let prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let mut out = [0u8; 42];
        hkdf_expand(&prk, &hex("f0f1f2f3f4f5f6f7f8f9"), &mut out);
        assert_eq!(
            out.to_vec(),
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }
}
