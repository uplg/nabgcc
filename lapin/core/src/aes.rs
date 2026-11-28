//! AES-128 and the 802.11 constructions on it: CCM (the CCMP cipher),
//! CMAC (the WPA3 handshake's integrity code, and BIP), and key wrap
//! (RFC 3394, how WPA2 hands over the group keys).

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// The inverse S-box, made from the S-box when the firmware is built.
const INV_SBOX: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    t
};

/// Times x in GF(2^8), the reduction applied by a mask: Thumb has no
/// conditional instructions, a test of the top bit would be a branch
/// on the key or the data.
fn xtime(x: u8) -> u8 {
    (x << 1) ^ (0u8.wrapping_sub(x >> 7) & 0x1b)
}

/// An expanded AES-128 key.
pub struct Aes {
    rounds: [[u8; 16]; 11],
}

pub type Block = [u8; 16];

impl Aes {
    pub fn new(key: &[u8; 16]) -> Aes {
        let mut rounds = [[0u8; 16]; 11];
        rounds[0] = *key;
        let mut rcon = 1u8;
        for r in 1..11 {
            let prev = rounds[r - 1];
            let mut t = [prev[13], prev[14], prev[15], prev[12]];
            for b in t.iter_mut() {
                *b = SBOX[*b as usize];
            }
            t[0] ^= rcon;
            rcon = xtime(rcon);
            let mut next = [0u8; 16];
            for i in 0..16 {
                let before = if i < 4 { t[i] } else { next[i - 4] };
                next[i] = prev[i] ^ before;
            }
            rounds[r] = next;
        }
        Aes { rounds }
    }

    #[allow(clippy::needless_range_loop)]
    pub fn encrypt(&self, block: &mut Block) {
        let s = block;
        add(s, &self.rounds[0]);
        for r in 1..11 {
            for b in s.iter_mut() {
                *b = SBOX[*b as usize];
            }
            // Shift rows: row i of the column-major state turns by i.
            let t = *s;
            for c in 0..4 {
                for row in 1..4 {
                    s[4 * c + row] = t[4 * ((c + row) % 4) + row];
                }
            }
            if r != 10 {
                for c in s.as_chunks_mut::<4>().0 {
                    let all = c[0] ^ c[1] ^ c[2] ^ c[3];
                    let first = c[0];
                    c[0] ^= all ^ xtime(c[0] ^ c[1]);
                    c[1] ^= all ^ xtime(c[1] ^ c[2]);
                    c[2] ^= all ^ xtime(c[2] ^ c[3]);
                    c[3] ^= all ^ xtime(c[3] ^ first);
                }
            }
            add(s, &self.rounds[r]);
        }
    }

    /// Decryption, for the key unwrap only: a few blocks per handshake,
    /// so it is built from the forward steps. Mixing the columns four
    /// times, or shifting the rows four times, gives the block back:
    /// three times is the inverse. The S-box is undone by a table, in
    /// the same time whatever the byte.
    pub fn decrypt(&self, block: &mut Block) {
        let s = block;
        for r in (1..11).rev() {
            add(s, &self.rounds[r]);
            if r != 10 {
                for _ in 0..3 {
                    mix_columns(s);
                }
            }
            for _ in 0..3 {
                shift_rows(s);
            }
            for b in s.iter_mut() {
                *b = INV_SBOX[*b as usize];
            }
        }
        add(s, &self.rounds[0]);
    }
}

#[allow(clippy::needless_range_loop)]
fn shift_rows(s: &mut Block) {
    let t = *s;
    for c in 0..4 {
        for row in 1..4 {
            s[4 * c + row] = t[4 * ((c + row) % 4) + row];
        }
    }
}

fn mix_columns(s: &mut Block) {
    for c in s.as_chunks_mut::<4>().0 {
        let all = c[0] ^ c[1] ^ c[2] ^ c[3];
        let first = c[0];
        c[0] ^= all ^ xtime(c[0] ^ c[1]);
        c[1] ^= all ^ xtime(c[1] ^ c[2]);
        c[2] ^= all ^ xtime(c[2] ^ c[3]);
        c[3] ^= all ^ xtime(c[3] ^ first);
    }
}

fn add(s: &mut Block, k: &Block) {
    for (a, b) in s.iter_mut().zip(k) {
        *a ^= b;
    }
}

fn double(b: &Block) -> Block {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = b[i] << 1 | if i < 15 { b[i + 1] >> 7 } else { 0 };
    }
    out[15] ^= 0u8.wrapping_sub(b[0] >> 7) & 0x87;
    out
}

/// AES-CMAC (RFC 4493) of the concatenation of `parts`.
pub fn cmac(key: &[u8; 16], parts: &[&[u8]]) -> Block {
    let aes = Aes::new(key);
    let mut l = [0u8; 16];
    aes.encrypt(&mut l);
    let k1 = double(&l);
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut x = [0u8; 16];
    let mut block = [0u8; 16];
    let mut filled = 0;
    let mut seen = 0;
    for &byte in parts.iter().flat_map(|p| p.iter()) {
        if filled == 16 {
            add(&mut x, &block);
            aes.encrypt(&mut x);
            filled = 0;
        }
        block[filled] = byte;
        filled += 1;
        seen += 1;
    }
    debug_assert_eq!(seen, total);
    if total != 0 && filled == 16 {
        add(&mut block, &k1);
    } else {
        block[filled] = 0x80;
        block[filled + 1..].fill(0);
        add(&mut block, &double(&k1));
    }
    add(&mut x, &block);
    aes.encrypt(&mut x);
    x
}

/// CCM with an 8-byte tag and 13-byte nonce, as CCMP uses it: encrypts
/// (or decrypts) `data` in place and returns the tag over the plain text.
pub fn ccm(aes: &Aes, nonce: &[u8; 13], aad: &[u8], data: &mut [u8], decrypt: bool) -> [u8; 8] {
    let counter = |i: u16| {
        let mut a = [0u8; 16];
        a[0] = 0x01;
        a[1..14].copy_from_slice(nonce);
        a[14..].copy_from_slice(&i.to_be_bytes());
        aes.encrypt(&mut a);
        a
    };
    let mut x = [0u8; 16];
    x[0] = 0x59;
    x[1..14].copy_from_slice(nonce);
    x[14..].copy_from_slice(&(data.len() as u16).to_be_bytes());
    aes.encrypt(&mut x);
    // The associated data, with its length in front, in whole blocks.
    let head = (aad.len() as u16).to_be_bytes();
    let mut rest = head.iter().chain(aad).peekable();
    while rest.peek().is_some() {
        for (slot, b) in x.iter_mut().zip(&mut rest) {
            *slot ^= b;
        }
        aes.encrypt(&mut x);
    }
    for (i, chunk) in data.chunks_mut(16).enumerate() {
        let s = counter(i as u16 + 1);
        if decrypt {
            add_into(chunk, &s);
        }
        add_into(&mut x[..chunk.len()], chunk);
        aes.encrypt(&mut x);
        if !decrypt {
            add_into(chunk, &s);
        }
    }
    let s0 = counter(0);
    core::array::from_fn(|i| x[i] ^ s0[i])
}

fn add_into(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

/// RFC 3394 key unwrap: `out` gets `wrapped.len() - 8` bytes. False if
/// the integrity check fails or the sizes are wrong. The check looks at
/// every byte of the integrity value, whatever it holds.
#[inline(never)]
pub fn unwrap(kek: &[u8; 16], wrapped: &[u8], out: &mut [u8]) -> bool {
    let n = wrapped.len() / 8;
    if wrapped.len() % 8 != 0 || n < 3 || out.len() != wrapped.len() - 8 {
        return false;
    }
    let n = n - 1;
    let aes = Aes::new(kek);
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[..8]);
    out.copy_from_slice(&wrapped[8..]);
    for j in (0..6).rev() {
        for i in (1..=n).rev() {
            let t = (n * j + i) as u64;
            let mut b = [0u8; 16];
            for (k, x) in a.iter().zip(t.to_be_bytes()).enumerate() {
                b[k] = x.0 ^ x.1;
            }
            b[8..].copy_from_slice(&out[(i - 1) * 8..i * 8]);
            aes.decrypt(&mut b);
            a.copy_from_slice(&b[..8]);
            out[(i - 1) * 8..i * 8].copy_from_slice(&b[8..]);
        }
    }
    crate::ccmp::constant_eq(&a, &[0xA6; 8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn fips_197() {
        let key: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let aes = Aes::new(&key);
        let mut b: Block = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        aes.encrypt(&mut b);
        assert_eq!(b[..], hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
        aes.decrypt(&mut b);
        assert_eq!(b[..], hex("00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn cmac_rfc4493() {
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let m = hex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51
             30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        assert_eq!(cmac(&key, &[])[..], hex("bb1d6929e95937287fa37d129b756746"));
        assert_eq!(
            cmac(&key, &[&m[..16]])[..],
            hex("070a16b46b4d4144f79bdd9dd04a287c")
        );
        assert_eq!(
            cmac(&key, &[&m[..40]])[..],
            hex("dfa66747de9ae63030ca32611497c827")
        );
        assert_eq!(
            cmac(&key, &[&m[..20], &m[20..]])[..],
            hex("51f0bebf7e3b9d92fc49741779363cfe")
        );
    }

    #[test]
    fn unwrap_rfc3394() {
        let kek: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let wrapped = hex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
        let mut out = [0u8; 16];
        assert!(unwrap(&kek, &wrapped, &mut out));
        assert_eq!(out[..], hex("00112233445566778899aabbccddeeff"));
        let mut bad = wrapped.clone();
        bad[3] ^= 1;
        assert!(!unwrap(&kek, &bad, &mut out));
    }

    #[test]
    fn ccm_rfc3610_packet_1() {
        // Eight-byte tag, two-byte length: the parameters of CCMP.
        let key: [u8; 16] = hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf").try_into().unwrap();
        let aes = Aes::new(&key);
        let nonce: [u8; 13] = hex("00000003020100a0a1a2a3a4a5").try_into().unwrap();
        let mut data = hex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
        let plain = data.clone();
        let tag = ccm(&aes, &nonce, &hex("0001020304050607"), &mut data, false);
        assert_eq!(data, hex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"));
        assert_eq!(tag[..], hex("17e8d12cfdf926e0"));
        let back = ccm(&aes, &nonce, &hex("0001020304050607"), &mut data, true);
        assert_eq!(data, plain);
        assert_eq!(tag, back);
    }
}
