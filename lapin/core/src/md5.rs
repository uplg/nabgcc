//! MD5 and HMAC-MD5, for the integrity code of WPA's (TKIP) handshake,
//! and RC4, which carries its group key.

use crate::hash::{Engine, Keyed, hasher};

const S: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

fn k(i: usize) -> u32 {
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    K[i]
}

const START: Engine = Engine::new(
    [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0, 0, 0, 0],
    compress,
    false,
);

hasher!(Md5, md5, 16);

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut m = [0u32; 16];
    for (slot, word) in m.iter_mut().zip(block.as_chunks::<4>().0) {
        *slot = u32::from_le_bytes(*word);
    }
    let [mut a, mut b, mut c, mut d, ..] = *state;
    for i in 0..64 {
        let (f, g) = match i / 16 {
            0 => ((b & c) | (!b & d), i),
            1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            2 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let f = f.wrapping_add(a).wrapping_add(k(i)).wrapping_add(m[g]);
        a = d;
        d = c;
        c = b;
        b = b.wrapping_add(f.rotate_left(S[(i / 16) * 4 + i % 4]));
    }
    for (s, x) in state.iter_mut().zip([a, b, c, d]) {
        *s = s.wrapping_add(x);
    }
}

pub fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    Keyed::new(&START, 16, key).code(parts)
}

/// RC4 over `data` in place, after throwing away the first `skip`
/// bytes of key stream (WPA skips 256).
pub fn rc4(key: &[u8], skip: usize, data: &mut [u8]) {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    for n in 0..skip + data.len() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        if n >= skip {
            data[n - skip] ^= s[s[i as usize].wrapping_add(s[j as usize]) as usize];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn md5_rfc1321() {
        assert_eq!(md5(&[])[..], hex("d41d8cd98f00b204e9800998ecf8427e"));
        assert_eq!(
            md5(&[
                b"1234567890123456789012345678901234567890",
                b"1234567890123456789012345678901234567890"
            ])[..],
            hex("57edf4a22be3c955ac49da2e2107b67a")
        );
    }

    #[test]
    fn hmac_rfc2104() {
        assert_eq!(
            hmac_md5(&[0x0b; 16], &[b"Hi There"])[..],
            hex("9294727a3638bb1c13f48ef8158bfc9d")
        );
        assert_eq!(
            hmac_md5(b"Jefe", &[b"what do ya want ", b"for nothing?"])[..],
            hex("750c783e6ab0b503eaa86e310a5db738")
        );
    }

    #[test]
    fn rc4_rfc6229() {
        // RFC 6229, 40-bit key 0102030405: key stream at offsets 0 and 256.
        let mut z = [0u8; 16];
        rc4(&hex("0102030405"), 0, &mut z);
        assert_eq!(z[..], hex("b2396305f03dc027ccc3524a0a1118a8"));
        let mut z = [0u8; 16];
        rc4(&hex("0102030405"), 256, &mut z);
        assert_eq!(z[..], hex("1cfcf62b03eddb641d77dfcf7f8d8c93"));
    }
}
