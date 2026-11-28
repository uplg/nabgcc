//! SHA-1 and what WPA and WPA2 build on it: HMAC, the passphrase to key
//! derivation (PBKDF2, 4096 rounds) and the pairwise key expansion PRF.

use crate::hash::{Engine, Keyed, hasher};

const START: Engine = Engine::new(
    [
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0, 0, 0, 0,
    ],
    compress,
    true,
);

hasher!(Sha1, sha1, 20);

/// The rounds' constants, twenty rounds each, and which function they
/// take (0: choose, 1: parity, 2: majority).
const ROUNDS: [(u32, u8); 4] = [
    (0x5A827999, 0),
    (0x6ED9EBA1, 1),
    (0x8F1BBCDC, 2),
    (0xCA62C1D6, 1),
];

/// A sum modulo 2^32, as an operator the ARM code can take inline
/// (`wrapping_add` would be a call into Thumb code), and ARM code itself
/// so that it can be.
#[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
#[inline(always)]
fn add(a: u32, b: u32) -> u32 {
    (a as u64 + b as u64) as u32
}

/// The block function, which PBKDF2 runs 16 384 times for a WPA2
/// passphrase. Each round's function comes from a loop of its own: `i /
/// 20` was a call to the library's division (the ARM7 has none), 80 a
/// block. Compiled as ARM code, whose shifts and rotations come with
/// the operation that takes them; written with plain loops and no call,
/// since the compiler will not inline the library's (Thumb) iterators
/// into it.
#[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
// The rotations written out: `rotate_left` is the library's (Thumb)
// function, not inlined into ARM code: a call each round, and the
// firmware 112 bytes larger (measured).
#[allow(clippy::manual_rotate)]
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 16];
    let mut i = 0;
    while i < 16 {
        w[i] = (block[4 * i] as u32) << 24
            | (block[4 * i + 1] as u32) << 16
            | (block[4 * i + 2] as u32) << 8
            | block[4 * i + 3] as u32;
        i += 1;
    }
    let [mut a, mut b, mut c, mut d, mut e, ..] = *state;
    let mut i = 0;
    let mut phase = 0;
    while phase < 4 {
        let (k, f) = ROUNDS[phase];
        let end = i + 20;
        while i < end {
            if i >= 16 {
                let x = w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15];
                w[i & 15] = x << 1 | x >> 31;
            }
            let f = match f {
                0 => (b & c) | (!b & d),
                1 => b ^ c ^ d,
                _ => (b & c) | (b & d) | (c & d),
            };
            let t = add(add(add(add(a << 5 | a >> 27, f), e), k), w[i & 15]);
            e = d;
            d = c;
            c = b << 30 | b >> 2;
            b = a;
            a = t;
            i += 1;
        }
        phase += 1;
    }
    state[0] = add(state[0], a);
    state[1] = add(state[1], b);
    state[2] = add(state[2], c);
    state[3] = add(state[3], d);
    state[4] = add(state[4], e);
}

fn keyed(key: &[u8]) -> Keyed {
    Keyed::new(&START, 20, key)
}

pub fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    keyed(key).code(parts)
}

/// The pairwise master key of a WPA or WPA2 network from its passphrase
/// (IEEE 802.11-2020, J.4: PBKDF2-SHA1, 4096 rounds). `progress` is
/// called every 64 rounds: the whole takes seconds on the rabbit.
pub fn passphrase_to_pmk(
    passphrase: &[u8],
    ssid: &[u8],
    progress: &mut dyn FnMut(u32),
) -> [u8; 32] {
    let key = keyed(passphrase);
    let mut pmk = [0u8; 40];
    for (block, out) in pmk.chunks_mut(20).enumerate() {
        let mut u = key.code::<20>(&[ssid, &(block as u32 + 1).to_be_bytes()]);
        let mut sum = u;
        for round in 1..4096 {
            key.code_in_place(&mut u);
            for (s, x) in sum.iter_mut().zip(u) {
                *s ^= x;
            }
            if round % 64 == 0 {
                progress(block as u32 * 4096 + round);
            }
        }
        out.copy_from_slice(&sum);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&pmk[..32]);
    out
}

/// The PRF of IEEE 802.11-2020 12.7.1.2: `out` filled from HMAC-SHA1
/// rounds over the label, a zero byte, the data and a counter.
pub fn prf(key: &[u8], label: &[u8], data: &[u8], out: &mut [u8]) {
    let key = keyed(key);
    for (i, chunk) in out.chunks_mut(20).enumerate() {
        let block: [u8; 20] = key.code(&[label, &[0], data, &[i as u8]]);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn hashes() {
        assert_eq!(
            sha1(&[b"abc"])[..],
            hex("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            sha1(&[b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"])[..],
            hex("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        );
    }

    #[test]
    fn hmac_rfc2202() {
        assert_eq!(
            hmac_sha1(&[0x0b; 20], &[b"Hi There"])[..],
            hex("b617318655057264e28bc0b6fb378c8ef146be00")
        );
        assert_eq!(
            hmac_sha1(
                &[0xaa; 80],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )[..],
            hex("aa4ae5e15272d00e95705637ce8a3b55ed402112")
        );
    }

    #[test]
    fn psk_ieee_j4() {
        let mut calls = 0;
        let pmk = passphrase_to_pmk(b"password", b"IEEE", &mut |_| calls += 1);
        assert_eq!(
            pmk[..],
            hex("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e")
        );
        assert_eq!(calls, 2 * 63);
        let pmk = passphrase_to_pmk(b"ThisIsAPassword", b"ThisIsASSID", &mut |_| {});
        assert_eq!(
            pmk[..],
            hex("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af")
        );
    }

    #[test]
    fn prf_ieee_j3() {
        // IEEE 802.11-2020 J.3.2, test case 1.
        let mut out = [0u8; 64];
        prf(&[0x0b; 20], b"prefix", b"Hi There", &mut out);
        assert_eq!(
            out[..],
            hex(
                "bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606e17d8da35402ffee75df78c3d31e0f889f012120c0862beb67753e7439ae242edb8373698356cf5a"
            )
        );
    }
}
