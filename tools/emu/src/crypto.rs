//! The cryptography of 802.11 links: WEP, TKIP and CCMP frame
//! protection as the Wi-Fi chip applies it, and the key derivations an
//! access point needs for the WPA handshakes.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use md5::Md5;
use sha1::{Digest, Sha1};
use sha2::Sha256;

pub const HEADER_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Wep,
    Tkip,
    Ccmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherError {
    /// The frame is too short to hold what the cipher adds.
    Malformed,
    /// WEP or TKIP integrity check value, or CCMP MIC, does not match.
    Icv,
    /// TKIP Michael message integrity code does not match.
    Mic,
}

// ---- hashes -------------------------------------------------------------

pub fn sha1(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hmac<const N: usize>(hash: fn(&[&[u8]]) -> [u8; N], key: &[u8], parts: &[&[u8]]) -> [u8; N] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..N].copy_from_slice(&hash(&[key]));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let ipad = block.map(|b| b ^ 0x36);
    let opad = block.map(|b| b ^ 0x5C);
    let mut inner: Vec<&[u8]> = vec![&ipad];
    inner.extend_from_slice(parts);
    let digest = hash(&inner);
    hash(&[&opad, &digest])
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    hmac(sha256, key, parts)
}

/// The 802.11 key derivation function over HMAC-SHA-256: `bits` of
/// output from a key, a label and a context.
pub fn kdf_sha256(key: &[u8], label: &str, context: &[u8], bits: u16) -> Vec<u8> {
    let len = (bits as usize).div_ceil(8);
    let mut out = Vec::with_capacity(len + 32);
    let mut counter = 1u16;
    while out.len() < len {
        out.extend_from_slice(&hmac_sha256(
            key,
            &[
                &counter.to_le_bytes(),
                label.as_bytes(),
                context,
                &bits.to_le_bytes(),
            ],
        ));
        counter += 1;
    }
    out.truncate(len);
    out
}

/// HKDF-Expand over SHA-256 (RFC 5869).
pub fn hkdf_expand_sha256(key: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut block: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        block = hmac_sha256(key, &[&block, info, &[counter]]).to_vec();
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(len);
    out
}

/// AES-128-CMAC (RFC 4493).
pub fn aes_cmac(key: &[u8; 16], message: &[u8]) -> [u8; 16] {
    let c = aes(key);
    let double = |block: [u8; 16]| {
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = block[i] << 1 | if i < 15 { block[i + 1] >> 7 } else { 0 };
        }
        if block[0] & 0x80 != 0 {
            out[15] ^= 0x87;
        }
        out
    };
    let k1 = double(aes_encrypt(&c, [0; 16]));
    let k2 = double(k1);
    let whole = !message.is_empty() && message.len().is_multiple_of(16);
    let blocks = message.len().div_ceil(16).max(1);
    let mut x = [0u8; 16];
    for i in 0..blocks {
        let chunk = &message[(i * 16).min(message.len())..((i + 1) * 16).min(message.len())];
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        if i == blocks - 1 {
            if !whole {
                block[chunk.len()] = 0x80;
            }
            let k = if whole { k1 } else { k2 };
            for (b, k) in block.iter_mut().zip(k) {
                *b ^= k;
            }
        }
        for (a, b) in x.iter_mut().zip(block) {
            *a ^= b;
        }
        x = aes_encrypt(&c, x);
    }
    x
}

/// MIC of BIP-CMAC-128 (IEEE 802.11-2020 12.5.4) over a management
/// frame whose management MIC element ends it, MIC field zero or not:
/// AES-CMAC over the header's frame control (retry, power management
/// and more data cleared) and three addresses, then the body with the
/// MIC zeroed; the first 8 bytes.
pub fn bip_mic(igtk: &[u8; 16], frame: &[u8]) -> [u8; 8] {
    let mut aad = vec![frame[0], frame[1] & !0x38];
    aad.extend_from_slice(&frame[4..22]);
    aad.extend_from_slice(&frame[HEADER_LEN..frame.len() - 8]);
    aad.extend_from_slice(&[0; 8]);
    aes_cmac(igtk, &aad)[..8].try_into().unwrap()
}

pub fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    hmac(sha1, key, parts)
}

pub fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    hmac(md5, key, parts)
}

/// The pairwise master key of a WPA passphrase: PBKDF2-HMAC-SHA1, 4096
/// rounds, salted with the network name.
pub fn wpa_psk(passphrase: &str, ssid: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(20).enumerate() {
        let mut u = hmac_sha1(
            passphrase.as_bytes(),
            &[ssid.as_bytes(), &(i as u32 + 1).to_be_bytes()],
        );
        let mut t = u;
        for _ in 1..4096 {
            u = hmac_sha1(passphrase.as_bytes(), &[&u]);
            for (a, b) in t.iter_mut().zip(u) {
                *a ^= b;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    out
}

/// The 802.11i pseudo-random function, used to expand keys.
pub fn prf(key: &[u8], label: &str, data: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 20);
    let mut counter = 0u8;
    while out.len() < len {
        out.extend_from_slice(&hmac_sha1(key, &[label.as_bytes(), &[0], data, &[counter]]));
        counter += 1;
    }
    out.truncate(len);
    out
}

// ---- AES ----------------------------------------------------------------

fn aes(key: &[u8; 16]) -> Aes128 {
    Aes128::new(&Array::from(*key))
}

fn aes_encrypt(c: &Aes128, block: [u8; 16]) -> [u8; 16] {
    let mut b = Array::from(block);
    c.encrypt_block(&mut b);
    b.into()
}

/// AES key wrap (RFC 3394). `plain` is a multiple of 8 bytes.
pub fn aes_wrap(kek: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    let c = aes(kek);
    let n = plain.len() / 8;
    let mut a = [0xA6u8; 8];
    let mut r = plain.to_vec();
    for j in 0..6 {
        for i in 0..n {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(&r[i * 8..i * 8 + 8]);
            let b = aes_encrypt(&c, b);
            a.copy_from_slice(&b[..8]);
            let t = (n * j + i + 1) as u64;
            for (x, y) in a.iter_mut().zip(t.to_be_bytes()) {
                *x ^= y;
            }
            r[i * 8..i * 8 + 8].copy_from_slice(&b[8..]);
        }
    }
    let mut out = a.to_vec();
    out.extend_from_slice(&r);
    out
}

/// Inverse of [`aes_wrap`]; `None` when the integrity check fails.
pub fn aes_unwrap(kek: &[u8; 16], wrapped: &[u8]) -> Option<Vec<u8>> {
    if wrapped.len() < 16 || !wrapped.len().is_multiple_of(8) {
        return None;
    }
    let c = aes(kek);
    let n = wrapped.len() / 8 - 1;
    let mut a: [u8; 8] = wrapped[..8].try_into().unwrap();
    let mut r = wrapped[8..].to_vec();
    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let t = (n * j + i + 1) as u64;
            for (x, y) in a.iter_mut().zip(t.to_be_bytes()) {
                *x ^= y;
            }
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(&r[i * 8..i * 8 + 8]);
            let mut blk = Array::from(b);
            c.decrypt_block(&mut blk);
            a.copy_from_slice(&blk[..8]);
            r[i * 8..i * 8 + 8].copy_from_slice(&blk[8..]);
        }
    }
    (a == [0xA6; 8]).then_some(r)
}

/// CCM with an 8-byte tag and a 2-byte length field, as CCMP uses it.
/// Returns the keystream-processed data and the tag for `plain`.
fn ccm(key: &[u8; 16], nonce: &[u8; 13], aad: &[u8], data: &mut [u8], decrypt: bool) -> [u8; 8] {
    let c = aes(key);
    let counter_block = |i: u16| {
        let mut a = [0u8; 16];
        a[0] = 0x01;
        a[1..14].copy_from_slice(nonce);
        a[14..].copy_from_slice(&i.to_be_bytes());
        aes_encrypt(&c, a)
    };
    let crypt = |data: &mut [u8]| {
        for (i, chunk) in data.chunks_mut(16).enumerate() {
            let s = counter_block(i as u16 + 1);
            for (d, k) in chunk.iter_mut().zip(s) {
                *d ^= k;
            }
        }
    };
    if decrypt {
        crypt(data);
    }
    // CBC-MAC over the length block, the associated data, the plaintext.
    let mut x = [0u8; 16];
    x[0] = 0x59;
    x[1..14].copy_from_slice(nonce);
    x[14..].copy_from_slice(&(data.len() as u16).to_be_bytes());
    x = aes_encrypt(&c, x);
    let mut auth = (aad.len() as u16).to_be_bytes().to_vec();
    auth.extend_from_slice(aad);
    for part in [&auth[..], &data[..]] {
        for chunk in part.chunks(16) {
            for (a, b) in x.iter_mut().zip(chunk) {
                *a ^= b;
            }
            x = aes_encrypt(&c, x);
        }
    }
    if !decrypt {
        crypt(data);
    }
    let s0 = counter_block(0);
    let mut tag = [0u8; 8];
    for i in 0..8 {
        tag[i] = x[i] ^ s0[i];
    }
    tag
}

// ---- RC4, CRC-32, Michael, TKIP key mixing ------------------------------

pub fn rc4(key: &[u8], skip: usize, data: &mut [u8]) {
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    let mut next = || {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        s[s[i as usize].wrapping_add(s[j as usize]) as usize]
    };
    for _ in 0..skip {
        next();
    }
    for d in data {
        *d ^= next();
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// Michael, the TKIP message integrity code, over already-assembled
/// input (the pseudo-header followed by the payload).
pub fn michael(key: &[u8; 8], message: &[u8]) -> [u8; 8] {
    let mut l = u32::from_le_bytes(key[..4].try_into().unwrap());
    let mut r = u32::from_le_bytes(key[4..].try_into().unwrap());
    let mut padded = message.to_vec();
    padded.push(0x5A);
    padded.extend_from_slice(&[0; 4]);
    while !padded.len().is_multiple_of(4) {
        padded.push(0);
    }
    for word in padded.chunks(4) {
        l ^= u32::from_le_bytes(word.try_into().unwrap());
        r ^= l.rotate_left(17);
        l = l.wrapping_add(r);
        r ^= ((l & 0xFF00_FF00) >> 8) | ((l & 0x00FF_00FF) << 8);
        l = l.wrapping_add(r);
        r ^= l.rotate_left(3);
        l = l.wrapping_add(r);
        r ^= l.rotate_right(2);
        l = l.wrapping_add(r);
    }
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&l.to_le_bytes());
    out[4..].copy_from_slice(&r.to_le_bytes());
    out
}

fn aes_sbox() -> [u8; 256] {
    let mut s = [0u8; 256];
    let (mut p, mut q) = (1u8, 1u8);
    loop {
        p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1B } else { 0 };
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        s[p as usize] =
            q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4) ^ 0x63;
        if p == 1 {
            break;
        }
    }
    s[0] = 0x63;
    s
}

/// TKIP per-packet key: the 16-byte RC4 key for transmitter `ta` and
/// the 48-bit sequence counter split as `iv32`/`iv16`.
pub fn tkip_mix(tk: &[u8; 16], ta: &[u8; 6], iv32: u32, iv16: u16) -> [u8; 16] {
    let sbox = aes_sbox();
    let xtime = |b: u8| (b << 1) ^ if b & 0x80 != 0 { 0x1B } else { 0 };
    let s = |v: u16| {
        let t = |b: u8| {
            let x = sbox[b as usize];
            (xtime(x) as u16) << 8 | (xtime(x) ^ x) as u16
        };
        t(v as u8) ^ t((v >> 8) as u8).swap_bytes()
    };
    let mk = |hi: u8, lo: u8| (hi as u16) << 8 | lo as u16;
    let tk16 = |i: usize| mk(tk[i + 1], tk[i]);

    let mut p = [
        iv32 as u16,
        (iv32 >> 16) as u16,
        mk(ta[1], ta[0]),
        mk(ta[3], ta[2]),
        mk(ta[5], ta[4]),
    ];
    for i in 0..8u16 {
        let j = 2 * (i & 1) as usize;
        p[0] = p[0].wrapping_add(s(p[4] ^ tk16(j)));
        p[1] = p[1].wrapping_add(s(p[0] ^ tk16(4 + j)));
        p[2] = p[2].wrapping_add(s(p[1] ^ tk16(8 + j)));
        p[3] = p[3].wrapping_add(s(p[2] ^ tk16(12 + j)));
        p[4] = p[4].wrapping_add(s(p[3] ^ tk16(j))).wrapping_add(i);
    }
    let mut k = [p[0], p[1], p[2], p[3], p[4], p[4].wrapping_add(iv16)];
    for i in 0..6 {
        k[i] = k[i].wrapping_add(s(k[(i + 5) % 6] ^ tk16(2 * i)));
    }
    k[0] = k[0].wrapping_add((k[5] ^ tk16(12)).rotate_right(1));
    k[1] = k[1].wrapping_add((k[0] ^ tk16(14)).rotate_right(1));
    for i in 2..6 {
        k[i] = k[i].wrapping_add(k[i - 1].rotate_right(1));
    }
    let mut out = [0u8; 16];
    out[0] = (iv16 >> 8) as u8;
    out[1] = ((iv16 >> 8) as u8 | 0x20) & 0x7F;
    out[2] = iv16 as u8;
    out[3] = ((k[5] ^ tk16(0)) >> 1) as u8;
    for i in 0..6 {
        out[4 + 2 * i..6 + 2 * i].copy_from_slice(&k[i].to_le_bytes());
    }
    out
}

// ---- frames -------------------------------------------------------------

/// Destination and source of a data frame, for the Michael pseudo-header.
fn da_sa(frame: &[u8]) -> ([u8; 6], [u8; 6]) {
    let a = |n: usize| -> [u8; 6] { frame[4 + 6 * n..10 + 6 * n].try_into().unwrap() };
    match frame[1] & 3 {
        1 => (a(2), a(1)),
        2 => (a(0), a(2)),
        _ => (a(0), a(1)),
    }
}

fn michael_of(key: &[u8; 8], frame: &[u8], payload: &[u8]) -> [u8; 8] {
    let (da, sa) = da_sa(frame);
    let mut m = Vec::with_capacity(16 + payload.len());
    m.extend_from_slice(&da);
    m.extend_from_slice(&sa);
    m.extend_from_slice(&[0; 4]);
    m.extend_from_slice(payload);
    michael(key, &m)
}

fn ccmp_nonce_aad(frame: &[u8], pn: u64) -> ([u8; 13], Vec<u8>) {
    // Management frames (protected ones, under 802.11w) are flagged in
    // the nonce and keep their subtype in the authenticated header.
    let management = frame[0] & 0x0C == 0;
    let mut nonce = [0u8; 13];
    nonce[0] = if management { 0x10 } else { 0 };
    nonce[1..7].copy_from_slice(&frame[10..16]);
    nonce[7..].copy_from_slice(&pn.to_be_bytes()[2..]);
    let fc0 = if management {
        frame[0]
    } else {
        frame[0] & 0x8F
    };
    let mut aad = vec![fc0, (frame[1] & 0xC7) | 0x40];
    aad.extend_from_slice(&frame[4..22]);
    aad.extend_from_slice(&[frame[22] & 0x0F, 0]);
    (nonce, aad)
}

/// Key material for one direction of a link.
pub struct Key<'a> {
    pub cipher: Cipher,
    /// 5 or 13 bytes for WEP, 16 for TKIP and CCMP.
    pub key: &'a [u8],
    /// Michael key for this direction (TKIP only).
    pub mic: &'a [u8; 8],
}

/// Turn a clear frame (24-byte header, then body) into what goes on the
/// air. `iv` and `eiv` are the two header words as the transmitter
/// built them (WEP only uses `iv`). The Protected bit is set.
pub fn protect(k: &Key, frame: &[u8], iv: u32, eiv: u32) -> Vec<u8> {
    let (header, body) = frame.split_at(HEADER_LEN);
    let mut out = header.to_vec();
    out[1] |= 0x40;
    out.extend_from_slice(&iv.to_le_bytes());
    match k.cipher {
        Cipher::Wep => {
            let mut seed = iv.to_le_bytes()[..3].to_vec();
            seed.extend_from_slice(k.key);
            let mut data = body.to_vec();
            data.extend_from_slice(&crc32(body).to_le_bytes());
            rc4(&seed, 0, &mut data);
            out.extend_from_slice(&data);
        }
        Cipher::Tkip => {
            out.extend_from_slice(&eiv.to_le_bytes());
            let ivb = iv.to_le_bytes();
            let iv16 = (ivb[0] as u16) << 8 | ivb[2] as u16;
            let ta: [u8; 6] = header[10..16].try_into().unwrap();
            let seed = tkip_mix(k.key.try_into().unwrap(), &ta, eiv, iv16);
            let mut data = body.to_vec();
            data.extend_from_slice(&michael_of(k.mic, header, body));
            let icv = crc32(&data);
            data.extend_from_slice(&icv.to_le_bytes());
            rc4(&seed, 0, &mut data);
            out.extend_from_slice(&data);
        }
        Cipher::Ccmp => {
            out.extend_from_slice(&eiv.to_le_bytes());
            let pn = (eiv as u64) << 16 | (iv & 0xFFFF) as u64;
            let (nonce, aad) = ccmp_nonce_aad(&out, pn);
            let mut data = body.to_vec();
            let tag = ccm(k.key.try_into().unwrap(), &nonce, &aad, &mut data, false);
            out.extend_from_slice(&data);
            out.extend_from_slice(&tag);
        }
    }
    out
}

/// Inverse of [`protect`]: the clear frame (Protected bit left set, as
/// the chip leaves it) and the two IV words that were stripped.
pub fn unprotect(k: &Key, mpdu: &[u8]) -> Result<(Vec<u8>, u32, u32), CipherError> {
    let overhead = match k.cipher {
        Cipher::Wep => 8,
        Cipher::Tkip => 20,
        Cipher::Ccmp => 16,
    };
    if mpdu.len() < HEADER_LEN + overhead {
        return Err(CipherError::Malformed);
    }
    let header = &mpdu[..HEADER_LEN];
    let iv = u32::from_le_bytes(mpdu[24..28].try_into().unwrap());
    let mut out = header.to_vec();
    match k.cipher {
        Cipher::Wep => {
            let mut seed = mpdu[24..27].to_vec();
            seed.extend_from_slice(k.key);
            let mut data = mpdu[28..].to_vec();
            rc4(&seed, 0, &mut data);
            let icv = data.split_off(data.len() - 4);
            if icv != crc32(&data).to_le_bytes() {
                return Err(CipherError::Icv);
            }
            out.extend_from_slice(&data);
            Ok((out, iv, 0))
        }
        Cipher::Tkip => {
            let eiv = u32::from_le_bytes(mpdu[28..32].try_into().unwrap());
            let iv16 = (mpdu[24] as u16) << 8 | mpdu[26] as u16;
            let ta: [u8; 6] = header[10..16].try_into().unwrap();
            let seed = tkip_mix(k.key.try_into().unwrap(), &ta, eiv, iv16);
            let mut data = mpdu[32..].to_vec();
            rc4(&seed, 0, &mut data);
            let icv = data.split_off(data.len() - 4);
            if icv != crc32(&data).to_le_bytes() {
                return Err(CipherError::Icv);
            }
            let mic = data.split_off(data.len() - 8);
            if mic != michael_of(k.mic, header, &data) {
                return Err(CipherError::Mic);
            }
            out.extend_from_slice(&data);
            Ok((out, iv, eiv))
        }
        Cipher::Ccmp => {
            let eiv = u32::from_le_bytes(mpdu[28..32].try_into().unwrap());
            let pn = (eiv as u64) << 16 | (iv & 0xFFFF) as u64;
            let (nonce, aad) = ccmp_nonce_aad(header, pn);
            let mut data = mpdu[32..mpdu.len() - 8].to_vec();
            let tag = ccm(k.key.try_into().unwrap(), &nonce, &aad, &mut data, true);
            if tag != mpdu[mpdu.len() - 8..] {
                return Err(CipherError::Icv);
            }
            out.extend_from_slice(&data);
            Ok((out, iv, eiv))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// IEEE 802.11-2012 M.9.1: BIP with a broadcast deauthentication.
    #[test]
    fn bip_matches_the_standards_vector() {
        let igtk: [u8; 16] = hex("4ea9543e09cf2b1eca66ffc58bdecbcf").try_into().unwrap();
        let unsigned = hex("c0000000ffffffffffff020000000000020000000000 0900 0200
             4c10 0400 040000000000 0000000000000000");
        assert_eq!(bip_mic(&igtk, &unsigned).to_vec(), hex("48dfbfa7b8278872"));
        // Retry, power management and more data do not enter the MIC.
        let mut retried = unsigned.clone();
        retried[1] |= 0x38;
        assert_eq!(bip_mic(&igtk, &retried), bip_mic(&igtk, &unsigned));
    }

    /// IEEE 802.11-2012 M.9.2: CCMP with a unicast deauthentication,
    /// the management flag in the nonce.
    #[test]
    fn ccmp_management_frames_match_the_standards_vector() {
        let tk = hex("66ed21042f9f26d7115706e40414cf2e");
        let plain = hex("c0000000020000000100020000000000020000000000 6000 0200");
        let key = Key {
            cipher: Cipher::Ccmp,
            key: &tk,
            mic: &[0; 8],
        };
        let sealed = protect(&key, &plain, 0x2000_0001, 0);
        assert_eq!(
            sealed,
            hex("c0400000020000000100020000000000020000000000 6000
                 0100002000000000 1d07 cafd0409bb8bafef")
        );
        let (opened, _, _) = unprotect(&key, &sealed).unwrap();
        assert_eq!(opened[24..], plain[24..]);
    }

    #[test]
    fn hashes_match_their_rfc_vectors() {
        assert_eq!(
            sha1(&[b"abc"]).to_vec(),
            hex("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            md5(&[b"abc"]).to_vec(),
            hex("900150983cd24fb0d6963f7d28e17f72")
        );
        // RFC 2202, test case 2.
        assert_eq!(
            hmac_sha1(b"Jefe", &[b"what do ya want ", b"for nothing?"]).to_vec(),
            hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
        );
        assert_eq!(
            hmac_md5(b"Jefe", &[b"what do ya want for nothing?"]).to_vec(),
            hex("750c783e6ab0b503eaa86e310a5db738")
        );
    }

    #[test]
    fn sha256_family_matches_published_vectors() {
        assert_eq!(
            sha256(&[b"abc"]).to_vec(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        // RFC 4231, test case 2.
        assert_eq!(
            hmac_sha256(b"Jefe", &[b"what do ya want for nothing?"]).to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        // RFC 5869, test case 1 (expand step, with its PRK).
        let prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        assert_eq!(
            hkdf_expand_sha256(&prk, &hex("f0f1f2f3f4f5f6f7f8f9"), 42),
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    #[test]
    fn aes_cmac_matches_rfc_4493() {
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        assert_eq!(
            aes_cmac(&key, &[]).to_vec(),
            hex("bb1d6929e95937287fa37d129b756746")
        );
        let m =
            hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
        assert_eq!(
            aes_cmac(&key, &m[..16]).to_vec(),
            hex("070a16b46b4d4144f79bdd9dd04a287c")
        );
        assert_eq!(
            aes_cmac(&key, &m).to_vec(),
            hex("dfa66747de9ae63030ca32611497c827")
        );
    }

    #[test]
    fn passphrase_to_psk_matches_the_ieee_vectors() {
        // IEEE 802.11i, H.4.3.
        assert_eq!(
            wpa_psk("password", "IEEE").to_vec(),
            hex("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e")
        );
        assert_eq!(
            wpa_psk("ThisIsAPassword", "ThisIsASSID").to_vec(),
            hex("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af")
        );
    }

    #[test]
    fn prf_matches_the_ieee_vector() {
        // IEEE 802.11i, H.3.1, test case 1.
        assert_eq!(
            prf(&[0x0B; 20], "prefix", b"Hi There", 64),
            hex(
                "bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606e17d8da35402ffee
                 75df78c3d31e0f889f012120c0862beb67753e7439ae242edb8373698356cf5a"
            )
        );
    }

    #[test]
    fn aes_key_wrap_matches_rfc_3394() {
        let kek: [u8; 16] = hex("000102030405060708090A0B0C0D0E0F").try_into().unwrap();
        let data = hex("00112233445566778899AABBCCDDEEFF");
        let wrapped = aes_wrap(&kek, &data);
        assert_eq!(
            wrapped,
            hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
        );
        assert_eq!(aes_unwrap(&kek, &wrapped), Some(data));
        let mut bad = wrapped;
        bad[3] ^= 1;
        assert_eq!(aes_unwrap(&kek, &bad), None);
    }

    #[test]
    fn rc4_and_crc32_match_known_values() {
        let mut d = *b"Plaintext";
        rc4(b"Key", 0, &mut d);
        assert_eq!(d.to_vec(), hex("BBF316E8D940AF0AD3"));
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn michael_matches_the_ieee_vectors() {
        // IEEE 802.11i, H.5: each result keys the next message.
        let mut key = [0u8; 8];
        for (msg, want) in [
            ("", "82925c1ca1d130b8"),
            ("M", "434721ca40639b3f"),
            ("Mi", "e8f9becae97e5d29"),
            ("Mic", "90038fc6cf13c1db"),
            ("Mich", "d55e100510128986"),
            ("Michael", "0a942b124ecaa546"),
        ] {
            let got = michael(&key, msg.as_bytes());
            assert_eq!(got.to_vec(), hex(want), "message {msg:?}");
            key = got;
        }
    }

    #[test]
    fn tkip_key_mixing_matches_the_ieee_vector() {
        // IEEE 802.11i, H.6.2, test vector 1.
        let tk: [u8; 16] = hex("000102030405060708090A0B0C0D0E0F").try_into().unwrap();
        let ta = [0x10, 0x22, 0x33, 0x44, 0x55, 0x66];
        assert_eq!(
            tkip_mix(&tk, &ta, 0, 0).to_vec(),
            hex("002000 33EA8D2F60CA6D1374234A660B")
        );
    }

    #[test]
    fn ccmp_matches_the_ieee_vector() {
        // IEEE 802.11-2012, M.6.4.
        let tk = hex("c97c1f67ce371185514a8a19f2bdd52f");
        let mut frame = hex("0848c32c0fd2e128a57c5030f1844408abaea5b8fcba8033");
        frame[1] &= !0x40;
        frame.extend(hex("f8ba1a55d02f85ae967bb62fb6cda8eb7e78a050"));
        let key = Key {
            cipher: Cipher::Ccmp,
            key: &tk,
            mic: &[0; 8],
        };
        // PN b5039776e70c: low two bytes in the first word, key id 0.
        let out = protect(&key, &frame, 0x2000_E70C, 0xB503_9776);
        assert_eq!(
            out,
            hex(
                "0848c32c0fd2e128a57c5030f1844408abaea5b8fcba8033 0ce70020769703b5
                 f3d0a2fe9a3dbf2342a643e43246e80c3c04d019 7845ce0b16f97623"
            )
        );
        let (clear, iv, eiv) = unprotect(&key, &out).unwrap();
        assert_eq!(clear[HEADER_LEN..], frame[HEADER_LEN..]);
        assert_eq!((iv, eiv), (0x2000_E70C, 0xB503_9776));
        let mut bad = out;
        bad[40] ^= 1;
        assert_eq!(unprotect(&key, &bad), Err(CipherError::Icv));
    }

    #[test]
    fn wep_and_tkip_round_trip_and_catch_tampering() {
        let mut frame = hex("0801 0000 020000000001 0019db000001 ffffffffffff 0000");
        frame.extend_from_slice(b"\xaa\xaa\x03\x00\x00\x00\x08\x06 some payload");
        let wep = Key {
            cipher: Cipher::Wep,
            key: b"abcde",
            mic: &[0; 8],
        };
        let air = protect(&wep, &frame, 0x0012_3456, 0);
        assert_eq!(air.len(), frame.len() + 8);
        assert_eq!(
            unprotect(&wep, &air).unwrap().0[HEADER_LEN..],
            frame[HEADER_LEN..]
        );
        let mut bad = air.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(unprotect(&wep, &bad), Err(CipherError::Icv));

        let tk = [7u8; 16];
        let mic = [9u8; 8];
        let tkip = Key {
            cipher: Cipher::Tkip,
            key: &tk,
            mic: &mic,
        };
        let air = protect(&tkip, &frame, 0x2001_2100, 0x0000_0002);
        assert_eq!(air.len(), frame.len() + 20);
        let (clear, iv, eiv) = unprotect(&tkip, &air).unwrap();
        assert_eq!(clear[HEADER_LEN..], frame[HEADER_LEN..]);
        assert_eq!((iv, eiv), (0x2001_2100, 2));
        let wrong = Key {
            cipher: Cipher::Tkip,
            key: &tk,
            mic: &[8u8; 8],
        };
        assert_eq!(unprotect(&wrong, &air), Err(CipherError::Mic));
    }
}
