//! CCMP done in software (IEEE 802.11-2020, 12.5.3), for links where
//! the stick may hold no key: with protected management frames it
//! would mangle the frames it cannot handle. And BIP (12.5.4), which
//! signs the access point's broadcast management frames.

use crate::aes::{Aes, ccm, cmac};

pub const HEADER: usize = 8;
pub const MIC: usize = 8;
/// What protection adds to a frame.
pub const OVERHEAD: usize = HEADER + MIC;

/// Length of the 802.11 header of `frame` (data or management, no
/// four-address frames): 24, or 26 with a QoS control field.
pub fn header_len(frame: &[u8]) -> usize {
    let qos = frame[0] & 0x0C == 0x08 && frame[0] & 0x80 != 0;
    if qos { 26 } else { 24 }
}

fn nonce_and_aad(frame: &[u8], hlen: usize, pn: u64, aad: &mut [u8; 32]) -> ([u8; 13], usize) {
    let management = frame[0] & 0x0C == 0;
    let qos = hlen == 26;
    let mut nonce = [0u8; 13];
    nonce[0] = if qos { frame[24] & 0x0F } else { 0 } | if management { 0x10 } else { 0 };
    nonce[1..7].copy_from_slice(&frame[10..16]);
    nonce[7..].copy_from_slice(&pn.to_be_bytes()[2..]);
    // Frame control: subtype bits of data frames, retry, power
    // management and more data masked; protected set.
    aad[0] = if management {
        frame[0]
    } else {
        frame[0] & 0x8F
    };
    aad[1] = (frame[1] & !0x38) | 0x40;
    if qos {
        aad[1] &= !0x80;
    }
    aad[2..20].copy_from_slice(&frame[4..22]);
    // Sequence control: the fragment number only.
    aad[20] = frame[22] & 0x0F;
    aad[21] = 0;
    let mut n = 22;
    if qos {
        aad[22] = frame[24] & 0x0F;
        aad[23] = 0;
        n = 24;
    }
    (nonce, n)
}

/// Protect `frame[..len]` in place with `tk` and packet number `pn`:
/// the CCMP header goes after the 802.11 header and the MIC at the end.
/// `frame` must have `OVERHEAD` bytes of room; returns the new length.
pub fn protect(tk: &[u8; 16], key_id: u8, pn: u64, frame: &mut [u8], len: usize) -> usize {
    let hlen = header_len(frame);
    frame.copy_within(hlen..len, hlen + HEADER);
    let p = pn.to_le_bytes();
    frame[hlen..hlen + HEADER].copy_from_slice(&[
        p[0],
        p[1],
        0,
        0x20 | key_id << 6,
        p[2],
        p[3],
        p[4],
        p[5],
    ]);
    frame[1] |= 0x40;
    let mut aad = [0u8; 32];
    let (nonce, n) = nonce_and_aad(frame, hlen, pn, &mut aad);
    let aes = Aes::new(tk);
    let end = len + HEADER;
    let mic = ccm(
        &aes,
        &nonce,
        &aad[..n],
        &mut frame[hlen + HEADER..end],
        false,
    );
    frame[end..end + MIC].copy_from_slice(&mic);
    end + MIC
}

/// The packet number and key identifier in a protected frame's CCMP
/// header, if it has one.
pub fn header(frame: &[u8]) -> Option<(u64, u8)> {
    let hlen = header_len(frame);
    let h = frame.get(hlen..hlen + HEADER)?;
    if frame[1] & 0x40 == 0 || h[3] & 0x20 == 0 || frame.len() < hlen + OVERHEAD {
        return None;
    }
    let pn = u64::from_le_bytes([h[0], h[1], h[4], h[5], h[6], h[7], 0, 0]);
    Some((pn, h[3] >> 6))
}

/// Open a protected frame in place: on success the frame holds its
/// 802.11 header followed by the plain body, and the new length and
/// the packet number come back. The caller checks the packet number
/// against the last one, after: a frame that fails changes nothing.
pub fn unprotect(tk: &[u8; 16], frame: &mut [u8]) -> Option<(usize, u64)> {
    let (pn, _) = header(frame)?;
    let hlen = header_len(frame);
    let len = frame.len();
    let mut aad = [0u8; 32];
    let (nonce, n) = nonce_and_aad(frame, hlen, pn, &mut aad);
    let aes = Aes::new(tk);
    let body = hlen + HEADER..len - MIC;
    let mut mic = [0u8; MIC];
    mic.copy_from_slice(&frame[len - MIC..]);
    let tag = ccm(&aes, &nonce, &aad[..n], &mut frame[body.clone()], true);
    if !constant_eq(&tag, &mic) {
        return None;
    }
    frame.copy_within(body, hlen);
    frame[1] &= !0x40;
    Some((len - OVERHEAD, pn))
}

/// Whether two codes are the same, in a time that does not depend on
/// where they differ. Out of line: one copy, the one tested.
#[inline(never)]
pub fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |d, (x, y)| d | (x ^ y)) == 0
}

/// The BIP integrity code of a group management frame whose last 18
/// bytes are its management MIC element (MIC field ignored).
pub fn bip_mic(igtk: &[u8; 16], frame: &[u8]) -> [u8; 8] {
    let mut aad = [0u8; 20];
    aad[0] = frame[0];
    aad[1] = frame[1] & !0x38;
    aad[2..].copy_from_slice(&frame[4..22]);
    let n = frame.len();
    let mac = cmac(igtk, &[&aad, &frame[24..n - 8], &[0; 8]]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&mac[..8]);
    out
}

/// Check a broadcast management frame signed with BIP: the key
/// identifier it names, its packet number, and whether the code holds.
pub fn bip_check(igtk: &[u8; 16], frame: &[u8]) -> Option<(u16, u64)> {
    let n = frame.len();
    if n < 24 + 18 || frame[n - 18..n - 16] != [76, 16] || frame[1] & 0x40 != 0 {
        return None;
    }
    let mme = &frame[n - 16..];
    let key_id = u16::from_le_bytes([mme[0], mme[1]]);
    let ipn = u64::from_le_bytes([mme[2], mme[3], mme[4], mme[5], mme[6], mme[7], 0, 0]);
    constant_eq(&bip_mic(igtk, frame), &mme[8..]).then_some((key_id, ipn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hex, hex_array};

    /// `plain` protected under `tk` (key 0), packet number `pn`.
    fn protected(tk: &[u8; 16], pn: u64, plain: &[u8]) -> std::vec::Vec<u8> {
        let mut f = plain.to_vec();
        f.resize(plain.len() + OVERHEAD, 0);
        let n = protect(tk, 0, pn, &mut f, plain.len());
        f.truncate(n);
        f
    }

    /// IEEE 802.11-2012 M.9.2: a unicast deauthentication.
    #[test]
    fn management_frame_vector() {
        let tk: [u8; 16] = hex_array("66ed21042f9f26d7115706e40414cf2e");
        let plain = hex("c0000000020000000100020000000000020000000000 6000 0200");
        let mut f = protected(&tk, 1, &plain);
        assert_eq!(
            f[..],
            hex("c0400000020000000100020000000000020000000000 6000
                 0100002000000000 1d07 cafd0409bb8bafef")[..]
        );
        assert_eq!(header(&f), Some((1, 0)));
        let (m, pn) = unprotect(&tk, &mut f).unwrap();
        assert_eq!((m, pn), (plain.len(), 1));
        assert_eq!(f[..m], plain[..]);
        // One bit off anywhere and it no longer opens.
        let mut g = protected(&tk, 1, &plain);
        g[30] ^= 4;
        assert!(unprotect(&tk, &mut g).is_none());
    }

    /// IEEE 802.11-2012 M.6.4: a data frame (CCMP test vector).
    #[test]
    fn data_frame_vector() {
        let tk: [u8; 16] = hex_array("c97c1f67ce371185514a8a19f2bdd52f");
        let plain = hex(
            "08 48 c3 2c 0f d2 e1 28 a5 7c 50 30 f1 84 44 08 ab ae a5 b8 fc ba 80 33
             f8 ba 1a 55 d0 2f 85 ae 96 7b b6 2f b6 cd a8 eb 7e 78 a0 50",
        );
        assert_eq!(
            protected(&tk, 0xB5039776E70C, &plain)[..],
            hex(
                "08 48 c3 2c 0f d2 e1 28 a5 7c 50 30 f1 84 44 08 ab ae a5 b8 fc ba 80 33
                 0c e7 00 20 76 97 03 b5
                 f3 d0 a2 fe 9a 3d bf 23 42 a6 43 e4 32 46 e8 0c 3c 04 d0 19
                 78 45 ce 0b 16 f9 76 23"
            )[..]
        );
    }

    /// IEEE 802.11-2012 M.9.1: BIP over a broadcast deauthentication.
    #[test]
    fn bip_vector() {
        let igtk: [u8; 16] = hex_array("4ea9543e09cf2b1eca66ffc58bdecbcf");
        let mut f = hex("c0000000ffffffffffff020000000000020000000000 0900 0200
             4c10 0400 040000000000 0000000000000000");
        assert_eq!(bip_mic(&igtk, &f)[..], hex("48dfbfa7b8278872"));
        let n = f.len();
        f[n - 8..].copy_from_slice(&hex("48dfbfa7b8278872"));
        assert_eq!(bip_check(&igtk, &f), Some((4, 4)));
        f[1] |= 0x08; // a retry does not change the code
        assert_eq!(bip_check(&igtk, &f), Some((4, 4)));
        f[25] ^= 1;
        assert_eq!(bip_check(&igtk, &f), None);
    }
}
