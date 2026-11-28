//! The boot bytecode is kept compressed in the flash and unpacked into
//! RAM at power-on: LZSS, for a decoder of a few dozen instructions.
//!
//! The items are flag bits, eight to a byte from the lowest: 0 a
//! literal byte, 1 a copy of two bytes, the high nibble of the first
//! plus three its length, the low one and the second byte how far back
//! it starts, minus one (up to 4096). The stream keeps them apart, so
//! that the bytecode's literals follow each other: two little-endian
//! half-words, how many flag bytes and how many literals, then the flag
//! bytes, the literals, the copies. `lapin-first.bin` packs the
//! application again (`pack`), which finds more in the literals side by
//! side than among flags and copies: 800 bytes less than with the
//! three interleaved, for the same length here.

/// Unpack `packed` into `out`; returns how many bytes came out (it
/// stops when `out` is full).
///
/// ARM code, twice as fast as Thumb at it, out of line, and made of
/// indexing and arithmetic alone: in ARM code the library's helpers,
/// Thumb, would be calls.
#[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
#[inline(never)]
pub fn unpack(packed: &[u8], out: &mut [u8]) -> usize {
    let (len, room) = (packed.len(), out.len());
    if len < 4 {
        return 0;
    }
    // Where each stream is read from, and where it ends.
    let mut f = 4;
    let mut flags_end = f + (packed[0] as usize | (packed[1] as usize) << 8);
    if flags_end > len {
        flags_end = len;
    }
    let mut l = flags_end;
    let mut literals_end = l + (packed[2] as usize | (packed[3] as usize) << 8);
    if literals_end > len {
        literals_end = len;
    }
    let mut c = literals_end;
    let mut n = 0;
    // The flag byte's bits still to read, above a 1 that marks their end.
    let mut flags = 1;
    while n < room {
        if flags == 1 {
            if f >= flags_end {
                break;
            }
            flags = packed[f] as u32 | 0x100;
            f += 1;
        }
        let copy = flags & 1;
        flags >>= 1;
        if copy == 0 {
            if l >= literals_end {
                break;
            }
            out[n] = packed[l];
            l += 1;
            n += 1;
            continue;
        }
        if c + 2 > len {
            break;
        }
        let (a, b) = (packed[c] as usize, packed[c + 1] as usize);
        c += 2;
        let back = ((a & 15) << 8 | b) + 1;
        if back > n {
            break;
        }
        let mut end = n + (a >> 4) + 3;
        if end > room {
            end = room;
        }
        // Byte by byte, forward: a copy may run into what it writes. The
        // three every copy has, then the rest.
        if n + 3 <= end {
            out[n] = out[n - back];
            out[n + 1] = out[n + 1 - back];
            out[n + 2] = out[n + 2 - back];
            n += 3;
        }
        while n < end {
            out[n] = out[n - back];
            n += 1;
        }
    }
    n
}

/// The compressor needs a heap, which this crate has not: the
/// firmware's build takes its file in (`fw/build.rs`), the tests here.
#[cfg(test)]
#[path = "lz_pack.rs"]
mod packer;

#[cfg(test)]
mod tests {
    use super::packer::pack;
    use super::unpack;
    use std::vec::Vec;

    /// A plain unpacker, one check per byte.
    fn reference(packed: &[u8], out: &mut [u8]) -> usize {
        if packed.len() < 4 {
            return 0;
        }
        let half = |at: usize| u16::from_le_bytes([packed[at], packed[at + 1]]) as usize;
        let rest = &packed[4..];
        let (flag_bytes, rest) = rest.split_at(half(0).min(rest.len()));
        let (mut literals, mut copies) = rest.split_at(half(2).min(rest.len()));
        let mut n = 0;
        for flags in flag_bytes {
            for bit in 0..8 {
                if n >= out.len() {
                    return n;
                }
                if flags >> bit & 1 == 0 {
                    let Some((&byte, more)) = literals.split_first() else {
                        return n;
                    };
                    out[n] = byte;
                    n += 1;
                    literals = more;
                } else {
                    let [a, b, ..] = *copies else {
                        return n;
                    };
                    let (a, b) = (a as usize, b as usize);
                    copies = &copies[2..];
                    let len = (a >> 4) + 3;
                    let back = ((a & 15) << 8 | b) + 1;
                    for _ in 0..len {
                        if n >= out.len() || back > n {
                            return n;
                        }
                        out[n] = out[n - back];
                        n += 1;
                    }
                }
            }
        }
        n
    }

    /// The same as the first unpacker on any stream, into any room.
    #[test]
    fn as_the_first() {
        let mut x = 0x2545_f491u32;
        for case in 0..3000 {
            let mut packed = Vec::new();
            for _ in 0..case % 97 {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                packed.push(x as u8);
            }
            // Half of them with counts that fall within the stream.
            if case % 2 == 0 && packed.len() >= 4 {
                packed[..4].copy_from_slice(&[x as u8 % 32, 0, (x >> 8) as u8 % 64, 0]);
            }
            let room = (x >> 8) as usize % 400;
            let (mut a, mut b) = (std::vec![7u8; room], std::vec![7u8; room]);
            assert_eq!(unpack(&packed, &mut a), reference(&packed, &mut b));
            assert_eq!(a, b);
        }
    }

    #[test]
    fn round_trips() {
        let mut d = Vec::new();
        for k in 0..5000u32 {
            d.extend_from_slice(&(k % 97).to_le_bytes());
            if k % 7 == 0 {
                d.extend_from_slice(b"abcabcabcabc");
            }
        }
        let p = pack(&d);
        assert!(p.len() < d.len() / 2);
        let mut out = std::vec![0u8; d.len()];
        assert_eq!(unpack(&p, &mut out), d.len());
        assert_eq!(out, d);
        // A stream that points before its start stops there.
        assert_eq!(unpack(&[1, 0, 0, 0, 0x01, 0x00, 0x05], &mut out), 0);
    }
}
