//! The boot bytecode is kept compressed in the flash and unpacked into
//! RAM at power-on: LZSS, for a decoder of a few dozen instructions.
//!
//! The stream is groups of a flag byte and eight items, its bits from
//! the lowest: 0 a literal byte, 1 a copy of two bytes, the high nibble
//! of the first plus three its length, the low one and the second byte
//! how far back it starts, minus one (up to 4096).

/// Unpack `packed` into `out`; returns how many bytes came out (it
/// stops when `out` is full).
pub fn unpack(packed: &[u8], out: &mut [u8]) -> usize {
    let (mut i, mut n) = (0, 0);
    while i < packed.len() {
        let flags = packed[i];
        i += 1;
        for bit in 0..8 {
            if i >= packed.len() || n >= out.len() {
                return n;
            }
            if flags >> bit & 1 == 0 {
                out[n] = packed[i];
                n += 1;
                i += 1;
            } else {
                let (a, b) = (
                    packed[i] as usize,
                    *packed.get(i + 1).unwrap_or(&0) as usize,
                );
                i += 2;
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
        assert_eq!(unpack(&[1, 0x00, 0x05], &mut out), 0);
    }
}
