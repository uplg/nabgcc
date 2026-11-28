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

#[cfg(test)]
mod tests {
    use super::unpack;
    use std::vec::Vec;

    /// A plain compressor for the tests (the firmware's build has its own).
    fn pack(d: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < d.len() {
            let at = out.len();
            out.push(0);
            for bit in 0..8 {
                if i >= d.len() {
                    break;
                }
                let (mut best, mut off) = (0, 0);
                for j in i.saturating_sub(4096)..i {
                    let mut k = 0;
                    while k < 18 && i + k < d.len() && d[j + k] == d[i + k] {
                        k += 1;
                    }
                    if k > best {
                        (best, off) = (k, i - j);
                    }
                }
                if best >= 3 {
                    out[at] |= 1 << bit;
                    out.push(((best - 3) << 4 | (off - 1) >> 8) as u8);
                    out.push((off - 1) as u8);
                    i += best;
                } else {
                    out.push(d[i]);
                    i += 1;
                }
            }
        }
        out
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
        assert_eq!(unpack(&[1, 0x00, 0x05], &mut out), 0);
    }
}
