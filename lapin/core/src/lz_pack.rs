//! LZSS as `lz::unpack` reads it, on a machine with a heap: the
//! firmware's build packs the boot bytecode with it (`fw/build.rs`
//! includes this file), the tests check `unpack` against it.

use std::collections::HashMap;
use std::vec::Vec;

/// Pack `d` as `lz::unpack` reads it: the counts, the flag bytes, the
/// literals, the two-byte copies (length 3 to 18, up to 4096 back), the
/// longest and then the nearest.
pub fn pack(d: &[u8]) -> Vec<u8> {
    let mut chains: HashMap<[u8; 3], Vec<usize>> = HashMap::new();
    let (mut flag_bytes, mut literals, mut copies) = (Vec::new(), Vec::new(), Vec::new());
    let mut i = 0;
    let note = |chains: &mut HashMap<[u8; 3], Vec<usize>>, at: usize| {
        if at + 3 <= d.len() {
            chains
                .entry([d[at], d[at + 1], d[at + 2]])
                .or_default()
                .push(at);
        }
    };
    while i < d.len() {
        let flags_at = flag_bytes.len();
        flag_bytes.push(0u8);
        for bit in 0..8 {
            if i >= d.len() {
                break;
            }
            let (mut best, mut off) = (0, 0);
            if i + 3 <= d.len()
                && let Some(starts) = chains.get(&[d[i], d[i + 1], d[i + 2]])
            {
                for &j in starts.iter().rev() {
                    if i - j > 4096 {
                        break;
                    }
                    let mut k = 0;
                    while k < 18 && i + k < d.len() && d[j + k] == d[i + k] {
                        k += 1;
                    }
                    if k > best {
                        (best, off) = (k, i - j);
                    }
                }
            }
            if best >= 3 {
                flag_bytes[flags_at] |= 1 << bit;
                copies.push(((best - 3) << 4 | (off - 1) >> 8) as u8);
                copies.push((off - 1) as u8);
                for at in i..i + best {
                    note(&mut chains, at);
                }
                i += best;
            } else {
                literals.push(d[i]);
                note(&mut chains, i);
                i += 1;
            }
        }
    }
    let count = |v: &Vec<u8>| {
        u16::try_from(v.len())
            .expect("too long to count")
            .to_le_bytes()
    };
    let mut out = [count(&flag_bytes), count(&literals)].concat();
    out.extend(flag_bytes);
    out.extend(literals);
    out.extend(copies);
    out
}
