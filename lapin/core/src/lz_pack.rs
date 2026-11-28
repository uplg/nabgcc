//! LZSS as `lz::unpack` reads it, on a machine with a heap: the
//! firmware's build packs the boot bytecode with it (`fw/build.rs`
//! includes this file), the tests check `unpack` against it.

use std::collections::HashMap;
use std::vec::Vec;

/// Pack `d` as `lz::unpack` reads it: flag bytes,
/// literals, two-byte copies (length 3 to 18, up to 4096 back), the
/// longest and then the nearest.
pub fn pack(d: &[u8]) -> Vec<u8> {
    let mut chains: HashMap<[u8; 3], Vec<usize>> = HashMap::new();
    let mut out = Vec::new();
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
        let flags_at = out.len();
        out.push(0u8);
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
                out[flags_at] |= 1 << bit;
                out.push(((best - 3) << 4 | (off - 1) >> 8) as u8);
                out.push((off - 1) as u8);
                for at in i..i + best {
                    note(&mut chains, at);
                }
                i += best;
            } else {
                out.push(d[i]);
                note(&mut chains, i);
                i += 1;
            }
        }
    }
    out
}
