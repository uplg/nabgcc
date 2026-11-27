use std::collections::HashMap;

/// LZSS as `lapin_core::lz` reads it: flag bytes, literals, two-byte
/// copies (length 3 to 18, up to 4096 back).
fn pack(d: &[u8]) -> Vec<u8> {
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

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // The linker script lives beside the crate.
    println!("cargo:rustc-link-search={dir}");
    println!("cargo:rerun-if-changed=link.x");

    // The boot bytecode goes in compressed, and must come out the same.
    println!("cargo:rerun-if-changed=src/boot.bc");
    let boot = std::fs::read(format!("{dir}/src/boot.bc")).unwrap();
    let packed = pack(&boot);
    let mut back = vec![0u8; boot.len()];
    assert_eq!(lapin_core::lz::unpack(&packed, &mut back), boot.len());
    assert!(
        back == boot,
        "the boot bytecode does not survive its packing"
    );
    // The firmware's buffer for it (`BOOT_LEN` in `bin/lapin.rs`).
    let main = std::fs::read_to_string(format!("{dir}/src/bin/lapin.rs")).unwrap();
    assert!(
        main.contains(&format!("const BOOT_LEN: usize = {};", boot.len())),
        "BOOT_LEN in bin/lapin.rs must be {}",
        boot.len()
    );
    println!("cargo:rerun-if-changed=src/bin/lapin.rs");
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::write(format!("{out}/boot.lz"), &packed).unwrap();
}
