//! Just enough ELF32 to load a firmware image and name its functions.

use std::collections::BTreeMap;

pub struct Elf {
    /// Loadable segments as (physical address, bytes).
    pub segments: Vec<(u32, Vec<u8>)>,
    /// Function and object symbols by address (Thumb bit cleared).
    pub symbols: BTreeMap<u32, String>,
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}

fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}

impl Elf {
    pub fn parse(d: &[u8]) -> Option<Elf> {
        if d.get(..6)? != b"\x7fELF\x01\x01" {
            return None;
        }
        let phoff = u32_at(d, 0x1C)? as usize;
        let shoff = u32_at(d, 0x20)? as usize;
        let phentsize = u16_at(d, 0x2A)? as usize;
        let phnum = u16_at(d, 0x2C)? as usize;
        let shentsize = u16_at(d, 0x2E)? as usize;
        let shnum = u16_at(d, 0x30)? as usize;

        let mut segments = Vec::new();
        for i in 0..phnum {
            let p = phoff + i * phentsize;
            if u32_at(d, p)? != 1 {
                continue;
            }
            let off = u32_at(d, p + 4)? as usize;
            let paddr = u32_at(d, p + 12)?;
            let filesz = u32_at(d, p + 16)? as usize;
            if filesz > 0 {
                segments.push((paddr, d.get(off..off + filesz)?.to_vec()));
            }
        }

        let mut symbols = BTreeMap::new();
        for i in 0..shnum {
            let s = shoff + i * shentsize;
            if u32_at(d, s + 4)? != 2 {
                continue;
            }
            let off = u32_at(d, s + 0x10)? as usize;
            let size = u32_at(d, s + 0x14)? as usize;
            let link = u32_at(d, s + 0x18)? as usize;
            let str_off = u32_at(d, shoff + link * shentsize + 0x10)? as usize;
            for e in (off..off + size).step_by(16) {
                let name = u32_at(d, e)? as usize;
                let value = u32_at(d, e + 4)?;
                let kind = d.get(e + 12)? & 0xF;
                if kind != 1 && kind != 2 {
                    continue;
                }
                let tail = d.get(str_off + name..)?;
                let end = tail.iter().position(|&b| b == 0)?;
                let name = String::from_utf8_lossy(&tail[..end]).into_owned();
                if !name.is_empty() && !name.starts_with('$') {
                    symbols.entry(value & !1).or_insert(name);
                }
            }
        }
        Some(Elf { segments, symbols })
    }

    /// Name of the symbol at or before `addr`, with the offset into it.
    pub fn locate(&self, addr: u32) -> Option<(&str, u32)> {
        let (base, name) = self.symbols.range(..=addr).next_back()?;
        Some((name.as_str(), addr - base))
    }
}

/// Decode a Violet `.sim` firmware file into the raw flash image.
///
/// The format is `-violet-`, the payload length as 8 hex digits, the
/// payload in hex, `-violet-`; each payload byte is tied to the one
/// before it (see `tools/mkfirmware`).
pub fn decode_sim(d: &[u8]) -> Option<Vec<u8>> {
    const MARKER: &[u8] = b"-violet-";
    let body = d.strip_prefix(MARKER)?.strip_suffix(MARKER)?;
    let (len, hex) = body.split_at_checked(8)?;
    let len = usize::from_str_radix(std::str::from_utf8(len).ok()?, 16).ok()?;
    if hex.len() != len || len % 2 != 0 {
        return None;
    }
    let mut key = 0x47u8;
    let mut out = Vec::with_capacity(len / 2);
    for pair in hex.chunks(2) {
        let enc = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        let v = enc.wrapping_sub(47).wrapping_mul(key);
        out.push(v);
        key = v.wrapping_mul(2).wrapping_add(1);
    }
    Some(out)
}
