//! Runs jsmolka's ARM7TDMI instruction tests (github.com/jsmolka/gba-tests,
//! MIT) against the core. The ROMs are not in the repository: fetch
//! `arm/arm.gba` and `thumb/thumb.gba` into `tests/roms/` to enable these.
//!
//! The ROMs target a Game Boy Advance, so they get a bus shaped like one.
//! A test ROM ends with the number of the failed test in a register
//! (r12 for ARM, r7 for Thumb), or 0 when everything passed.

use nabemu::cpu::{Bus, Cpu, MODE_SYS};

struct Gba {
    vblank: u8,
    rom: Vec<u8>,
    ewram: Vec<u8>,
    iwram: Vec<u8>,
}

impl Gba {
    fn slot(&mut self, addr: u32) -> Option<&mut u8> {
        match addr >> 24 {
            0x02 => self.ewram.get_mut(addr as usize & 0x3FFFF),
            0x03 => self.iwram.get_mut(addr as usize & 0x7FFF),
            0x08 => self.rom.get_mut(addr as usize & 0xFF_FFFF),
            _ => None,
        }
    }
}

impl Bus for Gba {
    fn read8(&mut self, a: u32) -> u8 {
        if a == 0x0400_0004 {
            // Display status: the ROMs wait for the vertical blank flag
            // to toggle before they draw their verdict.
            self.vblank ^= 1;
            return self.vblank;
        }
        self.slot(a).map(|b| *b).unwrap_or(0)
    }
    fn read16(&mut self, a: u32) -> u16 {
        self.read8(a) as u16 | (self.read8(a + 1) as u16) << 8
    }
    fn read32(&mut self, a: u32) -> u32 {
        self.read16(a) as u32 | (self.read16(a + 2) as u32) << 16
    }
    fn write8(&mut self, a: u32, v: u8) {
        if a >> 24 != 0x08
            && let Some(b) = self.slot(a)
        {
            *b = v;
        }
    }
    fn write16(&mut self, a: u32, v: u16) {
        self.write8(a, v as u8);
        self.write8(a + 1, (v >> 8) as u8);
    }
    fn write32(&mut self, a: u32, v: u32) {
        self.write16(a, v as u16);
        self.write16(a + 2, (v >> 16) as u16);
    }
}

fn run(name: &str, verdict: usize) {
    let path = format!("{}/tests/roms/{name}", env!("CARGO_MANIFEST_DIR"));
    let Ok(rom) = std::fs::read(&path) else {
        eprintln!("skipped: {path} is not there");
        return;
    };
    let mut bus = Gba {
        vblank: 0,
        rom,
        ewram: vec![0; 0x40000],
        iwram: vec![0; 0x8000],
    };
    let mut cpu = Cpu::new();
    // What the console's boot ROM leaves behind.
    cpu.set_cpsr(MODE_SYS);
    cpu.r[13] = 0x0300_7F00;
    cpu.r[15] = 0x0800_0000;
    for steps in 0..50_000_000u64 {
        let pc = cpu.pc();
        cpu.step(&mut bus);
        // The ROM is done when it branches to itself, or goes off to
        // draw its verdict with code it expects in the console's RAM.
        if cpu.pc() == pc || cpu.pc() >> 24 != 0x08 {
            assert_eq!(cpu.r[verdict], 0, "{name}: test {} failed", cpu.r[verdict]);
            eprintln!(
                "{name}: passed after {steps} instructions, stopped at {:08x}",
                cpu.pc()
            );
            assert!(steps > 1000, "{name}: stopped before running its tests");
            return;
        }
    }
    panic!("{name}: never finished, pc={:08x}", cpu.pc());
}

#[test]
fn arm_instructions() {
    run("arm.gba", 12);
}

#[test]
fn thumb_instructions() {
    run("thumb.gba", 7);
}
