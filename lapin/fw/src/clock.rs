//! Clock tree: 32 MHz from the 8 MHz crystal.

use crate::reg;
use crate::timer::{TMEN, TMOVF, TMRLR};

reg! {
    PECLKCNT: u32 = 0xB700_0000;
    PLL1: u32 = 0xB700_0008;
    PLL2: u32 = 0xB700_000C;
    CLKCNT: u32 = 0xB700_0010;
}

/// Processor and peripheral clock once [`init`] has run.
pub const HZ: u32 = 32_000_000;

pub fn init() {
    // Already done (by the rescue core, before handing over): the
    // processor on the system clock side (SRCSEL 00) through PLL A
    // (PLLSEL 01), PLL A running. Leave the running clock alone.
    let now = CLKCNT.read();
    if now & 0x303 == 0x001 && now & 0x1_0000 != 0 {
        return;
    }
    // Still on the ring oscillator, as out of reset: give the crystal
    // 10 ms to settle, timed by the system timer, before running on it
    // (the C's reset code, sys/asm/init.s, the same way).
    if CLKCNT.read() & 0x300 == 0x100 {
        TMEN.write(0);
        TMOVF.write(1);
        // The ring oscillator's 16 MHz, divided by 16: 10 000 counts.
        TMRLR.write((0x1_0000 - 10 * 16 * 1000 / 16) as u16);
        TMEN.write(1);
        // Bounded: a timer that never overflows must not hold the board
        // here (the ring oscillator runs 10 ms in well under 2^22 polls).
        let mut polls = 0u32;
        while TMOVF.read() & 1 == 0 && polls < 1 << 22 {
            polls += 1;
        }
        CLKCNT.write(CLKCNT.read() & 0xFFFF_FCFF);
        TMEN.write(0);
        TMOVF.write(1);
    }
    PLL1.write(0x3101_3110);
    PLL2.write(0x0003_0101);
    // System clock and PLL A on, ring oscillator still the source.
    CLKCNT.write(0x000D_0109);
    // Switch to the system clock, then stop the ring oscillator.
    CLKCNT.clear(0x0000_0300);
    CLKCNT.clear(0x0004_0000);
    // Clock for the two ports that double as the upper data bus.
    PECLKCNT.set(0x1800_0000);
}
