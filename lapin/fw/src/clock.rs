//! Clock tree: 32 MHz from the 8 MHz crystal.

use crate::reg;

reg! {
    PECLKCNT: u32 = 0xB700_0000;
    PLL1: u32 = 0xB700_0008;
    PLL2: u32 = 0xB700_000C;
    CLKCNT: u32 = 0xB700_0010;
}

/// Processor and peripheral clock once [`init`] has run.
pub const HZ: u32 = 32_000_000;

pub fn init() {
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
