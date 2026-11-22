//! The watchdog: restarts the rabbit when the firmware stops feeding it.

use crate::reg;

reg! {
    WDTCON: u8 = 0xB7E0_0000;
    TBGCON: u8 = 0xB7E0_0004;
    INTST: u8 = 0xB7E0_0008;
    OVFAST: u8 = 0xB7E0_000C;
}

/// Time the firmware has between two feeds.
pub const PERIOD_MS: u32 = 2097;

/// Start it. There is no stopping it afterwards.
pub fn start() {
    // Each of these registers takes a key before it takes a value.
    INTST.write(0x3C);
    INTST.write(0x00);
    // Clock divided by 1024 (32 microseconds a count, 65536 counts),
    // overflow resets the processor.
    TBGCON.write(0x5A);
    TBGCON.write(0x45);
    // Reset output held for 100 microseconds.
    OVFAST.write(0x63);
    WDTCON.write(0x3C);
    feed();
}

#[inline]
pub fn feed() {
    WDTCON.write(0xC3);
    WDTCON.write(0x3C);
}
