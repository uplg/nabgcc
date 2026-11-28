//! The watchdog: restarts the rabbit when the firmware stops feeding it.

use crate::reg;

reg! {
    WDTCON: u8 = 0xB7E0_0000;
    TBGCON: u8 = 0xB7E0_0004;
    INTST: u8 = 0xB7E0_0008;
    OVFAST: u8 = 0xB7E0_000C;
    WDTCNT: u16 = 0xB7E0_0010;
}

/// Time the firmware has between two feeds.
pub const PERIOD_MS: u32 = 2097;

/// Set it running on the time base `timebase` (its divider, and what
/// an overflow does).
fn arm(timebase: u8) {
    // Each of these registers takes a key before it takes a value.
    INTST.write(0x3C);
    INTST.write(0x00);
    TBGCON.write(0x5A);
    TBGCON.write(timebase);
    // Reset output held for 100 microseconds.
    OVFAST.write(0x63);
    WDTCON.write(0x3C);
}

/// Start it. There is no stopping it afterwards.
pub fn start() {
    // Clock divided by 1024 (32 microseconds a count, 65536 counts),
    // overflow resets the processor.
    arm(0x45);
    feed();
}

#[inline]
pub fn feed() {
    WDTCON.write(0xC3);
    WDTCON.write(0x3C);
}

/// Restart the board now, as the C firmware's `reset_uc` does: the
/// watchdog set to overflow in a quarter of a millisecond.
pub fn reset_now() -> ! {
    // Clock divided by 32: a microsecond a count.
    arm(0x40);
    WDTCNT.write(0x5A5A);
    WDTCNT.write(0xFF00);
    crate::halt()
}
