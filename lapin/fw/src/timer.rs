//! The system timer: a tick every millisecond.

use crate::sync::Shared;

use crate::{irq, reg, watchdog};

reg! {
    TMEN: u8 = 0xB800_1004;
    TMRLR: u16 = 0xB800_1008;
    TMOVF: u8 = 0xB800_1010;
}

static MILLIS: Shared<u32> = Shared::new(0);

/// Start ticking. Interrupts still have to be enabled.
pub fn init() {
    // The timer counts the clock divided by 16 up to 65536.
    let counts = crate::clock::HZ / 16 / 1000;
    TMRLR.write((0x1_0000 - counts) as u16);
    TMEN.write(1);
    irq::enable_system_timer();
}

pub(crate) fn on_tick() {
    // This handler is the only writer.
    MILLIS.set(MILLIS.get().wrapping_add(1));
    TMOVF.write(1);
}

/// Milliseconds since [`init`], wrapping after 49 days.
pub fn millis() -> u32 {
    MILLIS.get()
}

/// Wait, feeding the watchdog.
pub fn delay_ms(ms: u32) {
    let start = millis();
    while millis().wrapping_sub(start) < ms {
        watchdog::feed();
    }
}
