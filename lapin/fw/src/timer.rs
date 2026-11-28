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

/// Milliseconds gone by since `start`, an earlier [`millis`], across
/// its wrapping.
pub fn since(start: u32) -> u32 {
    millis().wrapping_sub(start)
}

/// Wait at least `ms` milliseconds, feeding the watchdog. With
/// interrupts held back (inside [`irq::free`]) the tick cannot come:
/// the timer's overflow flag is counted here instead, and the clock
/// kept, or the wait would never end.
pub fn delay_ms(ms: u32) {
    let on = irq::irq_disable();
    if on {
        irq::irq_enable();
        let start = millis();
        // One more than asked: `start` may be the end of a tick.
        while since(start) <= ms {
            watchdog::feed();
        }
        return;
    }
    let mut ticks = 0;
    while ticks <= ms {
        watchdog::feed();
        if TMOVF.read() & 1 != 0 {
            on_tick();
            ticks += 1;
        }
    }
}
