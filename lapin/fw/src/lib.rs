//! The hardware side of the rabbit's firmware: the ML67Q4051 and what
//! is soldered around it on the Nabaztag:tag board (revision LLC2_4c).
//!
//! Register addresses and initialisation sequences follow the C
//! firmware this one replaces (`sys/inc/ml674061.h`, `src/hal`).

#![no_std]

pub mod board;
pub mod clock;
pub mod codec;
pub mod ears;
pub mod flash;
pub mod host;
pub mod i2c;
pub mod irq;
pub mod led;
pub mod reg;
pub mod rfid;
pub mod spi;
pub mod start;
pub mod sync;
pub mod timer;
pub mod uart;
pub mod usb;
pub mod watchdog;
pub mod wifi;

/// Stop here. Nothing feeds the watchdog any more, so on the real
/// board this ends in a restart.
pub fn halt() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Where a panic ends: from the undefined instruction it is built as
/// (see `start.rs`), or from the panic handler. Tell the serial port,
/// then [`halt`].
#[unsafe(no_mangle)]
pub extern "C" fn panicked() -> ! {
    uart::write(b"PANIC\n");
    halt()
}
