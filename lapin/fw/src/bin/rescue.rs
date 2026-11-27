//! The rescue core: the first 20 KB of the flash, which the
//! application's updates never write (see `lapin_fw::boot`). It owns
//! the processor's vectors, checks the application at every start and
//! hands over to it; when the application is missing, damaged, or has
//! restarted three times in a row without saying it was well, it raises
//! its own Wi-Fi network and waits for a new image (`lapin_fw::rescue`).

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};

use lapin_fw::boot::{self, MAX_FAILED_BOOTS, Slots};
use lapin_fw::rescue::Rescue;
use lapin_fw::wifi::rt2573::Stick;
use lapin_fw::{board, clock, halt, irq, led, spi, timer, uart, usb, watchdog};

global_asm!(
    r#"
    .section .vectors, "ax"
    .arm
    .global _start
_start:
    ldr pc, =reset
    ldr pc, =undefined_relay
    ldr pc, =trap
    ldr pc, =trap
    ldr pc, =trap
    nop
    ldr pc, =irq_relay
    ldr pc, =trap
    .ltorg

    .section .text.relay, "ax"
    .arm
    /* To whoever runs (the application, or this core): the handlers
       their reset code wrote in the shared words (boot.rs, Slots).
       Every register as it came, the return address included. */
irq_relay:
    sub sp, sp, #8
    str r0, [sp]
    ldr r0, =0x10000008
    ldr r0, [r0]
    str r0, [sp, #4]
    ldmfd sp!, {{r0, pc}}
undefined_relay:
    ldr r0, =0x1000000C
    ldr pc, [r0]
    .ltorg
"#
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    lapin_fw::panicked()
}

const RED: u32 = 0xFF0000;

#[unsafe(no_mangle)]
extern "C" fn main() -> ! {
    lapin_fw::start::link();
    let failed = Slots::count_boot();
    // The application finds the clock running and leaves it so.
    clock::init();
    let app = boot::installed_app();
    if let Some(entry) = app.filter(|_| failed < MAX_FAILED_BOOTS) {
        // SAFETY: the application's reset code, at the address its whole
        // and checked header gives; it takes over the processor from
        // scratch, as from a reset.
        unsafe { asm!("bx {0}", in(reg) entry, options(noreturn)) }
    }

    board::init();
    irq::init();
    watchdog::start();
    timer::init();
    irq::irq_enable();
    spi::init();
    led::init();
    led::set_all(RED);
    uart::init();
    uart::write(if app.is_some() {
        b"secours: the application keeps restarting\n"
    } else {
        b"secours: no application\n"
    });
    let stick = usb::init()
        .and_then(|()| usb::attach(3000))
        .and_then(|()| usb::enumerate())
        .map_err(lapin_fw::wifi::rt2573::Error::Usb)
        .and_then(Stick::start);
    let Ok(mut stick) = stick else {
        uart::write(b"secours: no stick\n");
        // Nothing to offer: let the watchdog try the whole again.
        halt()
    };
    let mut rescue = Rescue::new(stick.mac);
    rescue.start(&mut stick);
    uart::write(b"secours: network up\n");
    rescue.run(&mut stick, app.is_some())
}
