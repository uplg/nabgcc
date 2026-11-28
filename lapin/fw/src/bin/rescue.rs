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
use lapin_fw::{board, clock, led, timer, uart, watchdog};

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
    // The watchdog first of all (on the ring oscillator its period is
    // only longer): whatever hangs from here, the clock's switch or the
    // check of the application, ends in a restart, which counts; and an
    // application that hangs before its own start of it comes back here.
    watchdog::start();
    let failed = Slots::count_boot();
    // The application finds the clock running and leaves it so.
    clock::init();
    // The pins at rest (amplifier off, codec in reset, ears still) as
    // the C sets them early, before the time the check below takes.
    board::init();
    let app = boot::installed_app();
    if let Some(entry) = app.filter(|_| failed < MAX_FAILED_BOOTS) {
        // SAFETY: the application's reset code, at the address its whole
        // and checked header gives; it takes over the processor from
        // scratch, as from a reset.
        unsafe { asm!("bx {0}", in(reg) entry, options(noreturn)) }
    }

    lapin_fw::init();
    led::set_all(RED);
    uart::init();
    uart::write(if failed == boot::ASKED {
        b"secours: asked for\n"
    } else if app.is_some() {
        b"secours: the application keeps restarting\n"
    } else {
        b"secours: no application\n"
    });
    let Ok(mut stick) = Stick::bring_up() else {
        uart::write(b"secours: no stick\n");
        if app.is_some() {
            // No network to offer: the application, without one, is
            // still more than a red rabbit. Its three tries again.
            Slots::fresh();
            watchdog::reset_now();
        }
        // Nothing at all to run: try the stick again in a while.
        timer::delay_ms(5000);
        watchdog::reset_now()
    };
    let mut rescue = Rescue::new(stick.mac);
    rescue.start(&mut stick);
    uart::write(b"secours: network up\n");
    rescue.run(&mut stick, app.is_some())
}
