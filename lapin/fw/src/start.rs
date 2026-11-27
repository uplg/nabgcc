//! Reset: what runs before `main`.
//!
//! The processor starts in ARM state, supervisor mode, interrupts off,
//! at the first word of the flash: the rescue core's vectors
//! (`bin/rescue.rs`), which run this same code for the rescue core, and
//! jump to it for the application, from its header.

use core::arch::global_asm;

global_asm!(
    r#"
    /* The application's header (see boot.rs): length and CRC are
       filled in by build.sh. The rescue core discards it. */
    .section .app_header, "a"
    .word 0x4150414C
    .word 0
    .word 0
    .word reset

    .section .text.reset, "ax"
    .arm
    .global reset, trap, undefined
reset:
    /* Interrupt mode gets its own small stack... */
    ldr r0, =__stack_top
    msr cpsr_c, #0xD2
    mov sp, r0
    ldr r1, =__irq_stack_size
    sub r0, r0, r1
    /* ...and the program runs in system mode, interrupts still off. */
    msr cpsr_c, #0xDF
    mov sp, r0

    /* The vectors are the rescue core's, in the first sector: they
       send interrupts and undefined instructions where these two
       words say (boot.rs, Slots). */
    ldr r0, =0x10000008
    ldr r1, =irq_entry
    str r1, [r0]
    ldr r1, =undefined
    str r1, [r0, #4]

    /* Initialised data comes from the flash, the rest starts at zero. */
    ldr r0, =__data_load
    ldr r1, =__data_start
    ldr r2, =__data_end
1:  cmp r1, r2
    ldrlo r3, [r0], #4
    strlo r3, [r1], #4
    blo 1b
    mov r3, #0
    ldr r1, =__bss_start
    ldr r2, =__bss_end
2:  cmp r1, r2
    strlo r3, [r1], #4
    blo 2b

    ldr r0, =main
    bx r0

    /* A panic ends on an undefined instruction (panics abort on the
       spot, see .cargo/config.toml): say so on the serial port, from
       a stack of its own, and stop. */
undefined:
    ldr sp, =__stack_top
    ldr r0, =panicked
    bx r0

    /* Abort, fast interrupt: none should happen. Stop there; the
       watchdog restarts the rabbit. */
trap:
    b trap
    .ltorg
"#
);

/// Makes sure the reset code above is linked into the image.
pub fn link() {
    // SAFETY: `reset` is the reset code's label above; only its address
    // is taken, never a byte read through it.
    unsafe extern "C" {
        static reset: u8;
    }
    core::hint::black_box(&raw const reset);
}
