//! Reset: what runs before `main`.
//!
//! The processor starts in ARM state, supervisor mode, interrupts off,
//! at the first word of the flash (mapped at address 0 too). The
//! vectors jump to absolute addresses in the flash proper.

use core::arch::global_asm;

global_asm!(
    r#"
    .section .vectors, "ax"
    .arm
    .global _start
_start:
    ldr pc, =reset
    ldr pc, =undefined
    ldr pc, =trap
    ldr pc, =trap
    ldr pc, =trap
    nop
    ldr pc, =irq_entry
    ldr pc, =trap
    .ltorg

    .section .text.reset, "ax"
    .arm
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
    unsafe extern "C" {
        static _start: u8;
    }
    // Only the address is taken.
    core::hint::black_box(&raw const _start);
}
