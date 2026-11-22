//! Interrupts: the controller, and the handler every source goes through.

use core::arch::global_asm;

use crate::reg;

reg! {
    FIQEN: u32 = 0x7800_0010;
    IRQS: u32 = 0x7800_0004;
    CIL: u32 = 0x7800_0018;
    ILC0: u32 = 0x7800_0020;
    ILC1: u32 = 0x7800_0024;
    EXILCA: u32 = 0x7BF0_0018;
    EXILCB: u32 = 0x7BF0_0028;
    EXILCC: u32 = 0x7BF0_0038;
}

pub const SYSTEM_TIMER: u32 = 0;
/// External interrupt 2: the USB controller.
pub const USB: u32 = 36;

unsafe extern "C" {
    /// Let interrupts through. Returns whether they were already on.
    pub safe fn irq_enable() -> bool;
    /// Hold interrupts back. Returns whether they were on.
    pub safe fn irq_disable() -> bool;
}

global_asm!(
    r#"
    .section .text.irq, "ax"
    .arm
    .global irq_entry, irq_enable, irq_disable

    /* Every interrupt arrives here, in interrupt mode, on its own
       stack, with further interrupts held back. */
irq_entry:
    sub lr, lr, #4
    stmfd sp!, {{r0-r3, r12, lr}}
    ldr r0, =0x78000014         /* IRN: which source, and it is now in service */
    ldr r0, [r0]
    ldr r1, =irq_dispatch
    mov lr, pc
    bx r1
    ldr r0, =0x78000028         /* CILCL: service over */
    str r0, [r0]
    ldmfd sp!, {{r0-r3, r12, pc}}^

irq_enable:
    mrs r1, cpsr
    bic r2, r1, #0x80
    msr cpsr_c, r2
    b 1f
irq_disable:
    mrs r1, cpsr
    orr r2, r1, #0x80
    msr cpsr_c, r2
1:  mov r0, #1
    tst r1, #0x80
    movne r0, #0
    bx lr
    .ltorg
"#
);

/// Reset the controller: every source off, nothing in service.
pub fn init() {
    ILC0.write(0);
    ILC1.write(0);
    EXILCA.write(0);
    EXILCB.write(0);
    EXILCC.write(0);
    FIQEN.write(0);
    IRQS.write(0);
    CIL.write(0xFE);
}

/// Let the system timer interrupt, at the highest level.
pub(crate) fn enable_system_timer() {
    ILC0.set(0x7);
}

/// Called from `irq_entry` with the number of the interrupting source.
#[unsafe(no_mangle)]
extern "C" fn irq_dispatch(source: u32) {
    match source {
        SYSTEM_TIMER => crate::timer::on_tick(),
        USB => crate::usb::on_interrupt(),
        _ => {}
    }
}

/// Run `f` with interrupts held back, then put them as they were.
pub fn free<R>(f: impl FnOnce() -> R) -> R {
    let were_on = irq_disable();
    let r = f();
    if were_on {
        irq_enable();
    }
    r
}
