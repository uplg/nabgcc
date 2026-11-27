//! The processor's own flash: 128 KB in 4 KB sectors. The last sector
//! holds the rabbit's settings; the rest is the firmware.
//!
//! While the flash erases or programs it cannot be read, so the code
//! that does it cannot live there: it is written in assembly, linked
//! into the initialised data and so copied to RAM at reset, and it
//! runs with interrupts off since their handlers are in the flash too.

use core::arch::global_asm;
use core::cell::UnsafeCell;

use crate::{irq, watchdog};

pub const BASE: usize = 0x0800_0000;
pub const SECTOR: usize = 4096;
/// Where the settings sector starts.
pub const SETTINGS: usize = BASE + 0x1_F000;

global_asm!(
    r#"
    .section .data.ramcode, "awx"
    .arm
    .global flash_sector_from_ram
    /* r0: sector address in the flash; r1: 4096 bytes to put there,
       word aligned, anywhere but the flash. Erases, then programs
       every word that is not all ones. */
flash_sector_from_ram:
    stmfd sp!, {{r4-r10, lr}}
    ldr r4, =0xB7000100         /* FLACON */
    ldr r5, =0x08015554
    ldr r6, =0x0800AAA8
    mov r2, #0xAA
    mov r3, #0x55
    mov r7, #0x03
    strb r7, [r4]               /* programming permitted */
    strb r2, [r5]               /* sector erase command */
    strb r3, [r6]
    mov r9, #0x80
    strb r9, [r5]
    strb r2, [r5]
    strb r3, [r6]
    mov r9, #0x30
    strb r9, [r0]
    bl 2f
    mov r8, #0
1:  ldr r12, [r1, r8]
    cmn r12, #1
    beq 3f
    strb r7, [r4]               /* clear the completion flag */
    strb r2, [r5]               /* word program command */
    strb r3, [r6]
    mov r9, #0xA0
    strb r9, [r5]
    add r10, r0, r8
    strb r12, [r10]
    mov r9, r12, lsr #8
    strb r9, [r10, #1]
    mov r9, r12, lsr #16
    strb r9, [r10, #2]
    mov r9, r12, lsr #24
    strb r9, [r10, #3]
    bl 2f
3:  add r8, r8, #4
    cmp r8, #4096
    blo 1b
    mov r9, #0x02
    strb r9, [r4]               /* programming forbidden again */
    ldmfd sp!, {{r4-r10, lr}}
    bx lr
    /* Wait for the command to complete. */
2:  ldrb r9, [r4]
    and r9, r9, #0x0E
    cmp r9, #0x02
    bne 2b
    bx lr
    .ltorg
"#
);

global_asm!(
    r#"
    .section .data.ramcode, "awx"
    .arm
    .global flash_image_from_ram
    /* r0: the new firmware, word aligned, outside the flash; r1: its
       length. Rewrites the flash from its first sector, as many
       sectors as the image needs (bytes past its end stay erased),
       feeding the watchdog after every word, then stops feeding it
       and waits: the watchdog restarts the board on the new image. */
flash_image_from_ram:
    ldr r4, =0xB7000100         /* FLACON */
    ldr r5, =0x08015554
    ldr r6, =0x0800AAA8
    mov r2, #0xAA
    mov r3, #0x55
    mov r7, #0x03
    mov r11, r1
    mov r1, r0
    mov r0, #0x08000000
    mov r8, #0
4:  cmp r8, r11
    bhs 6f
    strb r7, [r4]               /* sector erase */
    strb r2, [r5]
    strb r3, [r6]
    mov r9, #0x80
    strb r9, [r5]
    strb r2, [r5]
    strb r3, [r6]
    mov r9, #0x30
    add r10, r0, r8
    strb r9, [r10]
    bl 2f
5:  mvn r12, #0
    cmp r8, r11
    bhs 3f
    ldr r12, [r1, r8]
    sub r9, r11, r8             /* bytes of the image left */
    cmp r9, #4
    bhs 1f
    mov r9, r9, lsl #3          /* the rest of the word stays erased */
    mvn r10, #0
    orr r12, r12, r10, lsl r9
1:  cmn r12, #1
    beq 3f
    strb r7, [r4]               /* word program */
    strb r2, [r5]
    strb r3, [r6]
    mov r9, #0xA0
    strb r9, [r5]
    add r10, r0, r8
    strb r12, [r10]
    mov r9, r12, lsr #8
    strb r9, [r10, #1]
    mov r9, r12, lsr #16
    strb r9, [r10, #2]
    mov r9, r12, lsr #24
    strb r9, [r10, #3]
    bl 2f
3:  ldr r9, =0xB7E00000         /* WDTCON: feed */
    mov r10, #0xC3
    strb r10, [r9]
    mov r10, #0x3C
    strb r10, [r9]
    add r8, r8, #4
    movs r9, r8, lsl #20        /* still inside the sector? */
    bne 5b
    b 4b
6:  mov r9, #0x02
    strb r9, [r4]               /* programming forbidden again */
7:  b 7b
    /* Wait for the command to complete. */
2:  ldrb r9, [r4]
    and r9, r9, #0x0E
    cmp r9, #0x02
    bne 2b
    bx lr
    .ltorg
"#
);

unsafe extern "C" {
    fn flash_sector_from_ram(address: usize, data: *const u8);
    fn flash_image_from_ram(image: *const u8, len: usize) -> !;
}

/// Replace the firmware with `image` and restart on it: the end of
/// this firmware. `image` must be word aligned and lie outside the
/// flash, and its length leave the settings sector alone.
pub fn write_firmware(image: &[u8]) -> ! {
    let len = image.len().min(SETTINGS - BASE);
    irq::irq_disable();
    watchdog::feed();
    // SAFETY: interrupts are off for good, the routine runs from RAM
    // and never returns into the flash it rewrites.
    unsafe { flash_image_from_ram(image.as_ptr(), len) }
}

/// One sector's worth of scratch space, in the external RAM.
struct Scratch(UnsafeCell<[u32; SECTOR / 4]>);
// SAFETY: only used with interrupts off, by one caller at a time.
unsafe impl Sync for Scratch {}
#[unsafe(link_section = ".xram.flash")]
static SCRATCH: Scratch = Scratch(UnsafeCell::new([0; SECTOR / 4]));

/// The settings sector as it is now.
pub fn settings() -> &'static [u8; SECTOR] {
    // SAFETY: the sector is mapped, readable, and only changes inside
    // `write_settings`, which holds no such reference across the write.
    unsafe { &*(SETTINGS as *const [u8; SECTOR]) }
}

/// Replace the first bytes of the settings sector, keeping the rest.
/// Takes about 65 ms with interrupts off.
pub fn write_settings(data: &[u8]) {
    write_settings_at(0, data);
}

/// Replace bytes of the settings sector from `offset` on, keeping the
/// rest.
pub fn write_settings_at(offset: usize, data: &[u8]) {
    let offset = offset.min(SECTOR);
    let len = data.len().min(SECTOR - offset);
    irq::free(|| {
        watchdog::feed();
        // SAFETY: interrupts are off, so nobody else is in the scratch
        // buffer; it is in RAM and word aligned, the address is the
        // settings sector, and the routine itself runs from RAM.
        unsafe {
            let scratch = SCRATCH.0.get().cast::<u8>();
            core::ptr::copy_nonoverlapping(SETTINGS as *const u8, scratch, SECTOR);
            core::ptr::copy_nonoverlapping(data.as_ptr(), scratch.add(offset), len);
            flash_sector_from_ram(SETTINGS, scratch);
        }
        watchdog::feed();
    });
}
