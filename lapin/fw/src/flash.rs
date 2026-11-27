//! The processor's own flash: 128 KB in 4 KB sectors. The last sector
//! holds the rabbit's settings; the rest is the firmware.
//!
//! While the flash erases or programs it cannot be read, so the code
//! that does it cannot live there: it is linked into the initialised
//! data and so copied to RAM at reset, and it runs with interrupts off
//! since their handlers are in the flash too.

use core::cell::UnsafeCell;

use crate::{irq, watchdog};

pub const BASE: usize = 0x0800_0000;
pub const SECTOR: usize = 4096;
/// Where the settings sector starts.
pub const SETTINGS: usize = BASE + 0x1_F000;

const FLACON: *mut u8 = 0xB700_0100 as *mut u8;
const COMMAND_1: *mut u8 = 0x0801_5554 as *mut u8;
const COMMAND_2: *mut u8 = 0x0800_AAA8 as *mut u8;
const WDTCON: *mut u8 = 0xB7E0_0000 as *mut u8;

// What follows runs from RAM while the flash is busy: it is placed in
// the initialised data (copied to RAM at reset), and must reach nothing
// in the flash, no call at all, not even a bounds check's panic or a
// `memcpy`. Hence raw pointers, volatile accesses, and functions forced
// inline into their two callers. `lapin/build.sh` checks the result:
// no branch out of the RAM code.

/// Wait for the flash's command to complete.
#[inline(always)]
unsafe fn flash_wait() {
    // SAFETY: a register of the processor.
    while unsafe { FLACON.read_volatile() } & 0x0E != 0x02 {}
}

/// The unlock sequence of a flash command, then the command.
#[inline(always)]
unsafe fn flash_command(command: u8) {
    // SAFETY: the command registers of the flash, the routine in RAM.
    unsafe {
        FLACON.write_volatile(0x03);
        COMMAND_1.write_volatile(0xAA);
        COMMAND_2.write_volatile(0x55);
        COMMAND_1.write_volatile(command);
    }
}

#[inline(always)]
unsafe fn erase_sector(at: *mut u8) {
    // SAFETY: as above; `at` is a sector of the flash.
    unsafe {
        flash_command(0x80);
        COMMAND_1.write_volatile(0xAA);
        COMMAND_2.write_volatile(0x55);
        at.write_volatile(0x30);
        flash_wait();
    }
}

/// Program one word (skipped when all ones, the erased value).
#[inline(always)]
unsafe fn program_word(at: *mut u8, word: u32) {
    if word == u32::MAX {
        return;
    }
    // SAFETY: as above; `at` is word aligned in the flash.
    unsafe {
        flash_command(0xA0);
        at.write_volatile(word as u8);
        at.add(1).write_volatile((word >> 8) as u8);
        at.add(2).write_volatile((word >> 16) as u8);
        at.add(3).write_volatile((word >> 24) as u8);
        flash_wait();
    }
}

/// Erase the sector at `address` and program it with the 4096 bytes at
/// `data` (word aligned, outside the flash).
#[unsafe(link_section = ".data.ramcode")]
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn flash_sector_from_ram(address: usize, data: *const u32) {
    let at = address as *mut u8;
    // SAFETY: interrupts are off (the caller's duty), this runs from RAM.
    unsafe {
        erase_sector(at);
        let mut i = 0;
        while i < SECTOR / 4 {
            program_word(at.add(4 * i), data.add(i).read_volatile());
            i += 1;
        }
        FLACON.write_volatile(0x02);
    }
}

/// Rewrite the flash from its first sector with the `len` bytes at
/// `image`, feeding the watchdog after every word; then stop feeding
/// it and wait: the watchdog restarts the board on the new image.
#[unsafe(link_section = ".data.ramcode")]
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn flash_image_from_ram(image: *const u32, len: usize) -> ! {
    // SAFETY: interrupts are off for good, this runs from RAM.
    unsafe {
        let mut offset = 0;
        while offset < len {
            if offset % SECTOR == 0 {
                erase_sector((BASE + offset) as *mut u8);
            }
            let mut word = image.add(offset / 4).read_volatile();
            if len - offset < 4 {
                // The rest of the last word stays erased.
                word |= u32::MAX << (8 * (len - offset));
            }
            program_word((BASE + offset) as *mut u8, word);
            WDTCON.write_volatile(0xC3);
            WDTCON.write_volatile(0x3C);
            offset += 4;
        }
        FLACON.write_volatile(0x02);
        // Nothing else may run: anything (even a spin hint) could be a
        // call into the flash just rewritten.
        #[allow(clippy::empty_loop)]
        loop {}
    }
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
    unsafe { flash_image_from_ram(image.as_ptr().cast(), len) }
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
            flash_sector_from_ram(SETTINGS, scratch.cast());
        }
        watchdog::feed();
    });
}
