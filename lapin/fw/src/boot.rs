//! How the flash is shared between the rescue core and the application.
//!
//! The rescue core (`bin/rescue.rs`) holds the first 20 KB: the
//! processor's vectors, and a mode that raises a Wi-Fi network of its
//! own to take a new image when the application is missing, damaged,
//! or keeps restarting. An update that brings the same rescue core
//! rewrites the application alone, so a power cut in the middle no
//! longer kills the rabbit.
//!
//! The application (the firmware proper: `bin/lapin.rs`, and the bench
//! and self-test) starts at [`APP_BASE`] with a header the rescue core
//! checks before handing over:
//!
//! | Word | |
//! |---|---|
//! | 0 | [`MAGIC`] |
//! | 1 | length in bytes, header included |
//! | 2 | CRC-32 of the bytes after the header (filled in by `build.sh`) |
//! | 3 | address of its reset code |
//!
//! The two share four words at the bottom of the internal RAM, which
//! neither one's startup clears: see [`Slots`].

use crate::flash;

/// The application's first byte.
pub const APP_BASE: usize = flash::BASE + RESCUE_SIZE;
/// What the rescue core takes.
pub const RESCUE_SIZE: usize = 20 * 1024;
/// Where the application must end: the settings sector follows.
pub const APP_END: usize = flash::SETTINGS;
pub const HEADER_LEN: usize = 16;
/// "LAPA", little-endian.
pub const MAGIC: u32 = 0x4150_414C;

/// Restarts in a row without the application saying it is well, after
/// which the rescue core takes over.
pub const MAX_FAILED_BOOTS: u32 = 3;

/// The words at the bottom of the internal RAM, kept across a restart
/// (not across a power cut): `SLOT_MAGIC` there when the rest is
/// meaningful, the restarts since the application last said it was
/// well, and where the vectors of the rescue core send interrupts and
/// undefined instructions.
pub struct Slots;

const SLOTS: usize = 0x1000_0000;
const SLOT_MAGIC: u32 = 0x5A17_B007;

fn slot(i: usize) -> *mut u32 {
    (SLOTS + 4 * i) as *mut u32
}

impl Slots {
    /// Count one more start; returns how many in a row the application
    /// has had without saying it was well (0 after a power cut).
    pub fn count_boot() -> u32 {
        // SAFETY: the four words below the linker's RAM, reserved for
        // this (see link.x and rescue.x).
        unsafe {
            if slot(0).read_volatile() != SLOT_MAGIC {
                slot(0).write_volatile(SLOT_MAGIC);
                slot(1).write_volatile(0);
                return 0;
            }
            let n = slot(1).read_volatile().saturating_add(1);
            slot(1).write_volatile(n);
            n
        }
    }

    /// The application runs well: forget the restarts.
    pub fn confirm() {
        // SAFETY: as above.
        unsafe {
            slot(0).write_volatile(SLOT_MAGIC);
            slot(1).write_volatile(0);
        }
    }
}

/// CRC-32 (IEEE 802.3, as zlib's), four bits at a time.
pub fn crc32(data: &[u8]) -> u32 {
    const T: [u32; 16] = [
        0x0000_0000,
        0x1DB7_1064,
        0x3B6E_20C8,
        0x26D9_30AC,
        0x76DC_4190,
        0x6B6B_51F4,
        0x4DB2_6158,
        0x5005_713C,
        0xEDB8_8320,
        0xF00F_9344,
        0xD6D6_A3E8,
        0xCB61_B38C,
        0x9B64_C2B0,
        0x86D3_D2D4,
        0xA00A_E278,
        0xBDBD_F21C,
    ];
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        c = (c >> 4) ^ T[(c & 15) as usize];
        c = (c >> 4) ^ T[(c & 15) as usize];
    }
    !c
}

/// An application image, from its header: its length if it is whole.
pub fn check_app(image: &[u8]) -> Option<usize> {
    let word = |i: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            image.get(4 * i..4 * i + 4)?.try_into().ok()?,
        ))
    };
    if word(0)? != MAGIC {
        return None;
    }
    let len = word(1)? as usize;
    if !(HEADER_LEN..=APP_END - APP_BASE).contains(&len) || len > image.len() {
        return None;
    }
    (crc32(&image[HEADER_LEN..len]) == word(2)?).then_some(len)
}

/// The application in the flash, if it is whole: its reset address.
pub fn installed_app() -> Option<u32> {
    // SAFETY: the flash is mapped and readable; nothing writes it now.
    let flash = unsafe { core::slice::from_raw_parts(APP_BASE as *const u8, APP_END - APP_BASE) };
    check_app(flash)?;
    Some(u32::from_le_bytes([
        flash[12], flash[13], flash[14], flash[15],
    ]))
}

/// The rescue core as it is in the flash.
pub fn installed_rescue() -> &'static [u8] {
    // SAFETY: as above; the rescue core is never written by the
    // application's updates.
    unsafe { core::slice::from_raw_parts(flash::BASE as *const u8, RESCUE_SIZE) }
}

/// What part of `image` an update writes, from where: a whole image
/// (rescue core and application) whose rescue core is the one in place
/// rewrites the application alone; an application image alone, the
/// same; anything else (an older firmware, a new rescue core) the whole
/// flash, as before there was one. `None`: a damaged application,
/// refused.
pub fn update_plan(image: &[u8]) -> Option<(usize, &[u8])> {
    if image.len() > RESCUE_SIZE && image[..RESCUE_SIZE] == *installed_rescue() {
        let app = &image[RESCUE_SIZE..];
        let len = check_app(app)?;
        return Some((APP_BASE, &app[..len]));
    }
    if let Some(len) = check_app(image) {
        return Some((APP_BASE, &image[..len]));
    }
    Some((flash::BASE, image))
}
