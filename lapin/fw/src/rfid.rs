//! The tag reader in the nose: an ST CRX14, talking ISO 14443-B to the
//! tags (ST SRI family, sold as "Ztamps").

use crate::{i2c, timer};

const READER: u8 = 0xA0;
const REG_PARAMETER: u8 = 0x00;
const REG_FRAME: u8 = 0x01;
const REG_SLOT_MARKER: u8 = 0x03;
const CARRIER_ON: u8 = 0x10;

/// Tries before a transfer the reader keeps refusing is given up. The
/// reader does not answer while it talks to a tag.
const TRIES: u32 = 1000;

/// A tag's 64-bit identifier, most significant byte first.
pub type Uid = [u8; 8];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The reader itself does not answer.
    Reader,
    /// No tag with that identifier in front of the nose.
    NoSuchTag,
}

fn write(data: &[u8]) -> Result<(), Error> {
    for _ in 0..TRIES {
        if i2c::write(READER, data).is_ok() {
            return Ok(());
        }
    }
    Err(Error::Reader)
}

fn read(data: &mut [u8]) -> Result<(), Error> {
    for _ in 0..TRIES {
        if i2c::read(READER, data).is_ok() {
            return Ok(());
        }
    }
    Err(Error::Reader)
}

/// Send a frame to the tags.
fn send(frame: &[u8]) -> Result<(), Error> {
    let mut bytes = [0u8; 8];
    bytes[0] = REG_FRAME;
    bytes[1] = frame.len() as u8;
    bytes[2..2 + frame.len()].copy_from_slice(frame);
    write(&bytes[..2 + frame.len()])?;
    timer::delay_ms(1);
    Ok(())
}

/// Read the answer to the last frame, length byte first.
fn answer(data: &mut [u8]) -> Result<(), Error> {
    data.fill(0);
    write(&[REG_FRAME])?;
    read(data)
}

fn field(on: bool) -> Result<(), Error> {
    let wanted = if on { CARRIER_ON } else { 0 };
    write(&[REG_PARAMETER, wanted])?;
    let mut back = [0u8];
    read(&mut back)?;
    if back[0] == wanted {
        Ok(())
    } else {
        Err(Error::Reader)
    }
}

/// A tag found by [`scan`]: its identifier, and the short number it
/// answers to until the field goes off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tag {
    pub uid: Uid,
    chip_id: u8,
}

fn select(chip_id: u8) -> Result<(), Error> {
    send(&[0x0E, chip_id])?;
    let mut reply = [0u8; 2];
    answer(&mut reply)
}

/// Look for tags: fills `found` and returns how many there are. The
/// field is left on, so that the tags can be read or written next.
fn scan_keeping_field(found: &mut [Tag]) -> Result<usize, Error> {
    // Completion: any tag still selected lets go.
    send(&[0x0F])?;
    field(false)?;
    field(true)?;
    timer::delay_ms(1);
    // Initiate: every tag draws a number.
    send(&[0x06, 0x00])?;
    let mut reply = [0u8; 2];
    answer(&mut reply)?;
    if reply[0] == 0 {
        return Ok(0);
    }
    // Sixteen time slots, one tag in each at most.
    write(&[REG_SLOT_MARKER])?;
    timer::delay_ms(1);
    let mut slots = [0u8; 19];
    answer(&mut slots)?;
    let answered = u16::from_le_bytes([slots[1], slots[2]]);
    let mut count = 0;
    for slot in 0..16 {
        if answered & (1 << slot) == 0 || count == found.len() {
            continue;
        }
        let chip_id = slots[3 + slot];
        select(chip_id)?;
        send(&[0x0B])?;
        let mut uid = [0u8; 9];
        answer(&mut uid)?;
        // The identifier travels least significant byte first.
        let mut tag = Tag {
            uid: [0; 8],
            chip_id,
        };
        for (i, byte) in tag.uid.iter_mut().enumerate() {
            *byte = uid[8 - i];
        }
        found[count] = tag;
        count += 1;
    }
    Ok(count)
}

fn field_off() {
    let _ = send(&[0x0F]);
    let _ = field(false);
}

/// The tags in front of the nose.
pub fn scan(found: &mut [Tag]) -> Result<usize, Error> {
    let result = scan_keeping_field(found);
    field_off();
    result
}

fn with_tag<R>(uid: &Uid, f: impl FnOnce() -> Result<R, Error>) -> Result<R, Error> {
    let mut found = [Tag {
        uid: [0; 8],
        chip_id: 0,
    }; 16];
    let result = scan_keeping_field(&mut found).and_then(|count| {
        let tag = found[..count]
            .iter()
            .find(|t| &t.uid == uid)
            .ok_or(Error::NoSuchTag)?;
        select(tag.chip_id)?;
        f()
    });
    field_off();
    result
}

/// Read one of a tag's four-byte memory blocks. Block 0 here is the
/// first one free for use, the tag's block 7.
pub fn read_block(uid: &Uid, block: u8) -> Result<[u8; 4], Error> {
    with_tag(uid, || {
        send(&[0x08, block + 7])?;
        let mut reply = [0u8; 5];
        answer(&mut reply)?;
        Ok([reply[1], reply[2], reply[3], reply[4]])
    })
}

pub fn write_block(uid: &Uid, block: u8, data: &[u8; 4]) -> Result<(), Error> {
    with_tag(uid, || {
        send(&[0x09, block + 7, data[0], data[1], data[2], data[3]])
    })
}
