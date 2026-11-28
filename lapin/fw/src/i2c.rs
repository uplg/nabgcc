//! The I2C bus, as a master. One device on it: the tag reader.

use crate::{irq, reg};

reg! {
    SLAVE_ADDRESS: u16 = 0xB780_0C00;
    CONTROL: u16 = 0xB780_0C04;
    STATUS: u16 = 0xB780_0C08;
    DATA: u16 = 0xB780_0C0C;
    DATA8: u8 = 0xB780_0C0C;
    SPEED: u16 = 0xB780_0C14;
}

const NO_ACK: u16 = 1 << 3;
const TRANSMIT: u16 = 1 << 4;
const MASTER: u16 = 1 << 5;
const ENABLE: u16 = 1 << 7;
const ST_NO_ACK: u16 = 1 << 0;
const ST_ARBITRATION_LOST: u16 = 1 << 4;
const ST_BUSY: u16 = 1 << 5;
const ST_DONE: u16 = 1 << 7;

/// Polls before giving up on the bus: a few milliseconds, where a byte
/// takes a tenth of one. The C waits a million polls, about half a
/// second, but with interrupts on; these waits hold them back, so a
/// jammed bus must not hold them long.
const PATIENCE: u32 = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failed {
    /// The device did not answer, or another master took the bus: try
    /// again (the tag reader does not answer while it talks to a tag).
    Refused,
    /// The bus never came free, or a transfer never ended: something
    /// holds it, trying again only waits longer.
    Stuck,
}

pub fn init() {
    CONTROL.set(ENABLE);
    SLAVE_ADDRESS.write(0);
    SPEED.write(0x28);
    CONTROL.write(ENABLE);
}

fn wait(mask: u16, wanted: u16) -> Result<(), Failed> {
    for _ in 0..PATIENCE {
        if STATUS.read() & mask == wanted {
            return Ok(());
        }
    }
    Err(Failed::Stuck)
}

/// Send a start and the address, and check the device answers.
fn start(address: u8) -> Result<(), Failed> {
    wait(ST_BUSY, 0)?;
    DATA.write(address as u16);
    CONTROL.set(MASTER);
    if STATUS.read() & ST_ARBITRATION_LOST != 0 {
        STATUS.write(0);
        return Err(Failed::Refused);
    }
    wait(ST_DONE, ST_DONE)?;
    acknowledged()
}

fn acknowledged() -> Result<(), Failed> {
    if STATUS.read() & ST_NO_ACK != 0 {
        stop();
        return Err(Failed::Refused);
    }
    Ok(())
}

fn stop() {
    CONTROL.clear(MASTER);
    STATUS.write(0);
}

/// Write `data` to the device at `address` (the 8-bit form, low bit clear).
pub fn write(address: u8, data: &[u8]) -> Result<(), Failed> {
    // The controller wants each step followed closely: no interruption.
    irq::free(|| {
        CONTROL.set(TRANSMIT);
        start(address)?;
        STATUS.write(0);
        for &byte in data {
            DATA.write(byte as u16);
            wait(ST_DONE, ST_DONE)?;
            acknowledged()?;
            STATUS.clear(ST_DONE);
        }
        stop();
        Ok(())
    })
}

/// Read `data.len()` bytes from the device at `address`.
pub fn read(address: u8, data: &mut [u8]) -> Result<(), Failed> {
    let Some((last, first)) = data.split_last_mut() else {
        return Ok(());
    };
    irq::free(|| {
        CONTROL.clear(TRANSMIT);
        start(address | 1)?;
        for byte in first {
            STATUS.write(0);
            wait(ST_DONE, ST_DONE)?;
            *byte = DATA8.read();
        }
        STATUS.write(0);
        // The last byte is not acknowledged: that ends the read.
        CONTROL.set(NO_ACK);
        wait(ST_DONE, ST_DONE)?;
        *last = DATA8.read();
        stop();
        CONTROL.clear(NO_ACK);
        Ok(())
    })
}
