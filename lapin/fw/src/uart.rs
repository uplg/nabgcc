//! UART0, the debug serial port: 115200 baud, 8N1, polled.

use crate::board::PORTSEL1;
use crate::reg;

const UART0: usize = 0xB7B0_0000;

reg! {
    THR: u8 = UART0;
    DLL: u8 = UART0;
    DLM: u8 = UART0 + 0x04;
    IER: u8 = UART0 + 0x04;
    FCR: u8 = UART0 + 0x08;
    LCR: u8 = UART0 + 0x0C;
    MCR: u8 = UART0 + 0x10;
    LSR: u8 = UART0 + 0x14;
}

const LCR_DIVISOR_LATCH: u8 = 0x80;
const LCR_8N1: u8 = 0x03;
const LSR_HOLDING_EMPTY: u8 = 0x20;
/// 32 MHz / (16 * 17) is 117647 baud, within 2.2 % of 115200.
const DIVISOR: u16 = 17;

/// The hexadecimal digits, by value.
pub const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Before interrupts are enabled: the pin selection is read, changed
/// and written back.
pub fn init() {
    // Pins PB0 and PB1 to their serial function.
    PORTSEL1.set(0x0005_0000);
    LCR.write(LCR_DIVISOR_LATCH);
    DLL.write(DIVISOR as u8);
    DLM.write((DIVISOR >> 8) as u8);
    LCR.write(LCR_8N1);
    // FIFOs on and emptied, interrupts off, no modem lines.
    FCR.write(0x07);
    IER.write(0);
    MCR.write(0);
}

pub fn write(bytes: &[u8]) {
    for &byte in bytes {
        while LSR.read() & LSR_HOLDING_EMPTY == 0 {}
        THR.write(byte);
    }
}

/// Write a byte as two hexadecimal digits.
pub fn hex8(value: u8) {
    write(&[DIGITS[value as usize >> 4], DIGITS[value as usize & 15]]);
}
