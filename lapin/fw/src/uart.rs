//! UART0, the debug serial port: 115200 baud, 8N1, polled.

const PORTSEL1: *mut u32 = 0xB700_0024 as *mut u32;
const UART0: usize = 0xB7B0_0000;
const THR: *mut u8 = UART0 as *mut u8;
const DLL: *mut u8 = UART0 as *mut u8;
const DLM: *mut u8 = (UART0 + 0x04) as *mut u8;
const IER: *mut u8 = (UART0 + 0x04) as *mut u8;
const FCR: *mut u8 = (UART0 + 0x08) as *mut u8;
const LCR: *mut u8 = (UART0 + 0x0C) as *mut u8;
const MCR: *mut u8 = (UART0 + 0x10) as *mut u8;
const LSR: *const u8 = (UART0 + 0x14) as *const u8;

const LCR_DIVISOR_LATCH: u8 = 0x80;
const LCR_8N1: u8 = 0x03;
const LSR_HOLDING_EMPTY: u8 = 0x20;
/// 32 MHz / (16 * 17) is 117647 baud, within 2.2 % of 115200.
const DIVISOR: u16 = 17;

pub fn init() {
    // SAFETY: fixed registers of the processor; nothing else drives the
    // port, and this runs before interrupts are enabled.
    unsafe {
        // Pins PB0 and PB1 to their serial function.
        PORTSEL1.write_volatile(PORTSEL1.read_volatile() | 0x0005_0000);
        LCR.write_volatile(LCR_DIVISOR_LATCH);
        DLL.write_volatile(DIVISOR as u8);
        DLM.write_volatile((DIVISOR >> 8) as u8);
        LCR.write_volatile(LCR_8N1);
        // FIFOs on and emptied, interrupts off, no modem lines.
        FCR.write_volatile(0x07);
        IER.write_volatile(0);
        MCR.write_volatile(0);
    }
}

pub fn write(bytes: &[u8]) {
    for &byte in bytes {
        // SAFETY: as above; the status read has no side effect.
        unsafe {
            while LSR.read_volatile() & LSR_HOLDING_EMPTY == 0 {}
            THR.write_volatile(byte);
        }
    }
}

/// Write a 16-bit number as four hexadecimal digits.
pub fn hex16(value: u16) {
    for shift in [12, 8, 4, 0] {
        write(&[b"0123456789abcdef"[(value >> shift) as usize & 15]]);
    }
}

/// Write a byte as two hexadecimal digits.
pub fn hex8(value: u8) {
    for shift in [4, 0] {
        write(&[b"0123456789abcdef"[(value >> shift) as usize & 15]]);
    }
}
