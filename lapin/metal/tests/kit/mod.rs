//! What this crate's tests share: the assembler, a memory, and a board
//! that does little more than what the tests look at.
#![allow(dead_code)]

pub mod asm;

use lapin_metal::{Auth, Host, Memory, Motor, ScanResult};

/// The codec's input buffer.
pub const FIFO: usize = 2048;

/// A board with an I2C device that answers "abc...", and a codec that
/// plays as time goes and takes data only while its DREQ is up, as the
/// VS1003 does.
#[derive(Default)]
pub struct Board {
    pub console: Vec<u8>,
    /// Every I2C transfer: the address, and the bytes read or written.
    pub i2c: Vec<(u8, Vec<u8>)>,
    pub now: u32,
    /// Room in the codec's input buffer.
    pub room: usize,
    pub played: Vec<u8>,
    pub amplifier: bool,
}

/// How the board stops the machine when it resets.
pub struct Reset;

/// An 804 KB memory, straight on the heap.
pub fn memory() -> Box<Memory> {
    unsafe {
        let layout = std::alloc::Layout::new::<Memory>();
        Box::from_raw(std::alloc::alloc_zeroed(layout) as *mut Memory)
    }
}

impl Host for Board {
    fn console(&mut self, text: &[u8]) {
        self.console.extend_from_slice(text);
    }
    fn time_ms(&mut self) -> u32 {
        // Time passes as it is looked at; the codec plays meanwhile.
        self.now += 1;
        self.room = (self.room + 16).min(FIFO);
        self.now
    }
    fn time_s(&mut self) -> u32 {
        0
    }
    fn led(&mut self, _: u8, _: u32) {}
    fn motor(&mut self, _: u8, _: Motor) {}
    fn motor_position(&mut self, _: u8) -> u16 {
        0
    }
    fn button(&mut self) -> u8 {
        0
    }
    fn adc(&mut self) -> u8 {
        0
    }
    fn rfid_first(&mut self) -> Option<[u8; 8]> {
        None
    }
    fn rfid_count(&mut self) -> i32 {
        0
    }
    fn rfid_nth(&mut self, _: i32) -> [u8; 8] {
        [0; 8]
    }
    fn rfid_read(&mut self, _: &[u8; 8], _: i32, _: &mut [u8; 4]) -> i32 {
        1
    }
    fn rfid_write(&mut self, _: &[u8; 8], _: i32, _: &[u8; 4]) -> i32 {
        1
    }
    fn i2c_read(&mut self, address: u8, data: &mut [u8]) -> bool {
        for (i, b) in data.iter_mut().enumerate() {
            *b = b'a' + i as u8;
        }
        self.i2c.push((address, data.to_vec()));
        true
    }
    fn i2c_write(&mut self, address: u8, data: &[u8]) -> bool {
        self.i2c.push((address, data.to_vec()));
        true
    }
    fn settings_read(&mut self, _: u32, data: &mut [u8]) {
        data.fill(0xFF);
    }
    fn settings_write(&mut self, _: u32, _: &[u8]) {}
    fn flash_firmware(&mut self, _: &[u8]) -> ! {
        self.reboot()
    }
    fn reboot(&mut self) -> ! {
        std::panic::panic_any(Reset)
    }
    fn codec_read(&mut self, _: u8) -> u16 {
        0
    }
    fn codec_write(&mut self, register: u8, _: u16) {
        // Not a VS1003 register: the bytecode's way here to have the
        // codec fill up (DREQ down) while its callback runs, as a
        // collection's own feeding does on the rabbit.
        if register == 0x0F {
            self.room = 0;
        }
    }
    fn codec_ready(&mut self) -> bool {
        self.room >= 32
    }
    fn codec_feed(&mut self, data: &[u8]) -> usize {
        // As the VS1003 is fed (vlsi_feed_sdi): while DREQ is up.
        let mut n = 0;
        while n < data.len() && self.codec_ready() {
            self.played.push(data[n]);
            self.room -= 1;
            n += 1;
        }
        n
    }
    fn amplifier(&mut self, on: bool) {
        self.amplifier = on;
    }
    fn net_state(&mut self) -> i32 {
        0
    }
    fn net_send(&mut self, _: &[u8], _: &[u8; 6], _: i32) -> i32 {
        0
    }
    fn net_mac(&mut self) -> [u8; 6] {
        [0; 6]
    }
    fn net_set_mode(&mut self, _: i32, _: Option<&[u8]>, _: u8) {}
    fn net_scan(&mut self, _: Option<&[u8]>) -> usize {
        0
    }
    fn net_scan_result(&mut self, _: usize) -> ScanResult {
        unreachable!()
    }
    fn net_auth(&mut self, _: &Auth<'_>) {}
    fn net_pmk(&mut self, _: &[u8], _: &[u8]) -> [u8; 32] {
        [0; 32]
    }
    fn net_rssi(&mut self) -> i32 {
        0
    }
    fn net_pending(&mut self) -> Option<usize> {
        None
    }
    fn net_take(&mut self, _: &mut [u8], _: &mut [u8; 6]) {}
}
