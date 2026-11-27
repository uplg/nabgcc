//! A board for the bytecode machine: deterministic, quick, holding the
//! machine to the contract of `Host` (ears 1 and 2, settings inside
//! their sector, scan results that exist), and stopping it after a
//! budget of instructions.

use std::collections::VecDeque;

use lapin_metal::{Auth, Host, Memory, Motor, ScanResult};

use crate::Stop;
use crate::input::Input;

pub struct Board {
    pub console: Vec<u8>,
    now: u32,
    steps: u64,
    budget: u64,
    settings: Vec<u8>,
    rx: VecDeque<(Vec<u8>, [u8; 6])>,
    scanned: usize,
    seed: u32,
    collections: u32,
}

impl Board {
    pub fn new(budget: u64, input: &mut Input) -> Board {
        let mut rx = VecDeque::new();
        for _ in 0..input.u8() % 4 {
            let source = input.array();
            rx.push_back((input.chunk(false).to_vec(), source));
        }
        Board {
            console: Vec::new(),
            now: 0,
            steps: 0,
            budget,
            settings: vec![0xFF; 4096],
            rx,
            scanned: 0,
            seed: input.u32(),
            collections: 0,
        }
    }

    fn random(&mut self) -> u32 {
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 17;
        self.seed ^= self.seed << 5;
        self.seed
    }
}

impl Host for Board {
    fn console(&mut self, text: &[u8]) {
        if self.console.len() < 1 << 16 {
            self.console.extend_from_slice(text);
        }
        // Memory nearly full, every allocation collects, over the
        // whole 800 KB: slow, as on the rabbit, not wrong. Enough.
        if text.starts_with(b"#GC") {
            self.collections += 1;
            if self.collections > 16 {
                std::panic::panic_any(Stop);
            }
        }
    }
    fn watchdog(&mut self) {
        // Called every 256 instructions: half a millisecond each, as
        // before when it came with every instruction.
        self.steps += 256;
        self.now = self.now.wrapping_add(128);
        if self.steps > self.budget {
            std::panic::panic_any(Stop);
        }
    }
    fn time_ms(&mut self) -> u32 {
        self.now
    }
    fn time_s(&mut self) -> u32 {
        self.now / 1000
    }
    fn led(&mut self, _: u8, _: u32) {}
    fn motor(&mut self, motor: u8, _: Motor) {
        assert!(motor == 1 || motor == 2, "ear {motor}");
    }
    fn motor_position(&mut self, motor: u8) -> u16 {
        assert!(motor == 1 || motor == 2, "ear {motor}");
        self.random() as u16
    }
    fn button(&mut self) -> u8 {
        self.random() as u8 & 1
    }
    fn adc(&mut self) -> u8 {
        self.random() as u8
    }
    fn rfid_first(&mut self) -> Option<[u8; 8]> {
        (self.random() & 1 != 0).then_some([0xD0, 2, 0x18, 1, 2, 3, 4, 5])
    }
    fn rfid_count(&mut self) -> i32 {
        (self.random() % 3) as i32
    }
    fn rfid_nth(&mut self, i: i32) -> [u8; 8] {
        [i as u8; 8]
    }
    fn rfid_read(&mut self, _: &[u8; 8], _: i32, data: &mut [u8; 4]) -> i32 {
        *data = self.random().to_le_bytes();
        0
    }
    fn rfid_write(&mut self, _: &[u8; 8], _: i32, _: &[u8; 4]) -> i32 {
        0
    }
    fn i2c_read(&mut self, _: u8, data: &mut [u8]) -> bool {
        assert!(data.len() <= 255);
        data.fill(0x5A);
        true
    }
    fn i2c_write(&mut self, _: u8, _: &[u8]) -> bool {
        true
    }
    fn settings_read(&mut self, offset: u32, data: &mut [u8]) {
        // The board clips; the machine may ask for anything.
        let at = (offset as usize).min(4096);
        let n = data.len().min(4096 - at);
        data[..n].copy_from_slice(&self.settings[at..at + n]);
    }
    fn settings_write(&mut self, offset: u32, data: &[u8]) {
        let at = (offset as usize).min(4096);
        let n = data.len().min(4096 - at);
        self.settings[at..at + n].copy_from_slice(&data[..n]);
    }
    fn flash_firmware(&mut self, _: &[u8]) -> ! {
        std::panic::panic_any(Stop)
    }
    fn reboot(&mut self) -> ! {
        std::panic::panic_any(Stop)
    }
    fn codec_read(&mut self, register: u8) -> u16 {
        if register == 9 {
            0x80
        } else {
            self.random() as u16
        }
    }
    fn codec_write(&mut self, _: u8, _: u16) {}
    fn codec_ready(&mut self) -> bool {
        self.random() & 3 != 0
    }
    fn codec_feed(&mut self, data: &[u8]) -> usize {
        data.len().min(self.random() as usize % 64)
    }
    fn amplifier(&mut self, _: bool) {}
    fn net_state(&mut self) -> i32 {
        (self.random() % 6) as i32
    }
    fn net_send(&mut self, frame: &[u8], _: &[u8; 6], _: i32) -> i32 {
        assert!(frame.len() <= 1 << 22);
        0
    }
    fn net_mac(&mut self) -> [u8; 6] {
        [0x00, 0x19, 0xDB, 0x9C, 0x28, 0x15]
    }
    fn net_set_mode(&mut self, _: i32, _: Option<&[u8]>, _: u8) {}
    fn net_scan(&mut self, _: Option<&[u8]>) -> usize {
        self.scanned = (self.random() % 3) as usize;
        self.scanned
    }
    fn net_scan_result(&mut self, i: usize) -> ScanResult {
        assert!(i < self.scanned, "scan result {i} of {}", self.scanned);
        let mut ssid = [0u8; 33];
        ssid[..7].copy_from_slice(b"Terrier");
        ScanResult {
            ssid,
            mac: [2, 0, 0, 0, 0, i as u8],
            bssid: [2, 0, 0, 0, 0, i as u8],
            rssi: -40,
            channel: 6,
            rateset: 0xFFF,
            encryption: 0x4A,
        }
    }
    fn net_auth(&mut self, _: &Auth<'_>) {}
    fn net_pmk(&mut self, _: &[u8], _: &[u8]) -> [u8; 32] {
        [0x42; 32]
    }
    fn net_rssi(&mut self) -> i32 {
        -50
    }
    fn net_pending(&mut self) -> Option<usize> {
        self.rx.front().map(|(f, _)| f.len())
    }
    fn net_take(&mut self, data: &mut [u8], source: &mut [u8; 6]) {
        if let Some((f, s)) = self.rx.pop_front() {
            let n = data.len().min(f.len());
            data[..n].copy_from_slice(&f[..n]);
            *source = s;
        }
    }
    fn usb_events(&mut self) {
        self.now = self.now.wrapping_add(10);
    }
}

/// An 804 KB memory, zeroed, straight on the heap.
pub fn memory() -> Box<Memory> {
    let layout = std::alloc::Layout::new::<Memory>();
    unsafe {
        let p = std::alloc::alloc_zeroed(layout) as *mut Memory;
        assert!(!p.is_null());
        Box::from_raw(p)
    }
}

/// A bytecode from fuzzed parts: globals, code and a function table
/// whose sizes agree, so that the code runs rather than the loader
/// stopping at the first size.
pub fn assemble(input: &mut Input) -> Vec<u8> {
    let mut globals = Vec::new();
    for _ in 0..input.u8() % 8 {
        global(input, &mut globals, 0);
    }
    let nfun = 1 + input.u8() as usize % 8;
    let code = input.chunk(true).to_vec();
    let mut starts = Vec::new();
    for _ in 0..nfun {
        starts.push(input.u16() as u32 % code.len().max(1) as u32);
    }
    starts[0] = 0;
    let mut b = Vec::new();
    b.extend_from_slice(&(4 + globals.len() as u32).to_le_bytes());
    b.extend_from_slice(&globals);
    b.extend_from_slice(&(code.len() as u32).to_le_bytes());
    b.extend_from_slice(&code);
    b.extend_from_slice(&(nfun as u16).to_le_bytes());
    for s in starts {
        b.extend_from_slice(&s.to_le_bytes());
    }
    b
}

/// One global: an integer, nil, a string or a tuple.
fn global(input: &mut Input, out: &mut Vec<u8>, depth: u32) {
    match input.u8() % 4 {
        0 => out.extend_from_slice(&((input.u32() as i32) << 1).to_le_bytes()),
        1 => out.extend_from_slice(&(-1i32).to_le_bytes()),
        2 if depth < 3 => {
            let n = input.u8() % 5;
            out.extend_from_slice(&(((n as u32) << 2 | 3) as i32).to_le_bytes());
            for _ in 0..n {
                global(input, out, depth + 1);
            }
        }
        _ => {
            let s = input.chunk(false);
            out.extend_from_slice(&(((s.len() as u32) << 2) | 1).to_le_bytes());
            out.extend_from_slice(s);
        }
    }
}

/// Whether the globals of a bytecode are well formed: each ends where
/// the next starts, the last where the code starts. Malformed ones
/// make the loader (the C one as this one) walk backwards and forever,
/// or recurse as deep as the bytecode is long: the boot bytecode and
/// the server's are trusted not to.
pub fn globals_ok(b: &[u8]) -> bool {
    let int =
        |o: usize| -> Option<i32> { Some(i32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?)) };
    fn skip(b: &[u8], at: usize, depth: u32, int: &dyn Fn(usize) -> Option<i32>) -> Option<usize> {
        if depth > 64 {
            return None;
        }
        let l = int(at)?;
        let at = at + 4;
        if l == -1 || l & 1 == 0 {
            return Some(at);
        }
        let l = l >> 1;
        if l < 0 {
            return None;
        }
        if l & 1 != 0 {
            let mut at = at;
            for _ in 0..l >> 1 {
                at = skip(b, at, depth + 1, int)?;
            }
            Some(at)
        } else {
            let n = (l >> 1) as usize;
            (at + n <= b.len()).then_some(at + n)
        }
    }
    let Some(n) = int(0) else { return false };
    if n < 4 || n as usize > b.len() {
        return false;
    }
    let mut at = 4;
    while at < n as usize {
        match skip(b, at, 0, &int) {
            Some(next) => at = next,
            None => return false,
        }
    }
    at == n as usize
}
