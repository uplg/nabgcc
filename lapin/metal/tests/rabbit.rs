//! What the machine does the way the rabbit's processor does it, where
//! the C machine built for another processor would not show it (the
//! rest is checked against the C machine in `../cref`).

use lapin_metal::op::*;
use lapin_metal::{Auth, Host, Memory, Motor, ScanResult, Vm};

#[derive(Default)]
struct Board {
    console: Vec<u8>,
    i2c: Vec<(u8, Vec<u8>)>,
}

struct Reset;

impl Host for Board {
    fn console(&mut self, text: &[u8]) {
        self.console.extend_from_slice(text);
    }
    fn time_ms(&mut self) -> u32 {
        0
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
        std::panic::panic_any(Reset)
    }
    fn reboot(&mut self) -> ! {
        std::panic::panic_any(Reset)
    }
    fn codec_read(&mut self, _: u8) -> u16 {
        0
    }
    fn codec_write(&mut self, _: u8, _: u16) {}
    fn codec_ready(&mut self) -> bool {
        false
    }
    fn codec_feed(&mut self, _: &[u8]) -> usize {
        0
    }
    fn amplifier(&mut self, _: bool) {}
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

/// A program of one function printing what `code` leaves, one value per
/// `IECHOLN`, with `strings` as globals.
fn run(strings: &[&[u8]], code: &[u8]) -> String {
    let mut globals = Vec::new();
    for s in strings {
        globals.extend(((s.len() as u32) << 2 | 1).to_le_bytes());
        globals.extend_from_slice(s);
    }
    let mut bc = (globals.len() as u32 + 4).to_le_bytes().to_vec();
    bc.extend(globals);
    let mut f = vec![0, 0, 0];
    f.extend_from_slice(code);
    f.extend([NIL_ as u8, RET as u8]);
    bc.extend((f.len() as u32).to_le_bytes());
    bc.extend(f);
    bc.extend(1u16.to_le_bytes());
    bc.extend(0u32.to_le_bytes());
    let mut mem: Box<Memory> = unsafe {
        let layout = std::alloc::Layout::new::<Memory>();
        Box::from_raw(std::alloc::alloc_zeroed(layout) as *mut Memory)
    };
    let mut vm = Vm::new(Board::default(), &mut mem);
    vm.boot(&bc);
    String::from_utf8(vm.into_host().console).unwrap()
}

fn int(v: i32) -> Vec<u8> {
    let mut c = vec![INT as u8];
    c.extend(v.to_le_bytes());
    c
}

fn binary(a: i32, o: i32, b: i32) -> Vec<u8> {
    let mut c = int(a);
    c.extend(int(b));
    c.extend([o as u8, IECHOLN as u8, DROP as u8]);
    c
}

#[test]
fn dividing_by_zero_gives_what_libgcc_gives() {
    // __aeabi_idiv: the largest number of the dividend's sign, cut to
    // the machine's 31 bits; __aeabi_idivmod leaves a zero remainder.
    let mut code = Vec::new();
    for a in [5, -5, 0] {
        code.extend(binary(a, DIV, 0));
        code.extend(binary(a, MOD, 0));
    }
    assert_eq!(run(&[], &code), "-1\r\n0\r\n0\r\n0\r\n0\r\n0\r\n");
}

#[test]
fn shifts_by_32_and_more_shift_everything_out() {
    // The ARM shifts by the low byte of the count. (1 << 31 is 0 once
    // cut to the machine's 31 bits.)
    let mut code = Vec::new();
    for b in [31, 32, 33, 255, 256, 257] {
        code.extend(binary(1, SHL, b));
        code.extend(binary(-8, SHR, b));
    }
    assert_eq!(
        run(&[], &code),
        "0\r\n-1\r\n0\r\n-1\r\n0\r\n-1\r\n0\r\n-1\r\n1\r\n-8\r\n2\r\n-4\r\n"
    );
}

#[test]
fn a_checksum_from_an_odd_offset_reads_rotated_halfwords() {
    // From an odd address the ARM7TDMI loads the halfword below, rotated
    // by a byte across the 32-bit register.
    let mut code = vec![GETGLOBALB as u8, 0];
    code.extend(int(1));
    code.extend(int(2));
    code.extend(int(0));
    code.extend([NETCHK as u8, IECHOLN as u8, DROP as u8]);
    // Bytes 0 and 1 are 0x12 0x34: loaded as 0x3412 then rotated to
    // 0x12000034, folded to 0x1234, swapped to 0x3412.
    assert_eq!(
        run(&[&[0x12, 0x34, 0x56, 0x78]], &code),
        format!("{}\r\n", 0x3412)
    );
}

#[test]
fn i2c_read_returns_what_the_device_said() {
    let mut code = int(0x42);
    code.extend(int(3));
    code.extend([I2CREAD as u8, SECHOLN as u8, DROP as u8]);
    assert_eq!(run(&[], &code), "abc\r\n");
}
