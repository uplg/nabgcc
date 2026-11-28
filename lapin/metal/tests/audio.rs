//! The machine feeding the codec from the play callback (`audio.rs`),
//! against a codec that plays as time goes and takes data only while
//! its DREQ is up, as the VS1003 does.

use lapin_metal::op::*;
use lapin_metal::{Auth, Host, Memory, Motor, ScanResult, Vm};

/// The codec's input buffer.
const FIFO: usize = 2048;

#[derive(Default)]
struct Codec {
    now: u32,
    room: usize,
    played: Vec<u8>,
    amplifier: bool,
    resets: u32,
    console: Vec<u8>,
}

struct Reset;

impl Host for Codec {
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
    fn i2c_read(&mut self, _: u8, _: &mut [u8]) -> bool {
        true
    }
    fn i2c_write(&mut self, _: u8, _: &[u8]) -> bool {
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
    fn codec_write(&mut self, register: u8, value: u16) {
        if register == 0 && value & 4 != 0 {
            self.resets += 1;
        }
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

fn int(v: i32) -> Vec<u8> {
    let mut c = vec![INT as u8];
    c.extend(v.to_le_bytes());
    c
}

fn fun(narg: u8, code: &[u8]) -> Vec<u8> {
    let mut out = vec![narg, 4, 0];
    out.extend_from_slice(code);
    out
}

/// Globals (an empty one is the integer 0) and functions, the first run
/// when loaded.
fn bytecode(globals: &[&[u8]], funs: &[Vec<u8>]) -> Vec<u8> {
    let mut g = Vec::new();
    for s in globals {
        if s.is_empty() {
            g.extend(0u32.to_le_bytes());
            continue;
        }
        g.extend(((s.len() as u32) << 2 | 1).to_le_bytes());
        g.extend_from_slice(s);
    }
    let mut bc = (g.len() as u32 + 4).to_le_bytes().to_vec();
    bc.extend(g);
    let mut code: Vec<u8> = Vec::new();
    let mut starts = Vec::new();
    for f in funs {
        starts.push(code.len() as u32);
        code.extend(f);
    }
    bc.extend((code.len() as u32).to_le_bytes());
    bc.extend(code);
    bc.extend((funs.len() as u16).to_le_bytes());
    for s in starts {
        bc.extend(s.to_le_bytes());
    }
    bc
}

const CHUNK: i32 = 300;

/// `stream` played from the callback: `CHUNK` bytes every other call
/// (the calls between give nothing), and every other time it gives,
/// the codec fills up (DREQ falls) before it returns; with `eof` the
/// end is said once it is all in.
fn player(stream: &[u8], eof: bool) -> Vec<u8> {
    let mut main = int(1);
    main.extend(int(1));
    main.extend([PLAYSTART as u8, DROP as u8, NIL_ as u8, RET as u8]);
    let mut cb = int(2);
    cb.extend([GETGLOBALB as u8, 2]);
    cb.extend(int(1));
    cb.extend([ADD as u8, SETGLOBAL as u8]);
    cb.extend(int(1));
    cb.extend([AND as u8, ELSE as u8, 0, 0]);
    let to_skip = cb.len() - 2;
    cb.extend(int(1));
    cb.extend([GETGLOBALB as u8, 0, GETGLOBALB as u8, 1]);
    cb.extend(int(CHUNK));
    cb.extend([
        PLAYFEED as u8,
        GETGLOBALB as u8,
        1,
        ADD as u8,
        SETGLOBAL as u8,
        DROP as u8,
    ]);
    // Calls 3, 7, 11...: the codec fills up meanwhile.
    cb.extend([GETGLOBALB as u8, 2]);
    cb.extend(int(2));
    cb.extend([AND as u8, ELSE as u8, 0, 0]);
    let to_full = cb.len() - 2;
    cb.extend(int(0x0F));
    cb.extend(int(1));
    cb.extend([SNDWRITE as u8, DROP as u8]);
    let at = cb.len() as u16;
    cb[to_full..to_full + 2].copy_from_slice(&at.to_le_bytes());
    if eof {
        cb.extend([GETGLOBALB as u8, 1]);
        cb.extend(int(stream.len() as i32));
        cb.extend([SUB as u8, ELSE as u8, 0, 0]);
        let to_eof = cb.len() - 2;
        cb.extend([GOTO as u8, 0, 0]);
        let to_end = cb.len() - 2;
        let at = cb.len() as u16;
        cb[to_eof..to_eof + 2].copy_from_slice(&at.to_le_bytes());
        cb.extend([
            NIL_ as u8,
            NIL_ as u8,
            NIL_ as u8,
            PLAYFEED as u8,
            DROP as u8,
        ]);
        let at = cb.len() as u16;
        cb[to_end..to_end + 2].copy_from_slice(&at.to_le_bytes());
    }
    let at = cb.len() as u16;
    cb[to_skip..to_skip + 2].copy_from_slice(&at.to_le_bytes());
    cb.extend([NIL_ as u8, RET as u8]);
    let spare = [0u8; 4];
    bytecode(
        &[stream, &[], &[], &spare, &spare, &spare, &spare],
        &[fun(0, &main), fun(1, &cb)],
    )
}

fn play(stream: &[u8], eof: bool, turns: usize) -> Codec {
    let mut mem: Box<Memory> = unsafe {
        let layout = std::alloc::Layout::new::<Memory>();
        Box::from_raw(std::alloc::alloc_zeroed(layout) as *mut Memory)
    };
    let mut vm = Vm::new(
        Codec {
            room: FIFO,
            ..Codec::default()
        },
        &mut mem,
    );
    vm.boot(&player(stream, eof));
    for _ in 0..turns {
        vm.main_loop_once();
    }
    vm.into_host()
}

fn stream(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 + 1).collect()
}

/// The C writes the byte it took from the ring after the refill even if
/// the refill's collection filled the codec meanwhile (DREQ fell): the
/// VS1003 has room for it. Dropped, as lapin did, one byte lost swaps
/// every 16-bit sample after it (A14). It is held and goes next.
#[test]
fn no_byte_is_lost_when_the_refill_fills_the_codec() {
    let s = stream(30 * CHUNK as usize);
    let codec = play(&s, false, 400);
    assert!(
        codec.played.len() > s.len() / 2,
        "{} played",
        codec.played.len()
    );
    let n = codec.played.len().min(s.len());
    let wrong = (0..n).find(|&i| codec.played[i] != s[i]);
    assert_eq!(wrong, None, "{} bytes played", codec.played.len());
}

/// At the end of a stream (playFeed nil), 2048 zeros follow it so the
/// VS1003 plays its last frames (data sheet 9.3), then the amplifier
/// goes off; the C sent nothing and left it on (B40).
#[test]
fn the_end_of_a_stream_is_flushed_then_the_amplifier_goes_off() {
    let s = stream(4 * CHUNK as usize);
    let codec = play(&s, true, 400);
    assert_eq!(codec.played[..s.len()], s[..]);
    let tail = &codec.played[s.len()..];
    assert_eq!(tail.len(), 2048);
    assert!(tail.iter().all(|b| *b == 0));
    assert!(!codec.amplifier);
}

/// recVol from a negative start: the C reads the 256 bytes before the
/// string (B38); 0 here, as from a start too close to its end.
#[test]
fn rec_vol_from_a_negative_start_is_0() {
    let block = [0x77u8; 512];
    let mut main = Vec::new();
    for start in [-256, -1, 0, 300] {
        main.extend([GETGLOBALB as u8, 0]);
        main.extend(int(start));
        main.extend([RECVOL as u8, IECHOLN as u8, DROP as u8]);
    }
    main.extend([NIL_ as u8, RET as u8]);
    let mut mem: Box<Memory> = unsafe {
        let layout = std::alloc::Layout::new::<Memory>();
        Box::from_raw(std::alloc::alloc_zeroed(layout) as *mut Memory)
    };
    let mut vm = Vm::new(Codec::default(), &mut mem);
    vm.boot(&bytecode(&[&block], &[fun(0, &main)]));
    let console = String::from_utf8(vm.into_host().console).unwrap();
    let values: Vec<&str> = console.lines().collect();
    assert_eq!(values[0], "0");
    assert_eq!(values[1], "0");
    assert_ne!(values[2], "0", "a real block is loud");
    assert_eq!(values[3], "0");
}
