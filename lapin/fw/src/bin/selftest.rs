//! Exercises every driver of the board in turn and reports on the
//! serial port: the ears, the tag reader, the flash, the loudspeaker,
//! the microphone. The emulator's tests check each answer.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;

use lapin_fw::ears::Turn;
use lapin_fw::{
    board, clock, codec, ears, flash, halt, i2c, irq, led, rfid, spi, timer, uart, watchdog,
};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    uart::write(b"PANIC\n");
    halt()
}

fn hex(bytes: &[u8]) {
    for byte in bytes {
        for nibble in [byte >> 4, byte & 15] {
            uart::write(&[b"0123456789abcdef"[nibble as usize]]);
        }
    }
}

fn number(mut n: u32) {
    let mut digits = [0u8; 10];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    uart::write(&digits[at..]);
}

/// Turn an ear until its reference gap has gone by twice, and count
/// the teeth in between. 0 if that does not happen in fifteen seconds.
fn teeth_per_turn(ear: usize) -> u16 {
    ears::turn(ear, Turn::Forward);
    let start = timer::millis();
    let mut last = ears::teeth(ear);
    let mut last_at = start;
    let mut reference: Option<u16> = None;
    let mut result = 0;
    while timer::millis().wrapping_sub(start) < 15_000 {
        watchdog::feed();
        let now = ears::teeth(ear);
        if now == last {
            continue;
        }
        let waited = timer::millis().wrapping_sub(last_at);
        last = now;
        last_at = timer::millis();
        // A long wait between two teeth: the gap just went by.
        if waited > 600 {
            match reference {
                Some(at) => {
                    result = now.wrapping_sub(at);
                    break;
                }
                None => reference = Some(now),
            }
        }
    }
    ears::turn(ear, Turn::Stop);
    result
}

/// One period of a 500 Hz note sampled at 8000 Hz.
const NOTE: [i16; 16] = [
    0, 4592, 8485, 11087, 12000, 11087, 8485, 4592, 0, -4592, -8485, -11087, -12000, -11087, -8485,
    -4592,
];

/// Send a whole stream to the decoder, at the pace it takes it.
fn play(stream: &[u8]) {
    let mut sent = 0;
    while sent < stream.len() {
        watchdog::feed();
        sent += codec::feed(&stream[sent..]);
    }
}

fn wav_header(adpcm: bool, data_len: u32) -> [u8; 48] {
    let mut h = [0u8; 48];
    h[..4].copy_from_slice(b"RIFF");
    h[4..8].copy_from_slice(&(data_len + 40).to_le_bytes());
    h[8..16].copy_from_slice(b"WAVEfmt ");
    h[16] = 20;
    // Format, one channel, 8000 Hz.
    h[20] = if adpcm { 0x11 } else { 1 };
    h[22] = 1;
    h[24..28].copy_from_slice(&8000u32.to_le_bytes());
    let (byte_rate, block, bits): (u32, u16, u16) = if adpcm {
        (4055, 256, 4)
    } else {
        (16000, 2, 16)
    };
    h[28..32].copy_from_slice(&byte_rate.to_le_bytes());
    h[32..34].copy_from_slice(&block.to_le_bytes());
    h[34..36].copy_from_slice(&bits.to_le_bytes());
    // Extension: samples per block.
    h[36] = 2;
    h[38..40].copy_from_slice(&505u16.to_le_bytes());
    h[40..44].copy_from_slice(b"data");
    h[44..48].copy_from_slice(&data_len.to_le_bytes());
    h
}

/// Room for a second of recording, in the external RAM.
struct Tape(UnsafeCell<[u16; 2048]>);
// SAFETY: used by `main` alone.
unsafe impl Sync for Tape {}
#[unsafe(link_section = ".xram.tape")]
static TAPE: Tape = Tape(UnsafeCell::new([0; 2048]));

#[unsafe(no_mangle)]
extern "C" fn main() -> ! {
    lapin_fw::start::link();
    clock::init();
    board::init();
    irq::init();
    watchdog::start();
    timer::init();
    irq::irq_enable();
    spi::init();
    led::init();
    uart::init();
    ears::init();
    i2c::init();
    codec::init();
    uart::write(b"selftest\n");

    uart::write(b"ears ");
    number(teeth_per_turn(0) as u32);
    uart::write(b" ");
    number(teeth_per_turn(1) as u32);
    uart::write(b"\n");

    let mut tags = [rfid::Tag::default(); 4];
    match rfid::scan(&mut tags) {
        Ok(0) => uart::write(b"tag none\n"),
        Ok(_) => {
            let uid = tags[0].uid;
            uart::write(b"tag ");
            hex(&uid);
            uart::write(b"\nblock ");
            match rfid::read_block(&uid, 1) {
                Ok(block) => hex(&block),
                Err(_) => uart::write(b"unreadable"),
            }
            uart::write(if rfid::write_block(&uid, 2, b"lapi").is_ok() {
                b"\nwritten\n"
            } else {
                b"\nnot written\n"
            });
        }
        Err(_) => uart::write(b"tag reader silent\n"),
    }

    flash::write_settings(b"LAPINCFG");
    uart::write(if flash::settings().starts_with(b"LAPINCFG") {
        b"flash ok\n"
    } else {
        b"flash WRONG\n"
    });

    // A second of the note.
    codec::play_start();
    codec::set_volume(0x20);
    play(&wav_header(false, 16000));
    let mut period = [0u8; 32];
    for (bytes, sample) in period.as_chunks_mut::<2>().0.iter_mut().zip(NOTE) {
        *bytes = sample.to_le_bytes();
    }
    for _ in 0..500 {
        play(&period);
    }
    uart::write(b"tone played\n");

    // Listen for a second, then say it back.
    // SAFETY: the only reference to the tape.
    let tape = unsafe { &mut *TAPE.0.get() };
    codec::record_start(8000, 1024);
    let start = timer::millis();
    let mut words = 0;
    while timer::millis().wrapping_sub(start) < 1000 {
        watchdog::feed();
        words += codec::record_read(&mut tape[words..]);
    }
    codec::record_stop();
    uart::write(b"heard ");
    number(words as u32);
    uart::write(b" words\n");

    codec::play_start();
    codec::set_volume(0x20);
    play(&wav_header(true, words as u32 * 2));
    for word in &tape[..words] {
        play(&word.to_be_bytes());
    }
    codec::play_stop();
    uart::write(b"end\n");
    led::set_all(0x00FF00);
    loop {
        watchdog::feed();
    }
}
