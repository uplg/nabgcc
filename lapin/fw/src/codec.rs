//! The VLSI VS1003 audio codec: it decodes what it is fed (MP3, WAV,
//! MIDI) to the loudspeaker, and records the microphone as ADPCM.

use crate::{board, spi, timer, watchdog};

const READ: u8 = 0x03;
const WRITE: u8 = 0x02;

const MODE: u8 = 0x0;
const CLOCK: u8 = 0x3;
const DECODE_TIME: u8 = 0x4;
const WRAM: u8 = 0x6;
const WRAM_ADDRESS: u8 = 0x7;
const HDAT0: u8 = 0x8;
const HDAT1: u8 = 0x9;
const VOLUME: u8 = 0xB;
const AICTRL0: u8 = 0xC;
const AICTRL1: u8 = 0xD;

/// New serial mode, one chip select shared by commands and data.
const MODE_BASE: u16 = 0x0C00;
const MODE_RESET: u16 = 0x0004;
const MODE_RECORD: u16 = 0x3000;

/// Wait for the chip to take more, at most half a second: a codec that
/// never answers (the C waits for ever, feeding the watchdog) leaves a
/// rabbit without sound, not a frozen one.
fn wait_ready() {
    let start = timer::millis();
    while !board::codec_wants_data() && timer::since(start) < 500 {
        watchdog::feed();
    }
}

/// Read one of the chip's control registers.
pub fn read(register: u8) -> u16 {
    wait_ready();
    board::port2_clear(board::AUDIO_CONTROL_SELECT);
    spi::CODEC.transfer(READ);
    spi::CODEC.transfer(register);
    let high = spi::CODEC.transfer(0);
    let low = spi::CODEC.transfer(0);
    board::port2_set(board::AUDIO_CONTROL_SELECT);
    (high as u16) << 8 | low as u16
}

/// Write one of the chip's control registers.
pub fn write(register: u8, value: u16) {
    wait_ready();
    board::port2_clear(board::AUDIO_CONTROL_SELECT);
    spi::CODEC.transfer(WRITE);
    spi::CODEC.transfer(register);
    spi::CODEC.transfer((value >> 8) as u8);
    spi::CODEC.transfer(value as u8);
    board::port2_set(board::AUDIO_CONTROL_SELECT);
}

/// A patch the chip needs to play WMA streams properly, as register
/// writes: (register, value).
const WMA_PATCH: [(u8, u16); 10] = [
    (WRAM_ADDRESS, 0x800E),
    (WRAM, 0x2801),
    (WRAM, 0x3F80),
    (WRAM, 0x0006),
    (WRAM, 0x53D7),
    (WRAM_ADDRESS, 0x84FE),
    (WRAM, 0x2000),
    (WRAM, 0x0000),
    (WRAM, 0x3F05),
    (WRAM, 0xC024),
];

fn patch() {
    for (register, value) in WMA_PATCH {
        write(register, value);
    }
}

/// Empty the chip's buffers and stop whatever it was doing.
pub fn reset() {
    write(MODE, MODE_BASE | MODE_RESET);
}

pub fn init() {
    // The chip only takes a slow clock until its own is multiplied.
    spi::CODEC.set_divider(8);
    board::codec_reset(true);
    timer::delay_ms(1);
    board::codec_reset(false);
    timer::delay_ms(1);
    write(CLOCK, 0xC000);
    spi::CODEC.set_divider(2);
    reset();
    // Silence until somebody asks for sound.
    write(VOLUME, 0xFFFF);
    patch();
}

/// 0 is the loudest, 254 and above silence; the amplifier is switched
/// off with the sound.
pub fn set_volume(attenuation: u8) {
    write(VOLUME, (attenuation as u16) << 8 | attenuation as u16);
    board::amplifier(attenuation < 0x7F);
}

/// Whether the chip takes data now.
pub fn ready() -> bool {
    board::codec_wants_data()
}

pub fn amplifier(on: bool) {
    board::amplifier(on);
}

/// Get ready to play a new stream.
pub fn play_start() {
    reset();
    patch();
    board::amplifier(true);
}

pub fn play_stop() {
    board::amplifier(false);
    reset();
}

/// Feed the decoder as much of `stream` as it takes right now; returns
/// how many bytes went in.
pub fn feed(stream: &[u8]) -> usize {
    let mut sent = 0;
    board::codec_data_select(true);
    while sent < stream.len() && board::codec_wants_data() {
        spi::CODEC.transfer(stream[sent]);
        sent += 1;
    }
    board::codec_data_select(false);
    sent
}

/// Seconds of sound decoded since the stream began.
pub fn decode_time() -> u16 {
    read(DECODE_TIME)
}

/// Start recording the microphone at `rate` hertz; `gain` is in
/// 1/1024ths, 0 for automatic.
pub fn record_start(rate: u16, gain: u16) {
    reset();
    board::amplifier(false);
    write(AICTRL0, (192_000 / rate as u32) as u16);
    write(AICTRL1, gain);
    write(MODE, MODE_BASE | MODE_RECORD | MODE_RESET);
}

pub fn record_stop() {
    reset();
}

/// Take recorded sound: whole blocks of 128 words of IMA ADPCM, as
/// many as fit in `out`. Returns the number of words written.
pub fn record_read(out: &mut [u16]) -> usize {
    let waiting = (read(HDAT1) & 0xFF80) as usize;
    let take = waiting.min(out.len() & !127);
    for word in &mut out[..take] {
        *word = read(HDAT0);
    }
    take
}
