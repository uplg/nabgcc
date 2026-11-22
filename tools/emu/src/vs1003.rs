//! The VLSI VS1003 audio codec: an MP3/WAV/MIDI decoder fed over SPI,
//! and an ADPCM recorder behind the microphone.
//!
//! The model does not decode sound. It keeps what matters to the
//! firmware and to whoever listens: the stream that was sent, split
//! into tracks; the input buffer filling up and draining at the pace
//! of the stream, which is what makes a sound last its duration; the
//! microphone encoded as IMA ADPCM exactly as the chip delivers it.

use std::collections::VecDeque;

const REG_MODE: usize = 0;
const REG_DECODE_TIME: usize = 4;
const REG_HDAT0: usize = 8;
const REG_HDAT1: usize = 9;
const REG_VOLUME: usize = 11;
const REG_AICTRL0: usize = 12;
const REG_AICTRL1: usize = 13;

const SM_RESET: u16 = 0x0004;
const SM_ADPCM: u16 = 0x1000;

/// Size of the decoder's input buffer; the chip stops asking for data
/// when fewer than 32 bytes are free.
const FIFO_BYTES: usize = 2048;
const FIFO_MARGIN: usize = 32;
/// Words the recorder can hold before it starts losing them.
const RECORD_WORDS: usize = 1024;
/// Samples in one ADPCM block: one in the header, 504 as nibbles.
pub const ADPCM_BLOCK_SAMPLES: usize = 505;
pub const ADPCM_BLOCK_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Not enough of the stream seen yet.
    Unknown,
    Wav {
        sample_rate: u32,
        channels: u16,
        bits: u16,
        adpcm: bool,
    },
    Mp3 {
        bitrate: u32,
        sample_rate: u32,
    },
    Midi,
    /// Something else; drained at a nominal 32 kbit/s.
    Other,
}

/// One stretch of audio, from a decoder reset to the next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Track {
    pub data: Vec<u8>,
    pub format: Format,
    /// Board time when its first byte arrived, in ms.
    pub started_ms: u64,
}

pub struct Vs1003 {
    pub registers: [u16; 16],
    /// Finished tracks, oldest first.
    pub tracks: Vec<Track>,
    /// The track being played, if any byte arrived since the last reset.
    pub current: Option<Track>,
    /// Microphone signal waiting to be recorded: 16-bit samples at the
    /// recorder's rate. When it runs dry the microphone hears silence.
    pub microphone: VecDeque<i16>,
    /// Bytes waiting in the decoder's input buffer.
    pub buffered: usize,
    /// Bytes the decoder has consumed from the current track.
    pub consumed: u64,
    /// Words dropped because nobody read the recorder in time.
    pub record_overruns: u64,
    byte_rate: u32,
    drain_credit: u32,
    recording: bool,
    record_credit: u32,
    block: Vec<i16>,
    encoder: Adpcm,
    recorded: VecDeque<u16>,
    sci: Vec<u8>,
    reply: u8,
    now_ms: u64,
}

impl Default for Vs1003 {
    fn default() -> Self {
        Self::new()
    }
}

impl Vs1003 {
    pub fn new() -> Self {
        Vs1003 {
            registers: [0; 16],
            tracks: Vec::new(),
            current: None,
            microphone: VecDeque::new(),
            buffered: 0,
            consumed: 0,
            record_overruns: 0,
            byte_rate: 0,
            drain_credit: 0,
            recording: false,
            record_credit: 0,
            block: Vec::new(),
            encoder: Adpcm::default(),
            recorded: VecDeque::new(),
            sci: Vec::new(),
            reply: 0,
            now_ms: 0,
        }
    }

    /// Hardware reset: registers and buffers, not the tracks heard.
    pub fn reset(&mut self) {
        self.registers = [0; 16];
        self.software_reset();
        self.recording = false;
        self.sci.clear();
    }

    fn software_reset(&mut self) {
        if let Some(track) = self.current.take() {
            self.tracks.push(track);
        }
        self.buffered = 0;
        self.consumed = 0;
        self.byte_rate = 0;
        self.drain_credit = 0;
        self.registers[REG_DECODE_TIME] = 0;
        self.recorded.clear();
        self.block.clear();
        self.encoder = Adpcm::default();
        self.record_credit = 0;
    }

    /// The data request pin: high when the chip can take more.
    pub fn wants_data(&self) -> bool {
        FIFO_BYTES - self.buffered >= FIFO_MARGIN
    }

    /// Output attenuation of the left channel in half decibels: 0 is
    /// full volume, 254 and above silence.
    pub fn attenuation(&self) -> u8 {
        (self.registers[REG_VOLUME] >> 8) as u8
    }

    /// Every track heard so far, the current one included.
    pub fn all_tracks(&self) -> Vec<&Track> {
        self.tracks.iter().chain(&self.current).collect()
    }

    /// A byte on the control interface: command, register, two data bytes.
    pub fn control(&mut self, byte: u8) {
        self.reply = 0;
        self.sci.push(byte);
        let reg = self.sci.get(1).map_or(0, |r| (*r & 15) as usize);
        match (self.sci[0], self.sci.len()) {
            (3, 3) => {
                let value = self.read_register(reg);
                self.registers[reg] = value;
                self.reply = (value >> 8) as u8;
            }
            (3, 4) => self.reply = self.registers[reg] as u8,
            (2, 4) => {
                let value = (self.sci[2] as u16) << 8 | self.sci[3] as u16;
                self.write_register(reg, value);
            }
            _ => {}
        }
    }

    /// The control chip select was released.
    pub fn control_done(&mut self) {
        self.sci.clear();
    }

    /// What the last control byte brought back.
    pub fn reply(&self) -> u8 {
        self.reply
    }

    fn read_register(&mut self, reg: usize) -> u16 {
        match reg {
            REG_HDAT1 if self.recording => self.recorded.len() as u16,
            REG_HDAT0 if self.recording => self.recorded.pop_front().unwrap_or(0),
            // While decoding, the two words identify the format.
            REG_HDAT1 => match self.current.as_ref().map(|t| t.format) {
                Some(Format::Wav { .. }) => 0x7665,
                Some(Format::Midi) => 0x4D54,
                Some(Format::Mp3 { .. }) => 0xFFFA,
                _ => 0,
            },
            REG_DECODE_TIME if self.byte_rate > 0 => (self.consumed / self.byte_rate as u64) as u16,
            _ => self.registers[reg],
        }
    }

    fn write_register(&mut self, reg: usize, value: u16) {
        self.registers[reg] = value;
        if reg == REG_MODE {
            self.recording = value & SM_ADPCM != 0;
            if value & SM_RESET != 0 {
                self.software_reset();
                // The reset bit clears itself.
                self.registers[REG_MODE] = value & !SM_RESET;
            }
        }
    }

    /// A byte on the data interface: the stream to decode.
    pub fn data(&mut self, byte: u8) {
        let now = self.now_ms;
        let track = self.current.get_or_insert_with(|| Track {
            data: Vec::new(),
            format: Format::Unknown,
            started_ms: now,
        });
        track.data.push(byte);
        self.buffered = (self.buffered + 1).min(FIFO_BYTES);
        if track.format == Format::Unknown {
            track.format = recognise(&track.data);
            self.byte_rate = match track.format {
                Format::Unknown => 0,
                Format::Wav {
                    sample_rate,
                    channels,
                    bits,
                    adpcm: false,
                } => sample_rate * channels as u32 * bits as u32 / 8,
                // 256 bytes carry 505 samples.
                Format::Wav {
                    sample_rate,
                    adpcm: true,
                    ..
                } => sample_rate * ADPCM_BLOCK_BYTES as u32 / ADPCM_BLOCK_SAMPLES as u32,
                Format::Mp3 { bitrate, .. } => bitrate / 8,
                // A MIDI file is tiny next to the time it lasts: an
                // arbitrary slow pace stands for it.
                Format::Midi => 1000,
                Format::Other => 4000,
            };
        }
    }

    /// One millisecond passes: the decoder drains its buffer at the
    /// stream's pace, the recorder samples the microphone.
    pub fn tick_ms(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        self.drain_credit += self.byte_rate;
        let drained = ((self.drain_credit / 1000) as usize).min(self.buffered);
        self.drain_credit %= 1000;
        self.buffered -= drained;
        self.consumed += drained as u64;

        if !self.recording {
            return;
        }
        // The divider register sets the rate: 192000 / divider hertz.
        let rate = 192_000 / self.registers[REG_AICTRL0].max(1) as u32;
        // Gain is in 1/1024ths; zero asks for automatic gain, taken as 1.
        let gain = match self.registers[REG_AICTRL1] {
            0 => 1024,
            g => g as i32,
        };
        self.record_credit += rate;
        for _ in 0..self.record_credit / 1000 {
            let sample = self.microphone.pop_front().unwrap_or(0) as i32 * gain / 1024;
            self.block.push(sample.clamp(-32768, 32767) as i16);
            if self.block.len() == ADPCM_BLOCK_SAMPLES {
                let bytes = self.encoder.encode_block(&std::mem::take(&mut self.block));
                for pair in bytes.chunks(2) {
                    if self.recorded.len() < RECORD_WORDS {
                        self.recorded
                            .push_back((pair[0] as u16) << 8 | pair[1] as u16);
                    } else {
                        self.record_overruns += 1;
                    }
                }
            }
        }
        self.record_credit %= 1000;
    }
}

/// Tell what a stream is from its first bytes.
fn recognise(data: &[u8]) -> Format {
    if data.len() < 4 {
        return Format::Unknown;
    }
    if &data[..4] == b"RIFF" {
        if data.len() < 36 {
            return Format::Unknown;
        }
        let u16_at = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]);
        let sample_rate = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        return Format::Wav {
            sample_rate,
            channels: u16_at(22),
            bits: u16_at(34),
            adpcm: u16_at(20) == 0x11,
        };
    }
    if &data[..4] == b"MThd" {
        return Format::Midi;
    }
    // MPEG audio frame header, possibly after an ID3 tag.
    let mut at = 0;
    if &data[..3] == b"ID3" {
        if data.len() < 10 {
            return Format::Unknown;
        }
        at = 10
            + data[6..10]
                .iter()
                .fold(0usize, |n, b| n << 7 | (*b & 0x7F) as usize);
    }
    let Some(h) = data.get(at..at + 4) else {
        return if data.len() > 4096 {
            Format::Other
        } else {
            Format::Unknown
        };
    };
    if h[0] == 0xFF && h[1] & 0xE0 == 0xE0 {
        const KBPS_V1_L3: [u32; 16] = [
            0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
        ];
        const KBPS_V2_L3: [u32; 16] = [
            0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0,
        ];
        let v1 = h[1] & 0x18 == 0x18;
        let kbps = if v1 { KBPS_V1_L3 } else { KBPS_V2_L3 }[(h[2] >> 4) as usize];
        let base = [44100, 48000, 32000, 0][((h[2] >> 2) & 3) as usize];
        let sample_rate = match h[1] & 0x18 {
            0x18 => base,
            0x10 => base / 2,
            _ => base / 4,
        };
        if kbps != 0 && sample_rate != 0 {
            return Format::Mp3 {
                bitrate: kbps * 1000,
                sample_rate,
            };
        }
    }
    Format::Other
}

const STEPS: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449,
    494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272,
    2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493,
    10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];
const INDEX_MOVES: [i32; 8] = [-1, -1, -1, -1, 2, 4, 6, 8];

/// IMA ADPCM state: the predicted sample and the step index.
#[derive(Debug, Clone, Copy, Default)]
pub struct Adpcm {
    predicted: i32,
    index: i32,
}

impl Adpcm {
    /// Move the state by one 4-bit code, as both ends do.
    fn step(&mut self, code: u8) -> i16 {
        let step = STEPS[self.index as usize];
        let mut diff = step >> 3;
        if code & 4 != 0 {
            diff += step;
        }
        if code & 2 != 0 {
            diff += step >> 1;
        }
        if code & 1 != 0 {
            diff += step >> 2;
        }
        self.predicted =
            (self.predicted + if code & 8 != 0 { -diff } else { diff }).clamp(-32768, 32767);
        self.index = (self.index + INDEX_MOVES[(code & 7) as usize]).clamp(0, 88);
        self.predicted as i16
    }

    fn encode(&mut self, sample: i16) -> u8 {
        let step = STEPS[self.index as usize];
        let mut diff = sample as i32 - self.predicted;
        let mut code = 0u8;
        if diff < 0 {
            code = 8;
            diff = -diff;
        }
        if diff >= step {
            code |= 4;
            diff -= step;
        }
        if diff >= step >> 1 {
            code |= 2;
            diff -= step >> 1;
        }
        if diff >= step >> 2 {
            code |= 1;
        }
        self.step(code);
        code
    }

    /// Encode 505 samples into a 256-byte block: the first sample and
    /// the step index in clear, then one nibble per sample.
    pub fn encode_block(&mut self, samples: &[i16]) -> Vec<u8> {
        self.predicted = samples[0] as i32;
        let mut out = samples[0].to_le_bytes().to_vec();
        out.extend_from_slice(&[self.index as u8, 0]);
        for pair in samples[1..].chunks(2) {
            let low = self.encode(pair[0]);
            let high = pair.get(1).map_or(0, |s| self.encode(*s));
            out.push(low | high << 4);
        }
        out
    }
}

/// Decode ADPCM blocks back to samples.
pub fn adpcm_decode(blocks: &[u8]) -> Vec<i16> {
    let mut out = Vec::new();
    for block in blocks.chunks(ADPCM_BLOCK_BYTES) {
        if block.len() < 4 {
            break;
        }
        let first = i16::from_le_bytes([block[0], block[1]]);
        let mut state = Adpcm {
            predicted: first as i32,
            index: (block[2] as i32).clamp(0, 88),
        };
        out.push(first);
        for byte in &block[4..] {
            out.push(state.step(byte & 15));
            out.push(state.step(byte >> 4));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(c: &mut Vs1003, reg: u8, value: u16) {
        for b in [2, reg, (value >> 8) as u8, value as u8] {
            c.control(b);
        }
        c.control_done();
    }

    fn read(c: &mut Vs1003, reg: u8) -> u16 {
        c.control(3);
        c.control(reg);
        c.control(0);
        let hi = c.reply();
        c.control(0);
        let lo = c.reply();
        c.control_done();
        (hi as u16) << 8 | lo as u16
    }

    fn wav_header(rate: u32) -> Vec<u8> {
        let mut h = b"RIFF\0\0\0\0WAVEfmt \x10\0\0\0\x01\0\x01\0".to_vec();
        h.extend_from_slice(&rate.to_le_bytes());
        h.extend_from_slice(&(rate * 2).to_le_bytes());
        h.extend_from_slice(&[2, 0, 16, 0]);
        h.extend_from_slice(b"data\0\0\0\0");
        h
    }

    #[test]
    fn registers_read_back() {
        let mut c = Vs1003::new();
        write(&mut c, 11, 0x1234);
        assert_eq!(read(&mut c, 11), 0x1234);
        assert_eq!(c.attenuation(), 0x12);
    }

    #[test]
    fn a_wav_stream_drains_at_its_own_pace() {
        let mut c = Vs1003::new();
        for b in wav_header(8000) {
            c.data(b);
        }
        assert_eq!(
            c.current.as_ref().unwrap().format,
            Format::Wav {
                sample_rate: 8000,
                channels: 1,
                bits: 16,
                adpcm: false
            }
        );
        // The buffer fills up, and the chip stops asking.
        while c.wants_data() {
            c.data(0);
        }
        assert_eq!(c.buffered, FIFO_BYTES - FIFO_MARGIN + 1);
        // 8000 Hz, 16 bits: sixteen bytes a millisecond.
        for ms in 0..100 {
            c.tick_ms(ms);
        }
        assert_eq!(c.consumed, 1600);
        assert!(c.wants_data());
        assert_eq!(read(&mut c, 9), 0x7665);
    }

    #[test]
    fn a_reset_closes_the_track() {
        let mut c = Vs1003::new();
        for b in b"MThd\0\0\0\x06" {
            c.data(*b);
        }
        write(&mut c, 0, 0x0804);
        assert_eq!(c.tracks.len(), 1);
        assert_eq!(c.tracks[0].format, Format::Midi);
        assert_eq!(c.buffered, 0);
        assert_eq!(read(&mut c, 0), 0x0800, "the reset bit clears itself");
    }

    #[test]
    fn mp3_headers_give_the_bitrate() {
        assert_eq!(
            recognise(&[0xFF, 0xFB, 0x90, 0x00]),
            Format::Mp3 {
                bitrate: 128_000,
                sample_rate: 44100
            }
        );
        // MPEG-2 layer 3, 32 kbit/s, 22050 Hz, behind an empty ID3 tag.
        let mut tagged = b"ID3\x03\0\0\0\0\0\0".to_vec();
        tagged.extend_from_slice(&[0xFF, 0xF3, 0x40, 0x00]);
        assert_eq!(
            recognise(&tagged),
            Format::Mp3 {
                bitrate: 32_000,
                sample_rate: 22050
            }
        );
    }

    #[test]
    fn the_microphone_comes_out_as_adpcm_blocks() {
        let mut c = Vs1003::new();
        write(&mut c, 12, 24);
        write(&mut c, 13, 1024);
        write(&mut c, 0, 0x1804);
        // A second of a 440 Hz tone at 8000 Hz.
        let tone: Vec<i16> = (0..8000)
            .map(|i| (8000.0 * (i as f64 * 440.0 * std::f64::consts::TAU / 8000.0).sin()) as i16)
            .collect();
        c.microphone.extend(&tone);
        let mut bytes = Vec::new();
        for ms in 0..1000 {
            c.tick_ms(ms);
            while read(&mut c, 9) >= 128 {
                for _ in 0..128 {
                    bytes.extend_from_slice(&read(&mut c, 8).to_be_bytes());
                }
            }
        }
        assert_eq!(
            bytes.len(),
            15 * ADPCM_BLOCK_BYTES,
            "fifteen whole blocks in a second"
        );
        assert_eq!(c.record_overruns, 0);
        let decoded = adpcm_decode(&bytes);
        let worst = decoded
            .iter()
            .zip(&tone)
            .skip(50)
            .map(|(a, b)| (*a as i32 - *b as i32).abs())
            .max()
            .unwrap();
        assert!(worst < 800, "decoded tone strays by {worst}");
    }
}
