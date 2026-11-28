//! The VLSI VS1003 audio codec: an MP3/WAV/MIDI decoder fed over SPI,
//! and an ADPCM recorder behind the microphone.
//!
//! The model walks the stream as the chip's decoder does: WAV data at
//! its byte rate, MP3 frame after frame at each frame's own duration
//! (variable bit rates included), a format 0 MIDI file event after
//! event at its tempo; anything it does not recognise is skipped at
//! once. That is what makes the input buffer drain, DREQ rise, and a
//! sound last its duration. SCI_HDAT0/1, SCI_DECODE_TIME and SCI_AUDATA
//! read as the data sheet (version 1.10) says. The microphone comes out
//! as IMA ADPCM exactly as the chip delivers it.
//!
//! No MP3 is decoded to samples (a browser does that); MIDI is rendered
//! with a plain synthesiser so that it can be heard, its timing exact,
//! its timbre not the chip's 36 instruments.

use std::collections::VecDeque;

const REG_MODE: usize = 0;
const REG_DECODE_TIME: usize = 4;
const REG_AUDATA: usize = 5;
const REG_HDAT0: usize = 8;
const REG_HDAT1: usize = 9;
const REG_VOLUME: usize = 11;
const REG_AICTRL0: usize = 12;
const REG_AICTRL1: usize = 13;

const SM_RESET: u16 = 0x0004;
const SM_OUTOFWAV: u16 = 0x0008;
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
    /// A MIDI track rendered as it played: 16-bit mono at [`PCM_RATE`].
    pub pcm: Vec<i16>,
}

/// Sample rate of the rendered MIDI.
pub const PCM_RATE: u32 = 22050;

/// What the decoder is doing with the stream.
#[derive(Debug, Clone)]
enum Play {
    /// Not enough bytes yet to tell what the stream is.
    Detect,
    /// PCM or ADPCM samples at `byte_rate`.
    Wav {
        byte_rate: u32,
        credit: u32,
    },
    /// MPEG layer III: the next frame is decoded at `due_us`.
    Mp3 {
        due_us: u64,
    },
    Midi(Box<Midi>),
    /// Not something the decoder plays: skipped as it arrives.
    Skip,
}

/// A format 0 standard MIDI file being played.
#[derive(Debug, Clone, Default)]
struct Midi {
    /// Ticks per quarter note.
    division: u32,
    /// Microseconds per quarter note.
    tempo: u32,
    /// Bytes of the track chunk still to come.
    track_left: usize,
    running: u8,
    /// Time of the next event, when its delta time has been read.
    due_us: Option<u64>,
    voices: Vec<Voice>,
    /// Program and volume (0..127) of each channel.
    programs: [u8; 16],
    volumes: [u8; 16],
    sample_credit: u64,
    noise: u32,
    /// Time of the last event taken.
    last: Option<u64>,
}

#[derive(Debug, Clone)]
struct Voice {
    channel: u8,
    note: u8,
    velocity: u8,
    phase: f64,
    age: u32,
    released: Option<u32>,
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
    /// Underruns in the middle of a stream: when the decoder ran out of
    /// bytes it was due to play, and for how long (ms) until the next
    /// came. Running dry at the end of a stream is not one.
    pub gaps: Vec<(u64, u64)>,
    /// Since when the decoder has been waiting for bytes it was due.
    dry_since: Option<u64>,
    play: Play,
    /// Playback time of the current stream, in µs.
    clock_us: u64,
    /// Samples decoded, and their rate, for SCI_DECODE_TIME.
    decoded: u64,
    rate: u32,
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
            gaps: Vec::new(),
            dry_since: None,
            play: Play::Detect,
            clock_us: 0,
            decoded: 0,
            rate: 0,
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
        self.dry_since = None;
        self.play = Play::Detect;
        self.clock_us = 0;
        self.decoded = 0;
        self.rate = 0;
        // HDAT0/1 are cleared by a reset, and the decode time.
        self.registers[REG_DECODE_TIME] = 0;
        self.registers[REG_HDAT0] = 0;
        self.registers[REG_HDAT1] = 0;
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
            REG_HDAT0 => match &self.play {
                // MIDI: the current polyphony.
                Play::Midi(m) => m.voices.iter().filter(|v| v.released.is_none()).count() as u16,
                _ => self.registers[reg],
            },
            _ => self.registers[reg],
        }
    }

    fn write_register(&mut self, reg: usize, value: u16) {
        self.registers[reg] = value;
        if reg == REG_MODE && value & SM_OUTOFWAV != 0 && !matches!(self.play, Play::Mp3 { .. }) {
            // Stop a WAV or MIDI stream: what follows is skipped, the
            // bit clears itself, and HDAT1 with it.
            self.end_stream();
            self.play = Play::Skip;
            self.registers[REG_MODE] &= !SM_OUTOFWAV;
        }
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
            pcm: Vec::new(),
        });
        track.data.push(byte);
        if let Some(since) = self.dry_since.take() {
            self.gaps.push((since, now - since));
        }
        if track.format == Format::Unknown {
            track.format = recognise(&track.data);
        }
        self.buffered = track.data.len() - self.consumed as usize;
        // Headers and skipped bytes go at once.
        self.decode(0);
    }

    /// The decoder ends a WAV or MIDI stream: decode time and HDAT1 go
    /// back to zero.
    fn end_stream(&mut self) {
        self.registers[REG_DECODE_TIME] = 0;
        self.registers[REG_HDAT1] = 0;
        self.registers[REG_HDAT0] = 0;
        self.clock_us = 0;
        self.decoded = 0;
    }

    /// Work through the input buffer up to the playback clock, which has
    /// just moved `elapsed_us`: consume what is due, start what comes.
    fn decode(&mut self, elapsed_us: u64) {
        let Some(mut track) = self.current.take() else {
            return;
        };
        let data = &track.data;
        let mut at = self.consumed as usize;
        let mut play = std::mem::replace(&mut self.play, Play::Skip);
        // The clock only runs while there is something being played.
        if !matches!(play, Play::Detect | Play::Skip) {
            self.clock_us += elapsed_us;
        }
        let mut starved = false;
        loop {
            match &mut play {
                Play::Detect => {
                    let rest = &data[at..];
                    let format = recognise(rest);
                    if !matches!(format, Format::Unknown | Format::Other)
                        && matches!(track.format, Format::Unknown | Format::Other)
                    {
                        track.format = format;
                    }
                    match format {
                        Format::Unknown => break,
                        Format::Wav {
                            sample_rate,
                            channels,
                            bits,
                            adpcm,
                        } => {
                            // The header goes at once, up to the samples.
                            let Some(start) = rest.windows(4).position(|c| c == b"data") else {
                                break;
                            };
                            if rest.len() < start + 8 {
                                break;
                            }
                            at += start + 8;
                            let byte_rate = if adpcm {
                                sample_rate * ADPCM_BLOCK_BYTES as u32 / ADPCM_BLOCK_SAMPLES as u32
                            } else {
                                sample_rate * channels as u32 * bits as u32 / 8
                            };
                            self.registers[REG_HDAT0] = 0x7761;
                            self.registers[REG_HDAT1] = 0x7665;
                            self.registers[REG_AUDATA] =
                                (sample_rate as u16 & !1) | (channels > 1) as u16;
                            self.registers[REG_DECODE_TIME] = 0;
                            self.clock_us = 0;
                            self.decoded = 0;
                            self.rate = byte_rate;
                            play = Play::Wav {
                                byte_rate,
                                credit: 0,
                            };
                        }
                        Format::Mp3 { .. } => {
                            // Up to the first frame header (an ID3 tag
                            // before it is skipped).
                            let first = mp3_sync(rest).unwrap_or(0);
                            at += first;
                            play = Play::Mp3 {
                                due_us: self.clock_us,
                            };
                        }
                        Format::Midi => {
                            if rest.len() < 14 {
                                break;
                            }
                            let format = u16::from_be_bytes([rest[8], rest[9]]);
                            let division = u16::from_be_bytes([rest[12], rest[13]]);
                            if format != 0 || division & 0x8000 != 0 {
                                // Only format 0 with ticks per quarter.
                                play = Play::Skip;
                                continue;
                            }
                            at += 8 + u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]])
                                as usize;
                            self.end_stream();
                            self.registers[REG_HDAT1] = 0x4D54;
                            play = Play::Midi(Box::new(Midi {
                                division: division.max(1) as u32,
                                tempo: 500_000,
                                volumes: [100; 16],
                                noise: 0x1234_5678,
                                ..Midi::default()
                            }));
                        }
                        // Not the start of anything: the decoder looks
                        // further on.
                        Format::Other => at += 1,
                    }
                }
                Play::Skip => {
                    at = data.len();
                    break;
                }
                Play::Wav { byte_rate, credit } => {
                    *credit += (elapsed_us * *byte_rate as u64 / 1000) as u32;
                    let due = (*credit / 1000) as usize;
                    let take = due.min(data.len() - at);
                    if take < due {
                        starved = true;
                    }
                    *credit %= 1000;
                    at += take;
                    self.decoded += take as u64;
                    if self.rate > 0 {
                        self.registers[REG_DECODE_TIME] = (self.decoded / self.rate as u64) as u16;
                    }
                    break;
                }
                Play::Mp3 { due_us } => {
                    let rest = &data[at..];
                    if rest.len() < 4 {
                        starved = *due_us <= self.clock_us;
                        break;
                    }
                    let Some(frame) = mp3_frame(rest) else {
                        // Lost sync: search the next frame header.
                        at += 1;
                        continue;
                    };
                    if rest.len() < frame.len {
                        // Waiting for the rest of the frame: the output
                        // runs dry, playback resumes when it comes.
                        starved = *due_us <= self.clock_us;
                        *due_us = (*due_us).max(self.clock_us);
                        break;
                    }
                    if *due_us > self.clock_us {
                        break;
                    }
                    at += frame.len;
                    *due_us += frame.samples as u64 * 1_000_000 / frame.sample_rate as u64;
                    self.registers[REG_HDAT1] = u16::from_be_bytes([rest[0], rest[1]]);
                    self.registers[REG_HDAT0] = u16::from_be_bytes([rest[2], rest[3]]);
                    self.registers[REG_AUDATA] =
                        (frame.sample_rate as u16 & !1) | frame.stereo as u16;
                    if self.rate != frame.sample_rate {
                        self.decoded =
                            self.decoded * frame.sample_rate as u64 / self.rate.max(1) as u64;
                        self.rate = frame.sample_rate;
                    }
                    self.decoded += frame.samples as u64;
                    self.registers[REG_DECODE_TIME] = (self.decoded / self.rate as u64) as u16;
                }
                Play::Midi(midi) => match midi.step(&data[at..], self.clock_us) {
                    MidiStep::Consumed(n) => at += n,
                    MidiStep::Wait => break,
                    MidiStep::End(n) => {
                        at += n;
                        self.end_stream();
                        play = Play::Detect;
                    }
                },
            }
        }
        if let Play::Midi(midi) = &mut play {
            midi.render(&mut track.pcm, elapsed_us);
            self.registers[REG_DECODE_TIME] = (self.clock_us / 1_000_000) as u16;
        }
        self.play = play;
        self.consumed = at as u64;
        self.buffered = track.data.len() - at;
        self.current = Some(track);
        if starved && elapsed_us > 0 && self.dry_since.is_none() {
            self.dry_since = Some(self.now_ms);
        }
    }

    /// One millisecond passes: the decoder drains its buffer at the
    /// stream's pace, the recorder samples the microphone.
    pub fn tick_ms(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        self.decode(1000);

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
        at = id3_len(data);
    }
    let Some(h) = data.get(at..at + 4) else {
        return if data.len() > 4096 {
            Format::Other
        } else {
            Format::Unknown
        };
    };
    if h[0] == 0xFF && h[1] & 0xE0 == 0xE0 {
        let (kbps, sample_rate) = mpeg_rates(h);
        if kbps != 0 && sample_rate != 0 {
            return Format::Mp3 {
                bitrate: kbps * 1000,
                sample_rate,
            };
        }
    }
    Format::Other
}

/// The length of an ID3 tag at least 10 bytes long, header included.
fn id3_len(data: &[u8]) -> usize {
    10 + data[6..10]
        .iter()
        .fold(0usize, |n, b| n << 7 | (*b & 0x7F) as usize)
}

/// The bit rate in kbit/s and the sample rate in Hz of an MPEG audio
/// frame header, read as layer III; zero for the reserved values.
fn mpeg_rates(h: &[u8]) -> (u32, u32) {
    const KBPS_V1: [u32; 16] = [
        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
    ];
    const KBPS_V2: [u32; 16] = [
        0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0,
    ];
    let version = (h[1] >> 3) & 3;
    let kbps = if version == 3 { KBPS_V1 } else { KBPS_V2 }[(h[2] >> 4) as usize];
    let base = [44100, 48000, 32000, 0][((h[2] >> 2) & 3) as usize];
    let sample_rate = match version {
        3 => base,
        2 => base / 2,
        _ => base / 4,
    };
    (kbps, sample_rate)
}

/// One MPEG layer III frame header, as the decoder needs it.
struct Mp3Frame {
    len: usize,
    samples: u32,
    sample_rate: u32,
    stereo: bool,
}

/// The frame starting here, if it is one the VS1003 decodes: MPEG 1,
/// 2 or 2.5 layer III, not free format.
fn mp3_frame(h: &[u8]) -> Option<Mp3Frame> {
    if h.len() < 4 || h[0] != 0xFF || h[1] & 0xE0 != 0xE0 || h[1] & 0x06 != 0x02 {
        return None;
    }
    let version = (h[1] >> 3) & 3;
    if version == 1 {
        return None;
    }
    let v1 = version == 3;
    let (kbps, sample_rate) = mpeg_rates(h);
    if kbps == 0 || sample_rate == 0 {
        return None;
    }
    let pad = ((h[2] >> 1) & 1) as usize;
    let (samples, coef) = if v1 { (1152, 144) } else { (576, 72) };
    Some(Mp3Frame {
        len: (coef * kbps * 1000 / sample_rate) as usize + pad,
        samples,
        sample_rate,
        stereo: h[3] >> 6 != 3,
    })
}

/// Where the first frame header is, past an ID3 tag.
fn mp3_sync(data: &[u8]) -> Option<usize> {
    let mut at = 0;
    if data.starts_with(b"ID3") && data.len() >= 10 {
        at = id3_len(data);
    }
    (at..data.len()).find(|i| mp3_frame(&data[*i..]).is_some())
}

enum MidiStep {
    /// This many bytes of an event or a chunk header went.
    Consumed(usize),
    /// The next event is not due yet, or not all here.
    Wait,
    /// The end of the track: the stream is over after this many bytes.
    End(usize),
}

/// A variable-length quantity: value and length.
fn varint(data: &[u8]) -> Option<(u32, usize)> {
    let mut v = 0u32;
    for (i, b) in data.iter().enumerate().take(4) {
        v = v << 7 | (*b & 0x7F) as u32;
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

impl Midi {
    /// Take the next event if it is due at `now_us`.
    fn step(&mut self, data: &[u8], now_us: u64) -> MidiStep {
        if self.track_left == 0 {
            // A track chunk header.
            if data.len() < 8 {
                return MidiStep::Wait;
            }
            let len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
            if &data[..4] != b"MTrk" {
                // Another chunk: skipped whole.
                return if data.len() >= 8 + len {
                    MidiStep::Consumed(8 + len)
                } else {
                    MidiStep::Wait
                };
            }
            self.track_left = len;
            return MidiStep::Consumed(8);
        }
        let mut at = 0;
        if self.due_us.is_none() {
            let Some((ticks, n)) = varint(data) else {
                return MidiStep::Wait;
            };
            let us = ticks as u64 * self.tempo as u64 / self.division as u64;
            self.due_us = Some(now_us.max(self.last_us()) + us);
            self.track_left = self.track_left.saturating_sub(n);
            at = n;
            if at > 0 {
                return MidiStep::Consumed(at);
            }
        }
        if self.due_us.is_some_and(|due| due > now_us) {
            return MidiStep::Wait;
        }
        let ev = &data[at..];
        let Some(&first) = ev.first() else {
            return MidiStep::Wait;
        };
        let (status, body) = if first & 0x80 != 0 {
            (first, &ev[1..])
        } else {
            (self.running, ev)
        };
        let header = ev.len() - body.len();
        let len = match status {
            0xFF => {
                let Some(&kind) = body.first() else {
                    return MidiStep::Wait;
                };
                let Some((n, l)) = varint(&body[1..]) else {
                    return MidiStep::Wait;
                };
                let total = 1 + l + n as usize;
                let Some(meta) = body.get(1 + l..total) else {
                    return MidiStep::Wait;
                };
                if kind == 0x51 && meta.len() == 3 {
                    self.tempo = u32::from_be_bytes([0, meta[0], meta[1], meta[2]]).max(1);
                }
                if kind == 0x2F {
                    return MidiStep::End(header + total);
                }
                total
            }
            0xF0 | 0xF7 => {
                let Some((n, l)) = varint(body) else {
                    return MidiStep::Wait;
                };
                if body.len() < l + n as usize {
                    return MidiStep::Wait;
                }
                l + n as usize
            }
            s if s & 0x80 != 0 => {
                let n = if matches!(s & 0xF0, 0xC0 | 0xD0) {
                    1
                } else {
                    2
                };
                let Some(args) = body.get(..n) else {
                    return MidiStep::Wait;
                };
                self.running = s;
                self.event(s, args);
                n
            }
            // Data with no status before it: a broken file, skipped.
            _ => 0,
        };
        self.last = self.due_us;
        self.due_us = None;
        let total = header + len;
        self.track_left = self.track_left.saturating_sub(total);
        MidiStep::Consumed(total.max(1))
    }

    fn last_us(&self) -> u64 {
        self.last.unwrap_or(0)
    }

    fn event(&mut self, status: u8, args: &[u8]) {
        let channel = status & 15;
        match status & 0xF0 {
            0x90 if args[1] > 0 => self.voices.push(Voice {
                channel,
                note: args[0],
                velocity: args[1],
                phase: 0.0,
                age: 0,
                released: None,
            }),
            0x80 | 0x90 => {
                for v in &mut self.voices {
                    if v.channel == channel && v.note == args[0] && v.released.is_none() {
                        v.released = Some(v.age);
                    }
                }
            }
            0xB0 if args[0] == 7 => self.volumes[channel as usize] = args[1],
            // All notes off, all sound off.
            0xB0 if args[0] == 120 || args[0] == 123 => {
                for v in &mut self.voices {
                    if v.channel == channel {
                        v.released.get_or_insert(v.age);
                    }
                }
            }
            0xC0 => self.programs[channel as usize] = args[0],
            _ => {}
        }
        // The chip plays at most 40 notes at once: the oldest go.
        let sounding = self.voices.iter().filter(|v| v.released.is_none()).count();
        if sounding > 40
            && let Some(v) = self.voices.iter_mut().find(|v| v.released.is_none())
        {
            v.released = Some(v.age);
        }
    }

    /// Render `elapsed_us` of sound: a tone per note with a short attack
    /// and a decay, noise for the percussion channel.
    fn render(&mut self, out: &mut Vec<i16>, elapsed_us: u64) {
        self.sample_credit += elapsed_us * PCM_RATE as u64;
        let n = self.sample_credit / 1_000_000;
        self.sample_credit %= 1_000_000;
        let release = PCM_RATE / 20;
        for _ in 0..n {
            let mut mix = 0.0f64;
            for v in &mut self.voices {
                let t = v.age as f64 / PCM_RATE as f64;
                let attack = (t * 200.0).min(1.0);
                let mut level = attack * (-t * 1.5).exp();
                if let Some(at) = v.released {
                    level *= 1.0 - ((v.age - at) as f64 / release as f64).min(1.0);
                }
                let gain = level * v.velocity as f64 / 127.0
                    * self.volumes[v.channel as usize] as f64
                    / 127.0;
                let wave = if v.channel == 9 {
                    self.noise ^= self.noise << 13;
                    self.noise ^= self.noise >> 17;
                    self.noise ^= self.noise << 5;
                    let decay = (-t * 30.0).exp();
                    (self.noise as i32 as f64 / i32::MAX as f64) * decay
                } else {
                    let hz = 440.0 * 2f64.powf((v.note as f64 - 69.0) / 12.0);
                    v.phase = (v.phase + hz / PCM_RATE as f64).fract();
                    let x = v.phase * std::f64::consts::TAU;
                    x.sin() + 0.3 * (2.0 * x).sin() + 0.1 * (3.0 * x).sin()
                };
                mix += wave * gain;
                v.age += 1;
            }
            self.voices
                .retain(|v| v.released.is_none_or(|at| v.age - at < release));
            out.push((mix * 6000.0).clamp(-32768.0, 32767.0) as i16);
        }
    }
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
        // The 44-byte header goes at once; then 8000 Hz, 16 bits:
        // sixteen bytes a millisecond.
        for ms in 0..100 {
            c.tick_ms(ms);
        }
        assert_eq!(c.consumed, 44 + 1600);
        assert!(c.wants_data());
        assert_eq!((read(&mut c, 9), read(&mut c, 8)), (0x7665, 0x7761));
        // 8000 Hz mono.
        assert_eq!(read(&mut c, 5), 8000);
    }

    /// A frame of MPEG 1 layer III, 44100 Hz, at this bit rate index.
    fn mp3_frame_bytes(index: u8) -> Vec<u8> {
        let h = [0xFF, 0xFB, index << 4, 0x44];
        let len = mp3_frame(&h).unwrap().len;
        let mut f = h.to_vec();
        f.resize(len, 0x55);
        f
    }

    #[test]
    fn mp3_frames_go_one_by_one_at_their_own_duration() {
        let mut c = Vs1003::new();
        // A variable bit rate: 128, 320, 32 kbit/s frames, again and again.
        let mut stream = Vec::new();
        for _ in 0..20 {
            for index in [9, 14, 1] {
                stream.extend(mp3_frame_bytes(index));
            }
        }
        let frames: Vec<usize> = (0..60)
            .map(|i| mp3_frame_bytes([9, 14, 1][i % 3]).len())
            .collect();
        assert_eq!(&frames[..3], &[417, 1044, 104]);
        let mut sent = 0;
        let mut ms = 0;
        while sent < stream.len() || c.buffered > 0 {
            while sent < stream.len() && c.wants_data() {
                c.data(stream[sent]);
                sent += 1;
            }
            ms += 1;
            c.tick_ms(ms);
            assert!(ms < 5000);
        }
        // 60 frames of 1152 samples at 44100 Hz: 1567 ms, give or take
        // the first frame taken at once.
        assert!((1540..=1600).contains(&ms), "{ms} ms");
        assert_eq!(read(&mut c, 4), 1, "one full second decoded");
        assert_eq!(read(&mut c, 9), 0xFFFB);
        assert_eq!(read(&mut c, 8) >> 12, 1, "the last frame's bit rate index");
        // 44100 Hz stereo reads 0xAC45, as the data sheet's example.
        assert_eq!(read(&mut c, 5), 0xAC45);
    }

    #[test]
    fn bytes_before_a_stream_are_skipped() {
        let mut c = Vs1003::new();
        for b in [0u8; 100]
            .iter()
            .chain(&mp3_frame_bytes(9))
            .chain(&mp3_frame_bytes(9))
        {
            c.data(*b);
        }
        // The zeros and the first frame are gone; the second waits its turn.
        assert_eq!(c.consumed, 100 + 417);
        assert_eq!(c.buffered, 417);
        assert_eq!(
            c.current.as_ref().unwrap().format,
            Format::Mp3 {
                bitrate: 128_000,
                sample_rate: 44100
            }
        );
    }

    /// A format 0 MIDI file: tempo 120 (500 ms a quarter), 96 ticks a
    /// quarter, a chord of two notes for a quarter, a pause, one note.
    fn midi_file() -> Vec<u8> {
        let mut track = vec![
            0x00, 0xFF, 0x51, 0x03, 0x07, 0xA1, 0x20, // tempo 500000
            0x00, 0x90, 60, 100, // C4 on
            0x00, 64, 100, // E4 on, running status
            96, 0x80, 60, 0, // a quarter later, C4 off
            0x00, 0x90, 64, 0, // E4 off as note on with velocity 0
            96, 0x99, 38, 120, // a quarter later, snare on channel 10
            48, 0x89, 38, 0, 0x00, 0xFF, 0x2F, 0x00,
        ];
        let mut f = b"MThd\0\0\0\x06\0\0\0\x01\0\x60MTrk".to_vec();
        f.extend_from_slice(&(track.len() as u32).to_be_bytes());
        f.append(&mut track);
        f
    }

    #[test]
    fn a_midi_file_goes_at_its_tempo() {
        let mut c = Vs1003::new();
        for b in midi_file() {
            c.data(b);
        }
        assert_eq!(read(&mut c, 9), 0x4D54);
        assert_eq!(read(&mut c, 8), 2, "two notes sounding");
        let mut ms = 0;
        while c.buffered > 0 {
            ms += 1;
            c.tick_ms(ms);
            if ms == 600 {
                assert_eq!(read(&mut c, 8), 0, "both notes off after a quarter");
            }
            assert!(ms < 5000);
        }
        // Two quarters and an eighth: 1250 ms.
        assert_eq!(ms, 1250);
        // The track ended: decode time and HDAT1 back to zero.
        assert_eq!(read(&mut c, 4), 0);
        assert_eq!(read(&mut c, 9), 0);
        // And it was rendered, as long as it lasted.
        let pcm = &c.current.as_ref().unwrap().pcm;
        assert!(
            (pcm.len() as i64 - 1250 * 22050 / 1000).abs() < 50,
            "{}",
            pcm.len()
        );
        assert!(
            pcm[..5000].iter().any(|s| s.abs() > 1000),
            "the chord is heard"
        );
    }

    #[test]
    fn out_of_wav_stops_a_stream() {
        let mut c = Vs1003::new();
        for b in wav_header(8000) {
            c.data(b);
        }
        for _ in 0..1000 {
            c.data(0);
        }
        write(&mut c, 0, 0x0808);
        assert_eq!(read(&mut c, 0), 0x0800, "SM_OUTOFWAV clears itself");
        assert_eq!(read(&mut c, 9), 0);
        c.data(0);
        assert_eq!(c.buffered, 0, "what follows is not played");
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
