//! The emulator as a WebAssembly module, for a page in a browser.
//!
//! A plain C interface, no generated glue: the page allocates a buffer
//! with `nab_alloc`, copies a firmware file in, calls `nab_new`, then
//! `nab_run` on every animation frame and reads back `nab_state` and
//! `nab_console`. See `web/index.html`.

use std::cell::RefCell;
use std::rc::Rc;

use crate::air::{AccessPoint, Security, Wpa3};
use crate::config::{Config, Wifi};
use crate::lan::{Lan, Response};
use crate::vs1003::{ADPCM_BLOCK_BYTES, Format, PCM_RATE, adpcm_decode};
use crate::{DEFAULT_MAC, Machine};

const SSID: &str = "Terrier";
const PASSPHRASE: &str = "carotte-violette";

pub struct World {
    machine: Machine,
    bytecode: Rc<RefCell<Vec<u8>>>,
    console_seen: usize,
    console: Vec<u8>,
    state: [u8; STATE_LEN],
    audio: Vec<u8>,
    /// Track and offset up to which sound was handed to the page.
    heard: (usize, usize),
}

/// Layout of what `nab_state` points to.
pub const STATE_LEN: usize = 32;

#[unsafe(no_mangle)]
pub extern "C" fn nab_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
}

/// # Safety
/// `ptr` and `len` must come from one `nab_alloc` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_free(ptr: *mut u8, len: usize) {
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
}

/// A rabbit flashed with the given firmware file (ELF, `.sim` or raw).
///
/// # Safety
/// `ptr` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_new(ptr: *const u8, len: usize) -> *mut World {
    let image = unsafe { std::slice::from_raw_parts(ptr, len) };
    let (machine, _) = Machine::from_file(image);
    Box::into_raw(Box::new(World {
        machine,
        bytecode: Rc::new(RefCell::new(Vec::new())),
        console_seen: 0,
        console: Vec::new(),
        state: [0; STATE_LEN],
        audio: Vec::new(),
        heard: (0, 0),
    }))
}

/// # Safety
/// `world` must come from `nab_new` and not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_drop(world: *mut World) {
    drop(unsafe { Box::from_raw(world) });
}

/// Put a network around the rabbit and write matching settings in its
/// flash, then restart it. 0: nothing in range, settings untouched;
/// 1: open network; 2: WPA2; 3: WPA (TKIP); 4: WEP; 5: WPA2/WPA3
/// transition, like most home routers today.
///
/// # Safety
/// `world` must come from `nab_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_network(world: *mut World, kind: u32) {
    let w = unsafe { &mut *world };
    w.machine.air.clear();
    w.machine.lan = None;
    let (wifi, security) = match kind {
        1 => (Wifi::Open, Security::Open),
        2 => (
            Wifi::Wpa2 {
                passphrase: PASSPHRASE.into(),
            },
            Security::wpa2(PASSPHRASE),
        ),
        3 => (
            Wifi::Wpa {
                passphrase: PASSPHRASE.into(),
            },
            Security::wpa(PASSPHRASE),
        ),
        4 => (
            Wifi::Wep {
                key: "abcde".into(),
                shared_auth: false,
            },
            Security::Wep {
                key: b"abcde".to_vec(),
                shared_auth: false,
            },
        ),
        5 => (
            Wifi::Wpa2 {
                passphrase: PASSPHRASE.into(),
            },
            Security::wpa2(PASSPHRASE),
        ),
        _ => {
            w.machine.power_cycle();
            return;
        }
    };
    Config::new(SSID, wifi).install(&mut w.machine.soc.flash);
    let mut ap = AccessPoint::new(SSID, [2, 0, 0, 0, 0, 0xA1], 6, security);
    if kind == 5 {
        ap.wpa3 = Wpa3::Transition;
    }
    w.machine.air.push(ap);
    let mut lan = Lan::new();
    let bytecode = w.bytecode.clone();
    lan.handler = Box::new(move |request| {
        let bytecode = bytecode.borrow();
        if request.target.contains("bc.jsp") && !bytecode.is_empty() {
            Response::ok(bytecode.clone())
        } else {
            Response::not_found()
        }
    });
    w.machine.lan = Some(lan);
    w.machine.power_cycle();
}

/// What the server answers to `bc.jsp` from now on (a bytecode in its
/// `amber...Mind` envelope).
///
/// # Safety
/// `world` must come from `nab_new`, `ptr` point to `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_bytecode(world: *mut World, ptr: *const u8, len: usize) {
    let w = unsafe { &mut *world };
    *w.bytecode.borrow_mut() = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
}

/// Let `ms` milliseconds of board time pass.
///
/// # Safety
/// `world` must come from `nab_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_run(world: *mut World, ms: u32) {
    let w = unsafe { &mut *world };
    let until = w.machine.soc.millis() + ms as u64;
    w.machine.run_until_ms(until);
}

/// # Safety
/// `world` must come from `nab_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_button(world: *mut World, down: u32) {
    unsafe { &mut *world }.machine.soc.board.button = down != 0;
}

/// # Safety
/// `world` must come from `nab_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_volume(world: *mut World, volume: u32) {
    unsafe { &mut *world }.machine.soc.board.volume = volume.min(255) as u8;
}

/// Unplug and plug back in.
///
/// # Safety
/// `world` must come from `nab_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_power_cycle(world: *mut World) {
    unsafe { &mut *world }.machine.power_cycle();
}

/// A snapshot of the rabbit, [`STATE_LEN`] bytes:
/// 0..15 red, green, blue of leds 0..5 (0..=127 each);
/// 15, 16 ear slots (0..20); 17, 18 ear directions (0, 1, 255);
/// 19 link (0 no network, 1 in range, 2 joined); 20 resets so far;
/// 21 Wi-Fi channel; 22 loudspeaker amplifier on; 23 attenuation in
/// half decibels; 24..28 board time in ms; 28..32 audio bytes played.
///
/// # Safety
/// `world` must come from `nab_new`. The pointer is valid until the
/// next call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_state(world: *mut World) -> *const u8 {
    let w = unsafe { &mut *world };
    let m = &w.machine;
    let board = &m.soc.board;
    let s = &mut w.state;
    for (i, led) in board.leds.iter().enumerate() {
        s[i * 3..i * 3 + 3].copy_from_slice(led);
    }
    for (i, ear) in board.ears.iter().enumerate() {
        s[15 + i] = ear.slot as u8;
        s[17 + i] = ear.direction as u8;
    }
    s[19] = match m.air.first() {
        None => 0,
        Some(ap) if ap.is_authorized(DEFAULT_MAC) => 2,
        Some(_) => 1,
    };
    s[20] = m.resets as u8;
    s[21] = m.radio.borrow().channel;
    s[22] = board.amplifier as u8;
    s[23] = board.codec.attenuation();
    s[24..28].copy_from_slice(&(m.soc.millis() as u32).to_le_bytes());
    let played: usize = board.codec.all_tracks().iter().map(|t| t.data.len()).sum();
    s[28..32].copy_from_slice(&(played as u32).to_le_bytes());
    s.as_ptr()
}

/// Take what the firmware printed since the last call. Returns the
/// length; `nab_console_ptr` gives the bytes.
///
/// # Safety
/// `world` must come from `nab_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_console(world: *mut World) -> usize {
    let w = unsafe { &mut *world };
    let all = &w.machine.soc.uart_tx;
    w.console = all[w.console_seen..].to_vec();
    w.console_seen = all.len();
    w.console.len()
}

/// # Safety
/// `world` must come from `nab_new`. Valid until the next `nab_console`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_console_ptr(world: *mut World) -> *const u8 {
    unsafe { &*world }.console.as_ptr()
}

/// Take the next piece of sound the rabbit played. Returns its length
/// (0 when there is nothing new); `nab_audio_ptr` gives the bytes: a
/// 12-byte header, then the sound. Header: byte 0 is the kind (1:
/// 16-bit little-endian mono samples, 2: MP3 frames, 3: something the
/// page cannot play), bytes 4..8 the sample rate, 8..12 the track
/// number. Call again until it returns 0.
///
/// # Safety
/// `world` must come from `nab_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_audio(world: *mut World) -> usize {
    let w = unsafe { &mut *world };
    let tracks = w.machine.soc.board.codec.all_tracks();
    let finished = w.machine.soc.board.codec.tracks.len();
    w.audio.clear();
    while let Some(track) = tracks.get(w.heard.0) {
        let done = w.heard.0 < finished;
        let from = w.heard.1;
        let (kind, rate, sound, upto) = match track.format {
            Format::Unknown if !done => return 0,
            Format::Wav {
                sample_rate, adpcm, ..
            } => {
                // Samples start after the "data" chunk header.
                let start = track
                    .data
                    .windows(4)
                    .position(|c| c == b"data")
                    .map(|p| p + 8);
                match start {
                    None if !done => return 0,
                    None => (3, 0, Vec::new(), track.data.len()),
                    Some(start) => {
                        let from = from.max(start);
                        let unit = if adpcm { ADPCM_BLOCK_BYTES } else { 2 };
                        let whole = (track.data.len().saturating_sub(from)) / unit * unit;
                        let bytes = &track.data[from..from + whole];
                        let pcm = if adpcm {
                            adpcm_decode(bytes)
                                .iter()
                                .flat_map(|s| s.to_le_bytes())
                                .collect()
                        } else {
                            bytes.to_vec()
                        };
                        (1, sample_rate, pcm, from + whole)
                    }
                }
            }
            Format::Mp3 { sample_rate, .. } => (
                2,
                sample_rate,
                track.data[from..].to_vec(),
                track.data.len(),
            ),
            // MIDI comes rendered; `from` counts samples here.
            Format::Midi => (
                1,
                PCM_RATE,
                track.pcm[from.min(track.pcm.len())..]
                    .iter()
                    .flat_map(|s| s.to_le_bytes())
                    .collect(),
                track.pcm.len(),
            ),
            _ => (3, 0, Vec::new(), track.data.len()),
        };
        let number = w.heard.0;
        w.heard = if done {
            (number + 1, 0)
        } else {
            (number, upto)
        };
        if sound.is_empty() {
            if done {
                continue;
            }
            return 0;
        }
        w.audio.extend_from_slice(&[kind, 1, 0, 0]);
        w.audio.extend_from_slice(&rate.to_le_bytes());
        w.audio.extend_from_slice(&(number as u32).to_le_bytes());
        w.audio.extend_from_slice(&sound);
        return w.audio.len();
    }
    0
}

/// # Safety
/// `world` must come from `nab_new`. Valid until the next `nab_audio`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_audio_ptr(world: *mut World) -> *const u8 {
    unsafe { &*world }.audio.as_ptr()
}

/// What the microphone hears: 16-bit little-endian samples at 8000 Hz.
/// At most a second is kept waiting.
///
/// # Safety
/// `world` must come from `nab_new`, `ptr` point to `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_microphone(world: *mut World, ptr: *const u8, len: usize) {
    let w = unsafe { &mut *world };
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let queue = &mut w.machine.soc.board.codec.microphone;
    queue.extend(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| i16::from_le_bytes(*b)),
    );
    while queue.len() > 8000 {
        queue.pop_front();
    }
}

/// Hold a tag in front of the nose (8 bytes), or take it away (`len` 0).
///
/// # Safety
/// `world` must come from `nab_new`, `ptr` point to `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_tag(world: *mut World, ptr: *const u8, len: usize) {
    let w = unsafe { &mut *world };
    let tags = &mut w.machine.soc.board.rfid.tags;
    tags.clear();
    if len == 8 {
        let uid: [u8; 8] = unsafe { std::slice::from_raw_parts(ptr, 8) }
            .try_into()
            .unwrap();
        tags.push(crate::rfid::Tag::new(uid));
    }
}
