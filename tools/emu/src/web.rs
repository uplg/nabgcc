//! The emulator as a WebAssembly module, for a page in a browser.
//!
//! A plain C interface, no generated glue: the page allocates a buffer
//! with `nab_alloc`, copies a firmware file in and calls `nab_new`,
//! then drives the world it gets back. Every function takes that world
//! (from `nab_new`, until `nab_drop`) and, for its arguments, pointer
//! and length pairs of readable bytes (text in UTF-8). Those that hand
//! something back return its length and leave it where `nab_out`
//! points, until the next call. See `web/src/lib/emu/nabemu.ts`.
//!
//! The rabbit lives in a world of its own: access points in range, a
//! wired network behind them with a server, a phone that may come and
//! join the rabbit's own network.

// The contract above holds for every function here.
#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::fmt::Write;
use std::rc::Rc;

use crate::air::{AccessPoint, Security, Wpa3};
use crate::config::{Config, Wifi};
use crate::elf::decode_sim;
use crate::lan::{Lan, Request, Response};
use crate::rt2573::DEFAULT_RSSI;
use crate::soc::{CLOCK_HZ, ResetCause};
use crate::visitor::{Link, Visitor};
use crate::vs1003::{ADPCM_BLOCK_BYTES, Format, PCM_RATE, adpcm_decode};
use crate::{DEFAULT_MAC, Event, Machine, metal};

/// The phone's own address.
const PHONE: [u8; 6] = [0x02, 0, 0, 0, 0, 0xB2];

pub struct World {
    machine: Machine,
    server: Rc<RefCell<Server>>,
    /// What the last call handed back.
    out: Vec<u8>,
    console_seen: usize,
    /// Track and offset up to which sound was handed to the page.
    heard: (usize, usize),
    pages_seen: usize,
    datagrams_seen: usize,
}

/// The server behind the access points.
#[derive(Default)]
struct Server {
    /// What `bc.jsp` answers, in its envelope; nothing: not found.
    bytecode: Vec<u8>,
    /// A bytecode that flashes a new image, for the next `bc.jsp` only.
    update: Option<Vec<u8>>,
    /// Requests answered since the page last asked.
    log: Vec<String>,
    requests: usize,
}

impl Server {
    fn answer(&mut self, request: &Request) -> Response {
        let response = if !request.target.contains("bc.jsp") {
            Response::not_found()
        } else if let Some(update) = self.update.take() {
            Response::ok(update)
        } else if self.bytecode.is_empty() {
            Response::not_found()
        } else {
            Response::ok(self.bytecode.clone())
        };
        self.requests += 1;
        self.log.push(format!(
            "{} {} → {} ({} bytes)",
            request.method,
            request.target,
            response.status,
            response.body.len()
        ));
        response
    }
}

unsafe fn world<'a>(world: *mut World) -> &'a mut World {
    unsafe { &mut *world }
}

unsafe fn access_point<'a>(world: *mut World, n: u32) -> Option<&'a mut AccessPoint> {
    unsafe { self::world(world) }
        .machine
        .air
        .get_mut(n as usize)
}

unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

unsafe fn text(ptr: *const u8, len: usize) -> String {
    String::from_utf8_lossy(unsafe { bytes(ptr, len) }).into_owned()
}

/// A firmware image as a file may hold it: a `.sim` decoded, anything
/// else as it is.
fn image(file: &[u8]) -> Vec<u8> {
    decode_sim(file).unwrap_or_else(|| file.to_vec())
}

/// A JSON string.
fn quote(s: &str) -> String {
    let mut q = String::with_capacity(s.len() + 2);
    q.push('"');
    for c in s.chars() {
        match c {
            '"' => q.push_str("\\\""),
            '\\' => q.push_str("\\\\"),
            '\n' => q.push_str("\\n"),
            '\r' => q.push_str("\\r"),
            '\t' => q.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(q, "\\u{:04x}", c as u32);
            }
            c => q.push(c),
        }
    }
    q.push('"');
    q
}

fn list<T>(items: impl IntoIterator<Item = T>, each: impl Fn(T) -> String) -> String {
    let items: Vec<String> = items.into_iter().map(each).collect();
    format!("[{}]", items.join(","))
}

fn address(ip: [u8; 4]) -> String {
    quote(&format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))
}

fn cycles_to_ms(cycles: u64) -> u64 {
    cycles * 1000 / CLOCK_HZ
}

/// Signal strength in dBm as the stick's RSSI byte, and back.
fn rssi(dbm: i32) -> u8 {
    (dbm + 0x79).clamp(0, 255) as u8
}

fn dbm(rssi: u8) -> i32 {
    rssi as i32 - 0x79
}

/// Security of a network, by number: 0 open, 1 WEP, 2 WEP with
/// shared-key authentication, 3 WPA (TKIP), 4 WPA2, 5 WPA2/WPA3
/// transition, 6 WPA3 alone. The rabbit's settings know the first
/// five; a WPA3 network is "WPA2" to them.
fn wifi(kind: u32, key: String) -> Wifi {
    match kind {
        0 => Wifi::Open,
        1 | 2 => Wifi::Wep {
            key,
            shared_auth: kind == 2,
        },
        3 => Wifi::Wpa { passphrase: key },
        _ => Wifi::Wpa2 { passphrase: key },
    }
}

fn security_name(ap: &AccessPoint) -> &'static str {
    match (&ap.security, ap.wpa3) {
        (Security::Open, _) => "open",
        (Security::Wep { shared_auth, .. }, _) if *shared_auth => "WEP, shared key",
        (Security::Wep { .. }, _) => "WEP",
        (Security::Psk { wpa2: false, .. }, _) => "WPA",
        (Security::Psk { .. }, Wpa3::Off) => "WPA2",
        (Security::Psk { .. }, Wpa3::Transition) => "WPA2/WPA3",
        (Security::Psk { .. }, Wpa3::Only) => "WPA3",
    }
}

impl World {
    fn hand(&mut self, out: impl Into<Vec<u8>>) -> usize {
        self.out = out.into();
        self.out.len()
    }

    fn status(&self) -> String {
        let m = &self.machine;
        let board = &m.soc.board;
        let radio = m.radio.borrow();
        let leds = list(&board.leds, |[r, g, b]| format!("[{r},{g},{b}]"));
        let ears = list(&board.ears, |e| {
            format!(
                r#"{{"slot":{},"direction":{},"pulses":{}}}"#,
                e.slot, e.direction, e.pulses
            )
        });
        let joined = m.air.iter().position(|ap| ap.is_authorized(DEFAULT_MAC));
        let lease = m
            .lan
            .as_ref()
            .filter(|lan| lan.leased_to == Some(DEFAULT_MAC))
            .map_or("null".into(), |_| address(crate::lan::LEASE_IP));
        let last_reset = m.events.iter().rev().find_map(|e| match e {
            Event::Reset(ResetCause::Watchdog) => Some("\"watchdog\""),
            Event::Reset(ResetCause::PowerLoss) => Some("\"power loss\""),
            Event::Undefined { .. } => None,
        });
        let undefined = m
            .events
            .iter()
            .filter(|e| matches!(e, Event::Undefined { .. }))
            .count();
        let tag = board.rfid.tags.first().map_or("null".into(), |t| {
            quote(&t.uid.iter().map(|b| format!("{b:02x}")).collect::<String>())
        });
        let played: usize = board.codec.all_tracks().iter().map(|t| t.data.len()).sum();
        let soc = &m.soc;
        let server = self.server.borrow();
        format!(
            concat!(
                r#"{{"ms":{},"instructions":{},"skippedMs":{},"resets":{},"lastReset":{},"#,
                r#""undefined":{},"leds":{},"ears":{},"button":{},"volume":{},"#,
                r#""amplifier":{},"attenuation":{},"audioBytes":{},"tag":{},"#,
                r#""channel":{},"stick":{},"joined":{},"lease":{},"#,
                r#""watchdog":{{"unfedMs":{},"longestMs":{}}},"#,
                r#""flash":{{"erases":{},"programs":{},"cutArmed":{}}},"#,
                r#""server":{{"requests":{},"serving":{},"update":{}}},"phone":{}}}"#
            ),
            soc.millis(),
            m.instructions,
            cycles_to_ms(m.skipped),
            m.resets,
            last_reset.unwrap_or("null"),
            undefined,
            leds,
            ears,
            board.button,
            board.volume,
            board.amplifier,
            board.codec.attenuation(),
            played,
            tag,
            radio.channel,
            radio.firmware_loaded,
            joined.map_or("null".into(), |i| i.to_string()),
            lease,
            cycles_to_ms(soc.watchdog_unfed()),
            cycles_to_ms(soc.watchdog_longest),
            soc.flash_erases,
            soc.flash_programs,
            soc.cut_power_after_flash_ops.is_some(),
            server.requests,
            server.bytecode.len(),
            server.update.is_some(),
            self.phone(),
        )
    }

    fn phone(&self) -> String {
        let Some(v) = &self.machine.visitor else {
            return "null".into();
        };
        let link = match v.link {
            Link::Searching => "searching",
            Link::Authenticating => "authenticating",
            Link::Associating => "associating",
            Link::Associated => "associated",
        };
        format!(
            r#"{{"looksFor":{},"link":"{link}","network":{},"address":{},"pending":{}}}"#,
            quote(&v.network_prefix),
            v.network
                .as_ref()
                .map_or("null".into(), |(ssid, _)| quote(ssid)),
            v.address.map_or("null".into(), address),
            v.pending(),
        )
    }

    fn access_points(&self) -> String {
        list(&self.machine.air, |ap| {
            let from = ap.events.len().saturating_sub(12);
            format!(
                concat!(
                    r#"{{"ssid":{},"channel":{},"security":"{}","hidden":{},"dbm":{},"#,
                    r#""joined":{},"events":{}}}"#
                ),
                quote(&ap.ssid),
                ap.channel,
                security_name(ap),
                ap.hidden,
                dbm(ap.rssi),
                ap.is_authorized(DEFAULT_MAC),
                list(&ap.events[from..], |e| quote(&format!("{e:?}"))),
            )
        })
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn nab_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
}

/// `ptr` and `len` must come from one `nab_alloc` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_free(ptr: *mut u8, len: usize) {
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
}

/// A rabbit flashed with the given firmware file (ELF, `.sim` or raw),
/// a wired network with a server, and nothing in range yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_new(ptr: *const u8, len: usize) -> *mut World {
    let (mut machine, _) = Machine::from_file(unsafe { bytes(ptr, len) });
    let server = Rc::new(RefCell::new(Server::default()));
    let mut lan = Lan::new();
    let answering = server.clone();
    lan.handler = Box::new(move |request| answering.borrow_mut().answer(request));
    machine.lan = Some(lan);
    Box::into_raw(Box::new(World {
        machine,
        server,
        out: Vec::new(),
        console_seen: 0,
        heard: (0, 0),
        pages_seen: 0,
        datagrams_seen: 0,
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_drop(world: *mut World) {
    drop(unsafe { Box::from_raw(world) });
}

/// Where what the last call handed back is.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_out(world: *mut World) -> *const u8 {
    unsafe { self::world(world) }.out.as_ptr()
}

/// Let `ms` milliseconds of board time pass.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_run(world: *mut World, ms: u32) {
    let m = &mut unsafe { self::world(world) }.machine;
    m.run_until_ms(m.soc.millis() + ms as u64);
}

/// Unplug and plug back in.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_power_cycle(world: *mut World) {
    unsafe { self::world(world) }.machine.power_cycle();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_button(world: *mut World, down: u32) {
    unsafe { self::world(world) }.machine.soc.board.button = down != 0;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_volume(world: *mut World, volume: u32) {
    unsafe { self::world(world) }.machine.soc.board.volume = volume.min(255) as u8;
}

/// Turn ear 0 (left) or 1 (right) by hand, by `slots` of twenty to a
/// turn, backwards when negative.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_ear(world: *mut World, ear: u32, slots: i32) {
    let board = &mut unsafe { self::world(world) }.machine.soc.board;
    board.turn_ear_by_hand(ear.min(1) as usize, slots);
}

/// Hold a tag in front of the nose (its 8-byte identifier), or take it
/// away (`len` 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_tag(world: *mut World, ptr: *const u8, len: usize) {
    let tags = &mut unsafe { self::world(world) }.machine.soc.board.rfid.tags;
    tags.clear();
    if let Ok(uid) = unsafe { bytes(ptr, len) }.try_into() {
        tags.push(crate::rfid::Tag::new(uid));
    }
}

/// What the microphone hears: 16-bit little-endian samples at 8000 Hz.
/// At most a second is kept waiting.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_microphone(world: *mut World, ptr: *const u8, len: usize) {
    let bytes = unsafe { bytes(ptr, len) };
    let samples = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| i16::from_le_bytes(*b));
    let queue = &mut unsafe { self::world(world) }
        .machine
        .soc
        .board
        .codec
        .microphone;
    queue.extend(samples);
    while queue.len() > 8000 {
        queue.pop_front();
    }
}

/// What the firmware printed since the last call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_console(world: *mut World) -> usize {
    let w = unsafe { self::world(world) };
    let fresh = w.machine.soc.uart_tx[w.console_seen..].to_vec();
    w.console_seen = w.machine.soc.uart_tx.len();
    w.hand(fresh)
}

/// The rabbit as it is now, in JSON: leds (red, green, blue of the
/// nose, left, middle, right and bottom, 0..=127), ears, button,
/// sound, radio, network, watchdog, flash, server and phone.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_status(world: *mut World) -> usize {
    let w = unsafe { self::world(world) };
    let status = w.status();
    w.hand(status)
}

/// The next piece of sound the rabbit played, 0 when there is nothing
/// new: a 12-byte header, then the sound. Header: byte 0 is the kind
/// (1: 16-bit little-endian mono samples, 2: MP3 frames, 3: something
/// the page cannot play), bytes 4..8 the sample rate, 8..12 the track
/// number. Call again until it returns 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_audio(world: *mut World) -> usize {
    let w = unsafe { self::world(world) };
    let tracks = w.machine.soc.board.codec.all_tracks();
    let finished = w.machine.soc.board.codec.tracks.len();
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
        let mut piece = vec![kind, 1, 0, 0];
        piece.extend_from_slice(&rate.to_le_bytes());
        piece.extend_from_slice(&(number as u32).to_le_bytes());
        piece.extend_from_slice(&sound);
        w.out = piece;
        return w.out.len();
    }
    0
}

/// Put an access point in range; returns its number. `security` as
/// [`wifi`] numbers them; `key` is the passphrase, or the WEP key (5 or
/// 13 characters). Its frames arrive at `dbm`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_ap_add(
    world: *mut World,
    ssid: *const u8,
    ssid_len: usize,
    key: *const u8,
    key_len: usize,
    security: u32,
    channel: u32,
    dbm: i32,
    hidden: u32,
) -> u32 {
    let w = unsafe { self::world(world) };
    let ssid = unsafe { text(ssid, ssid_len) };
    let key = unsafe { text(key, key_len) };
    let air = match wifi(security, key.clone()) {
        Wifi::Open => Security::Open,
        Wifi::Wep { key, shared_auth } => Security::Wep {
            key: key.into_bytes(),
            shared_auth,
        },
        Wifi::Wpa { passphrase } => Security::wpa(&passphrase),
        Wifi::Wpa2 { passphrase } => Security::wpa2(&passphrase),
    };
    let n = w.machine.air.len();
    let bssid = [2, 0, 0, 0, 0, 0xA1 + n as u8];
    let mut ap = AccessPoint::new(&ssid, bssid, channel.clamp(1, 14) as u8, air);
    ap.wpa3 = match security {
        5 => Wpa3::Transition,
        6 => Wpa3::Only,
        _ => Wpa3::Off,
    };
    ap.hidden = hidden != 0;
    ap.rssi = if dbm == 0 { DEFAULT_RSSI } else { rssi(dbm) };
    w.machine.air.push(ap);
    n as u32
}

/// Switch an access point off for good: it tells everyone to leave,
/// then it is gone.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_ap_remove(world: *mut World, ap: u32) {
    let m = &mut unsafe { self::world(world) }.machine;
    if (ap as usize) < m.air.len() {
        let mut gone = m.air.remove(ap as usize);
        gone.shut_down(&mut m.radio.borrow_mut());
    }
}

/// An access point loses power and comes back at once, having
/// forgotten every station and its keys.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_ap_restart(world: *mut World, ap: u32) {
    if let Some(ap) = unsafe { access_point(world, ap) } {
        ap.power_cut();
    }
}

/// How strong an access point's frames arrive, in dBm.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_ap_signal(world: *mut World, ap: u32, dbm: i32) {
    if let Some(ap) = unsafe { access_point(world, ap) } {
        ap.rssi = rssi(dbm);
    }
}

/// The access points in range, in JSON, each with its latest events.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_aps(world: *mut World) -> usize {
    let w = unsafe { self::world(world) };
    let aps = w.access_points();
    w.hand(aps)
}

/// The settings in the rabbit's flash, in JSON (`null` when none were
/// ever saved): `server`, `ssid`, `security` numbered as [`wifi`]
/// does (0 to 4), `key`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_settings(world: *mut World) -> usize {
    let w = unsafe { self::world(world) };
    let json = Config::read(&w.machine.soc.flash).map_or("null".into(), |c| {
        let (security, key) = match &c.wifi {
            Wifi::Open => (0, ""),
            Wifi::Wep { key, shared_auth } => (1 + *shared_auth as u8, key.as_str()),
            Wifi::Wpa { passphrase } => (3, passphrase.as_str()),
            Wifi::Wpa2 { passphrase } => (4, passphrase.as_str()),
        };
        format!(
            r#"{{"server":{},"ssid":{},"security":{security},"key":{}}}"#,
            quote(&c.server),
            quote(&c.ssid),
            quote(key)
        )
    });
    w.hand(json)
}

/// Write settings in the rabbit's flash as its setup page would, for
/// the next start. `security` as [`wifi`] numbers them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_settings_write(
    world: *mut World,
    ssid: *const u8,
    ssid_len: usize,
    key: *const u8,
    key_len: usize,
    security: u32,
    server: *const u8,
    server_len: usize,
) {
    let w = unsafe { self::world(world) };
    let mut config = Config::new(
        &unsafe { text(ssid, ssid_len) },
        wifi(security, unsafe { text(key, key_len) }),
    );
    let server = unsafe { text(server, server_len) };
    if !server.is_empty() {
        config.server = server;
    }
    config.install(&mut w.machine.soc.flash);
}

/// Wipe the settings, as on a rabbit fresh from the factory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_settings_erase(world: *mut World) {
    let flash = &mut unsafe { self::world(world) }.machine.soc.flash;
    flash[crate::config::OFFSET..crate::config::OFFSET + crate::config::LENGTH].fill(0xFF);
}

/// What the server answers to `bc.jsp` from now on: a bytecode, put in
/// its `amber...Mind` envelope unless it comes in one. Nothing: not
/// found.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_serve(world: *mut World, ptr: *const u8, len: usize) {
    let bytecode = unsafe { bytes(ptr, len) };
    let body = if bytecode.is_empty() || bytecode.starts_with(b"amber") {
        bytecode.to_vec()
    } else {
        metal::boot_response(bytecode)
    };
    unsafe { self::world(world) }.server.borrow_mut().bytecode = body;
}

/// Serve a small program: 0 prints `arg` on the console, 1 restarts
/// the rabbit at once (every time it is loaded).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_serve_sample(world: *mut World, sample: u32, arg: i32) {
    let bytecode = match sample {
        0 => metal::print_number(arg),
        _ => {
            let mut f = metal::FUNCTION_HEADER.to_vec();
            f.extend(metal::int(0x0407_FE58));
            f.extend(metal::int(0x13FB_6754));
            // OPreboot, with the two magic numbers it demands.
            f.extend([136, metal::OP_RET]);
            metal::bytecode(&[], &f)
        }
    };
    unsafe { self::world(world) }.server.borrow_mut().bytecode = metal::boot_response(&bytecode);
}

/// Update the rabbit over the air: the next `bc.jsp` answers a
/// bytecode that writes this firmware file (`.sim` or raw image) over
/// the running one, then the server goes back to what it served.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_serve_update(world: *mut World, ptr: *const u8, len: usize) {
    let update = metal::flash_firmware(&image(unsafe { bytes(ptr, len) }));
    unsafe { self::world(world) }.server.borrow_mut().update = Some(metal::boot_response(&update));
}

/// What happened on the wired network since the last call, in JSON:
/// `requests`, the server's log lines, and `udp`, the datagrams the
/// rabbit sent but DNS and DHCP (garenne logs on port 9999).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_server(world: *mut World) -> usize {
    let w = unsafe { self::world(world) };
    let requests = std::mem::take(&mut w.server.borrow_mut().log);
    let datagrams = w.machine.lan.as_ref().map_or(&[][..], |l| &l.datagrams[..]);
    let fresh = datagrams[w.datagrams_seen.min(datagrams.len())..]
        .iter()
        .filter(|d| d.to_port != 53 && d.to_port != 67);
    let udp = list(fresh, |d| {
        quote(&format!(
            "{} → {}:{}  {}",
            d.from_port,
            address(d.to).trim_matches('"'),
            d.to_port,
            String::from_utf8_lossy(&d.payload).trim_end()
        ))
    });
    w.datagrams_seen = datagrams.len();
    let json = format!(
        r#"{{"requests":{},"udp":{udp}}}"#,
        list(&requests, |r| quote(r))
    );
    w.hand(json)
}

/// A phone comes looking for a network whose name starts with
/// `prefix` ("Nabaztag" in setup mode, "Nabaztag-secours" for lapin's
/// rescue), joins it and takes an address. It replaces any earlier one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_phone_join(world: *mut World, ptr: *const u8, len: usize) {
    let w = unsafe { self::world(world) };
    w.machine.visitor = Some(Visitor::new(PHONE, &unsafe { text(ptr, len) }));
    w.pages_seen = 0;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_phone_leave(world: *mut World) {
    unsafe { self::world(world) }.machine.visitor = None;
}

/// The phone asks the rabbit for a page: a GET of `target`, or a POST
/// of `body` when there is one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_phone_fetch(
    world: *mut World,
    target: *const u8,
    target_len: usize,
    body: *const u8,
    body_len: usize,
) {
    let w = unsafe { self::world(world) };
    let target = unsafe { text(target, target_len) };
    if let Some(v) = &mut w.machine.visitor {
        match unsafe { bytes(body, body_len) } {
            [] => v.get(&target),
            body => v.post(&target, body),
        }
    }
}

/// The answers the phone received since the last call, in JSON: each
/// with its `request` line and the `response` as it came.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_phone_pages(world: *mut World) -> usize {
    let w = unsafe { self::world(world) };
    let pages = w.machine.visitor.as_ref().map_or(&[][..], |v| &v.pages[..]);
    let json = list(&pages[w.pages_seen.min(pages.len())..], |p| {
        format!(
            r#"{{"request":{},"response":{}}}"#,
            quote(&p.request),
            quote(&p.text())
        )
    });
    w.pages_seen = pages.len();
    w.hand(json)
}

/// Cut the power once the flash has done `ops` more erases and word
/// programs: in the middle of an update, as a storm would. The next
/// power-on disarms it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nab_cut_power_after(world: *mut World, ops: u32) {
    let soc = &mut unsafe { self::world(world) }.machine.soc;
    soc.cut_power_after_flash_ops = Some(soc.flash_erases + soc.flash_programs + ops as u64);
}
