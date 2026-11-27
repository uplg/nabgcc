//! Firmware for the Nabaztag:tag.

#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use lapin_core::rng::Pool;
use lapin_core::wifi::{self, Link, ScanResult, Station};
use lapin_fw::wifi::link::Radio;
use lapin_fw::wifi::rt2573::{self, Stick, TxOptions};
use lapin_fw::{board, clock, flash, halt, irq, led, spi, timer, uart, usb, watchdog};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    uart::write(b"PANIC\n");
    halt()
}

const AMBER: u32 = 0xFF8000;
const BLUE: u32 = 0x0000FF;

#[unsafe(no_mangle)]
extern "C" fn main() -> ! {
    lapin_fw::start::link();
    clock::init();
    board::init();
    irq::init();
    watchdog::start();
    timer::init();
    irq_enable_checked();
    spi::init();
    led::init();
    uart::init();
    uart::write(b"lapin 0.1\n");

    // The button at power-on asks for setup mode, as it always did.
    let setup = board::button();
    led::set_all(if setup { BLUE } else { AMBER });
    uart::write(if setup { b"setup\n" } else { b"run\n" });

    let stick = usb::init()
        .and_then(|()| usb::attach(3000))
        .and_then(|()| usb::enumerate())
        .map_err(rt2573::Error::Usb)
        .and_then(Stick::start);
    let mut stick = match stick {
        Ok(stick) => {
            uart::write(b"wifi ");
            for (i, byte) in stick.mac.iter().enumerate() {
                if i > 0 {
                    uart::write(b":");
                }
                uart::hex8(*byte);
            }
            uart::write(b" radio ");
            uart::hex8(stick.radio());
            uart::write(b"\n");
            Some(stick)
        }
        Err(rt2573::Error::Radio(radio)) => {
            // Not the radio chip this firmware knows how to tune.
            uart::write(b"wifi: radio ");
            uart::hex8(radio);
            uart::write(b"\n");
            None
        }
        Err(_) => {
            uart::write(b"wifi: no stick\n");
            None
        }
    };
    let mut pool = Pool::new();
    // The volume wheel's last bits wander: a first handful of noise.
    for _ in 0..64 {
        pool.mix(board::volume() as u32 ^ timer::millis() << 8);
    }
    let settings = flash::settings();
    let configured = settings[207] == 0x47;
    if let Some(stick) = &mut stick {
        if configured {
            pool.mix(u32::from_le_bytes([
                stick.mac[2],
                stick.mac[3],
                stick.mac[4],
                stick.mac[5],
            ]));
            join_forever(stick, &mut pool, settings);
        }
        look_around(stick);
    }

    let mut beat = 0u32;
    loop {
        watchdog::feed();
        let now = timer::millis();
        if now / 1000 != beat {
            beat = now / 1000;
            uart::write(b".");
            // A press of more than a second stops the feeding: a way to
            // watch the watchdog do its job.
            if !setup && board::button() {
                uart::write(b"\nhang\n");
                halt();
            }
        }
    }
}

/// Go through the channels once: ask who is there, and name every
/// network heard, with its channel.
fn look_around(stick: &mut Stick) {
    let mut probe = [0u8; 42];
    probe[0] = 0x40;
    probe[4..10].fill(0xFF);
    probe[10..16].copy_from_slice(&stick.mac);
    probe[16..22].fill(0xFF);
    // Any network; the rates we take.
    probe[24..].copy_from_slice(&[
        0, 0, 1, 8, 0x02, 0x04, 0x0B, 0x16, 0x24, 0x30, 0x48, 0x6C, 50, 4, 0x0C, 0x12, 0x18, 0x60,
    ]);
    let mut frame = [0u8; 512];
    for channel in 1..=13 {
        if stick.set_channel(channel).is_err() {
            return;
        }
        stick.transmit(&probe, &TxOptions::PLAIN);
        let start = timer::millis();
        while timer::millis().wrapping_sub(start) < 120 {
            watchdog::feed();
            let Some(got) = stick.receive(&mut frame) else {
                continue;
            };
            // Beacons and probe responses carry the name after 36 bytes.
            if got.len < 38 || (frame[0] != 0x80 && frame[0] != 0x50) || frame[36] != 0 {
                continue;
            }
            let name = &frame[38..got.len.min(38 + frame[37] as usize)];
            uart::write(if frame[0] == 0x80 {
                b"beacon "
            } else {
                b"answer "
            });
            uart::write(name);
            uart::write(b" channel ");
            uart::hex8(channel);
            uart::write(b"\n");
        }
    }
}

#[unsafe(link_section = ".xram.station")]
static mut STATION: MaybeUninit<Station> = MaybeUninit::uninit();
#[unsafe(link_section = ".xram.frame")]
static mut FRAME: [u8; 2400] = [0; 2400];

/// Built where it lives: it is too big for the stack.
#[inline(never)]
fn station() -> &'static mut Station {
    // SAFETY: called once, before anything else touches it.
    unsafe {
        let slot = &mut *(&raw mut STATION);
        slot.write(Station::new())
    }
}

fn text(field: &[u8]) -> &[u8] {
    &field[..field.iter().position(|b| *b == 0).unwrap_or(field.len())]
}

fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// The WEP key as the bytecode turns what was typed into one: five or
/// thirteen characters as they are, otherwise hexadecimal.
fn wep_key(typed: &[u8], out: &mut [u8; 13]) -> usize {
    if typed.len() == 5 || typed.len() == 13 {
        out[..typed.len()].copy_from_slice(typed);
        return typed.len();
    }
    let mut digits = [0u8; 26];
    let mut n = 0;
    for &c in typed.iter().filter(|c| **c != b':') {
        if n < 26 {
            digits[n] = c;
            n += 1;
        }
    }
    let len = if typed.len() < 10 {
        0
    } else if typed.len() < 26 {
        5
    } else {
        13
    };
    for i in 0..len {
        out[i] = hex_digit(digits[2 * i]) << 4 | hex_digit(digits[2 * i + 1]);
    }
    len
}

/// Until the virtual machine runs the boot bytecode: what it does with
/// the network settings, scan, join, keep the link, try again.
fn join_forever(stick: &mut Stick, pool: &mut Pool, settings: &[u8; flash::SECTOR]) -> ! {
    let sta = station();
    // SAFETY: only this function uses the frame buffer.
    let frame = unsafe { &mut *(&raw mut FRAME) };
    let ssid = text(&settings[58..90]);
    let shared = settings[90] == 1;
    let crypt = settings[91];
    let typed = text(&settings[92..156]);
    let mut wep = [0u8; 13];
    let wep_len = wep_key(typed, &mut wep);
    let pmk = &settings[175..207];
    let mut radio = Radio { stick, pool };
    let mut last_state = -1;
    let mut retry_at = 0u32;
    let mut sent = false;
    let mut round = 0u32;
    loop {
        watchdog::feed();
        let now = timer::millis();
        if sta.net_state() == wifi::S_IDLE && (now.wrapping_sub(retry_at) as i32) >= 0 {
            uart::write(b"scan ");
            uart::write(ssid);
            uart::write(b"\n");
            let mut best: Option<ScanResult> = None;
            sta.scan(&mut radio, Some(ssid), frame, &mut |r| {
                if &r.ssid[..r.ssid_len] == ssid && best.is_none_or(|b| r.rssi > b.rssi) {
                    best = Some(*r);
                }
            });
            match best {
                Some(r) if r.encryption != wifi::CRYPT_UNSUPPORTED => {
                    let key: &[u8] = match r.encryption & 0xF0 {
                        wifi::CRYPT_WEP => &wep[..wep_len],
                        wifi::CRYPT_WPA | wifi::CRYPT_WPA2 => pmk,
                        _ => &[],
                    };
                    let password = if crypt == wifi::CRYPT_WPA2 {
                        typed
                    } else {
                        &[][..]
                    };
                    let t = timer::millis();
                    sta.auth(
                        &mut radio,
                        ssid,
                        &r.mac,
                        &r.bssid,
                        r.channel,
                        r.rateset,
                        shared,
                        r.encryption,
                        key,
                        password,
                    );
                    uart::write(b"auth ");
                    uart::hex8(r.encryption);
                    uart::write(b" ");
                    uart::hex16(timer::millis().wrapping_sub(t) as u16);
                    uart::write(b"\n");
                }
                _ => uart::write(b"not found\n"),
            }
            retry_at = timer::millis().wrapping_add(1000);
            sent = false;
        }
        // The C main loop: 50 ms of frames, the timer every fourth turn.
        let t = timer::millis();
        while timer::millis().wrapping_sub(t) < 50 {
            watchdog::feed();
            sta.poll(&mut radio);
            if let Some(rx) = radio.receive(frame) {
                if let Some(d) = sta.input(&mut radio, frame, rx) {
                    uart::write(b"rx ");
                    uart::hex16(d.len as u16);
                    uart::write(b"\n");
                }
            }
        }
        round = (round + 1) & 3;
        if round == 0 {
            sta.tick(&mut radio);
            let _ = radio.stick.tick();
        }
        let state = sta.net_state();
        if state != last_state {
            last_state = state;
            uart::write(b"state ");
            uart::hex8(state as u8);
            if state == wifi::S_CONNECTED {
                uart::write(if sta.is_wpa3() { b" wpa3 " } else { b" " });
                uart::hex16(timer::millis() as u16);
            }
            uart::write(b"\n");
        }
        if state == wifi::S_CONNECTED && !sent {
            // An IPv4 frame to everyone, as DHCP's first will be.
            let mut data = [0x45u8; 8 + 28];
            data[..8].copy_from_slice(&[0xAA, 0xAA, 0x03, 0, 0, 0, 0x08, 0x00]);
            sent = sta.send(&mut radio, &data, &wifi::BROADCAST, false);
        }
    }
}

fn irq_enable_checked() {
    irq::irq_enable();
}
