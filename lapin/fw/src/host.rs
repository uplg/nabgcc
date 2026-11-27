//! The board as the Metal machine sees it: each method one of the C
//! firmware's functions, done with this firmware's drivers.

use lapin_core::rng::Pool;
use lapin_core::sha1;
use lapin_core::wifi::{self, Delivery, Link, Station};
use lapin_metal::{Auth, Host, Motor, ScanResult};

use crate::ears::{self, Turn};
use crate::wifi::link::Radio;
use crate::wifi::rt2573::{self, Stick};
use crate::{board, codec, flash, i2c, led, rfid, timer, uart, usb, watchdog};

/// How many scan results are kept for the bytecode; the C driver put
/// them all on the machine's stack, every beacon of every network.
pub const SCAN_RESULTS: usize = 96;

pub struct Board {
    pub stick: Option<&'static mut Stick>,
    /// Where the stick goes once brought up, until it is.
    stick_slot: Option<&'static mut core::mem::MaybeUninit<Stick>>,
    pub station: &'static mut Station,
    pub pool: Pool,
    /// The last frame received, and what of it waits for the bytecode.
    pub frame: &'static mut [u8; 2400],
    held: Option<Delivery>,
    pub scan: &'static mut [ScanResult; SCAN_RESULTS],
    scanned: usize,
    tags: [rfid::Tag; 16],
    tag_count: usize,
}

pub const SCAN_NONE: ScanResult = ScanResult {
    ssid: [0; 33],
    mac: [0; 6],
    bssid: [0; 6],
    rssi: 0,
    channel: 0,
    rateset: 0,
    encryption: 0,
};

impl Board {
    pub fn new(
        stick_slot: &'static mut core::mem::MaybeUninit<Stick>,
        station: &'static mut Station,
        pool: Pool,
        frame: &'static mut [u8; 2400],
        scan: &'static mut [ScanResult; SCAN_RESULTS],
    ) -> Board {
        scan.fill(SCAN_NONE);
        Board {
            stick: None,
            stick_slot: Some(stick_slot),
            station,
            pool,
            frame,
            held: None,
            scan,
            scanned: 0,
            tags: [rfid::Tag::default(); 16],
            tag_count: 0,
        }
    }

    /// The station and the stick together, if there is a stick.
    fn radio(&mut self) -> Option<(&mut Station, Radio<'_>)> {
        let stick = self.stick.as_deref_mut()?;
        Some((
            &mut *self.station,
            Radio {
                stick,
                pool: &mut self.pool,
            },
        ))
    }

    /// Take frames from the stick until one is for the bytecode (kept
    /// in `frame`) or none is left. Handshakes are handled on the way.
    fn pump(&mut self) {
        if self.held.is_some() {
            return;
        }
        let frame = &mut *self.frame;
        let Some(stick) = self.stick.as_deref_mut() else {
            return;
        };
        let mut radio = Radio {
            stick,
            pool: &mut self.pool,
        };
        self.station.poll(&mut radio);
        while let Some(rx) = radio.receive(frame) {
            if let Some(d) = self.station.input(&mut radio, frame, rx) {
                self.held = Some(d);
                return;
            }
        }
    }

    /// Throw away everything received (`rt2501_setmode` does).
    fn flush(&mut self) {
        self.held = None;
        while self.net_pending().is_some() {
            self.held = None;
        }
    }
}

/// The bytes before the first zero.
fn cstr(s: &[u8]) -> &[u8] {
    &s[..s.iter().position(|b| *b == 0).unwrap_or(s.len())]
}

impl Host for Board {
    fn console(&mut self, text: &[u8]) {
        uart::write(text);
    }

    fn watchdog(&mut self) {
        watchdog::feed();
    }

    fn time_ms(&mut self) -> u32 {
        timer::millis()
    }

    fn time_s(&mut self) -> u32 {
        timer::millis() / 1000
    }

    fn led(&mut self, n: u8, color: u32) {
        // The C driver's table: numbers 5 to 7 land on the middle led.
        let n = match n & 7 {
            n @ 0..=4 => n as usize,
            _ => led::MIDDLE,
        };
        led::set(n, color);
    }

    fn motor(&mut self, motor: u8, run: Motor) {
        let turn = match run {
            Motor::Stop => Turn::Stop,
            Motor::Forward => Turn::Forward,
            Motor::Reverse => Turn::Backward,
        };
        ears::turn(motor as usize - 1, turn);
    }

    fn motor_position(&mut self, motor: u8) -> u16 {
        ears::teeth(motor as usize - 1)
    }

    fn button(&mut self) -> u8 {
        board::button() as u8
    }

    fn adc(&mut self) -> u8 {
        255 - board::volume()
    }

    fn rfid_first(&mut self) -> Option<[u8; 8]> {
        match rfid::scan(&mut self.tags) {
            // The C driver hands over the bytes of "Error".
            Err(_) => Some(*b"Error\0\0\0"),
            Ok(0) => {
                self.tag_count = 0;
                None
            }
            Ok(n) => {
                self.tag_count = n;
                Some(self.tags[0].uid)
            }
        }
    }

    fn rfid_count(&mut self) -> i32 {
        match rfid::scan(&mut self.tags) {
            Err(_) => -1,
            Ok(n) => {
                self.tag_count = n;
                n as i32
            }
        }
    }

    fn rfid_nth(&mut self, i: i32) -> [u8; 8] {
        self.tags.get(i as usize).map_or([0; 8], |t| t.uid)
    }

    fn rfid_read(&mut self, id: &[u8; 8], block: i32, data: &mut [u8; 4]) -> i32 {
        match rfid::read_block(id, block as u8) {
            Ok(d) => {
                *data = d;
                0
            }
            Err(_) => -1,
        }
    }

    fn rfid_write(&mut self, id: &[u8; 8], block: i32, data: &[u8; 4]) -> i32 {
        match rfid::write_block(id, block as u8, data) {
            Ok(()) => 0,
            Err(_) => -1,
        }
    }

    fn i2c_read(&mut self, address: u8, data: &mut [u8]) -> bool {
        i2c::read(address, data).is_ok()
    }

    fn i2c_write(&mut self, address: u8, data: &[u8]) -> bool {
        i2c::write(address, data).is_ok()
    }

    fn settings_read(&mut self, offset: u32, data: &mut [u8]) {
        let s = flash::settings();
        let at = offset as usize;
        let n = data.len().min(s.len().saturating_sub(at));
        data[..n].copy_from_slice(&s[at..at + n]);
    }

    fn settings_write(&mut self, offset: u32, data: &[u8]) {
        flash::write_settings_at(offset as usize, data);
    }

    fn flash_firmware(&mut self, image: &[u8]) -> ! {
        flash::write_firmware(image)
    }

    fn reboot(&mut self) -> ! {
        watchdog::reset_now()
    }

    fn codec_read(&mut self, register: u8) -> u16 {
        codec::read(register)
    }

    fn codec_write(&mut self, register: u8, value: u16) {
        codec::write(register, value);
    }

    fn codec_ready(&mut self) -> bool {
        codec::ready()
    }

    fn codec_feed(&mut self, data: &[u8]) -> usize {
        codec::feed(data)
    }

    fn amplifier(&mut self, on: bool) {
        codec::amplifier(on);
    }

    fn net_state(&mut self) -> i32 {
        if self.stick.is_none() {
            return wifi::S_BROKEN;
        }
        self.station.net_state()
    }

    fn net_send(&mut self, frame: &[u8], dest: &[u8; 6], low_rate: i32) -> i32 {
        let Some((sta, mut radio)) = self.radio() else {
            return 0;
        };
        sta.send(&mut radio, frame, dest, low_rate != 0) as i32
    }

    fn net_mac(&mut self) -> [u8; 6] {
        self.stick.as_ref().map_or([0; 6], |s| s.mac)
    }

    fn net_set_mode(&mut self, mode: i32, ssid: Option<&[u8]>, channel: u8) {
        let name = ssid.map(cstr).unwrap_or(&[]);
        if let Some((sta, mut radio)) = self.radio() {
            sta.set_mode(&mut radio, mode == 1, name, channel);
        }
        self.flush();
    }

    fn net_scan(&mut self, ssid: Option<&[u8]>) -> usize {
        let frame = &mut *self.frame;
        let scan = &mut *self.scan;
        let mut n = 0;
        let Some(stick) = self.stick.as_deref_mut() else {
            return 0;
        };
        let mut radio = Radio {
            stick,
            pool: &mut self.pool,
        };
        self.station
            .scan(&mut radio, ssid.map(cstr), frame, &mut |r| {
                if n < SCAN_RESULTS {
                    let mut ssid = [0u8; 33];
                    ssid[..r.ssid_len].copy_from_slice(&r.ssid[..r.ssid_len]);
                    scan[n] = ScanResult {
                        ssid,
                        mac: r.mac,
                        bssid: r.bssid,
                        rssi: r.rssi,
                        channel: r.channel,
                        rateset: r.rateset,
                        encryption: r.encryption,
                    };
                    n += 1;
                }
            });
        self.held = None;
        self.scanned = n;
        n
    }

    fn net_scan_result(&mut self, i: usize) -> ScanResult {
        if i < self.scanned {
            self.scan[i]
        } else {
            SCAN_NONE
        }
    }

    fn net_auth(&mut self, auth: &Auth<'_>) {
        // The passphrase, for WPA3: the setup page keeps it next to the
        // derived key (CONF_WIFIKEY0), and the bytecode hands over the
        // derived key only.
        let settings = flash::settings();
        let typed = cstr(&settings[92..156]);
        let password = if settings[91] == wifi::CRYPT_WPA2 && (8..=63).contains(&typed.len()) {
            typed
        } else {
            &[][..]
        };
        let ssid = auth.ssid.unwrap_or(&[]);
        let key = auth.key.unwrap_or(&[]);
        let key = match auth.encryption & 0xF0 {
            // WEP: the bytes the bytecode made of what was typed.
            wifi::CRYPT_WEP => &key[..key.len().min(13)],
            _ => &key[..key.len().min(32)],
        };
        if let Some((sta, mut radio)) = self.radio() {
            sta.auth(
                &mut radio,
                ssid,
                &auth.mac,
                &auth.bssid,
                auth.channel,
                auth.rateset,
                auth.authmode == 1,
                auth.encryption,
                key,
                password,
            );
        }
    }

    fn net_pmk(&mut self, ssid: &[u8], passphrase: &[u8]) -> [u8; 32] {
        let ssid = &cstr(ssid)[..cstr(ssid).len().min(32)];
        let passphrase = cstr(passphrase);
        let mut pmk = [0u8; 32];
        let this = &mut *self;
        // Seconds of work: the leds turn, the watchdog is fed, and what
        // arrives meanwhile is thrown away, as in the C firmware.
        pmk.copy_from_slice(&sha1::passphrase_to_pmk(passphrase, ssid, &mut |at| {
            let j = ((at % 4096) >> 6) & 3;
            led::set(1, if j == 0 { 0xFF } else { 0 });
            led::set(2, if j & 1 != 0 { 0xFF } else { 0 });
            led::set(3, if j == 2 { 0xFF } else { 0 });
            watchdog::feed();
            this.held = None;
            while this.net_pending().is_some() {
                this.held = None;
            }
        }));
        pmk
    }

    fn net_rssi(&mut self) -> i32 {
        self.station.rssi_average as i32
    }

    fn net_pending(&mut self) -> Option<usize> {
        self.pump();
        self.held.map(|d| d.len)
    }

    fn net_take(&mut self, data: &mut [u8], source: &mut [u8; 6]) {
        if let Some(d) = self.held.take() {
            let n = d.len.min(data.len());
            data[..n].copy_from_slice(&self.frame[d.start..d.start + n]);
            *source = d.source;
        }
    }

    fn usb_events(&mut self) {
        let Some(slot) = self.stick_slot.take() else {
            return;
        };
        let stick = usb::init()
            .and_then(|()| usb::attach(3000))
            .and_then(|()| usb::enumerate())
            .map_err(rt2573::Error::Usb)
            .and_then(Stick::start);
        match stick {
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
                let m = stick.mac;
                self.pool.mix(u32::from_le_bytes([m[2], m[3], m[4], m[5]]));
                self.stick = Some(slot.write(stick));
            }
            Err(rt2573::Error::Radio(radio)) => {
                // Not the radio chip this firmware knows how to tune.
                uart::write(b"wifi: radio ");
                uart::hex8(radio);
                uart::write(b"\n");
            }
            Err(_) => uart::write(b"wifi: no stick\n"),
        }
    }

    fn net_timer(&mut self) {
        let Some(stick) = self.stick.as_deref_mut() else {
            return;
        };
        let _ = stick.tick();
        let mut radio = Radio {
            stick,
            pool: &mut self.pool,
        };
        self.station.tick(&mut radio);
        // The main loop's rhythm, a little noise for the pool.
        self.pool.mix(timer::millis());
    }
}
