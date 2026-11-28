//! The board as the Metal machine sees it: each method one of the C
//! firmware's functions, done with this firmware's drivers.

use lapin_core::rng::Pool;
use lapin_core::sha1;
use lapin_core::wifi::{self, Link, Station};
use lapin_metal::{Auth, Host, Motor, ScanResult};

use crate::ears::{self, Turn};
use crate::inbox::{self, Inbox};
use crate::wifi::link::Radio;
use crate::wifi::rt2573::{self, Stick};
use crate::{board, codec, flash, i2c, led, rfid, timer, uart, usb, watchdog};

/// How many networks a scan keeps for the bytecode. The C driver put
/// every frame it heard on the machine's stack, as many as the heap
/// held; here frames of the same network (BSSID and name) are merged,
/// the strongest kept, so this counts networks: a dense block of flats
/// is heard as one or two hundred on 2.4 GHz. 256 of 52 bytes, 13 KB,
/// in the external RAM above the machine's memory, where 128 KB are free.
pub const SCAN_RESULTS: usize = 256;

pub struct Board {
    pub stick: Option<&'static mut Stick>,
    /// Where the stick goes once brought up, until it is.
    stick_slot: Option<&'static mut core::mem::MaybeUninit<Stick>>,
    pub station: &'static mut Station,
    pub pool: Pool,
    /// The last frame received; what of the frames is for the bytecode
    /// waits in `inbox`.
    pub frame: &'static mut [u8; 2400],
    inbox: Inbox,
    pub scan: &'static mut [ScanResult; SCAN_RESULTS],
    scanned: usize,
    tags: [rfid::Tag; 16],
    tag_count: usize,
    /// Frames the stick had delivered, and the USB transfer errors
    /// then: errors piling up with no frame since mean it has stopped
    /// receiving.
    rx_seen: u32,
    errors_at_rx: u32,
    /// The stick was looked for once, at the first turn of the main
    /// loop; after that it comes and goes with the port's events.
    stick_tried: bool,
}

/// Transfer errors in a row, no frame received, that make the stick
/// broken for the bytecode (a stalled endpoint fails every millisecond).
const RX_FAILURES: u32 = 16;

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
        inbox: &'static mut [u8; inbox::SIZE],
    ) -> Board {
        scan.fill(SCAN_NONE);
        Board {
            stick: None,
            stick_slot: Some(stick_slot),
            station,
            pool,
            frame,
            inbox: Inbox::new(inbox),
            scan,
            scanned: 0,
            tags: [rfid::Tag::default(); 16],
            tag_count: 0,
            rx_seen: 0,
            errors_at_rx: 0,
            stick_tried: false,
        }
    }

    /// The stick has stopped delivering what it receives, or the USB
    /// controller has failed: until a frame comes again.
    fn receiving_fails(&mut self) -> bool {
        let (got, errors) = (crate::wifi::received(), usb::bulk_errors());
        if got != self.rx_seen {
            self.rx_seen = got;
            self.errors_at_rx = errors;
        }
        usb::broken() || errors.wrapping_sub(self.errors_at_rx) >= RX_FAILURES
    }

    /// The station and the stick together, if there is a stick.
    fn radio(&mut self) -> Option<(&mut Station, Radio<'_>)> {
        Some((&mut *self.station, link(&mut self.stick, &mut self.pool)?))
    }

    /// Take every frame from the stick: the station handles what is
    /// its own (management, handshakes), what is for the bytecode goes
    /// to the inbox. As the C driver did in the USB interrupt, whatever
    /// the bytecode has not taken yet. With `work`, the station's
    /// pending work (a step of a password exchange) is done first: from
    /// the main loop's turns, which feed the sound between steps, not
    /// from a bytecode that asks the state in a loop.
    fn pump(&mut self, work: bool) {
        let frame = &mut *self.frame;
        let Some(mut radio) = link(&mut self.stick, &mut self.pool) else {
            return;
        };
        if work {
            self.station.poll(&mut radio);
        }
        while let Some(rx) = radio.receive(frame) {
            if let Some(d) = self.station.input(&mut radio, frame, rx) {
                self.inbox.push(&frame[d.start..d.start + d.len], &d.source);
            }
        }
    }

    /// Throw away everything received (`rt2501_setmode` does).
    fn flush(&mut self) {
        self.pump(false);
        self.inbox.clear();
    }
}

/// The stick and the random pool as the station's link, if there is a
/// stick: from the fields, so that the station and the frame can be
/// borrowed beside it.
fn link<'a>(stick: &'a mut Option<&'static mut Stick>, pool: &'a mut Pool) -> Option<Radio<'a>> {
    Some(Radio {
        stick: stick.as_deref_mut()?,
        pool,
    })
}

/// Where a frame heard during a scan goes among the `kept` networks:
/// over the same network (BSSID and name) if it is heard stronger, at
/// the end if it is new and there is room, else over the weakest if it
/// is stronger than that; `None` to drop it.
fn merge(kept: &[ScanResult], heard: &ScanResult) -> Option<usize> {
    if let Some(i) = kept
        .iter()
        .position(|k| k.bssid == heard.bssid && k.ssid == heard.ssid)
    {
        return (heard.rssi > kept[i].rssi).then_some(i);
    }
    if kept.len() < SCAN_RESULTS {
        return Some(kept.len());
    }
    let (weakest, k) = kept.iter().enumerate().min_by_key(|(_, k)| k.rssi)?;
    (heard.rssi > k.rssi).then_some(weakest)
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
        timer::seconds()
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
        // Asked for: not a start that failed, for the rescue core.
        crate::boot::Slots::confirm();
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
        // The C driver reported it broken once a receive failed, and
        // never received again; this one tries again, and says broken
        // only while receiving fails.
        if self.stick.is_none() || self.receiving_fails() {
            return wifi::S_BROKEN;
        }
        // The C driver handled management frames in the interrupt, so
        // the state moved while the bytecode ran: what has arrived is
        // taken into account first.
        self.pump(false);
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
        // A nil name for the access point is an empty one: the C driver
        // copied from address 0.
        let name = ssid.map(cstr).unwrap_or(&[]);
        // Any other mode changes nothing, as in the C driver; what was
        // received is thrown away all the same.
        if let (0 | 1, Some((sta, mut radio))) = (mode, self.radio()) {
            sta.set_mode(&mut radio, mode == 1, name, channel);
            // An access point hears its own announcements only.
            let own = radio.stick.mac;
            crate::wifi::keep_announcements((mode == 1).then_some(&own));
        }
        self.flush();
    }

    fn net_scan(&mut self, ssid: Option<&[u8]>) -> usize {
        // What came before stays for the bytecode, as in the C driver's
        // queue: the scan takes what comes during it.
        self.pump(false);
        let frame = &mut *self.frame;
        let scan = &mut *self.scan;
        let mut n = 0;
        let Some(mut radio) = link(&mut self.stick, &mut self.pool) else {
            return 0;
        };
        crate::wifi::keep_announcements(None);
        self.station
            .scan(&mut radio, ssid.map(cstr), frame, &mut |r| {
                let mut ssid = [0u8; 33];
                ssid[..r.ssid_len].copy_from_slice(&r.ssid[..r.ssid_len]);
                let heard = ScanResult {
                    ssid,
                    mac: r.mac,
                    bssid: r.bssid,
                    rssi: r.rssi,
                    channel: r.channel,
                    rateset: r.rateset,
                    encryption: r.encryption,
                };
                if let Some(slot) = merge(&scan[..n], &heard) {
                    if slot == n {
                        n += 1;
                    }
                    scan[slot] = heard;
                }
            });
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
        // From now on only this network's announcements matter.
        crate::wifi::keep_announcements(Some(&auth.bssid));
        if let Some((sta, mut radio)) = self.radio() {
            sta.auth(
                &mut radio,
                ssid,
                &auth.mac,
                &auth.bssid,
                auth.channel,
                auth.rateset,
                // Any mode but open system is a shared key's, as in the
                // C driver; only WEP has shared keys (the station uses
                // it for WEP alone, where the C driver sent it on any
                // network).
                auth.authmode != 0,
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
            this.flush();
        }));
        pmk
    }

    fn net_rssi(&mut self) -> i32 {
        self.station.rssi_average as i32
    }

    fn net_pending(&mut self) -> Option<usize> {
        self.pump(true);
        self.inbox.front()
    }

    fn net_take(&mut self, data: &mut [u8], source: &mut [u8; 6]) {
        self.inbox.pop(data, source);
    }

    // The stick lost and plugged back is brought up again, as the C's
    // usbhost_events does.
    fn usb_events(&mut self) {
        if usb::take_disconnected()
            && let Some(stick) = self.stick.take()
        {
            uart::write(b"wifi: stick lost\n");
            // SAFETY: a Stick has no destructor and nothing else refers
            // to it any more: its place is the slot again.
            self.stick_slot = Some(unsafe { &mut *(stick as *mut Stick).cast() });
        }
        let Some(slot) = self.stick_slot.take() else {
            return;
        };
        let again = self.stick_tried;
        let result = if !again {
            self.stick_tried = true;
            Stick::bring_up()
        } else if usb::take_connected() {
            Stick::reconnect()
        } else {
            self.stick_slot = Some(slot);
            return;
        };
        match result {
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
                // The 64 readings at boot came within a millisecond: a
                // quarter of a second more, spread over the ticks,
                // before the radio is of any use.
                for _ in 0..256 {
                    self.pool.mix(board::noise());
                }
                self.stick = Some(slot.write(stick));
                if again {
                    // A new stick knows nothing of the old link: the
                    // station starts again from idle (the C's
                    // ieee80211_init), and the bytecode joins anew.
                    if let Some((sta, mut radio)) = self.radio() {
                        sta.set_mode(&mut radio, false, &[], 0);
                    }
                }
            }
            Err(rt2573::Error::Radio(radio)) => {
                // Not the radio chip this firmware knows how to tune.
                uart::write(b"wifi: radio ");
                uart::hex8(radio);
                uart::write(b"\n");
            }
            Err(_) => {
                uart::write(b"wifi: no stick\n");
                // It may still come: the port says when.
                self.stick_slot = Some(slot);
            }
        }
    }

    fn net_timer(&mut self) {
        let Some(mut radio) = link(&mut self.stick, &mut self.pool) else {
            return;
        };
        let _ = radio.stick.tick();
        self.station.tick(&mut radio);
        // The main loop's rhythm, a little noise for the pool.
        self.pool.mix(timer::millis());
    }
}
