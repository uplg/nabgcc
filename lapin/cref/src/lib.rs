//! The C firmware's virtual machine and the Rust one, side by side, on
//! the same board.
//!
//! [`World`] is that board: a deterministic rabbit with a settings
//! sector, a codec, ears, a Wi-Fi driver that hears one access point
//! and a network behind it (the emulator's [`Lan`]: DHCP, DNS, HTTP).
//! It writes down every call the machine makes. [`run_c`] runs the C
//! machine (built by `build.rs`) on it, [`run_rust`] runs
//! `lapin-metal`; what they did, what they printed and what their
//! memory holds at the end can then be compared word for word.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Mutex;

use lapin_metal::{Auth, Host, Memory, Motor, ScanResult, VMEM_LENGTH, Vm};
use nabemu::lan::{Lan, Response};

pub const MAC: [u8; 6] = nabemu::DEFAULT_MAC;
pub const BSSID: [u8; 6] = [0x02, 0, 0, 0, 0, 0xA1];
const LLC_SNAP: [u8; 6] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];

/// How much board time a turn of the USB events takes.
const USB_EVENTS_MS: u64 = 10;
/// The codec's input buffer, and what it plays in a turn of the USB
/// events (16 KB/s, a 128 kbit/s MP3).
const CODEC_FIFO: usize = 2048;
const CODEC_DRAIN: usize = 160;

/// The board.
pub struct World {
    /// Every call the machine made, in order.
    pub log: Vec<String>,
    pub console: Vec<u8>,
    pub now_ms: u64,
    pub settings: Vec<u8>,
    pub net_state: i32,
    pub networks: Vec<ScanResult>,
    pub lan: Lan,
    rx: VecDeque<(Vec<u8>, [u8; 6])>,
    pub codec: [u16; 16],
    /// Bytes waiting in the codec's 2 KB input buffer.
    pub codec_level: usize,
    /// Bytes the codec took, all told.
    pub codec_fed: usize,
    pub motors: [u16; 2],
    pub button: u8,
    pub adc: u8,
    pub rebooted: bool,
    /// Set by the test to stop the run once the machine has printed it.
    pub stop_at: Option<Vec<u8>>,
    /// The tags in front of the reader, whose blocks read and write.
    pub tags: Vec<[u8; 8]>,
    /// What `net_send` answers: 1, the frame went.
    pub send_result: i32,
    /// Board time each call that shows in the log, and each byte
    /// printed, takes: the clock the machine reads moves between its
    /// calls.
    pub ms_per_call: u64,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl World {
    /// A rabbit set up for the open network "Terrier", whose server
    /// answers every request with `body`.
    pub fn new(body: Vec<u8>) -> Self {
        Self::with_wifi(body, nabemu::config::Wifi::Open, 0)
    }

    /// The same, its server answering every request with nothing.
    pub fn quiet() -> Self {
        Self::new(Vec::new())
    }

    /// The same, set up for `wifi`, the access point advertising
    /// `encryption` (`IEEE80211_CRYPT_*`).
    pub fn with_wifi(body: Vec<u8>, wifi: nabemu::config::Wifi, encryption: u8) -> Self {
        let mut settings = vec![0xFF; 4096];
        let config = nabemu::config::Config::new("Terrier", wifi);
        settings[..nabemu::config::LENGTH].copy_from_slice(&config.to_bytes());
        let mut lan = Lan::new();
        lan.handler = Box::new(move |_| Response::ok(body.clone()));
        let mut ssid = [0u8; 33];
        ssid[..7].copy_from_slice(b"Terrier");
        World {
            log: Vec::new(),
            console: Vec::new(),
            now_ms: 0,
            settings,
            net_state: 1,
            networks: vec![ScanResult {
                ssid,
                mac: BSSID,
                bssid: BSSID,
                rssi: 50,
                channel: 6,
                rateset: 255,
                encryption,
            }],
            lan,
            rx: VecDeque::new(),
            codec: [0; 16],
            codec_level: 0,
            codec_fed: 0,
            motors: [0; 2],
            button: 0,
            adc: 200,
            rebooted: false,
            stop_at: None,
            tags: vec![
                [0xD0, 0x02, 0x1A, 0x03, 0x52, 0xC4, 0x66, 0x7F],
                [0xD0, 0x02, 0x18, 0x01, 0x02, 0x03, 0x04, 0x05],
            ],
            send_result: 1,
            ms_per_call: 1,
        }
    }

    fn note(&mut self, s: String) {
        self.log.push(s);
        self.now_ms += self.ms_per_call;
    }

    /// What block `block` of tag `id` holds: made of both, so that a
    /// read shows which tag and block it was.
    fn block(id: &[u8; 8], block: i32) -> [u8; 4] {
        let b = block as u8;
        [id[7] ^ b, id[6].wrapping_add(b), b, id[0]]
    }

    /// Frames the network sent to the rabbit, as the driver hands them
    /// over: from the LLC header on.
    fn collect(&mut self) {
        self.lan.poll(self.now_ms);
        while let Some(eth) = self.lan.output() {
            if eth.len() < 14 || (eth[..6] != MAC && eth[..6] != [0xFF; 6]) {
                continue;
            }
            let mut data = LLC_SNAP.to_vec();
            data.extend_from_slice(&eth[12..]);
            let source = eth[6..12].try_into().unwrap();
            self.rx.push_back((data, source));
        }
    }

    fn note_flash(&mut self, image: &[u8]) {
        self.note(format!("flash {} bytes", image.len()));
        self.rebooted = true;
    }

    fn note_reboot(&mut self) {
        self.note("reboot".into());
        self.rebooted = true;
    }

    fn done(&self) -> bool {
        match &self.stop_at {
            Some(text) => self.console.windows(text.len()).any(|w| w == text),
            None => false,
        }
    }
}

impl Host for World {
    fn console(&mut self, text: &[u8]) {
        self.console.extend_from_slice(text);
        // By the byte: the serial port carries bytes, and the two
        // machines may cut the same text into different calls.
        self.now_ms += self.ms_per_call * text.len() as u64;
    }
    fn time_ms(&mut self) -> u32 {
        self.now_ms as u32
    }
    fn time_s(&mut self) -> u32 {
        (self.now_ms / 1000) as u32
    }
    fn led(&mut self, led: u8, color: u32) {
        self.note(format!("led {led} {color:06x}"));
    }
    fn motor(&mut self, motor: u8, run: Motor) {
        self.note(format!("motor {motor} {run:?}"));
    }
    fn motor_position(&mut self, motor: u8) -> u16 {
        let p = &mut self.motors[(motor & 1) as usize];
        *p = p.wrapping_add(1);
        *p
    }
    fn button(&mut self) -> u8 {
        self.button
    }
    fn adc(&mut self) -> u8 {
        self.adc
    }
    fn rfid_first(&mut self) -> Option<[u8; 8]> {
        self.tags.first().copied()
    }
    fn rfid_count(&mut self) -> i32 {
        self.tags.len() as i32
    }
    fn rfid_nth(&mut self, i: i32) -> [u8; 8] {
        self.tags.get(i as usize).copied().unwrap_or([0; 8])
    }
    fn rfid_read(&mut self, id: &[u8; 8], block: i32, data: &mut [u8; 4]) -> i32 {
        self.note(format!("rfid read {} {block}", hex(id)));
        if !self.tags.contains(id) {
            return 1;
        }
        *data = Self::block(id, block);
        0
    }
    fn rfid_write(&mut self, id: &[u8; 8], block: i32, data: &[u8; 4]) -> i32 {
        self.note(format!("rfid write {} {block} {}", hex(id), hex(data)));
        if self.tags.contains(id) { 0 } else { 1 }
    }
    fn i2c_read(&mut self, address: u8, data: &mut [u8]) -> bool {
        self.note(format!("i2c read {address} {}", data.len()));
        true
    }
    fn i2c_write(&mut self, address: u8, data: &[u8]) -> bool {
        self.note(format!("i2c write {address} {}", hex(data)));
        true
    }
    fn settings_read(&mut self, offset: u32, data: &mut [u8]) {
        let o = offset as usize;
        data.copy_from_slice(&self.settings[o..o + data.len()]);
    }
    fn settings_write(&mut self, offset: u32, data: &[u8]) {
        self.note(format!("settings write {offset} {}", hex(data)));
        let o = offset as usize;
        self.settings[o..o + data.len()].copy_from_slice(data);
    }
    fn flash_firmware(&mut self, image: &[u8]) -> ! {
        self.note_flash(image);
        std::panic::panic_any(Rebooted)
    }
    fn reboot(&mut self) -> ! {
        self.note_reboot();
        std::panic::panic_any(Rebooted)
    }
    fn codec_read(&mut self, register: u8) -> u16 {
        let recording = self.codec[0] & 0x1000 != 0;
        match register {
            // While recording: a block of 128 words ready, and its words.
            9 if recording => 0x80,
            8 if recording => {
                self.codec[8] = self.codec[8].wrapping_add(0x0101);
                self.codec[8]
            }
            _ => self.codec[(register & 15) as usize],
        }
    }
    fn codec_write(&mut self, register: u8, value: u16) {
        self.note(format!("codec {register} {value:04x}"));
        self.codec[(register & 15) as usize] = value;
    }
    fn codec_ready(&mut self) -> bool {
        // DREQ: room for 32 more bytes.
        self.codec_level + 32 <= CODEC_FIFO
    }
    fn codec_feed(&mut self, data: &[u8]) -> usize {
        let mut n = 0;
        while n < data.len() && self.codec_ready() {
            self.codec_level += 1;
            n += 1;
        }
        self.codec_fed += n;
        // One line per run of bytes keeps the log readable.
        if let Some(last) = self.log.last_mut()
            && last.starts_with("sdi ")
        {
            last.push_str(&hex(&data[..n]));
        } else {
            self.note(format!("sdi {}", hex(&data[..n])));
        }
        n
    }
    fn amplifier(&mut self, on: bool) {
        self.note(format!("amplifier {on}"));
    }
    fn net_state(&mut self) -> i32 {
        self.net_state
    }
    fn net_send(&mut self, frame: &[u8], dest: &[u8; 6], low_rate: i32) -> i32 {
        self.note(format!("send {} {low_rate} {}", hex(dest), hex(frame)));
        if frame.len() >= 8 && frame[..6] == LLC_SNAP {
            let mut eth = dest.to_vec();
            eth.extend_from_slice(&MAC);
            eth.extend_from_slice(&frame[6..]);
            self.lan.input(eth);
            self.collect();
        }
        self.send_result
    }
    fn net_mac(&mut self) -> [u8; 6] {
        MAC
    }
    fn net_set_mode(&mut self, mode: i32, ssid: Option<&[u8]>, channel: u8) {
        self.note(format!("setmode {mode} {:?} {channel}", ssid.map(hex)));
    }
    fn net_scan(&mut self, ssid: Option<&[u8]>) -> usize {
        self.note(format!("scan {:?}", ssid.map(hex)));
        self.networks.len()
    }
    fn net_scan_result(&mut self, i: usize) -> ScanResult {
        self.networks[i]
    }
    fn net_auth(&mut self, a: &Auth<'_>) {
        self.note(format!(
            "auth {:?} {} {} {} {} {} {} {:?}",
            a.ssid.map(hex),
            hex(&a.mac),
            hex(&a.bssid),
            a.channel,
            a.rateset,
            a.authmode,
            a.encryption,
            a.key.map(hex)
        ));
        self.net_state = 4;
    }
    fn net_pmk(&mut self, ssid: &[u8], passphrase: &[u8]) -> [u8; 32] {
        self.note(format!("pmk {} {}", hex(ssid), hex(passphrase)));
        nabemu::crypto::wpa_psk(
            std::str::from_utf8(passphrase).unwrap_or(""),
            std::str::from_utf8(ssid).unwrap_or(""),
        )
    }
    fn net_rssi(&mut self) -> i32 {
        -40
    }
    fn net_pending(&mut self) -> Option<usize> {
        self.rx.front().map(|(f, _)| f.len())
    }
    fn net_take(&mut self, data: &mut [u8], source: &mut [u8; 6]) {
        if let Some((f, s)) = self.rx.pop_front() {
            let n = data.len().min(f.len());
            data[..n].copy_from_slice(&f[..n]);
            *source = s;
        }
    }
    fn usb_events(&mut self) {
        self.now_ms += USB_EVENTS_MS;
        self.codec_level = self.codec_level.saturating_sub(CODEC_DRAIN);
        self.collect();
    }
}

// The C machine, and its way back to the world.

unsafe extern "C" {
    fn cvm_boot(bytecode: *const u8);
    fn cvm_loop_once();
    fn cvm_heap_address() -> u32;
    fn cvm_heap() -> *const i32;
    fn cvm_fifo() -> *const u8;
    fn cvm_stack() -> i32;
    fn cvm_heapindex() -> i32;
    fn cvm_start() -> i32;
}

thread_local! {
    static WORLD: RefCell<Option<World>> = const { RefCell::new(None) };
}

/// One C machine per process: its state is global.
static C_MACHINE: Mutex<()> = Mutex::new(());

fn with<R>(f: impl FnOnce(&mut World) -> R) -> R {
    WORLD.with(|w| f(w.borrow_mut().as_mut().expect("a world for the C machine")))
}

unsafe fn bytes<'a>(p: *const u8, n: u32) -> &'a [u8] {
    if n == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(p, n as usize) }
    }
}

unsafe fn bytes_mut<'a>(p: *mut u8, n: u32) -> &'a mut [u8] {
    if n == 0 {
        &mut []
    } else {
        unsafe { std::slice::from_raw_parts_mut(p, n as usize) }
    }
}

unsafe fn array<const N: usize>(p: *const u8) -> [u8; N] {
    unsafe { bytes(p, N as u32) }.try_into().unwrap()
}

mod ffi {
    use super::*;

    #[unsafe(no_mangle)]
    extern "C" fn rs_console(p: *const u8, n: u32) {
        let s = unsafe { bytes(p, n) };
        with(|w| w.console(s));
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_time_ms() -> u32 {
        with(|w| w.time_ms())
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_time_s() -> u32 {
        with(|w| w.time_s())
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_led(led: u32, color: u32) {
        with(|w| w.led(led as u8, color));
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_motor(motor: u32, run: u32) {
        let run = match run {
            0 => Motor::Stop,
            1 => Motor::Forward,
            _ => Motor::Reverse,
        };
        with(|w| w.motor(motor as u8, run));
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_motor_position(motor: u32) -> u32 {
        with(|w| w.motor_position(motor as u8)) as u32
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_button() -> u32 {
        with(|w| w.button()) as u32
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_adc() -> u32 {
        with(|w| w.adc()) as u32
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_rfid_first(id: *mut u8) -> i32 {
        match with(|w| w.rfid_first()) {
            Some(v) => {
                unsafe { bytes_mut(id, 8) }.copy_from_slice(&v);
                1
            }
            None => 0,
        }
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_rfid_count() -> i32 {
        with(|w| w.rfid_count())
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_rfid_nth(i: i32, id: *mut u8) {
        let v = with(|w| w.rfid_nth(i));
        unsafe { bytes_mut(id, 8) }.copy_from_slice(&v);
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_rfid_read(id: *const u8, block: i32, data: *mut u8) -> i32 {
        let id = unsafe { array::<8>(id) };
        let mut d = [0u8; 4];
        let r = with(|w| w.rfid_read(&id, block, &mut d));
        unsafe { bytes_mut(data, 4) }.copy_from_slice(&d);
        r
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_rfid_write(id: *const u8, block: i32, data: *const u8) -> i32 {
        let (id, d) = unsafe { (array::<8>(id), array::<4>(data)) };
        with(|w| w.rfid_write(&id, block, &d))
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_i2c_read(address: u32, data: *mut u8, n: u32) -> i32 {
        let d = unsafe { bytes_mut(data, n) };
        with(|w| w.i2c_read(address as u8, d)) as i32
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_i2c_write(address: u32, data: *const u8, n: u32) -> i32 {
        let d = unsafe { bytes(data, n) };
        with(|w| w.i2c_write(address as u8, d)) as i32
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_settings_read(offset: u32, data: *mut u8, n: u32) {
        let d = unsafe { bytes_mut(data, n) };
        with(|w| w.settings_read(offset, d));
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_settings_write(offset: u32, data: *const u8, n: u32) {
        let d = unsafe { bytes(data, n) };
        with(|w| w.settings_write(offset, d));
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_flash_firmware(data: *const u8, n: i32) {
        let d = unsafe { bytes(data, n as u32) };
        with(|w| w.note_flash(d));
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_reboot() {
        with(|w| w.note_reboot());
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_codec_read(reg: u32) -> u32 {
        with(|w| w.codec_read(reg as u8)) as u32
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_codec_write(reg: u32, value: u32) {
        with(|w| w.codec_write(reg as u8, value as u16));
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_codec_ready() -> i32 {
        with(|w| w.codec_ready()) as i32
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_codec_feed(data: *const u8, n: u32) -> u32 {
        let d = unsafe { bytes(data, n) };
        with(|w| w.codec_feed(d)) as u32
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_amplifier(on: i32) {
        with(|w| w.amplifier(on != 0));
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_net_state() -> i32 {
        with(|w| w.net_state())
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_net_send(frame: *const u8, n: u32, dest: *const u8, low_rate: i32) -> i32 {
        let (f, d) = unsafe { (bytes(frame, n), array::<6>(dest)) };
        with(|w| w.net_send(f, &d, low_rate))
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_net_mac(mac: *mut u8) {
        let m = with(|w| w.net_mac());
        unsafe { bytes_mut(mac, 6) }.copy_from_slice(&m);
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_net_set_mode(mode: i32, ssid: *const u8, len: u32, has: i32, channel: u32) {
        let s = (has != 0).then(|| unsafe { bytes(ssid, len) });
        with(|w| w.net_set_mode(mode, s, channel as u8));
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_net_scan(ssid: *const u8, len: u32, has: i32) -> i32 {
        let s = (has != 0).then(|| unsafe { bytes(ssid, len) });
        with(|w| w.net_scan(s)) as i32
    }
    #[unsafe(no_mangle)]
    #[allow(clippy::too_many_arguments)]
    extern "C" fn rs_net_scan_result(
        i: i32,
        ssid: *mut u8,
        mac: *mut u8,
        bssid: *mut u8,
        rssi: *mut i32,
        channel: *mut u32,
        rateset: *mut u32,
        encryption: *mut u32,
    ) {
        let r = with(|w| w.net_scan_result(i as usize));
        unsafe {
            bytes_mut(ssid, 33).copy_from_slice(&r.ssid);
            bytes_mut(mac, 6).copy_from_slice(&r.mac);
            bytes_mut(bssid, 6).copy_from_slice(&r.bssid);
            *rssi = r.rssi as i32;
            *channel = r.channel as u32;
            *rateset = r.rateset as u32;
            *encryption = r.encryption as u32;
        }
    }
    #[unsafe(no_mangle)]
    #[allow(clippy::too_many_arguments)]
    extern "C" fn rs_net_auth(
        ssid: *const u8,
        ssid_len: u32,
        has_ssid: i32,
        mac: *const u8,
        bssid: *const u8,
        channel: u32,
        rateset: u32,
        authmode: u32,
        encryption: u32,
        key: *const u8,
        key_len: u32,
        has_key: i32,
    ) {
        let a = unsafe {
            Auth {
                ssid: (has_ssid != 0).then(|| bytes(ssid, ssid_len)),
                mac: array(mac),
                bssid: array(bssid),
                channel: channel as u8,
                rateset: rateset as u16,
                authmode: authmode as u8,
                encryption: encryption as u8,
                key: (has_key != 0).then(|| bytes(key, key_len)),
            }
        };
        with(|w| w.net_auth(&a));
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_net_pmk(
        ssid: *const u8,
        ssid_len: u32,
        key: *const u8,
        key_len: u32,
        pmk: *mut u8,
    ) {
        let (s, k) = unsafe { (bytes(ssid, ssid_len), bytes(key, key_len)) };
        let p = with(|w| w.net_pmk(s, k));
        unsafe { bytes_mut(pmk, 32) }.copy_from_slice(&p);
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_net_rssi() -> i32 {
        with(|w| w.net_rssi())
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_net_pending() -> i32 {
        with(|w| w.net_pending()).map_or(-1, |n| n as i32)
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_net_take(data: *mut u8, mac: *mut u8) {
        let len = with(|w| w.net_pending()).unwrap_or(0).min(4096);
        let d = unsafe { bytes_mut(data, len as u32) };
        let mut m = [0u8; 6];
        with(|w| w.net_take(d, &mut m));
        unsafe { bytes_mut(mac, 6) }.copy_from_slice(&m);
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_usb_events() {
        with(|w| w.usb_events());
    }
    #[unsafe(no_mangle)]
    extern "C" fn rs_net_timer() {
        with(|w| w.net_timer());
    }
}

/// How the Rust machine's board stops it when it resets.
pub struct Rebooted;

/// What a run leaves behind.
pub struct Outcome {
    pub world: World,
    pub heap: Vec<i32>,
    pub fifo: Vec<u8>,
    /// Stack pointer, next free word, first heap word.
    pub registers: (i32, i32, i32),
    pub turns: usize,
}

/// Run the C machine: boot `bytecode`, then up to `turns` turns of the
/// main loop, fewer if the world says it has seen enough.
pub fn run_c(world: World, bytecode: &[u8], turns: usize) -> Outcome {
    let _one = C_MACHINE.lock().unwrap_or_else(|e| e.into_inner());
    WORLD.with(|w| *w.borrow_mut() = Some(world));
    let mut done = 0;
    unsafe {
        cvm_boot(bytecode.as_ptr());
        while done < turns && !with(|w| w.done() || w.rebooted) {
            cvm_loop_once();
            done += 1;
        }
    }
    let world = WORLD.with(|w| w.borrow_mut().take().unwrap());
    unsafe {
        Outcome {
            world,
            heap: std::slice::from_raw_parts(cvm_heap(), VMEM_LENGTH).to_vec(),
            fifo: std::slice::from_raw_parts(cvm_fifo(), lapin_metal::AUDIO_FIFOPLAY).to_vec(),
            registers: (cvm_stack(), cvm_heapindex(), cvm_start()),
            turns: done,
        }
    }
}

/// Run both machines on worlds `world` makes alike, fail on the first
/// difference between them, and give back what the C one did.
pub fn run_both(world: impl Fn() -> World, bytecode: &[u8], turns: usize) -> Outcome {
    let c = run_c(world(), bytecode, turns);
    let r = run_rust(world(), bytecode, turns);
    assert_same(&c, &r);
    c
}

/// Fail on the first difference between a run of the C machine and one
/// of the Rust machine.
pub fn assert_same(c: &Outcome, r: &Outcome) {
    let (cc, rc) = (
        String::from_utf8_lossy(&c.world.console),
        String::from_utf8_lossy(&r.world.console),
    );
    if cc != rc {
        let at = cc
            .chars()
            .zip(rc.chars())
            .take_while(|(a, b)| a == b)
            .count();
        panic!(
            "consoles differ at {at}:\nC:    {:?}\nRust: {:?}",
            &cc[at.saturating_sub(200).min(cc.len())..(at + 200).min(cc.len())],
            &rc[at.saturating_sub(200).min(rc.len())..(at + 200).min(rc.len())]
        );
    }
    for (i, (a, b)) in c.world.log.iter().zip(&r.world.log).enumerate() {
        assert_eq!(a, b, "call {i} differs");
    }
    assert_eq!(c.world.log.len(), r.world.log.len(), "number of calls");
    assert_eq!(c.registers, r.registers, "stack, heap index, heap start");
    assert_same_memory(&c.heap, &r.heap, "");
    assert_eq!(c.fifo, r.fifo, "audio buffer");
    assert_eq!(c.turns, r.turns, "turns");
}

/// Fail on the first word where the C machine's memory and the Rust
/// one's differ; `what` heads the message.
pub fn assert_same_memory(c: &[i32], r: &[i32], what: &str) {
    if let Some(i) = (0..c.len()).find(|&i| c[i] != r[i]) {
        panic!(
            "{what}memory differs from word {i}: C {:08x}, Rust {:08x}",
            c[i], r[i]
        );
    }
}

/// Where the C machine's heap is, as its collector prints it.
pub fn c_heap_address() -> u32 {
    unsafe { cvm_heap_address() }
}

/// Run `lapin-metal` the same way.
pub fn run_rust(world: World, bytecode: &[u8], turns: usize) -> Outcome {
    let mut mem: Box<Memory> = vec_memory();
    let mut vm = Vm::new(world, &mut mem);
    vm.heap_address = c_heap_address();
    let mut done = 0;
    let quiet = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.payload().downcast_ref::<Rebooted>().is_none() {
            quiet(info)
        }
    }));
    let run = |vm: &mut Vm<'_, World>, f: &dyn Fn(&mut Vm<'_, World>)| {
        if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(vm)))
            && e.downcast_ref::<Rebooted>().is_none()
        {
            std::panic::resume_unwind(e);
        }
    };
    run(&mut vm, &|vm| vm.boot(bytecode));
    while done < turns && !(vm.host.done() || vm.host.rebooted) {
        run(&mut vm, &|vm| vm.main_loop_once());
        done += 1;
    }
    let registers = vm.registers();
    let world = vm.into_host();
    Outcome {
        world,
        heap: mem.heap.to_vec(),
        fifo: mem.fifo.to_vec(),
        registers,
        turns: done,
    }
}

/// An 804 KB memory, straight on the heap.
fn vec_memory() -> Box<Memory> {
    let layout = std::alloc::Layout::new::<Memory>();
    unsafe {
        let p = std::alloc::alloc_zeroed(layout) as *mut Memory;
        assert!(!p.is_null());
        Box::from_raw(p)
    }
}

/// The boot bytecode the r3 firmware carries, found in its image: the
/// first place where a whole bytecode parses (sizes that fit, globals
/// that end exactly where the code starts).
pub fn boot_bytecode() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../artifacts/Nab-wpa23-gtk-r3.sim"
    );
    let sim = std::fs::read(path).expect("the r3 image in artifacts/");
    let image = nabemu::elf::decode_sim(&sim).expect("a .sim image");
    for o in (0..image.len() - 16).step_by(4) {
        if let Some(n) = parse_bytecode(&image[o..]) {
            return image[o..o + n].to_vec();
        }
    }
    panic!("no bytecode in the r3 image");
}

/// The size of the bytecode at the start of `b`, if one is there.
pub fn parse_bytecode(b: &[u8]) -> Option<usize> {
    let int =
        |o: usize| -> Option<u32> { Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?)) };
    let globals = int(0)? as usize;
    if !(8..0x10000).contains(&globals) {
        return None;
    }
    let code = int(globals)? as usize;
    if !(0x100..0x20000).contains(&code) {
        return None;
    }
    let tab = globals + 4 + code;
    let nfun = u16::from_le_bytes(b.get(tab..tab + 2)?.try_into().ok()?) as usize;
    if !(1..4096).contains(&nfun) {
        return None;
    }
    let total = tab + 2 + 4 * nfun;
    if total > b.len() {
        return None;
    }
    // Every function starts inside the code.
    for f in 0..nfun {
        if int(tab + 2 + 4 * f)? as usize >= code {
            return None;
        }
    }
    let mut at = 4;
    while at < globals {
        at = skip_global(b, at, 0)?;
    }
    (at == globals).then_some(total)
}

fn skip_global(b: &[u8], at: usize, depth: u32) -> Option<usize> {
    if depth > 4096 {
        return None;
    }
    let l = i32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?);
    let at = at + 4;
    if l == -1 || l & 1 == 0 {
        return Some(at);
    }
    let l = l >> 1;
    if l & 1 != 0 {
        let mut at = at;
        for _ in 0..(l >> 1).max(0) {
            at = skip_global(b, at, depth + 1)?;
        }
        Some(at)
    } else {
        let n = (l >> 1) as usize;
        (n < 0x10000).then_some(at + n)
    }
}

/// Garenne, the rabbit's application, when its build is around: the
/// `NABEMU_GARENNE` file, or `clapier/garenne/build/garenne.bin` beside
/// any directory above this one.
pub fn garenne() -> Option<Vec<u8>> {
    if let Ok(path) = std::env::var("NABEMU_GARENNE") {
        return std::fs::read(path).ok();
    }
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    here.ancestors()
        .map(|d| d.join("clapier/garenne/build/garenne.bin"))
        .find_map(|p| std::fs::read(p).ok())
}

/// The bytecode in the envelope the boot bytecode expects from its
/// server.
pub fn served(bytecode: &[u8]) -> Vec<u8> {
    nabemu::metal::boot_response(bytecode)
}
