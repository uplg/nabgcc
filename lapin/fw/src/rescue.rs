//! The rescue core's network: an open access point of its own, an
//! address for whoever joins it (DHCP), and a page to send it a new
//! firmware image from a phone or a computer. Small on purpose, and
//! made of nothing the application's updates can touch.
//!
//! One station at a time is served, one TCP connection at a time, with
//! one segment in flight: enough for a page and an upload.

use crate::boot::{self, RESCUE_SIZE, Slots};
use crate::flash::{self, SECTOR};
use crate::wifi::rt2573::{Stick, TxOptions};
use crate::{timer, uart, watchdog};

pub const IP: [u8; 4] = [192, 168, 0, 1];
const CLIENT_IP: [u8; 4] = [192, 168, 0, 100];
const BROADCAST: [u8; 6] = [0xFF; 6];
const CHANNEL: u8 = 1;
const MSS: usize = 1024;
const WINDOW: u16 = 4096;
const RETRY_MS: u32 = 300;
/// With an application in place, the rescue core gives it another try
/// after this long without a visit.
const IDLE_MS: u32 = 10 * 60 * 1000;

const PAGE: &[u8] = b"HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width\">\
<title>Nabaztag</title><h1>Lapin en secours</h1>\
<p>Choisis l'image <b>lapin-full.bin</b> et envoie-la :</p>\
<p><input type=file id=f> <button onclick=\"m.textContent='Envoi...';\
fetch('/flash',{method:'POST',body:f.files[0]}).then(r=>r.text()).then(t=>m.textContent=t)\">\
Envoyer</button></p><p id=m></p>\
<p><a href=/restart>Red\xc3\xa9marrer sans rien changer</a></p>";
const FLASHING: &[u8] =
    b"HTTP/1.0 200 OK\r\n\r\nImage re\xc3\xa7ue, \xc3\xa9criture puis red\xc3\xa9marrage.\n";
const REFUSED: &[u8] = b"HTTP/1.0 400 Bad Request\r\n\r\nCe n'est pas une image du lapin.\n";
const RESTARTING: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nRed\xc3\xa9marrage.\n";
const NO_APP: &[u8] =
    b"HTTP/1.0 409 Conflict\r\n\r\nAucune application en place : envoie une image.\n";
const NOT_FOUND: &[u8] = b"HTTP/1.0 404 Not Found\r\n\r\n";

/// What to do once the answer has gone.
#[derive(Clone, Copy, PartialEq)]
enum After {
    Nothing,
    Flash(usize),
    Restart,
}

#[derive(Clone, Copy, PartialEq)]
enum Tcp {
    Listen,
    SynReceived,
    Established,
    /// Answer sent, our FIN out.
    Closing,
}

/// The end of a connection: whether our FIN was acknowledged, the
/// peer's FIN received.
#[derive(Clone, Copy, PartialEq)]
struct Ends {
    ours_acked: bool,
    theirs: bool,
}

impl Ends {
    /// Neither end closed yet.
    const OPEN: Ends = Ends {
        ours_acked: false,
        theirs: false,
    };
}

// Word aligned: the flash routine reads it a word at a time.
#[repr(C, align(4))]
struct Upload(core::cell::UnsafeCell<[u8; 128 * 1024]>);
// SAFETY: the rescue core's main loop alone touches it.
unsafe impl Sync for Upload {}
#[unsafe(link_section = ".xram.upload")]
static UPLOAD: Upload = Upload(core::cell::UnsafeCell::new([0; 128 * 1024]));

/// The first start after the C firmware wrote `lapin-first.bin`: the
/// packed application (`boot::packed_app`) unpacked into the upload
/// buffer, behind a copy of this core (the history it was packed
/// against), checked whole, then written. Returns only if there is
/// nothing to install, or it does not check.
///
/// It is written in two steps, each ending in a restart: first the
/// sectors past the packed application's, which leaves it whole (a
/// power cut there: unpacked and written again); then the rest, over
/// it (a cut there leaves neither: the rescue network). The sectors
/// already right are left alone, so the second time round the first
/// step is skipped.
pub fn install_packed() {
    let Some((stream, len, crc)) = boot::packed_app() else {
        return;
    };
    // SAFETY: the upload buffer, which nothing else uses before the
    // rescue network is up; an application fits in it behind the core.
    let buf = unsafe { &mut (&mut *UPLOAD.0.get())[..RESCUE_SIZE + len] };
    buf[..RESCUE_SIZE].copy_from_slice(boot::installed_rescue());
    if !lapin_core::pack::unpack(stream, buf, RESCUE_SIZE, watchdog::feed) {
        return;
    }
    let app = &mut buf[RESCUE_SIZE..];
    lapin_core::pack::thumb_calls(app, true);
    if boot::crc32(app) != crc || boot::check_app(app).is_none() {
        return;
    }
    uart::init();
    uart::write(b"secours: unpacked\n");
    let packed_end = (lapin_core::pack::HEADER_LEN + stream.len()).next_multiple_of(SECTOR);
    let placed = boot::installed_area();
    if packed_end < len && placed[packed_end..len] != app[packed_end..] {
        flash::write_at(&app[packed_end..], boot::APP_BASE + packed_end)
    }
    Slots::fresh();
    flash::write_app(app)
}

/// Supported rates: 802.11b's four, 1 Mbit/s the basic one (all the
/// rescue core sends at), which phones expect to find.
const RATES: [u8; 6] = [1, 4, 0x82, 0x04, 0x0B, 0x16];

pub struct Rescue {
    mac: [u8; 6],
    ssid: [u8; 21],
    /// The one station associated.
    peer: Option<[u8; 6]>,
    tcp: Tcp,
    remote: ([u8; 4], u16),
    rcv_nxt: u32,
    iss: u32,
    /// Bytes of the answer acknowledged so far.
    acked: usize,
    sent_at: u32,
    request: usize,
    answer: &'static [u8],
    after: After,
    ends: Ends,
    last_visit: u32,
    /// When the connection under way was last heard from.
    heard_at: u32,
    /// How much of the request was searched for the end of its headers.
    scanned: usize,
    frame: [u8; 1600],
}

fn csum(data: &[u8], mut sum: u32) -> u32 {
    for pair in data.chunks(2) {
        sum += (pair[0] as u32) << 8 | *pair.get(1).unwrap_or(&0) as u32;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Each element of a type, length, value list (802.11's elements,
/// DHCP's options) to `each`, up to the `end` type if there is one or
/// an element cut short.
fn elements<'a>(mut list: &'a [u8], end: Option<u8>, mut each: impl FnMut(u8, &'a [u8])) {
    while let [kind, len, rest @ ..] = list {
        if Some(*kind) == end {
            break;
        }
        let Some(value) = rest.get(..*len as usize) else {
            break;
        };
        each(*kind, value);
        list = &rest[*len as usize..];
    }
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

impl Rescue {
    pub fn new(mac: [u8; 6]) -> Rescue {
        let mut ssid = *b"Nabaztag-secours-0000";
        for (i, nibble) in [mac[4] >> 4, mac[4] & 15, mac[5] >> 4, mac[5] & 15]
            .iter()
            .enumerate()
        {
            ssid[17 + i] = uart::DIGITS[*nibble as usize];
        }
        Rescue {
            mac,
            ssid,
            peer: None,
            tcp: Tcp::Listen,
            remote: ([0; 4], 0),
            rcv_nxt: 0,
            iss: 0,
            acked: 0,
            sent_at: 0,
            request: 0,
            answer: &[],
            after: After::Nothing,
            ends: Ends::OPEN,
            last_visit: timer::millis(),
            heard_at: 0,
            scanned: 0,
            frame: [0; 1600],
        }
    }

    /// Raise the network: beacons, our address as its identity.
    pub fn start(&mut self, stick: &mut Stick) {
        let _ = stick.set_bssid(&self.mac);
        let _ = stick.set_answer_rates(1);
        let _ = stick.set_channel(CHANNEL);
        let n = self.beacon_like(0x80, &BROADCAST);
        let _ = stick.set_beacon(Some(&self.frame[..n]));
    }

    fn header(&mut self, fc0: u8, fc1: u8, a1: &[u8; 6]) -> usize {
        let f = &mut self.frame;
        f[..24].fill(0);
        f[0] = fc0;
        f[1] = fc1;
        f[4..10].copy_from_slice(a1);
        f[10..16].copy_from_slice(&self.mac);
        f[16..22].copy_from_slice(&self.mac);
        24
    }

    fn beacon_like(&mut self, fc0: u8, to: &[u8; 6]) -> usize {
        let mut at = self.header(fc0, 0, to);
        let ssid = self.ssid;
        let f = &mut self.frame;
        f[at..at + 12].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0, 0x01, 0]);
        at += 12;
        f[at] = 0;
        f[at + 1] = ssid.len() as u8;
        f[at + 2..at + 2 + ssid.len()].copy_from_slice(&ssid);
        at += 2 + ssid.len();
        f[at..at + 6].copy_from_slice(&RATES);
        at += 6;
        f[at..at + 3].copy_from_slice(&[3, 1, CHANNEL]);
        at += 3;
        if fc0 == 0x80 {
            // A beacon carries a TIM (802.11-2020 9.3.3.2): every beacon a
            // DTIM, nothing buffered (frames are never held back for a
            // station that dozes).
            f[at..at + 6].copy_from_slice(&[5, 4, 0, 1, 0, 0]);
            at += 6;
        }
        at
    }

    fn send(&self, stick: &mut Stick, len: usize, ack: bool) {
        let mut options = TxOptions::PLAIN;
        options.ack = ack;
        let start = timer::millis();
        while !stick.transmit(&self.frame[..len], &options) && timer::since(start) < 50 {
            watchdog::feed();
        }
    }

    /// Run: frames in, answers out, until an image is written (which
    /// does not come back) or, with an application in place, it is time
    /// to give it another try.
    pub fn run(&mut self, stick: &mut Stick, app_present: bool) -> ! {
        let mut rx = [0u8; 2400];
        loop {
            watchdog::feed();
            while let Some(got) = stick.receive(&mut rx) {
                watchdog::feed();
                self.input(stick, &rx[..got.len]);
            }
            self.retransmit(stick);
            // Once the answer is through (or its end left unacknowledged
            // for two seconds), do what it said.
            let through = self.tcp == Tcp::Listen
                || (self.tcp == Tcp::Closing
                    && (self.ends.ours_acked || timer::since(self.sent_at) > 2000));
            if through && self.after != After::Nothing {
                match self.after {
                    After::Flash(len) => {
                        uart::write(b"secours: writing\n");
                        Slots::fresh();
                        // SAFETY: the upload buffer, alone in use now.
                        let image = unsafe { &(&*UPLOAD.0.get())[..len] };
                        let app = if boot::check_app(image).is_some() {
                            image
                        } else {
                            &image[RESCUE_SIZE..]
                        };
                        flash::write_app(app)
                    }
                    _ => {
                        Slots::fresh();
                        watchdog::reset_now()
                    }
                }
            }
            // Ten minutes without a request (a phone that joined and
            // left, or rejoins on its own, does not count): give the
            // application another try.
            if app_present && self.tcp == Tcp::Listen && timer::since(self.last_visit) > IDLE_MS {
                uart::write(b"secours: back to the application\n");
                Slots::fresh();
                watchdog::reset_now();
            }
        }
    }

    fn input(&mut self, stick: &mut Stick, f: &[u8]) {
        if f.len() < 24 {
            return;
        }
        let a1: [u8; 6] = f[4..10].try_into().unwrap_or([0; 6]);
        let a2: [u8; 6] = f[10..16].try_into().unwrap_or([0; 6]);
        let for_us = a1 == self.mac;
        match (f[0], f[1] & 3) {
            (0x40, 0) => {
                let mut name: &[u8] = &[];
                elements(&f[24..], None, |id, body| {
                    if id == 0 {
                        name = body;
                    }
                });
                if name.is_empty() || name == self.ssid {
                    let n = self.beacon_like(0x50, &a2);
                    self.send(stick, n, true);
                }
            }
            (0xB0, 0) if for_us && f.len() >= 30 => {
                // Open system only.
                let n = self.header(0xB0, 0, &a2);
                let ok = f[24] == 0 && f[25] == 0 && f[26] == 1;
                self.frame[n..n + 6].copy_from_slice(&[0, 0, 2, 0, if ok { 0 } else { 13 }, 0]);
                self.send(stick, n + 6, true);
            }
            (0x00, 0) if for_us => {
                let n = self.header(0x10, 0, &a2);
                self.frame[n..n + 6].copy_from_slice(&[0x01, 0, 0, 0, 0x01, 0xC0]);
                self.frame[n + 6..n + 12].copy_from_slice(&RATES);
                self.send(stick, n + 12, true);
                self.peer = Some(a2);
            }
            (0xA0 | 0xC0, 0) if for_us && self.peer == Some(a2) => {
                self.peer = None;
                self.tcp = Tcp::Listen;
                self.after = After::Nothing;
            }
            (0x08, 1)
                if for_us
                    && self.peer == Some(a2)
                    && f.len() >= 32
                    && f[24..30] == [0xAA, 0xAA, 3, 0, 0, 0] =>
            {
                match be16(f, 30) {
                    0x0806 => self.arp(stick, &a2, &f[32..]),
                    0x0800 => self.ip(stick, &a2, &f[32..]),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Start a data frame to `to` carrying `ethertype`; returns where
    /// the payload goes.
    fn data(&mut self, to: &[u8; 6], ethertype: u16) -> usize {
        let n = self.header(0x08, 0x02, to);
        self.frame[n..n + 8].copy_from_slice(&[
            0xAA,
            0xAA,
            3,
            0,
            0,
            0,
            (ethertype >> 8) as u8,
            ethertype as u8,
        ]);
        n + 8
    }

    fn arp(&mut self, stick: &mut Stick, from: &[u8; 6], p: &[u8]) {
        if p.len() < 28 || be16(p, 6) != 1 || p[24..28] != IP {
            return;
        }
        let mut sender = [0u8; 10];
        sender.copy_from_slice(&p[8..18]);
        let at = self.data(from, 0x0806);
        let f = &mut self.frame[at..at + 28];
        f[..8].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
        f[8..14].copy_from_slice(&self.mac);
        f[14..18].copy_from_slice(&IP);
        f[18..28].copy_from_slice(&sender);
        self.send(stick, at + 28, true);
    }

    /// An IPv4 header for `len` bytes of `proto` to `to`, at `at`.
    fn ipv4(&mut self, at: usize, proto: u8, to: [u8; 4], len: usize) {
        let h = &mut self.frame[at..at + 20];
        h.fill(0);
        h[0] = 0x45;
        h[2..4].copy_from_slice(&((20 + len) as u16).to_be_bytes());
        h[8] = 64;
        h[9] = proto;
        h[12..16].copy_from_slice(&IP);
        h[16..20].copy_from_slice(&to);
        let c = fold(csum(h, 0));
        h[10..12].copy_from_slice(&c.to_be_bytes());
    }

    fn ip(&mut self, stick: &mut Stick, from: &[u8; 6], p: &[u8]) {
        if p.len() < 20 || p[0] >> 4 != 4 {
            return;
        }
        let ihl = ((p[0] & 15) as usize) * 4;
        let total = (be16(p, 2) as usize).min(p.len());
        if ihl < 20 || total < ihl {
            return;
        }
        let src: [u8; 4] = p[12..16].try_into().unwrap_or([0; 4]);
        let body = &p[ihl..total];
        match p[9] {
            17 if body.len() >= 8 && be16(body, 2) == 67 => self.dhcp(stick, from, &body[8..]),
            6 if p[16..20] == IP => self.tcp(stick, from, src, body),
            _ => {}
        }
    }

    fn dhcp(&mut self, stick: &mut Stick, from: &[u8; 6], m: &[u8]) {
        if m.len() < 240 || m[0] != 1 || m[236..240] != [99, 130, 83, 99] {
            return;
        }
        let mut kind = 0;
        elements(&m[240..], Some(255), |code, v| {
            if code == 53 && !v.is_empty() {
                kind = v[0];
            }
        });
        let reply = match kind {
            1 => 2, // discover: offer
            3 => 5, // request: acknowledge
            _ => return,
        };
        let mut xid = [0u8; 4];
        xid.copy_from_slice(&m[4..8]);
        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&m[28..44]);
        let at = self.data(&BROADCAST, 0x0800);
        let udp = at + 20;
        let d = udp + 8;
        let f = &mut self.frame;
        f[d..d + 240].fill(0);
        f[d..d + 4].copy_from_slice(&[2, 1, 6, 0]);
        f[d + 4..d + 8].copy_from_slice(&xid);
        f[d + 16..d + 20].copy_from_slice(&CLIENT_IP);
        f[d + 20..d + 24].copy_from_slice(&IP);
        f[d + 28..d + 44].copy_from_slice(&chaddr);
        f[d + 236..d + 240].copy_from_slice(&[99, 130, 83, 99]);
        let options = [
            53, 1, reply, 54, 4, IP[0], IP[1], IP[2], IP[3], 51, 4, 0, 1, 0x51, 0x80, 1, 4, 255,
            255, 255, 0, 3, 4, IP[0], IP[1], IP[2], IP[3], 255,
        ];
        f[d + 240..d + 240 + options.len()].copy_from_slice(&options);
        let len = 8 + 240 + options.len();
        f[udp..udp + 8].copy_from_slice(&[0, 67, 0, 68, (len >> 8) as u8, len as u8, 0, 0]);
        self.ipv4(at, 17, [255; 4], len);
        let _ = from;
        self.send(stick, udp + len, false);
    }

    /// Send a TCP segment to the peer with `flags`, carrying the answer
    /// from byte `from` (up to one MSS) when it is data.
    fn segment(&mut self, stick: &mut Stick, flags: u8, seq: u32, from: Option<usize>) {
        let Some(to) = self.peer else { return };
        let at = self.data(&to, 0x0800);
        let t = at + 20;
        let payload = match from {
            Some(i) => &self.answer[i..(i + MSS).min(self.answer.len())],
            None => &[][..],
        };
        let n = payload.len();
        let (remote_ip, remote_port) = self.remote;
        let f = &mut self.frame;
        f[t..t + 20].fill(0);
        f[t..t + 2].copy_from_slice(&80u16.to_be_bytes());
        f[t + 2..t + 4].copy_from_slice(&remote_port.to_be_bytes());
        f[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
        f[t + 8..t + 12].copy_from_slice(&self.rcv_nxt.to_be_bytes());
        f[t + 12] = 5 << 4;
        f[t + 13] = flags;
        f[t + 14..t + 16].copy_from_slice(&WINDOW.to_be_bytes());
        f[t + 20..t + 20 + n].copy_from_slice(payload);
        let mut pseudo = [0u8; 12];
        pseudo[..4].copy_from_slice(&IP);
        pseudo[4..8].copy_from_slice(&remote_ip);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&((20 + n) as u16).to_be_bytes());
        let c = fold(csum(&f[t..t + 20 + n], csum(&pseudo, 0)));
        f[t + 16..t + 18].copy_from_slice(&c.to_be_bytes());
        self.ipv4(at, 6, remote_ip, 20 + n);
        self.send(stick, t + 20 + n, true);
        self.sent_at = timer::millis();
    }

    /// The next piece of the answer, or our FIN once all of it went.
    fn send_next(&mut self, stick: &mut Stick) {
        let seq = self.iss.wrapping_add(1).wrapping_add(self.acked as u32);
        if self.acked < self.answer.len() {
            self.segment(stick, 0x18, seq, Some(self.acked));
        } else {
            self.tcp = Tcp::Closing;
            self.segment(stick, 0x11, seq, None);
        }
    }

    fn retransmit(&mut self, stick: &mut Stick) {
        if matches!(self.tcp, Tcp::Established | Tcp::Closing)
            && !(self.tcp == Tcp::Closing && self.ends.ours_acked)
            && !self.answer.is_empty()
            && timer::since(self.sent_at) > RETRY_MS
        {
            self.send_next(stick);
        }
    }

    fn tcp(&mut self, stick: &mut Stick, from: &[u8; 6], src: [u8; 4], s: &[u8]) {
        if s.len() < 20 || be16(s, 2) != 80 {
            return;
        }
        let port = be16(s, 0);
        let seq = be32(s, 4);
        let ack = be32(s, 8);
        let flags = s[13];
        let off = ((s[12] >> 4) as usize * 4).min(s.len());
        let payload = &s[off..];
        let ours = self.remote == (src, port) && self.peer == Some(*from);
        if flags & 0x04 != 0 {
            if ours {
                self.tcp = Tcp::Listen;
            }
            return;
        }
        if ours {
            self.heard_at = timer::millis();
        }
        if flags & 0x02 != 0 {
            // A second connection while one is under way (a browser's
            // spare one, a favicon) is not taken: it would drop the
            // upload. One silent for ten seconds is given up.
            let busy = self.tcp != Tcp::Listen && !ours && timer::since(self.heard_at) < 10_000;
            if busy {
                return;
            }
            // A new connection drops whatever was going on.
            self.heard_at = timer::millis();
            self.scanned = 0;
            self.remote = (src, port);
            self.rcv_nxt = seq.wrapping_add(1);
            self.iss = timer::millis().wrapping_mul(2_654_435_761);
            self.acked = 0;
            self.request = 0;
            self.answer = &[];
            self.after = After::Nothing;
            self.ends = Ends::OPEN;
            self.tcp = Tcp::SynReceived;
            self.segment(stick, 0x12, self.iss, None);
            return;
        }
        if !ours {
            return;
        }
        if self.tcp == Tcp::Listen {
            // A late FIN of the connection just closed: acknowledge it,
            // or the peer waits on it before opening the next.
            if flags & 0x01 != 0 {
                let fin = self.iss.wrapping_add(2 + self.answer.len() as u32);
                self.rcv_nxt = seq.wrapping_add(payload.len() as u32 + 1);
                self.segment(stick, 0x10, fin, None);
            }
            return;
        }
        if flags & 0x10 != 0 {
            let done = ack.wrapping_sub(self.iss.wrapping_add(1)) as usize;
            if self.tcp == Tcp::SynReceived && ack == self.iss.wrapping_add(1) {
                self.tcp = Tcp::Established;
            }
            if self.tcp == Tcp::Closing && done > self.answer.len() {
                self.ends.ours_acked = true;
            }
            if !self.answer.is_empty() && done > self.acked && done <= self.answer.len() {
                self.acked = done;
                self.send_next(stick);
            }
        }
        if !payload.is_empty() && self.answer.is_empty() {
            if seq == self.rcv_nxt {
                // SAFETY: the upload buffer, touched by this loop alone.
                let buf = unsafe { &mut *UPLOAD.0.get() };
                let n = payload.len().min(buf.len() - self.request);
                buf[self.request..self.request + n].copy_from_slice(&payload[..n]);
                self.request += n;
                self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
            }
            self.segment(stick, 0x10, self.iss.wrapping_add(1), None);
            self.serve(stick);
        }
        if flags & 0x01 != 0 && seq.wrapping_add(payload.len() as u32) == self.rcv_nxt {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.ends.theirs = true;
            // Past our FIN when it went.
            let ours = self
                .iss
                .wrapping_add(1 + self.acked as u32 + (self.tcp == Tcp::Closing) as u32);
            self.segment(stick, 0x10, ours, None);
        }
        if self.tcp == Tcp::Closing && self.ends.ours_acked && self.ends.theirs {
            // Both ends closed: the exchange is over.
            self.tcp = Tcp::Listen;
        }
    }

    /// The request, once whole: choose the answer and what follows it.
    fn serve(&mut self, stick: &mut Stick) {
        // SAFETY: as above.
        let buf = unsafe { &*UPLOAD.0.get() };
        let req = &buf[..self.request];
        // Look for the end of the headers in what came since last time
        // only: an upload is 110 KB.
        let from = self.scanned.saturating_sub(3);
        let Some(end) = req[from..].windows(4).position(|w| w == b"\r\n\r\n") else {
            self.scanned = req.len();
            return;
        };
        let end = from + end;
        self.scanned = end;
        let head = &req[..end];
        let body = end + 4;
        let length = head
            .split(|b| *b == b'\n')
            .find_map(|l| {
                let l = l.strip_suffix(b"\r").unwrap_or(l);
                let v = l
                    .strip_prefix(b"Content-Length: ")
                    .or_else(|| l.strip_prefix(b"content-length: "))?;
                // Decimal digits only (`str::parse` and `trim` would
                // bring Unicode's tables into the rescue core's 20 KB).
                let v = v.trim_ascii();
                let mut n = (!v.is_empty()).then_some(0usize)?;
                for &c in v {
                    let digit = c.wrapping_sub(b'0');
                    if digit > 9 {
                        return None;
                    }
                    n = n.checked_mul(10)?.checked_add(digit as usize)?;
                }
                Some(n)
            })
            .unwrap_or(0);
        // More than the buffer holds (or a length that wraps): refused at
        // once, not waited for.
        let too_big = body.checked_add(length).is_none_or(|n| n > buf.len());
        if !too_big && req.len() < body + length {
            return;
        }
        self.last_visit = timer::millis();
        let (answer, after) = if too_big {
            (REFUSED, After::Nothing)
        } else if head.starts_with(b"POST /flash") {
            let image = &req[body..body + length];
            let whole =
                image.len() > RESCUE_SIZE && boot::check_app(&image[RESCUE_SIZE..]).is_some();
            if whole || boot::check_app(image).is_some() {
                // Keep it where the upload already is: move it to the
                // buffer's start for the writer (word aligned), in pieces
                // that do not overlap (no `memmove` in the rescue core).
                // SAFETY: as above.
                let b = unsafe { &mut *UPLOAD.0.get() };
                let mut done = 0;
                while done < length {
                    let n = (length - done).min(body);
                    let (to, from) = b.split_at_mut(body + done);
                    to[done..done + n].copy_from_slice(&from[..n]);
                    done += n;
                }
                (FLASHING, After::Flash(length))
            } else {
                (REFUSED, After::Nothing)
            }
        } else if head.starts_with(b"GET /restart") {
            if boot::installed_app().is_some() {
                (RESTARTING, After::Restart)
            } else {
                (NO_APP, After::Nothing)
            }
        } else if head.starts_with(b"GET / ") || head.starts_with(b"GET /index") {
            (PAGE, After::Nothing)
        } else {
            (NOT_FOUND, After::Nothing)
        };
        self.answer = answer;
        self.after = after;
        self.acked = 0;
        self.send_next(stick);
    }
}
