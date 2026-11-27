//! The rabbit's 802.11 side: a station that scans, authenticates
//! (open, shared key, SAE), associates and runs the key handshakes of
//! WPA, WPA2 and WPA3, and the small access point the setup mode
//! raises. It follows the C firmware (`src/net/ieee80211.c`, `eapol.c`)
//! in what the bytecode can see: the same states, the same timers, the
//! same scan, the same frames handed up; it departs from it where the
//! C was wrong, and adds WPA3.
//!
//! Everything that touches the stick goes through [`Link`].

use crate::aes;
use crate::ccmp;
use crate::md5::{hmac_md5, rc4};
use crate::p256::Point;
use crate::sae;
use crate::sha1::{hmac_sha1, prf};
use crate::sha256;

pub type Mac = [u8; 6];

pub const BROADCAST: Mac = [0xFF; 6];

/// The ciphers the stick runs itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwCipher {
    None = 0,
    Wep40 = 1,
    Wep104 = 2,
    Tkip = 3,
    Ccmp = 4,
}

/// How the stick is to send a frame.
#[derive(Debug, Clone, Copy)]
pub struct Tx {
    /// The stick's rate number, 0 (1 Mb/s) to 11 (54 Mb/s).
    pub rate: u8,
    pub ack: bool,
    pub cipher: HwCipher,
    pub key: u8,
    pub iv: u32,
    pub eiv: u32,
    /// The stick fills in the timestamp (probe responses).
    pub timestamp: bool,
}

/// A received frame, as the stick reports it.
#[derive(Debug, Clone, Copy)]
pub struct Rx {
    pub len: usize,
    pub rssi: i8,
    /// The stick decrypted it.
    pub decrypted: bool,
    /// The IV and extended IV of a frame the stick decrypted, as its
    /// receive descriptor gives them (words 2 and 3): the packet number
    /// is in them, and the stick checks none.
    pub iv: u32,
    pub eiv: u32,
}

/// What the station needs from the stick and the board.
pub trait Link {
    fn mac(&self) -> Mac;
    fn millis(&self) -> u32;
    fn transmit(&mut self, frame: &[u8], tx: &Tx) -> bool;
    fn receive(&mut self, buffer: &mut [u8]) -> Option<Rx>;
    fn set_channel(&mut self, channel: u8);
    fn set_bssid(&mut self, bssid: &Mac);
    fn set_key(
        &mut self,
        index: u8,
        cipher: HwCipher,
        key: &[u8],
        tx_mic: &[u8; 8],
        rx_mic: &[u8; 8],
    );
    fn set_beacon(&mut self, frame: Option<&[u8]>);
    /// Rates the stick's automatic answers (acknowledgements) may use,
    /// as a mask of its rate numbers.
    fn set_answer_rates(&mut self, mask: u16);
    /// Called during long computations and waits: feed the watchdog.
    fn pause(&mut self);
    fn random(&mut self, out: &mut [u8]);
}

// The states and modes the bytecode reads through `netState`.
pub const S_BROKEN: i32 = 0;
pub const S_IDLE: i32 = 1;
pub const S_SCAN: i32 = 2;
pub const S_CONNECTING: i32 = 3;
pub const S_CONNECTED: i32 = 4;
pub const S_MASTER: i32 = 5;

// Encryption as the bytecode names it (scan results, `netAuth`).
pub const CRYPT_NONE: u8 = 0x00;
pub const CRYPT_WEP: u8 = 0x10;
pub const CRYPT_WPA: u8 = 0x20;
pub const CRYPT_WPA2: u8 = 0x40;
pub const CRYPT_UNSUPPORTED: u8 = 0xFF;

const AUTH_TIMEOUT: u32 = 10;
const ASSOC_TIMEOUT: u32 = 10;
const RUN_TIMEOUT: u32 = 600;
const EAPOL_TIMEOUT: u32 = 600;
const STA_ASSOC_TIMEOUT: u32 = 200;
const STA_MAX_IDLE: u32 = 3000;
/// The longest association comeback time waited for, in time units
/// (1.024 ms): access points ask for one second.
const MAX_COMEBACK_TU: u32 = 10_000;
const MAX_STATIONS: usize = 5;
/// How long the key of a password exchange is kept for the next
/// association: hostapd's and wpa_supplicant's default, twelve hours.
/// (The clock wraps after 49 days: a key that old may pass for new, and
/// the access point then refuses it, status 53.)
const PMKSA_LIFETIME_MS: u32 = 12 * 3600 * 1000;
const RSSI_SAMPLES: usize = 15;
/// How long the scan listens on each channel: one beacon interval
/// (102.4 ms) and the time to switch. The C driver stayed 350 ms, which
/// made every scan last 4.9 s.
pub const SCAN_DWELL_MS: u32 = 120;

pub const LLC_EAPOL: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];
const MULTICAST: [u8; 3] = [0x01, 0x00, 0x5E];

/// The rates every frame we send advertises: the supported rates
/// element, then the extended one.
const RATES: [u8; 16] = [
    1, 8, 0x02, 0x04, 0x0B, 0x16, 0x24, 0x30, 0x48, 0x6C, 50, 4, 0x0C, 0x12, 0x18, 0x60,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Managed,
    Master,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    Scan,
    Auth,
    Assoc,
    Eapol,
    Run,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyState {
    Msg1,
    Msg3,
    Group,
    Run,
}

/// A suite of the RSN element: TKIP (2) or CCMP (4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Tkip = 2,
    Ccmp = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Security {
    Open,
    Wep {
        key: [u8; 13],
        long: bool,
    },
    /// WPA (vendor element) or WPA2 (RSN element), with the pre-shared
    /// key; the stick encrypts.
    Psk {
        wpa2: bool,
        group: Cipher,
        pairwise: Option<Cipher>,
    },
    /// WPA3: SAE, protected management frames, CCMP in software.
    Sae {
        h2e: bool,
    },
}

/// A network as the scan reports it to the bytecode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanResult {
    pub ssid: [u8; 33],
    pub ssid_len: usize,
    pub mac: Mac,
    pub bssid: Mac,
    pub rssi: i16,
    pub channel: u8,
    pub rateset: u16,
    pub encryption: u8,
}

/// What the scan saw of a network beyond what the bytecode is told:
/// the parts of its security offer `auth` needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Offer {
    bssid: Mac,
    /// RSN: group cipher, pairwise ciphers (bit per suite), key
    /// managements (bit 2 PSK, bit 8 SAE), capabilities.
    rsn: Option<(u8, u8, u16, u16)>,
    /// WPA (vendor element): group cipher, pairwise ciphers.
    wpa: Option<(u8, u8)>,
    /// SAE by hash to element offered (RSNX element, bit 5).
    h2e: bool,
    /// SHA-256 of the RSN element and the RSN extension element (or of
    /// the WPA element, without RSN), as the network announced them:
    /// message 3 has to bring the same.
    digest: [u8; 32],
}

impl Offer {
    /// The offer in a list of elements: a beacon's, a probe response's,
    /// or message 3's key data.
    fn from_elements(bssid: Mac, ies: &[u8]) -> Offer {
        let mut o = Offer {
            bssid,
            ..Offer::default()
        };
        let (mut rsne, mut rsnxe, mut wpa) = (None, None, None);
        for (id, e) in elements(ies) {
            match id {
                48 if rsne.is_none() => {
                    o.rsn = suites(e, [0x00, 0x0F, 0xAC]);
                    rsne = Some(e);
                }
                221 if wpa.is_none() && e.len() >= 6 && e[..4] == [0x00, 0x50, 0xF2, 0x01] => {
                    o.wpa = suites(&e[4..], [0x00, 0x50, 0xF2]).map(|(g, p, _, _)| (g, p));
                    wpa = Some(e);
                }
                244 if rsnxe.is_none() && !e.is_empty() => {
                    o.h2e = e[0] & 0x20 != 0;
                    rsnxe = Some(e);
                }
                _ => {}
            }
        }
        let mut h = sha256::Sha256::new();
        let mut add = |id: u8, e: &[u8]| {
            h.update(&[id, e.len() as u8]);
            h.update(e);
        };
        match (rsne, wpa) {
            (Some(r), _) => {
                add(48, r);
                if let Some(x) = rsnxe {
                    add(244, x);
                }
            }
            (None, Some(w)) => add(221, w),
            (None, None) => {}
        }
        o.digest = h.finish();
        o
    }
}

const OFFERS: usize = 16;

#[derive(Debug, Clone, Copy)]
struct Peer {
    state: State,
    timer: u32,
    mac: Mac,
}

/// What `input` hands up: a frame body (from its LLC header on) for
/// the bytecode, at `frame[start..start + len]`, from `source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivery {
    pub start: usize,
    pub len: usize,
    pub source: Mac,
    pub destination: Mac,
}

/// The keys of a link the firmware protects itself (WPA3).
#[derive(Clone)]
struct SoftKeys {
    tk: [u8; 16],
    gtk: Option<(u8, [u8; 16])>,
    igtk: Option<(u16, [u8; 16])>,
    mgmt_rx_pn: u64,
    igtk_ipn: u64,
}

/// The SA Query procedure (802.11-2020 11.13): the transaction
/// identifiers sent (`sent` of them; none, no procedure), when it began,
/// when the next request is due, when the last one began.
#[derive(Clone, Copy)]
struct SaQuery {
    ids: [[u8; 2]; 5],
    sent: u8,
    start: u32,
    next: u32,
    last: Option<u32>,
}

/// wpa_supplicant's timings: a request every 201 time units, an answer
/// within 1000 (in milliseconds here), and no new procedure within ten
/// seconds of the last.
const SA_QUERY_RETRY_MS: u32 = 206;
const SA_QUERY_MAX_MS: u32 = 1024;
const SA_QUERY_QUIET_MS: u32 = 10_000;

/// A password exchange under way.
#[derive(Clone)]
struct SaeRun {
    session: sae::Session,
    /// The commit, to send again with an anti-clogging token.
    commit: [u8; 6 + sae::COMMIT_LEN],
    confirmed: bool,
}

#[derive(Clone)]
pub struct Station {
    pub mode: Mode,
    pub state: State,
    timeout: u32,
    ap: Mac,
    bssid: Mac,
    ssid: [u8; 33],
    ssid_len: usize,
    channel: u8,
    rateset: u16,
    txrate: u16,
    lowest_txrate: u16,
    rssi: [i16; RSSI_SAMPLES],
    rssi_index: usize,
    pub rssi_average: i16,
    shared_auth: bool,
    security: Security,
    pmk: [u8; 32],
    password: [u8; 64],
    password_len: usize,
    keys: KeyState,
    replay_active: bool,
    replay: [u8; 8],
    anonce: [u8; 32],
    ptk: [u8; 64],
    /// Packet number (or TKIP sequence counter) of the next frame.
    tx_pn: u64,
    /// The last packet number received under the pairwise key, and
    /// under each group key (by key identifier): a frame that does not
    /// exceed it is a replay.
    rx_pn: u64,
    group_rsc: [u64; 4],
    /// The group keys installed, by identifier (bit `i` of `gtk_set`
    /// says key `i` is): the same key handed over again is not
    /// installed again, which would wind its counter back.
    gtks: [[u8; 32]; 4],
    gtk_set: u8,
    soft: Option<SoftKeys>,
    sae: Option<SaeRun>,
    /// The hash-to-element password point of the last network, kept:
    /// computing it takes an eighth of a second.
    pt: Option<([u8; 32], Point)>,
    retry_assoc_at: Option<u32>,
    /// A new pairwise key, between messages 1 and 3 of a handshake on a
    /// running link: the current key stays in use until message 4.
    next_ptk: Option<[u8; 64]>,
    /// The key of the last password exchange, for the network it was
    /// made with (BSSID, PMK, PMKID, when it was made): joining it again
    /// within its lifetime needs no SAE.
    pmksa: Option<(Mac, [u8; 32], [u8; 16], u32)>,
    /// The current attempt uses that cached key.
    cached: bool,
    peers: [Peer; MAX_STATIONS],
    offers: [Offer; OFFERS],
    next_offer: usize,
    /// The offer of the network being joined, as known when joining
    /// (`bss_known`: the scan saw it); and the one an authenticated
    /// message 3 showed, which beats the scan's for that network.
    bss: Offer,
    bss_known: bool,
    learned: Option<Offer>,
    /// The replay counter of the message 1 being answered: not the
    /// last one checked (`replay`), message 1 carries no integrity code.
    msg1_replay: [u8; 8],
    /// Our nonce, kept for every message 1 of a handshake.
    snonce: [u8; 32],
    renew_snonce: bool,
    /// The access point has shown it holds the pairwise key (a frame
    /// from it opened with it): from then on nothing comes in clear,
    /// handshake messages included.
    ap_keyed: bool,
    /// The cached key led to a checked message 3.
    pmksa_proven: bool,
    sa_query: SaQuery,
    tx: [u8; 2400],
}

impl Default for Station {
    fn default() -> Self {
        Self::new()
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// Whether two addresses are the same: a call, not six comparisons
/// at each of the many places that ask.
#[inline(never)]
fn same(a: &Mac, b: &Mac) -> bool {
    a == b
}

/// Put `bytes` in a frame being built, at `at`; returns where they end.
#[inline(never)]
fn put(frame: &mut [u8], at: usize, bytes: &[u8]) -> usize {
    frame[at..at + bytes.len()].copy_from_slice(bytes);
    at + bytes.len()
}

/// Put an element (identifier, length, body); returns where it ends.
#[inline(never)]
fn put_element(frame: &mut [u8], at: usize, id: u8, body: &[u8]) -> usize {
    let at = put(frame, at, &[id, body.len() as u8]);
    put(frame, at, body)
}

fn mac_at(b: &[u8], at: usize) -> Mac {
    let mut m = [0u8; 6];
    m.copy_from_slice(&b[at..at + 6]);
    m
}

/// Rate in 500 kb/s units to the rate mask of the C driver.
fn rate_to_mask(rate: u8) -> u16 {
    match rate {
        2 => 1 << 0,
        4 => 1 << 1,
        11 => 1 << 2,
        12 => 1 << 3,
        18 => 1 << 4,
        22 => 1 << 5,
        24 => 1 << 6,
        36 => 1 << 7,
        48 => 1 << 8,
        72 => 1 << 9,
        96 => 1 << 10,
        108 => 1 << 11,
        _ => 0,
    }
}

/// One rate of the mask to its 500 kb/s units and the stick's number.
fn mask_rate(mask: u16) -> (u8, u8) {
    match mask {
        0x001 => (2, 0),
        0x002 => (4, 1),
        0x004 => (11, 2),
        0x008 => (12, 4),
        0x010 => (18, 5),
        0x020 => (22, 3),
        0x040 => (24, 6),
        0x080 => (36, 7),
        0x100 => (48, 8),
        0x200 => (72, 9),
        0x400 => (96, 10),
        0x800 => (108, 11),
        _ => (2, 0),
    }
}

/// The stick's mask (by its rate numbers) for a rate mask.
fn stick_rates(mask: u16) -> u16 {
    (0..12)
        .filter(|b| mask & (1 << b) != 0)
        .fold(0, |m, b| m | 1 << mask_rate(1 << b).1)
}

/// Air time of a frame, in microseconds, as the C driver counts it.
fn txtime(len: usize, rate: u8) -> u16 {
    let bits = 11 + len as u32 * 4;
    let rate = rate as u32;
    (26 + 4 * (bits / rate) + if !bits.is_multiple_of(rate) { 4 } else { 0 }) as u16
}

/// Walk the elements of a frame body.
fn elements(mut ies: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    core::iter::from_fn(move || {
        let [id, len, rest @ ..] = ies else {
            return None;
        };
        let body = rest.get(..*len as usize)?;
        ies = &rest[*len as usize..];
        Some((*id, body))
    })
}

/// Suites of an RSN or WPA element: (group, pairwise bits, AKM bits,
/// capabilities). `oui` is 00-0F-AC (RSN) or 00-50-F2 (WPA).
fn suites(body: &[u8], oui: [u8; 3]) -> Option<(u8, u8, u16, u16)> {
    if body.len() < 2 + 4 {
        return None;
    }
    let mut at = 2;
    let suite = |b: &[u8], at: usize| -> Option<u8> {
        let s = b.get(at..at + 4)?;
        (s[..3] == oui).then_some(s[3])
    };
    let group = suite(body, at)?;
    at += 4;
    let list = |at: &mut usize| -> Option<u16> {
        let n = le16(body.get(*at..*at + 2)?, 0) as usize;
        *at += 2;
        let mut bits = 0u16;
        for _ in 0..n {
            // Suites past 15 are none of ours, and must not alias one
            // that is (SAE-EXT-KEY, 24, is not SAE, 8).
            if let Some(s) = suite(body, *at).filter(|s| *s < 16) {
                bits |= 1 << s;
            }
            *at += 4;
            if *at > body.len() {
                return None;
            }
        }
        Some(bits)
    };
    let pairwise = list(&mut at)? as u8;
    let akm = list(&mut at)?;
    let caps = body.get(at..at + 2).map_or(0, |c| le16(c, 0));
    Some((group, pairwise, akm, caps))
}

impl Station {
    pub const fn new() -> Self {
        Station {
            mode: Mode::Managed,
            state: State::Idle,
            timeout: 0,
            ap: [0; 6],
            bssid: [0; 6],
            ssid: [0; 33],
            ssid_len: 0,
            channel: 1,
            rateset: 1,
            txrate: 1,
            lowest_txrate: 1,
            rssi: [0; RSSI_SAMPLES],
            rssi_index: 0,
            rssi_average: 0,
            shared_auth: false,
            security: Security::Open,
            pmk: [0; 32],
            password: [0; 64],
            password_len: 0,
            keys: KeyState::Msg1,
            replay_active: false,
            replay: [0; 8],
            anonce: [0; 32],
            ptk: [0; 64],
            tx_pn: 1,
            rx_pn: 0,
            group_rsc: [0; 4],
            gtks: [[0; 32]; 4],
            gtk_set: 0,
            soft: None,
            sae: None,
            pt: None,
            retry_assoc_at: None,
            next_ptk: None,
            pmksa: None,
            cached: false,
            peers: [Peer {
                state: State::Idle,
                timer: 0,
                mac: [0; 6],
            }; MAX_STATIONS],
            offers: [Offer {
                bssid: [0; 6],
                rsn: None,
                wpa: None,
                h2e: false,
                digest: [0; 32],
            }; OFFERS],
            bss: Offer {
                bssid: [0; 6],
                rsn: None,
                wpa: None,
                h2e: false,
                digest: [0; 32],
            },
            bss_known: false,
            learned: None,
            msg1_replay: [0; 8],
            snonce: [0; 32],
            renew_snonce: true,
            ap_keyed: false,
            pmksa_proven: false,
            sa_query: SaQuery {
                ids: [[0; 2]; 5],
                sent: 0,
                start: 0,
                next: 0,
                last: None,
            },
            next_offer: 0,
            tx: [0; 2400],
        }
    }

    /// What `netState` returns.
    pub fn net_state(&self) -> i32 {
        if self.mode == Mode::Master {
            return S_MASTER;
        }
        match self.state {
            State::Idle => S_IDLE,
            State::Scan => S_SCAN,
            State::Auth | State::Assoc | State::Eapol => S_CONNECTING,
            State::Run => S_CONNECTED,
        }
    }

    /// Whether the link runs WPA3 (the firmware encrypts).
    pub fn is_wpa3(&self) -> bool {
        matches!(self.security, Security::Sae { .. })
    }

    // ---- frames out ------------------------------------------------

    /// Start a management frame in the transmit buffer; returns the
    /// header length.
    fn header(&mut self, own: &Mac, fc0: u8, fc1: u8, a1: &Mac, a3: &Mac) -> usize {
        let h = &mut self.tx[..24];
        h[0] = fc0;
        h[1] = fc1;
        h[2] = 0;
        h[3] = 0;
        h[4..10].copy_from_slice(a1);
        h[10..16].copy_from_slice(own);
        h[16..22].copy_from_slice(a3);
        h[22] = 0;
        h[23] = 0;
        24
    }

    /// Fill in the duration and send `tx[..len]` as a management frame
    /// at the lowest rate, protected in software if `protect`.
    fn send_management(&mut self, link: &mut impl Link, len: usize, protect: bool) -> bool {
        let (units, rate) = mask_rate(self.lowest_txrate);
        let mut len = len;
        if protect {
            let Some(soft) = &self.soft else { return false };
            let tk = soft.tk;
            len = ccmp::protect(&tk, 0, self.tx_pn, &mut self.tx, len);
            self.tx_pn += 1;
        }
        let d = txtime(len, units) + 10;
        self.tx[2..4].copy_from_slice(&d.to_le_bytes());
        let tx = Tx {
            rate,
            ack: true,
            cipher: HwCipher::None,
            key: 0,
            iv: 0,
            eiv: 0,
            timestamp: false,
        };
        link.transmit(&self.tx[..len], &tx)
    }

    fn send_auth(&mut self, link: &mut impl Link, to: &Mac, algorithm: u16, seq: u16, status: u16) {
        let own = link.mac();
        let bssid = self.bssid;
        let at = self.header(&own, 0xB0, 0, to, &bssid);
        let [a0, a1] = algorithm.to_le_bytes();
        let [q0, q1] = seq.to_le_bytes();
        let [s0, s1] = status.to_le_bytes();
        let at = put(&mut self.tx, at, &[a0, a1, q0, q1, s0, s1]);
        self.send_management(link, at, false);
    }

    /// The RSN (or WPA) element we offer, the same in the association
    /// request and in message 2: the access point compares them. After
    /// a hash-to-element exchange the RSN extension element follows,
    /// which says so (802.11-2020 12.4.2): without it, the access point
    /// cannot tell a downgrade to hunting and pecking.
    fn own_element(&self, out: &mut [u8; 48]) -> usize {
        const WPA: [u8; 24] = [
            0xDD, 22, 0x00, 0x50, 0xF2, 0x01, 0x01, 0x00, 0x00, 0x50, 0xF2, 0, 1, 0, 0x00, 0x50,
            0xF2, 0, 1, 0, 0x00, 0x50, 0xF2, 2,
        ];
        const RSN: [u8; 22] = [
            48, 20, 1, 0, 0x00, 0x0F, 0xAC, 0, 1, 0, 0x00, 0x0F, 0xAC, 0, 1, 0, 0x00, 0x0F, 0xAC,
            2, 0, 0,
        ];
        // Management frames protected, and required.
        const SAE: [u8; 22] = [
            48, 20, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC,
            8, 0xC0, 0x00,
        ];
        match self.security {
            Security::Psk {
                wpa2: false,
                group,
                pairwise,
            } => {
                out[..24].copy_from_slice(&WPA);
                out[11] = group as u8;
                out[17] = pairwise.unwrap_or(Cipher::Tkip) as u8;
                24
            }
            Security::Psk {
                group, pairwise, ..
            } => {
                out[..22].copy_from_slice(&RSN);
                out[7] = group as u8;
                out[13] = pairwise.unwrap_or(Cipher::Ccmp) as u8;
                22
            }
            Security::Sae { h2e } => {
                out[..22].copy_from_slice(&SAE);
                let n = match self.pmksa.filter(|_| self.cached) {
                    // The cached exchange, named by its PMKID.
                    Some((_, _, pmkid, _)) => {
                        out[1] = 38;
                        out[22..24].copy_from_slice(&[1, 0]);
                        out[24..40].copy_from_slice(&pmkid);
                        40
                    }
                    None => 22,
                };
                if !h2e {
                    return n;
                }
                out[n..n + 3].copy_from_slice(&[244, 1, 0x20]);
                n + 3
            }
            _ => 0,
        }
    }

    fn associate(&mut self, link: &mut impl Link) {
        let own = link.mac();
        let (ap, bssid) = (self.ap, self.bssid);
        let at = self.header(&own, 0x00, 0, &ap, &bssid);
        // Capabilities (ESS), listen interval 100.
        let at = put(&mut self.tx, at, &[0x01, 0x00, 0x64, 0x00]);
        let at = put_element(&mut self.tx, at, 0, &self.ssid[..self.ssid_len]);
        let at = put(&mut self.tx, at, &RATES);
        let mut e = [0u8; 48];
        let n = self.own_element(&mut e);
        let at = put(&mut self.tx, at, &e[..n]);
        if !self.send_management(link, at, false) {
            self.state = State::Idle;
            return;
        }
        self.state = State::Assoc;
        self.timeout = ASSOC_TIMEOUT;
    }

    // ---- what the bytecode calls -------------------------------------

    /// `netSetmode`: 0 joins networks, 1 is an access point named `ssid`
    /// on `channel`.
    #[inline(never)]
    pub fn set_mode(&mut self, link: &mut impl Link, master: bool, ssid: &[u8], channel: u8) {
        if !master {
            self.state = State::Idle;
            self.mode = Mode::Managed;
            link.set_beacon(None);
            return;
        }
        self.state = State::Run;
        self.mode = Mode::Master;
        self.set_ssid(ssid);
        self.bssid = link.mac();
        self.channel = channel;
        for p in self.peers.iter_mut() {
            p.state = State::Idle;
        }
        self.security = Security::Open;
        self.soft = None;
        self.rateset = 1;
        self.txrate = 1;
        self.lowest_txrate = 1;
        link.set_bssid(&self.bssid.clone());
        // The access point only does 1 Mb/s; so do its acknowledgements.
        link.set_answer_rates(1);
        link.set_channel(channel);
        let n = self.beacon_like(link, 0x80, &BROADCAST);
        link.set_beacon(Some(&self.tx[..n]));
    }

    fn set_ssid(&mut self, ssid: &[u8]) {
        let n = ssid
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(ssid.len())
            .min(32);
        self.ssid = [0; 33];
        self.ssid[..n].copy_from_slice(&ssid[..n]);
        self.ssid_len = n;
    }

    /// A beacon (0x80) or probe response (0x50) of our access point.
    fn beacon_like(&mut self, link: &mut impl Link, fc0: u8, to: &Mac) -> usize {
        let own = link.mac();
        let bssid = self.bssid;
        let at = self.header(&own, fc0, 0, to, &bssid);
        let at = put(
            &mut self.tx,
            at,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0, 0x01, 0],
        );
        let at = put_element(&mut self.tx, at, 0, &self.ssid[..self.ssid_len]);
        put(&mut self.tx, at, &[1, 1, 0x82, 3, 1, self.channel])
    }

    /// `netScan`: go through the fourteen channels, asking (for `ssid`,
    /// or anyone) and listening a while on each; `found` gets every
    /// beacon and probe response heard, as the C driver gave them.
    #[inline(never)]
    pub fn scan(
        &mut self,
        link: &mut impl Link,
        ssid: Option<&[u8]>,
        buffer: &mut [u8],
        found: &mut dyn FnMut(&ScanResult),
    ) {
        if self.mode != Mode::Managed {
            return;
        }
        self.state = State::Scan;
        link.set_bssid(&[0; 6]);
        let own = link.mac();
        for channel in 1..=14 {
            link.set_channel(channel);
            let at = self.header(&own, 0x40, 0, &BROADCAST, &BROADCAST);
            // The network's name, or the wildcard: an empty one. (The C
            // driver left the element out, which the standard forbids.)
            let name = ssid.map_or(&[][..], |s| {
                &s[..s.iter().position(|b| *b == 0).unwrap_or(s.len()).min(32)]
            });
            let at = put_element(&mut self.tx, at, 0, name);
            let at = put(&mut self.tx, at, &RATES);
            let tx = Tx {
                rate: 0,
                ack: true,
                cipher: HwCipher::None,
                key: 0,
                iv: 0,
                eiv: 0,
                timestamp: false,
            };
            // Channel 14 is Japan's alone, and only for listening
            // elsewhere: no probe there.
            if channel != 14 {
                link.transmit(&self.tx[..at], &tx);
            }
            let start = link.millis();
            while link.millis().wrapping_sub(start) < SCAN_DWELL_MS {
                link.pause();
                let Some(rx) = link.receive(buffer) else {
                    continue;
                };
                let f = &buffer[..rx.len];
                if f.len() >= 24
                    && (f[0] == 0x80 || f[0] == 0x50)
                    && f[1] & 3 == 0
                    && let Some(result) = self.heard(f, rx.rssi as i16)
                {
                    found(&result);
                }
            }
        }
        self.state = State::Idle;
    }

    /// A beacon or probe response heard during a scan: what to tell the
    /// bytecode, and what to remember of the network's offer.
    #[inline(never)]
    fn heard(&mut self, f: &[u8], rssi: i16) -> Option<ScanResult> {
        let body = &f[24..];
        if body.len() < 12 {
            return None;
        }
        let capabilities = le16(body, 10);
        let mut r = ScanResult {
            ssid: [0; 33],
            ssid_len: 0,
            mac: mac_at(f, 10),
            bssid: mac_at(f, 16),
            rssi,
            channel: 0,
            rateset: 0,
            encryption: if capabilities & 0x10 != 0 {
                CRYPT_WEP
            } else {
                CRYPT_NONE
            },
        };
        let offer = Offer::from_elements(r.bssid, &body[12..]);
        for (id, e) in elements(&body[12..]) {
            match id {
                0 if e.len() <= 32 => {
                    r.ssid[..e.len()].copy_from_slice(e);
                    r.ssid_len = e.len();
                }
                3 if !e.is_empty() => r.channel = e[0],
                1 | 50 => {
                    for rate in e {
                        r.rateset |= rate_to_mask(rate & 0x7F);
                    }
                }
                _ => {}
            }
        }
        if r.rateset == 0 {
            r.rateset = 1;
        }
        r.encryption = match (offer.rsn, offer.wpa) {
            (Some((group, pairwise, akm, _)), _) => {
                // PSK or SAE: both are "WPA2" to the bytecode, which hands
                // over the derived key and lets the firmware choose.
                let g = match group {
                    2 => 0x04,
                    4 => 0x08,
                    _ => 0,
                };
                let p = (if pairwise & 1 << 2 != 0 { 1 } else { 0 })
                    | (if pairwise & 1 << 4 != 0 { 2 } else { 0 });
                if g == 0 || p == 0 || akm & (1 << 2 | 1 << 8) == 0 {
                    CRYPT_UNSUPPORTED
                } else {
                    CRYPT_WPA2 | g | p
                }
            }
            (None, Some((_, pairwise))) => {
                if pairwise & (1 << 2 | 1 << 4) != 0 {
                    CRYPT_WPA
                } else {
                    CRYPT_UNSUPPORTED
                }
            }
            _ => r.encryption,
        };
        if offer.rsn.is_some() || offer.wpa.is_some() {
            let slot = self
                .offers
                .iter()
                .position(|o| same(&o.bssid, &offer.bssid))
                .unwrap_or_else(|| {
                    self.next_offer = (self.next_offer + 1) % OFFERS;
                    self.next_offer
                });
            self.offers[slot] = offer;
        }
        Some(r)
    }

    /// `netAuth`: join the network a scan found. `encryption` is the
    /// scan's byte, `key` the WEP key or the pre-shared key the
    /// bytecode derived; `password`, when the settings have one, lets
    /// the firmware use WPA3 where the network offers it.
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    pub fn auth(
        &mut self,
        link: &mut impl Link,
        ssid: &[u8],
        mac: &Mac,
        bssid: &Mac,
        channel: u8,
        rateset: u16,
        shared_auth: bool,
        encryption: u8,
        key: &[u8],
        password: &[u8],
    ) {
        if self.mode != Mode::Managed {
            return;
        }
        // The cached key of the last attempt never led to a checked
        // message 3: the access point does not hold it (any more).
        if self.cached && !self.pmksa_proven {
            self.pmksa = None;
        }
        if let Some((.., made)) = self.pmksa
            && link.millis().wrapping_sub(made) >= PMKSA_LIFETIME_MS
        {
            self.pmksa = None;
        }
        self.pmksa_proven = false;
        self.renew_snonce = true;
        self.sa_query.sent = 0;
        self.sa_query.last = None;
        self.state = State::Idle;
        self.ap = *mac;
        self.bssid = *bssid;
        self.set_ssid(ssid);
        self.channel = channel;
        self.rateset = rateset;
        self.shared_auth = false;
        self.soft = None;
        self.sae = None;
        self.retry_assoc_at = None;
        // What an authenticated message 3 showed of this network beats
        // what a scan heard, which anyone can forge or crowd out.
        let offer = self
            .learned
            .filter(|o| same(&o.bssid, bssid))
            .or_else(|| self.offers.iter().find(|o| same(&o.bssid, bssid)).copied());
        self.bss_known = offer.is_some();
        self.bss = offer.unwrap_or(Offer {
            bssid: *bssid,
            ..Offer::default()
        });
        let none = [0u8; 8];
        // Every key of the last network goes, the group keys too: one
        // left in its slot would open the next network's broadcasts.
        for slot in 0..4 {
            link.set_key(slot, HwCipher::None, &[], &none, &none);
        }
        self.gtk_set = 0;
        self.group_rsc = [0; 4];
        self.rx_pn = 0;
        self.security = match encryption & 0xF0 {
            CRYPT_NONE => Security::Open,
            CRYPT_WEP => {
                // The key's own length decides (the C driver measured the
                // pointer, and cut every 104-bit key to 40).
                let long = key.len() >= 13;
                let mut k = [0u8; 13];
                let n = if long { 13 } else { 5.min(key.len()) };
                k[..n].copy_from_slice(&key[..n]);
                self.shared_auth = shared_auth;
                let cipher = if long {
                    HwCipher::Wep104
                } else {
                    HwCipher::Wep40
                };
                link.set_key(0, cipher, &k[..if long { 13 } else { 5 }], &none, &none);
                Security::Wep { key: k, long }
            }
            CRYPT_WPA | CRYPT_WPA2 => {
                self.pmk = [0; 32];
                let n = key.len().min(32);
                self.pmk[..n].copy_from_slice(&key[..n]);
                self.keys = KeyState::Msg1;
                self.replay_active = false;
                let rsn = offer.and_then(|o| o.rsn);
                let sae_offered = rsn.is_some_and(|(_, _, akm, _)| akm & 1 << 8 != 0);
                let psk_offered = rsn.is_none_or(|(_, _, akm, _)| akm & 1 << 2 != 0);
                if encryption & 0xF0 == CRYPT_WPA2
                    && sae_offered
                    && (!password.is_empty() || !psk_offered)
                {
                    let n = password.len().min(64);
                    self.password[..n].copy_from_slice(&password[..n]);
                    self.password_len = n;
                    Security::Sae {
                        h2e: offer.is_some_and(|o| o.h2e),
                    }
                } else if encryption & 0xF0 == CRYPT_WPA2 {
                    let group = if encryption & 0x08 != 0 {
                        Cipher::Ccmp
                    } else {
                        Cipher::Tkip
                    };
                    let pairwise = if encryption & 0x02 != 0 || encryption & 0x03 == 0 {
                        Cipher::Ccmp
                    } else {
                        Cipher::Tkip
                    };
                    Security::Psk {
                        wpa2: true,
                        group: if encryption & 0x0C == 0 {
                            Cipher::Ccmp
                        } else {
                            group
                        },
                        pairwise: Some(pairwise),
                    }
                } else {
                    let (group, pairwise) = offer.and_then(|o| o.wpa).unwrap_or((2, 1 << 2));
                    Security::Psk {
                        wpa2: false,
                        group: if group == 4 {
                            Cipher::Ccmp
                        } else {
                            Cipher::Tkip
                        },
                        // The cipher of message 1 decides when both are
                        // offered, as the C driver did.
                        pairwise: match pairwise & (1 << 2 | 1 << 4) {
                            0x04 => Some(Cipher::Tkip),
                            0x10 => Some(Cipher::Ccmp),
                            _ => None,
                        },
                    }
                }
            }
            _ => return,
        };
        self.lowest_txrate = self.closest_rate(1);
        self.txrate = self.lowest_txrate;
        link.set_bssid(bssid);
        link.set_answer_rates(stick_rates(self.rateset));
        link.set_channel(channel);
        self.state = State::Auth;
        self.timeout = AUTH_TIMEOUT;
        self.cached = false;
        if let Security::Sae { h2e } = self.security {
            match self.pmksa.filter(|(b, ..)| b == bssid) {
                // A key from an earlier exchange with this network: open
                // authentication, and the PMKID in the association.
                Some((_, pmk, ..)) => {
                    self.cached = true;
                    self.pmk = pmk;
                    self.send_auth(link, &mac.clone(), 0, 1, 0);
                }
                None => self.sae_commit(link, h2e),
            }
        } else {
            let algorithm = self.shared_auth as u16;
            self.send_auth(link, &mac.clone(), algorithm, 1, 0);
        }
    }

    fn closest_rate(&self, wanted: u16) -> u16 {
        let mut i = wanted;
        while self.rateset & i == 0 && i != 1 {
            i >>= 1;
        }
        if self.rateset & i != 0 {
            return i;
        }
        if self.rateset == 0 {
            return 1;
        }
        let mut i = 1;
        while self.rateset & i == 0 {
            i <<= 1;
        }
        i
    }

    fn rssi_sample(&mut self, rssi: i16) {
        self.rssi[self.rssi_index] = rssi;
        self.rssi_index += 1;
        if self.rssi_index < RSSI_SAMPLES {
            return;
        }
        self.rssi_index = 0;
        let sum: i32 = self.rssi.iter().map(|r| *r as i32).sum();
        self.rssi_average = (sum / RSSI_SAMPLES as i32) as i16;
        let a = self.rssi_average;
        let wanted = match a {
            _ if a >= -65 => 1 << 11,
            -66 => 1 << 10,
            -70..=-67 => 1 << 9,
            -74..=-71 => 1 << 8,
            -77..=-75 => 1 << 7,
            -79..=-78 => 1 << 6,
            -81..=-80 => 1 << 5,
            -84..=-82 => 1 << 2,
            -85 => 1 << 1,
            _ => 1,
        };
        self.txrate = self.closest_rate(wanted);
    }

    /// `netSend`: an Ethernet payload from its LLC header on, to
    /// `destination`; an empty one sends a null frame. False if it
    /// could not go: on a WPA link, until the handshake has put the
    /// keys in place (the C sent the bytecode's frames in clear then).
    #[inline(never)]
    pub fn send(
        &mut self,
        link: &mut impl Link,
        data: &[u8],
        destination: &Mac,
        low_rate: bool,
    ) -> bool {
        let keyed = matches!(self.security, Security::Psk { .. } | Security::Sae { .. });
        let handshake = matches!(self.keys, KeyState::Msg1 | KeyState::Msg3);
        if keyed && handshake && !data.is_empty() {
            return false;
        }
        self.transmit_data(link, data, destination, low_rate, false)
    }

    /// A data frame; in clear if `clear` (handshake messages to an
    /// access point that holds no key yet).
    fn transmit_data(
        &mut self,
        link: &mut impl Link,
        data: &[u8],
        destination: &Mac,
        low_rate: bool,
        clear: bool,
    ) -> bool {
        if self.state != State::Eapol && self.state != State::Run {
            return false;
        }
        if 24 + data.len() + ccmp::OVERHEAD > self.tx.len() {
            return false;
        }
        let own = link.mac();
        let managed = self.mode == Mode::Managed;
        let multicast = destination[0] & 1 != 0;
        // Handshake frames may go in clear, and so does the null frame.
        let handshake = clear;
        let cipher = match self.security {
            _ if data.is_empty() => HwCipher::None,
            Security::Open | Security::Sae { .. } => HwCipher::None,
            Security::Wep { long, .. } => {
                if long {
                    HwCipher::Wep104
                } else {
                    HwCipher::Wep40
                }
            }
            Security::Psk { .. } if handshake => HwCipher::None,
            Security::Psk { pairwise, .. } => match pairwise {
                Some(Cipher::Tkip) => HwCipher::Tkip,
                _ => HwCipher::Ccmp,
            },
        };
        let soft = self.soft.is_some() && !data.is_empty() && !handshake;
        let t = &mut self.tx;
        t[0] = if data.is_empty() { 0x48 } else { 0x08 };
        t[1] = if managed { 0x01 } else { 0x02 } | if cipher != HwCipher::None { 0x40 } else { 0 };
        if managed {
            t[4..10].copy_from_slice(&self.bssid);
            t[10..16].copy_from_slice(&own);
            t[16..22].copy_from_slice(destination);
        } else {
            t[4..10].copy_from_slice(destination);
            t[10..16].copy_from_slice(&self.bssid);
            t[16..22].copy_from_slice(&own);
        }
        t[22] = 0;
        t[23] = 0;
        t[24..24 + data.len()].copy_from_slice(data);
        let mut len = 24 + data.len();
        let overhead = match cipher {
            HwCipher::None => 0,
            HwCipher::Wep40 | HwCipher::Wep104 => 8,
            HwCipher::Tkip => 20,
            HwCipher::Ccmp => 16,
        };
        let mask = if low_rate {
            self.lowest_txrate
        } else {
            self.txrate
        };
        let (units, rate) = mask_rate(mask);
        let d = if !managed && multicast {
            0
        } else {
            txtime(len + overhead, units) + 10
        };
        t[2..4].copy_from_slice(&d.to_le_bytes());
        let mut tx = Tx {
            rate,
            ack: managed || !multicast,
            cipher,
            key: 0,
            iv: 0,
            eiv: 0,
            timestamp: false,
        };
        match cipher {
            HwCipher::Wep40 | HwCipher::Wep104 => {
                let mut iv = [0u8; 3];
                link.random(&mut iv);
                tx.iv = u32::from_le_bytes([iv[0], iv[1], iv[2], 0]);
            }
            HwCipher::Tkip => {
                let p = self.tx_pn.to_le_bytes();
                tx.iv = u32::from_le_bytes([p[1], (p[1] | 0x20) & 0x7F, p[0], 0x20]);
                tx.eiv = u32::from_le_bytes([p[2], p[3], p[4], p[5]]);
                self.tx_pn += 1;
            }
            HwCipher::Ccmp => {
                let p = self.tx_pn.to_le_bytes();
                tx.iv = u32::from_le_bytes([p[0], p[1], 0, 0x20]);
                tx.eiv = u32::from_le_bytes([p[2], p[3], p[4], p[5]]);
                self.tx_pn += 1;
            }
            HwCipher::None => {}
        }
        if soft {
            let tk = self.soft.as_ref().map(|s| s.tk).unwrap_or([0; 16]);
            len = ccmp::protect(&tk, 0, self.tx_pn, &mut self.tx, len);
            self.tx_pn += 1;
        }
        link.transmit(&self.tx[..len], &tx)
    }

    /// Every couple of hundred milliseconds, from the main loop: time
    /// out what did not answer, age the stations of the access point.
    #[inline(never)]
    pub fn tick(&mut self, link: &mut impl Link) {
        if self.mode == Mode::Managed {
            if self.timeout > 0 {
                self.timeout -= 1;
            }
            if self.timeout == 0 {
                self.state = State::Idle;
            }
            return;
        }
        for i in 0..MAX_STATIONS {
            if self.peers[i].state == State::Idle {
                continue;
            }
            self.peers[i].timer = self.peers[i].timer.saturating_sub(1);
            if self.peers[i].timer == 0 {
                // Authentication expired.
                self.peers[i].state = State::Idle;
                let to = self.peers[i].mac;
                let own = link.mac();
                let bssid = self.bssid;
                let at = self.header(&own, 0xC0, 0, &to, &bssid);
                let at = put(&mut self.tx, at, &2u16.to_le_bytes());
                self.send_management(link, at, false);
            }
        }
    }

    /// As often as possible: what waits on a clock (an association to
    /// try again after the access point said to come back).
    #[inline(never)]
    pub fn poll(&mut self, link: &mut impl Link) {
        if self.sa_query.sent != 0 {
            let now = link.millis();
            if self.state != State::Run {
                self.sa_query.sent = 0;
            } else if now.wrapping_sub(self.sa_query.start) >= SA_QUERY_MAX_MS {
                // No answer under the keys: the access point no longer
                // holds the association. Join again.
                self.sa_query.sent = 0;
                self.state = State::Idle;
            } else if (now.wrapping_sub(self.sa_query.next) as i32) >= 0 {
                self.sa_query_round(link);
            }
        }
        if let Some(at) = self.retry_assoc_at
            && (link.millis().wrapping_sub(at) as i32) >= 0
        {
            self.retry_assoc_at = None;
            if self.state == State::Assoc {
                self.associate(link);
            }
        }
    }

    // ---- frames in -----------------------------------------------------

    /// A frame from the stick, in `frame[..rx.len]` (the buffer may be
    /// changed). Returns the data to hand up, if any.
    #[inline(never)]
    pub fn input(&mut self, link: &mut impl Link, frame: &mut [u8], rx: Rx) -> Option<Delivery> {
        if self.state == State::Idle || rx.len < 10 {
            return None;
        }
        match frame[0] & 0x0C {
            0x00 => {
                self.input_management(link, frame, rx);
                None
            }
            0x08 => self.input_data(link, frame, rx),
            _ => None,
        }
    }

    #[inline(never)]
    fn input_management(&mut self, link: &mut impl Link, frame: &mut [u8], rx: Rx) {
        let len = rx.len;
        if len < 24 || frame[1] & 3 != 0 {
            return;
        }
        let own = link.mac();
        let (a1, a2, a3) = (mac_at(frame, 4), mac_at(frame, 10), mac_at(frame, 16));
        let managed = self.mode == Mode::Managed;
        // Each address compared once (nothing below changes them).
        let to_us = same(&a1, &own);
        let sent_by_ap = same(&a2, &self.ap);
        let our_bss = same(&a3, &self.bssid);
        if managed && self.state == State::Run && sent_by_ap {
            self.rssi_sample(rx.rssi as i16);
        }
        let from_ap = to_us && sent_by_ap && our_bss;
        let subtype = frame[0] & 0xF0;
        match subtype {
            0x40 if !managed => {
                // Probe request: answer if for us or for anyone.
                let mut name: &[u8] = &[];
                for (id, e) in elements(&frame[24..len]) {
                    if id == 0 && e.len() <= 32 {
                        name = e;
                    }
                }
                let ours = &self.ssid[..self.ssid_len];
                if name.is_empty() || name == ours {
                    let n = self.beacon_like(link, 0x50, &a2);
                    let d = txtime(n, 2) + 10;
                    self.tx[2..4].copy_from_slice(&d.to_le_bytes());
                    let tx = Tx {
                        rate: 0,
                        ack: false,
                        cipher: HwCipher::None,
                        key: 0,
                        iv: 0,
                        eiv: 0,
                        timestamp: true,
                    };
                    link.transmit(&self.tx[..n], &tx);
                }
            }
            0x50 | 0x80 => {
                if managed && self.state == State::Run && sent_by_ap && our_bss {
                    self.timeout = RUN_TIMEOUT;
                }
            }
            0xB0 if len >= 30 => {
                let algorithm = le16(frame, 24);
                let seq = le16(frame, 26);
                let status = le16(frame, 28);
                if managed {
                    if self.state != State::Auth || !from_ap {
                        return;
                    }
                    if let Security::Sae { h2e } = self.security {
                        if !self.cached {
                            self.input_sae(link, algorithm, seq, status, frame, len);
                        } else if algorithm == 0 && seq == 2 && status == 0 {
                            self.associate(link);
                        } else {
                            self.forget_cached(link, h2e);
                        }
                    } else if !self.shared_auth {
                        if algorithm == 0 && seq == 2 && status == 0 {
                            self.associate(link);
                        } else {
                            self.state = State::Idle;
                        }
                    } else {
                        self.input_shared_auth(link, algorithm, seq, status, frame, len);
                    }
                } else if to_us && our_bss {
                    self.accept_auth(link, &a2, algorithm, seq, status);
                }
            }
            0x00 if !managed => {
                if !to_us || !our_bss {
                    return;
                }
                if let Some(i) = self.peer(&a2) {
                    self.send_association_response(link, &a2, i as u16 + 1);
                    self.peers[i].state = State::Run;
                    self.peers[i].timer = STA_MAX_IDLE;
                }
            }
            0x10 if managed && self.state == State::Assoc && from_ap && len >= 30 => {
                let status = le16(frame, 26);
                if status == 30 && self.is_wpa3() {
                    // Refused for now: the access point is asking our
                    // old association whether it is still alive (after a
                    // restart, say). Come back when it says, within ten
                    // seconds: a longer wait (up to fifty days, and the
                    // frame is unprotected) counts as a refusal.
                    let tu = elements(&frame[30..len])
                        .find(|(id, e)| *id == 56 && e.len() == 5 && e[0] == 3)
                        .map(|(_, e)| u32::from_le_bytes([e[1], e[2], e[3], e[4]]))
                        .filter(|tu| *tu <= MAX_COMEBACK_TU);
                    match tu {
                        Some(tu) => {
                            let ms = (tu * 1024).div_ceil(1000);
                            self.retry_assoc_at = Some(link.millis().wrapping_add(ms));
                            self.timeout = ASSOC_TIMEOUT + ms / 200;
                        }
                        None => self.state = State::Idle,
                    }
                    return;
                }
                if status != 0 {
                    match self.security {
                        // The access point no longer has the cached key
                        // (status 53): the whole exchange, then.
                        Security::Sae { h2e } if self.cached => self.forget_cached(link, h2e),
                        _ => self.state = State::Idle,
                    }
                    return;
                }
                self.rssi_index = 0;
                self.rssi_average = -100;
                if let Security::Psk { .. } | Security::Sae { .. } = self.security {
                    self.state = State::Eapol;
                    self.timeout = EAPOL_TIMEOUT;
                    self.keys = KeyState::Msg1;
                    self.ap_keyed = false;
                    self.replay_active = false;
                } else {
                    self.state = State::Run;
                    self.timeout = RUN_TIMEOUT;
                }
            }
            0xA0 | 0xC0 => {
                if managed {
                    if self.state == State::Idle || !sent_by_ap || !our_bss {
                        return;
                    }
                    // Protected management frames once message 4 is out:
                    // before, the access point holds no key to protect a
                    // deauthentication with, and one in clear counts.
                    let protected =
                        self.soft.is_some() && matches!(self.keys, KeyState::Group | KeyState::Run);
                    if protected && !self.trusted_management(frame, len, to_us) {
                        // Forged, or from an access point that lost our
                        // keys (it restarted, or never got message 4)
                        // and says the frames it gets are from nobody it
                        // knows (reasons 6 and 7): ask it, under the
                        // keys (802.11-2020 11.13, as wpa_supplicant).
                        if to_us
                            && frame[1] & 0x40 == 0
                            && len >= 26
                            && matches!(le16(frame, 24), 6 | 7)
                        {
                            self.start_sa_query(link);
                        }
                        return;
                    }
                    if to_us || protected {
                        self.state = State::Idle;
                    }
                } else if to_us
                    && our_bss
                    && let Some(i) = self.peer(&a2)
                {
                    if subtype == 0xA0 {
                        self.peers[i].state = State::Auth;
                        self.peers[i].timer = STA_ASSOC_TIMEOUT;
                    } else {
                        self.peers[i].state = State::Idle;
                    }
                }
            }
            0xD0 if managed && from_ap => self.input_action(link, frame, len),
            _ => {}
        }
    }

    /// On a WPA3 link, a disassociation or deauthentication is believed
    /// only if the access point's keys vouch for it.
    #[inline(never)]
    fn trusted_management(&mut self, frame: &mut [u8], len: usize, unicast: bool) -> bool {
        let Some(soft) = self.soft.as_mut() else {
            return true;
        };
        if !unicast {
            let Some((id, igtk)) = soft.igtk else {
                return false;
            };
            match ccmp::bip_check(&igtk, &frame[..len]) {
                Some((key_id, ipn)) if key_id == id && ipn > soft.igtk_ipn => {
                    soft.igtk_ipn = ipn;
                    true
                }
                _ => false,
            }
        } else {
            if frame[1] & 0x40 == 0 {
                return false;
            }
            let tk = soft.tk;
            match ccmp::unprotect(&tk, &mut frame[..len]) {
                Some((_, pn)) if pn > soft.mgmt_rx_pn => {
                    soft.mgmt_rx_pn = pn;
                    self.ap_keyed = true;
                    true
                }
                _ => false,
            }
        }
    }

    /// An action frame from the access point: an SA Query gets its
    /// answer.
    #[inline(never)]
    fn input_action(&mut self, link: &mut impl Link, frame: &mut [u8], len: usize) {
        if self.soft.is_none() || frame[1] & 0x40 == 0 || !self.trusted_management(frame, len, true)
        {
            return;
        }
        let body = &frame[24..len - ccmp::OVERHEAD];
        match *body {
            [8, 0, a, b, ..] => {
                let own = link.mac();
                let (ap, bssid) = (self.ap, self.bssid);
                let at = self.header(&own, 0xD0, 0, &ap, &bssid);
                let at = put(&mut self.tx, at, &[8, 1, a, b]);
                self.send_management(link, at, true);
            }
            // The access point still holds our association.
            [8, 1, a, b, ..]
                if self.sa_query.ids[..self.sa_query.sent as usize].contains(&[a, b]) =>
            {
                self.sa_query.sent = 0;
            }
            _ => {}
        }
    }

    /// Begin the SA Query procedure, unless it runs or ran less than ten
    /// seconds ago (forged deauthentications must not keep the radio
    /// busy).
    fn start_sa_query(&mut self, link: &mut impl Link) {
        let now = link.millis();
        let q = &mut self.sa_query;
        if q.sent != 0
            || q.last
                .is_some_and(|at| now.wrapping_sub(at) < SA_QUERY_QUIET_MS)
        {
            return;
        }
        q.last = Some(now);
        q.start = now;
        self.sa_query_round(link);
    }

    /// One SA Query request, under the pairwise key, with a new
    /// transaction identifier: an answer to any of them will do.
    fn sa_query_round(&mut self, link: &mut impl Link) {
        let mut id = [0u8; 2];
        link.random(&mut id);
        let q = &mut self.sa_query;
        if (q.sent as usize) < q.ids.len() {
            q.ids[q.sent as usize] = id;
            q.sent += 1;
        }
        q.next = link.millis().wrapping_add(SA_QUERY_RETRY_MS);
        let own = link.mac();
        let (ap, bssid) = (self.ap, self.bssid);
        let at = self.header(&own, 0xD0, 0, &ap, &bssid);
        let at = put(&mut self.tx, at, &[8, 0, id[0], id[1]]);
        self.send_management(link, at, true);
    }

    #[inline(never)]
    fn input_shared_auth(
        &mut self,
        link: &mut impl Link,
        algorithm: u16,
        seq: u16,
        status: u16,
        frame: &[u8],
        len: usize,
    ) {
        if algorithm != 1 || status != 0 {
            self.state = State::Idle;
            return;
        }
        match seq {
            2 => {
                let challenge = elements(&frame[30..len])
                    .find(|(id, _)| *id == 16)
                    .map(|(_, e)| e);
                let Some(challenge) = challenge.filter(|c| c.len() == 128) else {
                    self.state = State::Idle;
                    return;
                };
                let own = link.mac();
                let (ap, bssid) = (self.ap, self.bssid);
                let at = self.header(&own, 0xB0, 0x40, &ap, &bssid);
                let at = put(&mut self.tx, at, &[1, 0, 3, 0, 0, 0]);
                let n = put_element(&mut self.tx, at, 16, challenge);
                let Security::Wep { long, .. } = self.security else {
                    return;
                };
                let (units, rate) = mask_rate(self.lowest_txrate);
                let d = txtime(n, units) + 10;
                self.tx[2..4].copy_from_slice(&d.to_le_bytes());
                let mut iv = [0u8; 3];
                link.random(&mut iv);
                let tx = Tx {
                    rate,
                    ack: true,
                    cipher: if long {
                        HwCipher::Wep104
                    } else {
                        HwCipher::Wep40
                    },
                    key: 0,
                    iv: u32::from_le_bytes([iv[0], iv[1], iv[2], 0]),
                    eiv: 0,
                    timestamp: false,
                };
                if !link.transmit(&self.tx[..n], &tx) {
                    self.state = State::Idle;
                }
            }
            4 => self.associate(link),
            _ => self.state = State::Idle,
        }
    }

    // ---- the access point ----------------------------------------------

    fn peer(&self, mac: &Mac) -> Option<usize> {
        self.peers
            .iter()
            .position(|p| p.state != State::Idle && same(&p.mac, mac))
    }

    #[inline(never)]
    fn accept_auth(
        &mut self,
        link: &mut impl Link,
        sta: &Mac,
        algorithm: u16,
        seq: u16,
        status: u16,
    ) {
        let refuse = if algorithm != 0 {
            Some(13)
        } else if seq != 1 {
            Some(14)
        } else if status != 0 {
            Some(12)
        } else {
            None
        };
        if let Some(code) = refuse {
            return self.send_auth(link, sta, algorithm, seq.wrapping_add(1), code);
        }
        let slot = self
            .peer(sta)
            .or_else(|| self.peers.iter().position(|p| p.state == State::Idle));
        let Some(slot) = slot else {
            return self.send_auth(link, sta, 0, 2, 22);
        };
        self.peers[slot] = Peer {
            state: State::Assoc,
            timer: STA_ASSOC_TIMEOUT,
            mac: *sta,
        };
        self.send_auth(link, sta, 0, 2, 0);
    }

    fn send_association_response(&mut self, link: &mut impl Link, sta: &Mac, id: u16) {
        let own = link.mac();
        let bssid = self.bssid;
        let at = self.header(&own, 0x10, 0, sta, &bssid);
        let at = put(
            &mut self.tx,
            at,
            &[0x01, 0, 0, 0, id as u8, (id >> 8) as u8],
        );
        let at = put(&mut self.tx, at, &RATES);
        self.send_management(link, at, false);
    }

    #[inline(never)]
    fn input_data(&mut self, link: &mut impl Link, frame: &mut [u8], rx: Rx) -> Option<Delivery> {
        if self.state != State::Eapol && self.state != State::Run {
            return None;
        }
        let mut len = rx.len;
        if len < 24 {
            return None;
        }
        let own = link.mac();
        let (a1, a2, a3) = (mac_at(frame, 4), mac_at(frame, 10), mac_at(frame, 16));
        let direction = frame[1] & 3;
        let (source, destination) = if direction == 2 && self.mode == Mode::Managed {
            if !same(&a1, &own) && !same(&a1, &BROADCAST) && a1[..3] != MULTICAST {
                return None;
            }
            if !same(&a2, &self.bssid) {
                return None;
            }
            self.rssi_sample(rx.rssi as i16);
            (a3, a1)
        } else if direction == 1 && self.mode == Mode::Master {
            if !same(&a1, &self.bssid) {
                return None;
            }
            let i = self
                .peer(&a2)
                .filter(|i| self.peers[*i].state == State::Run)?;
            self.peers[i].timer = STA_MAX_IDLE;
            if !same(&a3, &own) && !same(&a3, &BROADCAST) && a3[..3] != MULTICAST {
                return None;
            }
            (a2, a3)
        } else {
            return None;
        };
        let mut decrypted = rx.decrypted;
        let group = destination[0] & 1 != 0;
        if frame[1] & 0x40 != 0 && self.soft.is_some() && !decrypted {
            // WPA3: the stick holds no key, the frame is opened here.
            let soft = self.soft.as_mut()?;
            let (pn, key_id) = ccmp::header(&frame[..len])?;
            let key = if group {
                match soft.gtk {
                    Some((id, k)) if id == key_id => k,
                    _ => return None,
                }
            } else {
                soft.tk
            };
            let (n, _) = ccmp::unprotect(&key, &mut frame[..len])?;
            if !self.fresh(group, key_id, pn) {
                return None;
            }
            self.ap_keyed |= !group;
            len = n;
            decrypted = true;
        } else if decrypted
            && let Security::Psk {
                pairwise, group: g, ..
            } = self.security
        {
            // What the stick opened: its packet number, from the IV
            // words of the descriptor, must be new (the C driver never
            // looked, and a frame recorded on the air went up again).
            let cipher = if group {
                g
            } else {
                pairwise.unwrap_or(Cipher::Ccmp)
            };
            let (iv, eiv) = (rx.iv, rx.eiv as u64);
            let pn = match cipher {
                Cipher::Ccmp => eiv << 16 | (iv & 0xFFFF) as u64,
                Cipher::Tkip => eiv << 16 | ((iv & 0xFF) << 8 | (iv >> 16) & 0xFF) as u64,
            };
            if !self.fresh(group, (iv >> 30) as u8, pn) {
                return None;
            }
            self.ap_keyed |= !group;
        }
        if frame[1] & 0x40 != 0 && !decrypted {
            // Still sealed: the stick had no key for it (it hands such
            // frames up as they came). What follows the header is
            // whatever the sender wrote, in clear: not to be believed.
            return None;
        }
        match frame[0] & 0xF0 {
            0x00 => {
                let body = &frame[24..len];
                let eapol = body.len() >= 8 && body[..8] == LLC_EAPOL;
                let keyed = matches!(self.security, Security::Psk { .. } | Security::Sae { .. });
                if self.mode == Mode::Managed
                    && keyed
                    && !decrypted
                    && frame[1] & 0x40 == 0
                    && !eapol
                {
                    // In clear on a keyed link: not from the key holder.
                    return None;
                }
                if self.ap_keyed && !decrypted {
                    // The access point uses the pairwise key: nothing
                    // comes in clear from it any more, not even the
                    // handshake. (Until then a message 3 sent again in
                    // clear, message 4 lost, is let in and answered.)
                    return None;
                }
                if eapol && self.mode == Mode::Managed {
                    let mut copy = [0u8; 400];
                    let n = (len - 24).min(copy.len());
                    copy[..n].copy_from_slice(&frame[24..24 + n]);
                    self.input_eapol(link, &mut copy[..n], decrypted);
                    return None;
                }
                Some(Delivery {
                    start: 24,
                    len: len - 24,
                    source,
                    destination,
                })
            }
            0x40 => {
                if self.mode == Mode::Managed && same(&source, &self.ap) {
                    let ap = self.ap;
                    self.send(link, &[], &ap, true);
                }
                None
            }
            _ => None,
        }
    }

    /// Whether a packet number is past the last one of its key, which
    /// it then becomes.
    fn fresh(&mut self, group: bool, key_id: u8, pn: u64) -> bool {
        let last = if group {
            &mut self.group_rsc[key_id as usize & 3]
        } else {
            &mut self.rx_pn
        };
        if pn <= *last {
            return false;
        }
        *last = pn;
        true
    }

    // ---- WPA and WPA2: the key handshakes ---------------------------------

    fn version(&self) -> u16 {
        match self.security {
            Security::Sae { .. } => 0,
            Security::Psk {
                pairwise: Some(Cipher::Ccmp),
                ..
            } => 2,
            _ => 1,
        }
    }

    /// The keys the handshake under way signs and encrypts with.
    fn handshake_ptk(&self) -> &[u8; 64] {
        self.next_ptk.as_ref().unwrap_or(&self.ptk)
    }

    /// Drop the cached key and run the password exchange after all.
    fn forget_cached(&mut self, link: &mut impl Link, h2e: bool) {
        self.pmksa = None;
        self.cached = false;
        self.state = State::Auth;
        self.timeout = AUTH_TIMEOUT;
        self.sae_commit(link, h2e);
    }

    fn mic(&self, data: &[u8]) -> [u8; 16] {
        let kck = &self.handshake_ptk()[..16];
        match self.version() {
            0 => {
                let mut k = [0u8; 16];
                k.copy_from_slice(kck);
                aes::cmac(&k, &[data])
            }
            2 => {
                let full = hmac_sha1(kck, &[data]);
                let mut out = [0u8; 16];
                out.copy_from_slice(&full[..16]);
                out
            }
            _ => hmac_md5(kck, &[data]),
        }
    }

    /// Build, sign and send an EAPOL-Key frame with replay counter
    /// `counter`; in clear if `clear` (the access point has no key yet).
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn send_key(
        &mut self,
        link: &mut impl Link,
        info: u16,
        counter: &[u8; 8],
        nonce: &[u8; 32],
        data: &[u8],
        clear: bool,
    ) {
        let mut e = [0u8; 99 + 48];
        let wpa1 = matches!(self.security, Security::Psk { wpa2: false, .. });
        e[0] = 1;
        e[1] = 3;
        e[2..4].copy_from_slice(&((95 + data.len()) as u16).to_be_bytes());
        e[4] = if wpa1 { 0xFE } else { 0x02 };
        e[5..7].copy_from_slice(&(info | self.version()).to_be_bytes());
        e[9..17].copy_from_slice(counter);
        e[17..49].copy_from_slice(nonce);
        e[97..99].copy_from_slice(&(data.len() as u16).to_be_bytes());
        e[99..99 + data.len()].copy_from_slice(data);
        let n = 99 + data.len();
        let mic = self.mic(&e[..n]);
        e[81..97].copy_from_slice(&mic);
        let mut body = [0u8; 8 + 99 + 48];
        body[..8].copy_from_slice(&LLC_EAPOL);
        body[8..8 + n].copy_from_slice(&e[..n]);
        let ap = self.ap;
        self.transmit_data(link, &body[..8 + n], &ap, true, clear);
    }

    /// An EAPOL-Key frame from the access point; `sealed` if it came
    /// under the pairwise key.
    #[inline(never)]
    fn input_eapol(&mut self, link: &mut impl Link, body: &mut [u8], sealed: bool) {
        let f = &mut body[8..];
        if f.len() < 99 || (f[0] != 1 && f[0] != 2) || f[1] != 3 || (f[4] != 0xFE && f[4] != 0x02) {
            return;
        }
        let declared = be16(f, 2) as usize + 4;
        // The length it declares may cut the frame short, but not
        // before the end of its fixed fields.
        if declared < 99 || declared > f.len() {
            return;
        }
        let f = &mut f[..declared];
        if self.replay_active && f[9..17] <= self.replay[..] {
            return;
        }
        let info = be16(f, 5);
        let pairwise = info & 0x0008 != 0;
        let index = (info >> 4) & 3;
        let (ack, mic, secure, error, request) = (
            info & 0x80 != 0,
            info & 0x100 != 0,
            info & 0x200 != 0,
            info & 0x400 != 0,
            info & 0x800 != 0,
        );
        if !ack || error || request {
            return;
        }
        if pairwise && index == 0 && !mic && !secure {
            self.message_1(link, f, info);
        } else if pairwise && index == 0 && mic {
            self.message_3(link, f, sealed);
        } else if !pairwise && mic && secure {
            self.group_message(link, f, info, sealed);
        }
    }

    #[inline(never)]
    fn message_1(&mut self, link: &mut impl Link, f: &[u8], info: u16) {
        // On a running link: a new pairwise key (the access point's
        // periodic rekey), used once the handshake is through.
        let rekey =
            matches!(self.keys, KeyState::Group | KeyState::Run) && self.state == State::Run;
        if !rekey && self.keys != KeyState::Msg1 && self.keys != KeyState::Msg3 {
            return;
        }
        if !rekey {
            self.keys = KeyState::Msg1;
            // A rekey left half done (the link went down between its
            // messages 1 and 3) is over: its keys would sign this
            // handshake, and every one after it.
            self.next_ptk = None;
        }
        // Message 2 answers with this counter. Message 1 carries no
        // integrity code: its counter is not taken as the last one
        // seen (a forged one, huge, would make every genuine frame
        // after it look replayed, the access point's own message 1
        // retransmitted included); only a checked frame moves that.
        self.msg1_replay.copy_from_slice(&f[9..17]);
        if let Security::Psk {
            wpa2: false,
            pairwise: ref mut p @ None,
            ..
        } = self.security
        {
            *p = Some(if info & 7 == 2 {
                Cipher::Ccmp
            } else {
                Cipher::Tkip
            });
        }
        self.anonce.copy_from_slice(&f[17..49]);
        // One nonce for the whole handshake, whatever the number of
        // messages 1 (as wpa_supplicant): a new one is drawn once a
        // message 3 has been answered.
        if self.renew_snonce {
            let mut snonce = [0u8; 32];
            link.random(&mut snonce);
            self.snonce = snonce;
            self.renew_snonce = false;
        }
        let snonce = self.snonce;
        let ptk = self.derive_ptk(&link.mac(), &snonce);
        if rekey {
            self.next_ptk = Some(ptk);
        } else {
            self.ptk = ptk;
        }
        let mut e = [0u8; 48];
        let n = self.own_element(&mut e);
        let counter = self.msg1_replay;
        self.send_key(link, 0x0008 | 0x0100, &counter, &snonce, &e[..n], !rekey);
        if rekey {
            return;
        }
        // The pairwise key goes in now, as the C driver did: message 4
        // still leaves in clear, what follows does not.
        self.install_pairwise(link, false);
        self.ap_keyed = false;
        self.keys = KeyState::Msg3;
    }

    /// The pairwise keys from the PMK and both nonces (PRF-512, or the
    /// SHA-256 KDF after SAE).
    fn derive_ptk(&self, own: &Mac, snonce: &[u8; 32]) -> [u8; 64] {
        let (lo, hi) = if *own < self.ap {
            (*own, self.ap)
        } else {
            (self.ap, *own)
        };
        let (n_lo, n_hi) = if *snonce < self.anonce {
            (*snonce, self.anonce)
        } else {
            (self.anonce, *snonce)
        };
        let mut seed = [0u8; 76];
        seed[..6].copy_from_slice(&lo);
        seed[6..12].copy_from_slice(&hi);
        seed[12..44].copy_from_slice(&n_lo);
        seed[44..].copy_from_slice(&n_hi);
        let mut ptk = [0u8; 64];
        if self.is_wpa3() {
            sha256::kdf(&self.pmk, b"Pairwise key expansion", &seed, &mut ptk[..48]);
        } else {
            prf(&self.pmk, b"Pairwise key expansion", &seed, &mut ptk);
        }
        ptk
    }

    /// Put `self.ptk`'s temporal key to use: in the stick, or (WPA3) in
    /// the firmware's own keys, keeping the group keys on a rekey.
    fn install_pairwise(&mut self, link: &mut impl Link, keep_group: bool) {
        let none = [0u8; 8];
        let mut tk = [0u8; 16];
        tk.copy_from_slice(&self.ptk[32..48]);
        match self.security {
            Security::Sae { .. } => {
                let old = self.soft.take().filter(|_| keep_group);
                self.soft = Some(SoftKeys {
                    tk,
                    gtk: old.as_ref().and_then(|o| o.gtk),
                    igtk: old.as_ref().and_then(|o| o.igtk),
                    mgmt_rx_pn: 0,
                    igtk_ipn: old.as_ref().map_or(0, |o| o.igtk_ipn),
                });
            }
            Security::Psk {
                pairwise: Some(Cipher::Tkip),
                ..
            } => {
                let mut tx_mic = [0u8; 8];
                let mut rx_mic = [0u8; 8];
                tx_mic.copy_from_slice(&self.ptk[56..64]);
                rx_mic.copy_from_slice(&self.ptk[48..56]);
                link.set_key(0, HwCipher::Tkip, &tk, &tx_mic, &rx_mic);
            }
            _ => link.set_key(0, HwCipher::Ccmp, &tk, &none, &none),
        }
        // The first frame is numbered 1 (the C driver started at 0, and
        // access points dropped it as a replay); the access point's
        // numbers start again too.
        self.tx_pn = 1;
        self.rx_pn = 0;
    }

    fn check_mic(&self, f: &mut [u8]) -> bool {
        let mut got = [0u8; 16];
        got.copy_from_slice(&f[81..97]);
        f[81..97].fill(0);
        let want = self.mic(f);
        f[81..97].copy_from_slice(&got);
        ccmp::constant_eq(&want, &got)
    }

    /// The key data of a message, decrypted into `out`; its length.
    #[inline(never)]
    fn key_data(&self, f: &[u8], out: &mut [u8]) -> Option<usize> {
        let n = be16(f, 97) as usize;
        let data = f.get(99..99 + n)?;
        let mut kek = [0u8; 16];
        kek.copy_from_slice(&self.handshake_ptk()[16..32]);
        if self.version() == 1 {
            // RC4 under the key IV and the KEK.
            if n > out.len() {
                return None;
            }
            let mut key = [0u8; 32];
            key[..16].copy_from_slice(&f[49..65]);
            key[16..].copy_from_slice(&kek);
            out[..n].copy_from_slice(data);
            rc4(&key, 256, &mut out[..n]);
            Some(n)
        } else {
            if n < 24 || n - 8 > out.len() {
                return None;
            }
            aes::unwrap(&kek, data, &mut out[..n - 8]).then_some(n - 8)
        }
    }

    /// The key data of message 3, in clear in `out`: WPA's carries the
    /// access point's element as is, the others are encrypted.
    fn message_3_data(&self, f: &[u8], out: &mut [u8; 256]) -> Option<usize> {
        if !matches!(self.security, Security::Psk { wpa2: false, .. }) {
            return self.key_data(f, out);
        }
        let n = be16(f, 97) as usize;
        let data = f.get(99..99 + n)?;
        out.get_mut(..n)?.copy_from_slice(data);
        Some(n)
    }

    /// Whether message 3's key data brings everything the link needs:
    /// the group key (WPA2 and WPA3), whole for its cipher, and with
    /// WPA3 the integrity group key. Checked before message 4 goes:
    /// after it, the access point takes the station for ready.
    fn group_keys_present(&self, plain: &[u8]) -> bool {
        if matches!(self.security, Security::Psk { wpa2: false, .. }) {
            return true;
        }
        let tkip = matches!(
            self.security,
            Security::Psk {
                group: Cipher::Tkip,
                ..
            }
        );
        let gtk_len = if tkip { 32 } else { 16 };
        let kde = |kind: u8, len: usize| {
            elements(plain)
                .any(|(id, e)| id == 0xDD && e.len() >= len && e[..4] == [0x00, 0x0F, 0xAC, kind])
        };
        let gtk = elements(plain).any(|(id, e)| {
            id == 0xDD && e.len() >= 6 + gtk_len && e[..4] == [0x00, 0x0F, 0xAC, 1] && e[4] & 3 != 0
        });
        gtk && (!self.is_wpa3() || kde(9, 28))
    }

    /// Whether the elements of message 3 are those the network
    /// announced (802.11-2020 12.7.6.4): its RSN element, and RSN
    /// extension element, byte for byte (or WPA's element). An attacker
    /// can change a beacon, not message 3: a network that offered WPA3
    /// and was made to look as if it did not shows here. When they
    /// differ, or nothing was known of the network, what message 3 says
    /// is kept for the next attempt (see `auth`).
    fn same_offer(&mut self, plain: &[u8]) -> bool {
        let offer = Offer::from_elements(self.bssid, plain);
        if self.bss_known && offer.digest == self.bss.digest {
            return true;
        }
        self.learned = Some(offer);
        false
    }

    #[inline(never)]
    fn message_3(&mut self, link: &mut impl Link, f: &mut [u8], sealed: bool) {
        if self.next_ptk.is_some() && matches!(self.keys, KeyState::Group | KeyState::Run) {
            return self.rekey_message_3(link, f);
        }
        // Msg3: the first. Group or Run: the same one again (message 4
        // was lost, the access point sends message 3 again), to be
        // answered, nothing installed again.
        if self.keys == KeyState::Msg1 {
            return;
        }
        if f[17..49] != self.anonce || !self.check_mic(f) {
            return;
        }
        let mut plain = [0u8; 256];
        let Some(n) = self.message_3_data(f, &mut plain) else {
            return;
        };
        let plain = &plain[..n];
        if !self.same_offer(plain) {
            // Not the network the scan saw: no further with it.
            self.state = State::Idle;
            return;
        }
        if !self.group_keys_present(plain) {
            return;
        }
        let wpa1 = matches!(self.security, Security::Psk { wpa2: false, .. });
        self.replay.copy_from_slice(&f[9..17]);
        self.replay_active = true;
        let secure = if wpa1 { 0 } else { 0x200 };
        // Message 4 goes as message 3 came: in clear while the access
        // point holds no key (it would drop it otherwise).
        let counter = self.replay;
        self.send_key(
            link,
            0x0008 | 0x0100 | secure,
            &counter,
            &[0; 32],
            &[],
            !sealed,
        );
        self.renew_snonce = true;
        self.pmksa_proven = true;
        self.state = State::Run;
        self.timeout = RUN_TIMEOUT;
        if wpa1 {
            // The group key follows in its own handshake.
            if self.keys == KeyState::Msg3 {
                self.keys = KeyState::Group;
            }
            return;
        }
        self.install_group_keys(link, plain, Self::key_rsc(f));
        self.keys = KeyState::Run;
    }

    /// Message 3 of a rekey: checked whole, message 4 leaves under the
    /// current key, then the new one takes over.
    fn rekey_message_3(&mut self, link: &mut impl Link, f: &mut [u8]) {
        if f[17..49] != self.anonce || !self.check_mic(f) {
            return;
        }
        let mut plain = [0u8; 256];
        let Some(n) = self.message_3_data(f, &mut plain) else {
            return;
        };
        let plain = &plain[..n];
        if !self.same_offer(plain) {
            self.state = State::Idle;
            return;
        }
        if !self.group_keys_present(plain) {
            return;
        }
        self.replay.copy_from_slice(&f[9..17]);
        let secure = if matches!(self.security, Security::Psk { wpa2: false, .. }) {
            0
        } else {
            0x200
        };
        let counter = self.replay;
        self.send_key(
            link,
            0x0008 | 0x0100 | secure,
            &counter,
            &[0; 32],
            &[],
            false,
        );
        self.renew_snonce = true;
        if let Some(ptk) = self.next_ptk.take() {
            self.ptk = ptk;
        }
        self.install_pairwise(link, true);
        if !matches!(self.security, Security::Psk { wpa2: false, .. }) {
            self.install_group_keys(link, plain, Self::key_rsc(f));
        }
        self.timeout = RUN_TIMEOUT;
    }

    /// The key receive sequence counter of an EAPOL-Key frame: where the
    /// group key it brings stands.
    fn key_rsc(f: &[u8]) -> u64 {
        let mut rsc = [0u8; 8];
        rsc[..6].copy_from_slice(&f[65..71]);
        u64::from_le_bytes(rsc)
    }

    /// Install the group key (and, on WPA3, the integrity group key)
    /// from a list of key data elements, the group key's counter at
    /// `rsc`. False if there was none.
    #[inline(never)]
    fn install_group_keys(&mut self, link: &mut impl Link, plain: &[u8], rsc: u64) -> bool {
        let mut found = false;
        for (id, e) in elements(plain) {
            if id != 0xDD || e.len() < 4 || e[..3] != [0x00, 0x0F, 0xAC] {
                continue;
            }
            match e[3] {
                1 if e.len() >= 6 + 16 => {
                    let index = e[4] & 3;
                    if index == 0 {
                        continue;
                    }
                    found |= self.install_gtk(link, index, &e[6..], rsc);
                }
                9 if e.len() >= 28 => {
                    if let Some(soft) = self.soft.as_mut() {
                        let mut k = [0u8; 16];
                        k.copy_from_slice(&e[12..28]);
                        let igtk = Some((le16(e, 4), k));
                        // The same key again keeps its counter.
                        if soft.igtk != igtk {
                            soft.igtk = igtk;
                            soft.igtk_ipn =
                                u64::from_le_bytes([e[6], e[7], e[8], e[9], e[10], e[11], 0, 0]);
                        }
                    }
                }
                _ => {}
            }
        }
        found
    }

    /// Install group key `index`, its counter at `rsc`; the key it
    /// already holds is left alone, counter and all (a retransmitted
    /// message 3 or group message, or a replayed one, must not wind the
    /// counter back: CVE-2017-13080).
    fn install_gtk(&mut self, link: &mut impl Link, index: u8, key: &[u8], rsc: u64) -> bool {
        let group = match self.security {
            Security::Psk { group, .. } => group,
            _ => Cipher::Ccmp,
        };
        let len = if group == Cipher::Tkip && self.soft.is_none() {
            32
        } else {
            16
        };
        if key.len() < len {
            return false;
        }
        let i = index as usize & 3;
        let mut k = [0u8; 32];
        k[..len].copy_from_slice(&key[..len]);
        if self.gtk_set & 1 << i != 0 && ccmp::constant_eq(&self.gtks[i], &k) {
            return true;
        }
        self.gtks[i] = k;
        self.gtk_set |= 1 << i;
        self.group_rsc[i] = rsc;
        if let Some(soft) = self.soft.as_mut() {
            let mut k = [0u8; 16];
            k.copy_from_slice(&key[..16]);
            soft.gtk = Some((index, k));
            return true;
        }
        let none = [0u8; 8];
        match group {
            Cipher::Tkip => {
                let mut tx_mic = [0u8; 8];
                let mut rx_mic = [0u8; 8];
                tx_mic.copy_from_slice(&key[24..32]);
                rx_mic.copy_from_slice(&key[16..24]);
                link.set_key(index, HwCipher::Tkip, &key[..16], &tx_mic, &rx_mic);
            }
            Cipher::Ccmp => link.set_key(index, HwCipher::Ccmp, &key[..16], &none, &none),
        }
        true
    }

    /// A group message is signed with the keys in use: a rekey under
    /// way (perhaps begun by a forged message 1) has not replaced them.
    #[inline(never)]
    fn group_message(&mut self, link: &mut impl Link, f: &mut [u8], info: u16, sealed: bool) {
        let pending = self.next_ptk.take();
        self.group_message_current(link, f, info, sealed);
        self.next_ptk = pending;
    }

    fn group_message_current(
        &mut self,
        link: &mut impl Link,
        f: &mut [u8],
        info: u16,
        sealed: bool,
    ) {
        if self.keys != KeyState::Group && self.keys != KeyState::Run {
            return;
        }
        if !self.check_mic(f) {
            return;
        }
        self.replay.copy_from_slice(&f[9..17]);
        self.replay_active = true;
        let index = (info >> 4) & 3;
        let mut plain = [0u8; 256];
        let n = self.key_data(f, &mut plain);
        let rsc = Self::key_rsc(f);
        // The key goes in before the answer: an access point told the
        // key is in place while it is not would leave the rabbit deaf
        // to every broadcast.
        let ok = match (n, self.security) {
            (Some(n), Security::Psk { wpa2: false, .. }) => {
                // WPA: the bare key, in the slot the key information names.
                index != 0 && self.install_gtk(link, index as u8, &plain[..n], rsc)
            }
            (Some(n), _) => {
                self.group_keys_present(&plain[..n])
                    && self.install_group_keys(link, &plain[..n], rsc)
            }
            (None, _) => false,
        };
        if !ok {
            // Better start over.
            self.keys = KeyState::Msg1;
            self.state = State::Idle;
            return;
        }
        let counter = self.replay;
        self.send_key(
            link,
            (index << 4) | 0x0100 | 0x0200,
            &counter,
            &[0; 32],
            &[],
            !sealed,
        );
        self.keys = KeyState::Run;
        self.state = State::Run;
        self.timeout = RUN_TIMEOUT;
    }

    // ---- WPA3: the password exchange --------------------------------------

    #[inline(never)]
    fn sae_commit(&mut self, link: &mut impl Link, h2e: bool) {
        let own = link.mac();
        let password_len = self.password_len;
        let password = self.password;
        let password = &password[..password_len];
        let element = if h2e {
            let mut id = [0u8; 32];
            id.copy_from_slice(&sha256::sha256(&[
                &self.ssid[..self.ssid_len],
                &[0],
                password,
            ]));
            let point = match &self.pt {
                Some((k, p)) if *k == id => Some(*p),
                _ => sae::password_point(&self.ssid[..self.ssid_len], password, &[]),
            };
            link.pause();
            let Some(point) = point else {
                self.state = State::Idle;
                return;
            };
            let e = sae::password_element_from_point(&point, &own, &self.ap);
            self.pt = Some((id, point));
            e
        } else {
            match sae::password_element_looping(&own, &self.ap, password) {
                Some(e) => e,
                None => {
                    self.state = State::Idle;
                    return;
                }
            }
        };
        link.pause();
        let mut rand = [0u8; 32];
        let mut mask = [0u8; 32];
        link.random(&mut rand);
        link.random(&mut mask);
        let session = sae::Session::new(element, &rand, &mask);
        link.pause();
        let mut commit = [0u8; 6 + sae::COMMIT_LEN];
        commit[..6].copy_from_slice(&[3, 0, 1, 0, if h2e { 126 } else { 0 }, 0]);
        commit[6..].copy_from_slice(&session.commit().to_bytes());
        self.sae = Some(SaeRun {
            session,
            commit,
            confirmed: false,
        });
        self.send_sae(link, &commit, &[]);
        self.timeout = AUTH_TIMEOUT;
    }

    /// An authentication frame with `body`; `token` goes where the
    /// access point wants it (after the group, or in a container).
    fn send_sae(&mut self, link: &mut impl Link, body: &[u8], token: &[u8]) {
        let own = link.mac();
        let (ap, bssid) = (self.ap, self.bssid);
        let at = self.header(&own, 0xB0, 0, &ap, &bssid);
        let h2e = matches!(self.security, Security::Sae { h2e: true });
        let n = if token.is_empty() || h2e {
            let n = put(&mut self.tx, at, body);
            if token.is_empty() {
                n
            } else {
                let n = put(&mut self.tx, n, &[255, 1 + token.len() as u8, 93]);
                put(&mut self.tx, n, token)
            }
        } else {
            let n = put(&mut self.tx, at, &body[..8]);
            let n = put(&mut self.tx, n, token);
            put(&mut self.tx, n, &body[8..])
        };
        self.send_management(link, n, false);
    }

    #[inline(never)]
    fn input_sae(
        &mut self,
        link: &mut impl Link,
        algorithm: u16,
        seq: u16,
        status: u16,
        frame: &[u8],
        len: usize,
    ) {
        if algorithm != 3 {
            self.state = State::Idle;
            return;
        }
        let Some(run) = self.sae.as_mut() else { return };
        let body = &frame[30..len];
        match seq {
            1 if status == 76 && !run.confirmed => {
                // Anti-clogging: the same commit again, with the token.
                let h2e = matches!(self.security, Security::Sae { h2e: true });
                let mut token = [0u8; 64];
                let t: &[u8] = if h2e {
                    match body.get(2..) {
                        Some([255, l, 93, rest @ ..])
                            if *l >= 1 && rest.len() >= *l as usize - 1 =>
                        {
                            &rest[..*l as usize - 1]
                        }
                        _ => {
                            self.state = State::Idle;
                            return;
                        }
                    }
                } else {
                    body.get(2..).unwrap_or(&[])
                };
                let n = t.len().min(64);
                token[..n].copy_from_slice(&t[..n]);
                let commit = run.commit;
                self.send_sae(link, &commit, &token[..n]);
            }
            1 if !run.confirmed => {
                if (status != 0 && status != 126) || body.len() < 2 {
                    self.state = State::Idle;
                    return;
                }
                let Some(theirs) = sae::Commit::from_bytes(body) else {
                    self.state = State::Idle;
                    return;
                };
                let ok = run.session.process_commit(&theirs).is_ok();
                link.pause();
                let run = self.sae.as_mut().unwrap();
                let Some(confirm) = run.session.confirm(1).filter(|_| ok) else {
                    self.state = State::Idle;
                    return;
                };
                run.confirmed = true;
                let mut reply = [0u8; 8 + 32];
                reply[..8].copy_from_slice(&[3, 0, 2, 0, 0, 0, 1, 0]);
                reply[8..].copy_from_slice(&confirm);
                self.send_sae(link, &reply, &[]);
                self.timeout = AUTH_TIMEOUT;
            }
            2 if run.confirmed => {
                let ok = status == 0
                    && body.len() >= 34
                    && run.session.check_confirm(le16(body, 0), &body[2..34]);
                if !ok {
                    self.state = State::Idle;
                    return;
                }
                self.pmk = run.session.pmk;
                self.pmksa = Some((
                    self.bssid,
                    run.session.pmk,
                    run.session.pmkid,
                    link.millis(),
                ));
                self.sae = None;
                self.associate(link);
            }
            _ => {}
        }
    }
}

/// Frames found by fuzzing (`lapin/fuzz`), each of which halted the
/// rabbit or got past a check; the station set up by hand in the state
/// each one needs.
#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    const AP: Mac = [0x02, 0, 0, 0, 0, 0xA1];
    const OWN: Mac = [0x00, 0x19, 0xDB, 0x9C, 0x28, 0x15];

    #[derive(Default)]
    struct Air {
        now: u32,
        sent: Vec<Vec<u8>>,
        keys: Vec<(u8, Vec<u8>)>,
        /// The packet number of the last frame handed in.
        pn: u64,
        /// Random numbers drawn.
        drawn: u8,
    }

    impl Link for Air {
        fn mac(&self) -> Mac {
            OWN
        }
        fn millis(&self) -> u32 {
            self.now
        }
        fn transmit(&mut self, frame: &[u8], _: &Tx) -> bool {
            self.sent.push(frame.to_vec());
            true
        }
        fn receive(&mut self, _: &mut [u8]) -> Option<Rx> {
            None
        }
        fn set_channel(&mut self, _: u8) {}
        fn set_bssid(&mut self, _: &Mac) {}
        fn set_key(&mut self, i: u8, _: HwCipher, key: &[u8], _: &[u8; 8], _: &[u8; 8]) {
            self.keys.push((i, key.to_vec()));
        }
        fn set_beacon(&mut self, _: Option<&[u8]>) {}
        fn set_answer_rates(&mut self, _: u16) {}
        fn pause(&mut self) {}
        fn random(&mut self, out: &mut [u8]) {
            // Never twice the same.
            self.drawn += 1;
            out.fill(0x33);
            out[0] = self.drawn;
        }
    }

    /// A station on a running link to `AP`.
    fn running(security: Security) -> Station {
        let mut s = Station::new();
        s.ap = AP;
        s.bssid = AP;
        s.security = security;
        s.state = State::Run;
        s.timeout = RUN_TIMEOUT;
        s.keys = KeyState::Run;
        s
    }

    const WPA2: Security = Security::Psk {
        wpa2: true,
        group: Cipher::Ccmp,
        pairwise: Some(Cipher::Ccmp),
    };

    /// A data frame from the access point, `fc1` its flags beyond
    /// "from the network".
    fn from_ap(fc1: u8, to: &Mac, body: &[u8]) -> Vec<u8> {
        let mut f = std::vec![0x08, 0x02 | fc1, 0, 0];
        f.extend_from_slice(to);
        f.extend_from_slice(&AP);
        f.extend_from_slice(&AP);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(body);
        f
    }

    fn input(s: &mut Station, air: &mut Air, f: &[u8], decrypted: bool) -> Option<Delivery> {
        air.pn += 1;
        let pn = air.pn;
        input_numbered(s, air, f, decrypted, pn)
    }

    /// A frame the stick opened (if `decrypted`) under packet number
    /// `pn`, with CCMP's IV words.
    fn input_numbered(
        s: &mut Station,
        air: &mut Air,
        f: &[u8],
        decrypted: bool,
        pn: u64,
    ) -> Option<Delivery> {
        let mut buf = [0u8; 2400];
        buf[..f.len()].copy_from_slice(f);
        let rx = Rx {
            len: f.len(),
            rssi: -40,
            decrypted,
            iv: pn as u32 & 0xFFFF | 0x2000_0000 | (f[4] as u32 & 1) << 30,
            eiv: (pn >> 16) as u32,
        };
        s.input(air, &mut buf, rx)
    }

    /// An EAPOL-Key frame whose length field says less than its fixed
    /// fields take: it was cut there, and every field read past the cut
    /// panicked. In clear, and before any integrity check: anyone near
    /// the rabbit could halt it.
    #[test]
    fn an_eapol_frame_shorter_than_its_fields_is_dropped() {
        for declared in [0u16, 8, 50, 94] {
            let mut s = running(WPA2);
            s.replay_active = true;
            let mut e = std::vec![0u8; 99];
            e[..2].copy_from_slice(&[2, 3]);
            e[2..4].copy_from_slice(&declared.to_be_bytes());
            e[4] = 2;
            // Message 3: pairwise, ack, MIC, secure.
            e[5..7].copy_from_slice(&0x038Au16.to_be_bytes());
            e[9..17].fill(0xFF);
            let mut body = LLC_EAPOL.to_vec();
            body.extend_from_slice(&e);
            let mut air = Air::default();
            assert_eq!(
                input(&mut s, &mut air, &from_ap(0, &OWN, &body), false),
                None
            );
            assert_eq!(s.state, State::Run);
            assert!(air.sent.is_empty());
        }
    }

    /// A frame with its protected bit set that the stick could not open
    /// (no key in the slot its header names: the stick hands it up as
    /// it came) was handed to the bytecode: whoever sent it could
    /// write, in clear, what the rabbit received on a WPA2 link.
    #[test]
    fn a_frame_still_sealed_is_not_handed_up() {
        // The CCMP header names key 3; then an IP datagram, in clear.
        let mut body = std::vec![0, 0, 0, 0xE0, 0, 0, 0, 0];
        body.extend_from_slice(&[0xAA, 0xAA, 3, 0, 0, 0, 0x08, 0x00, 0x45, 0, 0, 20]);
        for security in [
            WPA2,
            Security::Open,
            Security::Wep {
                key: [7; 13],
                long: true,
            },
        ] {
            let mut s = running(security);
            let mut air = Air::default();
            let sealed = from_ap(0x40, &BROADCAST, &body);
            assert_eq!(input(&mut s, &mut air, &sealed, false), None);
            // What the stick did open still goes up.
            let opened = from_ap(0, &BROADCAST, &body[8..]);
            assert!(input(&mut s, &mut air, &opened, true).is_some());
        }
    }

    /// A group message (key 1) of replay counter `counter`, signed and
    /// its key data encrypted as version 1 does it (MD5, RC4).
    fn group_message(s: &Station, counter: u64, key: &[u8]) -> Vec<u8> {
        group_message_at(s, counter, key, 0)
    }

    /// The same, the group key's counter at `rsc`.
    fn group_message_at(s: &Station, counter: u64, key: &[u8], rsc: u64) -> Vec<u8> {
        let mut e = std::vec![0u8; 99];
        e[..2].copy_from_slice(&[1, 3]);
        e[4] = if matches!(s.security, Security::Psk { wpa2: false, .. }) {
            0xFE
        } else {
            2
        };
        // Group, key 1, ack, MIC, secure; version 1.
        e[5..7].copy_from_slice(&0x0391u16.to_be_bytes());
        e[9..17].copy_from_slice(&counter.to_be_bytes());
        e[65..73].copy_from_slice(&rsc.to_le_bytes());
        e[97..99].copy_from_slice(&(key.len() as u16).to_be_bytes());
        let mut data = key.to_vec();
        let mut k = [0u8; 32];
        k[16..].copy_from_slice(&s.ptk[16..32]);
        rc4(&k, 256, &mut data);
        e.extend_from_slice(&data);
        let n = e.len() as u16 - 4;
        e[2..4].copy_from_slice(&n.to_be_bytes());
        let mic = hmac_md5(&s.ptk[..16], &[&e]);
        e[81..97].copy_from_slice(&mic);
        let mut body = LLC_EAPOL.to_vec();
        body.extend_from_slice(&e);
        from_ap(0, &OWN, &body)
    }

    /// The stick opens frames and checks none of their packet numbers
    /// (its descriptor gives them); the station did not either: a frame
    /// recorded on the air and sent again went up twice.
    #[test]
    fn frames_the_stick_opened_are_not_taken_twice() {
        let mut s = running(WPA2);
        let mut air = Air::default();
        let ip = [0xAA, 0xAA, 3, 0, 0, 0, 0x08, 0x00, 0x45, 0, 0, 20];
        let unicast = from_ap(0, &OWN, &ip);
        let group = from_ap(0, &BROADCAST, &ip);
        for (f, pn, up) in [
            (&unicast, 5, true),
            (&unicast, 5, false),
            (&unicast, 4, false),
            (&unicast, 6, true),
            // Group frames count apart, by key.
            (&group, 3, true),
            (&group, 3, false),
            (&group, 7, true),
        ] {
            let got = input_numbered(&mut s, &mut air, f, true, pn);
            assert_eq!(got.is_some(), up, "{pn}");
        }
    }

    /// A group message handed over again (the access point retransmits
    /// it when the answer is lost; anyone can replay it) installed the
    /// same key again, its counter back at zero: every broadcast frame
    /// recorded since went up again (CVE-2017-13080). And the counter
    /// the message gave for the key was ignored.
    #[test]
    fn a_group_key_handed_over_again_keeps_its_counter() {
        let mut s = running(Security::Psk {
            wpa2: true,
            group: Cipher::Ccmp,
            pairwise: Some(Cipher::Tkip),
        });
        s.ptk = [0x5C; 64];
        let mut kde = std::vec![0xDD, 22, 0x00, 0x0F, 0xAC, 1, 1, 0];
        kde.extend_from_slice(&[0x47; 16]);
        let mut air = Air::default();
        let f = group_message_at(&s, 1, &kde, 100);
        input(&mut s, &mut air, &f, true);
        assert_eq!(air.keys, [(1, std::vec![0x47; 16])]);
        let ip = [0xAA, 0xAA, 3, 0, 0, 0, 0x08, 0x00, 0x45, 0, 0, 20];
        let group = from_ap(0, &BROADCAST, &ip);
        // At or below the counter the access point gave: old frames.
        assert!(input_numbered(&mut s, &mut air, &group, true, 100).is_none());
        assert!(input_numbered(&mut s, &mut air, &group, true, 101).is_some());
        // The same key again.
        let f = group_message_at(&s, 2, &kde, 0);
        input(&mut s, &mut air, &f, true);
        assert_eq!(air.keys.len(), 1, "installed again");
        assert!(input_numbered(&mut s, &mut air, &group, true, 101).is_none());
        assert_eq!(s.state, State::Run);
    }

    /// WPA with a CCMP group key: a group message whose key data is
    /// shorter than a key had the station read sixteen bytes of it.
    #[test]
    fn a_group_key_too_short_is_refused() {
        let mut s = running(Security::Psk {
            wpa2: false,
            group: Cipher::Ccmp,
            pairwise: Some(Cipher::Tkip),
        });
        s.ptk = [0x5C; 64];
        let f = group_message(&s, 1, &[0xAB; 8]);
        let mut air = Air::default();
        assert_eq!(input(&mut s, &mut air, &f, true), None);
        // Not installed, and not answered either (the access point
        // would take the key for in place): the link starts over.
        assert!(air.sent.is_empty());
        assert!(air.keys.is_empty());
        assert_eq!(s.state, State::Idle);
    }

    /// A message 1 on a running link (anyone can send one: it carries
    /// no integrity code) with the largest replay counter. The station
    /// took the counter as the newest, and refused every genuine frame
    /// after it as replayed; and it checked the next group message
    /// with the keys of the rekey that message 1 began, which the
    /// access point knew nothing of. Either way the next group rekey
    /// failed and the link went down.
    #[test]
    fn a_forged_message_1_does_not_move_the_replay_counter() {
        let mut s = running(Security::Psk {
            wpa2: true,
            group: Cipher::Ccmp,
            pairwise: Some(Cipher::Tkip),
        });
        s.ptk = [0x5C; 64];
        s.replay = 5u64.to_be_bytes();
        s.replay_active = true;
        let mut e = std::vec![0u8; 99];
        e[..2].copy_from_slice(&[2, 3]);
        e[2..4].copy_from_slice(&95u16.to_be_bytes());
        e[4] = 2;
        e[5..7].copy_from_slice(&0x0089u16.to_be_bytes());
        e[9..17].fill(0xFF);
        e[17..49].fill(0x77);
        let mut body = LLC_EAPOL.to_vec();
        body.extend_from_slice(&e);
        let mut air = Air::default();
        input(&mut s, &mut air, &from_ap(0, &OWN, &body), true);
        // Answered, with its counter.
        assert_eq!(air.sent.len(), 1);
        assert_eq!(air.sent[0][24 + 8 + 9..24 + 8 + 17], [0xFF; 8]);
        // The access point's next group key still goes in.
        let mut kde = std::vec![0xDD, 22, 0x00, 0x0F, 0xAC, 1, 1, 0];
        kde.extend_from_slice(&[0x47; 16]);
        let f = group_message(&s, 6, &kde);
        input(&mut s, &mut air, &f, true);
        assert_eq!(air.keys, [(1, std::vec![0x47; 16])]);
        assert_eq!(s.state, State::Run);
    }

    /// A rekey begun (message 1 on a running link, which anyone can
    /// send) and never finished: its keys stayed, and signed every
    /// handshake after it. The link went down and never came back up
    /// until the rabbit restarted.
    #[test]
    fn a_rekey_left_half_done_does_not_sign_the_next_handshake() {
        let mut s = running(Security::Psk {
            wpa2: true,
            group: Cipher::Ccmp,
            pairwise: Some(Cipher::Tkip),
        });
        let msg1 = |anonce: u8| {
            let mut e = std::vec![0u8; 99];
            e[..2].copy_from_slice(&[2, 3]);
            e[2..4].copy_from_slice(&95u16.to_be_bytes());
            e[4] = 2;
            e[5..7].copy_from_slice(&0x0089u16.to_be_bytes());
            e[9..17].copy_from_slice(&1u64.to_be_bytes());
            e[17..49].fill(anonce);
            let mut body = LLC_EAPOL.to_vec();
            body.extend_from_slice(&e);
            from_ap(0, &OWN, &body)
        };
        let mut air = Air::default();
        input(&mut s, &mut air, &msg1(0x77), true);
        assert!(s.next_ptk.is_some());
        // The link goes down; a new association, a new handshake.
        s.state = State::Eapol;
        s.keys = KeyState::Msg1;
        s.replay_active = false;
        s.ap_keyed = false;
        air.sent.clear();
        input(&mut s, &mut air, &msg1(0x66), false);
        let mut msg2 = air.sent[0][24 + 8..].to_vec();
        let mic: [u8; 16] = msg2[81..97].try_into().unwrap();
        msg2[81..97].fill(0);
        assert_eq!(mic, hmac_md5(&s.ptk[..16], &[&msg2]));
        assert_eq!(s.keys, KeyState::Msg3);
    }

    /// WPA3: an association refused for now, "come back in" fifty days
    /// (a time interval of 2^32 - 1 units). The multiplication wrapped,
    /// and the station waited in the association state for as long as
    /// the access point (or anyone using its address) asked.
    #[test]
    fn a_comeback_time_too_long_is_a_refusal() {
        for (tu, waits) in [
            (1000u32, true),
            (10_000, true),
            (10_001, false),
            (u32::MAX, false),
        ] {
            let mut s = running(Security::Sae { h2e: false });
            s.state = State::Assoc;
            s.timeout = ASSOC_TIMEOUT;
            let mut f = std::vec![0x10, 0, 0, 0];
            f.extend_from_slice(&OWN);
            f.extend_from_slice(&AP);
            f.extend_from_slice(&AP);
            f.extend_from_slice(&[0, 0, 0x01, 0, 30, 0, 1, 0xC0]);
            f.extend_from_slice(&[56, 5, 3]);
            f.extend_from_slice(&tu.to_le_bytes());
            let mut air = Air::default();
            input(&mut s, &mut air, &f, false);
            if waits {
                assert_eq!(s.state, State::Assoc);
                assert!(s.timeout <= ASSOC_TIMEOUT + 52);
                assert!(s.retry_assoc_at.is_some());
            } else {
                assert_eq!(s.state, State::Idle);
            }
        }
    }

    /// An RSN element offering SAE-EXT-KEY (suite 24) alone: the bit of
    /// the suite modulo 16 was set, 8, and the station took the network
    /// for one offering SAE (and 18 for PSK, 2).
    #[test]
    fn a_key_management_suite_past_15_aliases_none() {
        let mut rsn = std::vec![1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4];
        rsn.extend_from_slice(&[2, 0, 0x00, 0x0F, 0xAC, 24, 0x00, 0x0F, 0xAC, 18, 0, 0]);
        let (_, _, akm, _) = suites(&rsn, [0x00, 0x0F, 0xAC]).unwrap();
        assert_eq!(akm, 0);
    }

    /// Joining a network cleared the stick's key 0 alone: the group
    /// keys of the last network stayed in slots 1 to 3, and the stick
    /// kept opening frames with them.
    #[test]
    fn joining_clears_every_key_slot() {
        let mut s = running(WPA2);
        s.state = State::Idle;
        let mut air = Air::default();
        s.auth(
            &mut air,
            b"Terrier",
            &AP,
            &AP,
            6,
            1,
            false,
            CRYPT_NONE,
            &[],
            &[],
        );
        let mut cleared: Vec<u8> = air.keys.iter().map(|(i, _)| *i).collect();
        cleared.sort();
        assert_eq!(cleared, [0, 1, 2, 3]);
        assert!(air.keys.iter().all(|(_, k)| k.is_empty()));
    }

    /// WPA2 with TKIP: key descriptor version 1 (MD5, RC4), which the
    /// tests can build by hand.
    const WPA2_TKIP: Security = Security::Psk {
        wpa2: true,
        group: Cipher::Ccmp,
        pairwise: Some(Cipher::Tkip),
    };

    /// The access point's RSN element (CCMP group, TKIP pairwise, PSK).
    const AP_RSN: [u8; 22] = [
        48, 20, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 2, 1, 0, 0x00, 0x0F, 0xAC, 2, 0,
        0,
    ];

    /// An EAPOL-Key frame from the access point, version 1: `info`
    /// (pairwise, ack, ...), its replay counter, nonce and key data,
    /// which is encrypted (RC4) and signed (MD5) if `s` has keys.
    fn eapol_key(s: &Station, info: u16, counter: u64, nonce: &[u8; 32], data: &[u8]) -> Vec<u8> {
        let mut e = std::vec![0u8; 99];
        e[..2].copy_from_slice(&[1, 3]);
        e[4] = 2;
        e[5..7].copy_from_slice(&(info | 1).to_be_bytes());
        e[9..17].copy_from_slice(&counter.to_be_bytes());
        e[17..49].copy_from_slice(nonce);
        e[97..99].copy_from_slice(&(data.len() as u16).to_be_bytes());
        let mut data = data.to_vec();
        if info & 0x100 != 0 {
            let mut k = [0u8; 32];
            k[16..].copy_from_slice(&s.ptk[16..32]);
            rc4(&k, 256, &mut data);
        }
        e.extend_from_slice(&data);
        let n = e.len() as u16 - 4;
        e[2..4].copy_from_slice(&n.to_be_bytes());
        if info & 0x100 != 0 {
            let mic = hmac_md5(&s.ptk[..16], &[&e]);
            e[81..97].copy_from_slice(&mic);
        }
        let mut body = LLC_EAPOL.to_vec();
        body.extend_from_slice(&e);
        from_ap(0, &OWN, &body)
    }

    /// A station between messages 1 and 3 of its first handshake with
    /// `AP`, which it scanned (`AP_RSN`).
    fn in_handshake() -> (Station, Air) {
        let mut s = running(WPA2_TKIP);
        s.state = State::Eapol;
        s.keys = KeyState::Msg1;
        s.bss = Offer::from_elements(AP, &AP_RSN);
        s.bss_known = true;
        let mut air = Air::default();
        let msg1 = eapol_key(&s, 0x0088, 1, &[0x77; 32], &[]);
        input(&mut s, &mut air, &msg1, false);
        assert_eq!(s.keys, KeyState::Msg3);
        (s, air)
    }

    const MSG3: u16 = 0x0008 | 0x0040 | 0x0080 | 0x0100 | 0x0200 | 0x1000;

    /// Message 3 without a group key: message 4 went first, the keys
    /// were taken as in place, and the key data was looked at after.
    /// The access point then took the station for ready, and the
    /// rabbit heard no broadcast. Now message 3 is checked whole before
    /// it is answered.
    #[test]
    fn message_3_without_a_group_key_is_not_answered() {
        let (mut s, mut air) = in_handshake();
        air.sent.clear();
        let f = eapol_key(&s, MSG3, 2, &[0x77; 32], &AP_RSN);
        input(&mut s, &mut air, &f, false);
        assert!(air.sent.is_empty(), "answered");
        assert_eq!(s.keys, KeyState::Msg3);
        assert_eq!(s.state, State::Eapol);
        // With it, the same message goes through.
        let mut data = AP_RSN.to_vec();
        data.extend_from_slice(&[0xDD, 22, 0x00, 0x0F, 0xAC, 1, 1, 0]);
        data.extend_from_slice(&[0x47; 16]);
        let f = eapol_key(&s, MSG3, 3, &[0x77; 32], &data);
        input(&mut s, &mut air, &f, false);
        assert_eq!(air.sent.len(), 1);
        assert_eq!(s.state, State::Run);
        assert!(air.keys.contains(&(1, std::vec![0x47; 16])));
    }

    /// Message 3 brings an RSN element other than the one the scan saw:
    /// the station went on (802.11 says to stop: the beacon may have
    /// been forged to hide the network's WPA3). It now stops, and keeps
    /// what message 3 said for the next attempt.
    #[test]
    fn message_3_with_another_element_ends_the_attempt() {
        let (mut s, mut air) = in_handshake();
        air.sent.clear();
        // The genuine element offers SAE as well (and protection).
        let mut rsn = AP_RSN.to_vec();
        rsn[1] = 24;
        rsn[14] = 2;
        rsn.splice(20..20, [0x00, 0x0F, 0xAC, 8]);
        rsn[24] = 0x80;
        let mut data = rsn.clone();
        data.extend_from_slice(&[0xDD, 22, 0x00, 0x0F, 0xAC, 1, 1, 0]);
        data.extend_from_slice(&[0x47; 16]);
        let f = eapol_key(&s, MSG3, 2, &[0x77; 32], &data);
        input(&mut s, &mut air, &f, false);
        assert!(air.sent.is_empty(), "answered");
        assert_eq!(s.state, State::Idle);
        let learned = s.learned.unwrap();
        assert_eq!(learned.bssid, AP);
        assert!(learned.rsn.is_some_and(|(_, _, akm, _)| akm & 1 << 8 != 0));
    }

    /// The access point sends message 1 again (message 2 lost): the
    /// station drew a new nonce for each, as if each began a handshake.
    /// One nonce now serves the whole handshake, as in wpa_supplicant.
    #[test]
    fn every_message_1_of_a_handshake_gets_the_same_nonce() {
        let (mut s, mut air) = in_handshake();
        let msg1 = eapol_key(&s, 0x0088, 2, &[0x77; 32], &[]);
        input(&mut s, &mut air, &msg1, false);
        assert_eq!(air.sent.len(), 2);
        let nonce = |f: &Vec<u8>| f[24 + 8 + 17..24 + 8 + 49].to_vec();
        assert_eq!(nonce(&air.sent[0]), nonce(&air.sent[1]));
    }

    /// Between association and message 3 the bytecode's frames went out
    /// in clear, on a WPA link. Only the handshake may.
    #[test]
    fn nothing_but_the_handshake_goes_in_clear() {
        let (mut s, mut air) = in_handshake();
        air.sent.clear();
        let ip = [0xAA, 0xAA, 3, 0, 0, 0, 0x08, 0x00, 0x45, 0, 0, 20];
        assert!(!s.send(&mut air, &ip, &BROADCAST, false));
        assert!(air.sent.is_empty());
        // The null frame carries nothing: it may.
        assert!(s.send(&mut air, &[], &AP, false));
    }

    /// The access point refused the cached key in the 4-way handshake
    /// (it accepted the association, then the handshake failed): the
    /// station came back with the same key every time, forever. And it
    /// kept the key for ever, where access points keep theirs twelve
    /// hours.
    #[test]
    fn a_cached_key_that_fails_or_expires_is_forgotten() {
        let commit_sent = |s: &mut Station, air: &mut Air| {
            air.sent.clear();
            s.state = State::Idle;
            s.auth(
                air,
                b"Terrier",
                &AP,
                &AP,
                6,
                1,
                false,
                CRYPT_WPA2 | 0x0A,
                &[0; 32],
                b"carotte",
            );
            // Algorithm 3: SAE; 0: open, with the cached key.
            le16(&air.sent[0], 24) == 3
        };
        let mut s = Station::new();
        let mut rsn = std::vec![1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4];
        rsn.extend_from_slice(&[1, 0, 0x00, 0x0F, 0xAC, 8, 0xC0, 0]);
        s.offers[0] = Offer {
            bssid: AP,
            rsn: suites(&rsn, [0x00, 0x0F, 0xAC]),
            ..Offer::default()
        };
        let mut air = Air::default();
        s.pmksa = Some((AP, [9; 32], [8; 16], 0));
        assert!(!commit_sent(&mut s, &mut air));
        // That attempt goes nowhere: the next one runs SAE.
        assert!(commit_sent(&mut s, &mut air));
        // A key that worked is kept, for twelve hours.
        s.pmksa = Some((AP, [9; 32], [8; 16], 0));
        s.cached = false;
        assert!(!commit_sent(&mut s, &mut air));
        s.pmksa_proven = true;
        air.now = PMKSA_LIFETIME_MS - 1;
        assert!(!commit_sent(&mut s, &mut air));
        s.pmksa_proven = true;
        air.now = PMKSA_LIFETIME_MS;
        assert!(commit_sent(&mut s, &mut air));
    }

    /// The access point mode answers an authentication of any sequence
    /// number with the next one, as the C did (in 16 bits).
    #[test]
    fn the_access_point_refuses_the_last_sequence_number() {
        let mut s = Station::new();
        let mut air = Air::default();
        s.set_mode(&mut air, true, b"Nabaztag", 4);
        air.sent.clear();
        let mut f = std::vec![0xB0, 0, 0, 0];
        f.extend_from_slice(&OWN);
        f.extend_from_slice(&AP);
        f.extend_from_slice(&OWN);
        f.extend_from_slice(&[0, 0, 0, 0, 0xFF, 0xFF, 0, 0]);
        input(&mut s, &mut air, &f, false);
        assert_eq!(air.sent.len(), 1);
        assert_eq!(air.sent[0][26..30], [0, 0, 14, 0]);
    }
}
