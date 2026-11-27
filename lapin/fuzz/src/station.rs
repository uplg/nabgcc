//! The station against an access point the harness plays: it is taken
//! to a state of its connection (open, WEP, WPA, WPA2, WPA3, cached
//! WPA3, or the access point mode with a laptop in it) by the real
//! exchange, then fed frames built from the fuzzer's bytes. The access
//! point knows the keys, so a fuzzed frame can carry a good integrity
//! code and get to the parsers behind the checks.
//!
//! Besides panics and hangs, it checks what the station hands up: never
//! out of the frame, and on a keyed link never a frame no key opened.

use std::collections::{HashMap, VecDeque};

use lapin_core::aes::{self, Aes};
use lapin_core::ccmp;
use lapin_core::md5::{hmac_md5, rc4};
use lapin_core::sae::{self, Commit, Session};
use lapin_core::sha1::{hmac_sha1, prf};
use lapin_core::sha256;
use lapin_core::wifi::{self, HwCipher, LLC_EAPOL, Link, Mac, Rx, Station, Tx};

use crate::input::Input;

pub const AP: Mac = [0x02, 0, 0, 0, 0, 0xA1];
pub const STA: Mac = [0x00, 0x19, 0xDB, 0x9C, 0x28, 0x15];
const LAPTOPS: [Mac; 3] = [
    [0x02, 0, 0, 0, 0, 0x77],
    [0x02, 0, 0, 0, 0, 0x78],
    [0x02, 0, 0, 0, 0, 0x79],
];
const SSID: &[u8] = b"Terrier";
const PASSWORD: &[u8] = b"carotte-violette";
const WEP40: &[u8] = b"carot";
const WEP104: &[u8] = b"thirteenchars";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Open,
    Wep {
        long: bool,
        shared: bool,
    },
    /// WPA (vendor element) or WPA2 (RSN): suites as numbers (2 TKIP,
    /// 4 CCMP).
    Psk {
        wpa2: bool,
        group: u8,
        pairwise: u8,
    },
    Sae {
        h2e: bool,
        transition: bool,
        cached: bool,
    },
    Master,
}

pub const KINDS: [Kind; 15] = [
    Kind::Open,
    Kind::Wep {
        long: false,
        shared: false,
    },
    Kind::Wep {
        long: true,
        shared: false,
    },
    Kind::Wep {
        long: false,
        shared: true,
    },
    Kind::Psk {
        wpa2: false,
        group: 2,
        pairwise: 2,
    },
    Kind::Psk {
        wpa2: false,
        group: 4,
        pairwise: 4,
    },
    Kind::Psk {
        wpa2: false,
        group: 4,
        pairwise: 2,
    },
    Kind::Psk {
        wpa2: true,
        group: 4,
        pairwise: 4,
    },
    Kind::Psk {
        wpa2: true,
        group: 2,
        pairwise: 4,
    },
    Kind::Psk {
        wpa2: true,
        group: 2,
        pairwise: 2,
    },
    Kind::Sae {
        h2e: false,
        transition: false,
        cached: false,
    },
    Kind::Sae {
        h2e: true,
        transition: false,
        cached: false,
    },
    Kind::Sae {
        h2e: false,
        transition: true,
        cached: false,
    },
    Kind::Sae {
        h2e: false,
        transition: false,
        cached: true,
    },
    Kind::Master,
];

/// The access point's side of the keys.
#[derive(Clone, Default)]
struct Keys {
    anonce: [u8; 32],
    replay: u64,
    /// The pairwise keys in use, and those of a handshake under way.
    ptk: Option<[u8; 64]>,
    pending: Option<[u8; 64]>,
    gtk: (u8, [u8; 32]),
    igtk: (u16, [u8; 16]),
    pn: u64,
    group_pn: u64,
    ipn: u64,
}

/// The air between the station and the harness's access point.
#[derive(Clone)]
pub struct Air {
    pub kind: Kind,
    now: u32,
    rng: u64,
    rx: VecDeque<(Vec<u8>, Rx)>,
    /// Frames handed over so far: what the stick's descriptor says of
    /// their packet numbers, always new.
    pushed: u32,
    /// Calls the station made: a bound on its work for one input.
    work: u64,
    pmk: [u8; 32],
    keys: Keys,
    sae: Option<Session>,
    /// The station's last commit and confirm.
    commit: Option<Commit>,
    confirmed: bool,
    /// The algorithm of the station's last authentication request.
    auth_alg: Option<u16>,
    pub transmitted: usize,
}

impl Air {
    fn new(kind: Kind) -> Self {
        let pmk = lapin_core::sha1::passphrase_to_pmk(PASSWORD, SSID, &mut |_| {});
        Air {
            kind,
            now: 1000,
            rng: 0x1234_5678_9ABC_DEF1,
            rx: VecDeque::new(),
            pushed: 0,
            work: 0,
            pmk,
            keys: Keys {
                gtk: (1, [0x47; 32]),
                igtk: (4, [0x49; 16]),
                ..Keys::default()
            },
            sae: None,
            commit: None,
            confirmed: false,
            auth_alg: None,
            transmitted: 0,
        }
    }

    fn next(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn spend(&mut self) {
        self.work += 1;
        assert!(self.work < 2_000_000, "unbounded work");
    }

    fn sae_kind(&self) -> bool {
        matches!(self.kind, Kind::Sae { .. })
    }

    /// What the station's MIC and key data use: 0 (AES, after SAE),
    /// 1 (MD5 and RC4) or 2 (SHA-1 and AES).
    fn version(&self) -> u16 {
        match self.kind {
            Kind::Sae { .. } => 0,
            Kind::Psk { pairwise: 4, .. } => 2,
            _ => 1,
        }
    }

    fn derive(&self, snonce: &[u8; 32]) -> [u8; 64] {
        let (lo, hi) = if STA < AP { (STA, AP) } else { (AP, STA) };
        let a = self.keys.anonce;
        let (n_lo, n_hi) = if *snonce < a {
            (*snonce, a)
        } else {
            (a, *snonce)
        };
        let mut seed = [0u8; 76];
        seed[..6].copy_from_slice(&lo);
        seed[6..12].copy_from_slice(&hi);
        seed[12..44].copy_from_slice(&n_lo);
        seed[44..].copy_from_slice(&n_hi);
        let mut ptk = [0u8; 64];
        if self.sae_kind() {
            sha256::kdf(&self.pmk, b"Pairwise key expansion", &seed, &mut ptk[..48]);
        } else {
            prf(&self.pmk, b"Pairwise key expansion", &seed, &mut ptk);
        }
        ptk
    }

    fn tk(&self) -> Option<[u8; 16]> {
        let ptk = self.keys.ptk?;
        let mut tk = [0u8; 16];
        tk.copy_from_slice(&ptk[32..48]);
        Some(tk)
    }

    /// Learn from what the station sent: its SAE commit and confirm,
    /// its handshake messages.
    fn heard(&mut self, frame: &[u8]) {
        if frame.len() < 24 {
            return;
        }
        let mut f = frame.to_vec();
        if f[0] == 0xB0 && f.len() >= 30 {
            let (alg, seq) = (le16(&f, 24), le16(&f, 26));
            if seq == 1 {
                self.auth_alg = Some(alg);
            }
            if alg == 3 && seq == 1 {
                // Group, then (anti-clogging token, without H2E) scalar
                // and element: the last 96 bytes.
                if f.len() >= 30 + 98 {
                    let n = f.len();
                    let mut c = vec![19, 0];
                    c.extend_from_slice(&f[n - 96..]);
                    self.commit = Commit::from_bytes(&c);
                }
            } else if alg == 3 && seq == 2 {
                self.confirmed = true;
            }
            return;
        }
        if f[0] & 0x0C != 0x08 {
            return;
        }
        if f[1] & 0x40 != 0 {
            // Protected in software (WPA3, on a running link).
            let Some(tk) = self.tk() else { return };
            match ccmp::unprotect(&tk, &mut f) {
                Some((n, _)) => f.truncate(n),
                None => return,
            }
        }
        let body = &f[24..];
        if body.len() < 8 + 99 || body[..8] != LLC_EAPOL {
            return;
        }
        let e = &body[8..];
        let info = be16(e, 5);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&e[17..49]);
        if info & 0x0008 == 0 {
            return;
        }
        if nonce != [0; 32] {
            // Message 2.
            self.keys.pending = Some(self.derive(&nonce));
        } else if let Some(p) = self.keys.pending.take() {
            // Message 4.
            self.keys.ptk = Some(p);
        }
    }

    fn push(&mut self, frame: Vec<u8>, decrypted: bool, rssi: i8) {
        // The stick holds no key on an open or WPA3 link: it opens
        // nothing.
        let decrypted = decrypted && matches!(self.kind, Kind::Wep { .. } | Kind::Psk { .. });
        if self.rx.len() < 64 {
            self.pushed += 1;
            self.rx.push_back((
                frame.clone(),
                Rx {
                    len: frame.len(),
                    rssi,
                    decrypted,
                    iv: 0,
                    eiv: self.pushed,
                },
            ));
        }
    }
}

impl Link for Air {
    fn mac(&self) -> Mac {
        STA
    }
    fn millis(&self) -> u32 {
        self.now
    }
    fn transmit(&mut self, frame: &[u8], tx: &Tx) -> bool {
        self.spend();
        assert!(
            frame.len() <= 2400 && frame.len() >= 10,
            "frame of {}",
            frame.len()
        );
        assert!(tx.rate < 12);
        self.transmitted += 1;
        self.heard(frame);
        true
    }
    fn receive(&mut self, buffer: &mut [u8]) -> Option<Rx> {
        self.spend();
        let (f, rx) = self.rx.pop_front()?;
        buffer[..f.len()].copy_from_slice(&f);
        Some(rx)
    }
    fn set_channel(&mut self, channel: u8) {
        self.spend();
        let _ = channel;
    }
    fn set_bssid(&mut self, _: &Mac) {
        self.spend();
    }
    fn set_key(&mut self, index: u8, _: HwCipher, key: &[u8], _: &[u8; 8], _: &[u8; 8]) {
        self.spend();
        assert!(index < 4 && key.len() <= 32);
    }
    fn set_beacon(&mut self, frame: Option<&[u8]>) {
        self.spend();
        if let Some(f) = frame {
            assert!(f.len() <= 2400);
        }
    }
    fn set_answer_rates(&mut self, _: u16) {
        self.spend();
    }
    fn pause(&mut self) {
        self.spend();
        self.now = self.now.wrapping_add(1);
    }
    fn random(&mut self, out: &mut [u8]) {
        self.spend();
        for b in out {
            *b = (self.next() >> 24) as u8;
        }
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

// ---- frames the access point builds -------------------------------------

fn header(fc0: u8, fc1: u8, a1: &Mac, a2: &Mac, a3: &Mac) -> Vec<u8> {
    let mut f = vec![fc0, fc1, 0, 0];
    f.extend_from_slice(a1);
    f.extend_from_slice(a2);
    f.extend_from_slice(a3);
    f.extend_from_slice(&[0, 0]);
    f
}

fn management(fc0: u8, body: &[u8]) -> Vec<u8> {
    let mut f = header(fc0, 0, &STA, &AP, &AP);
    f.extend_from_slice(body);
    f
}

fn element(out: &mut Vec<u8>, id: u8, body: &[u8]) {
    out.push(id);
    out.push(body.len() as u8);
    out.extend_from_slice(body);
}

fn beacon(kind: Kind) -> Vec<u8> {
    let privacy = !matches!(kind, Kind::Open | Kind::Master);
    let mut f = header(0x80, 0, &[0xFF; 6], &AP, &AP);
    f.extend_from_slice(&[0; 8]);
    f.extend_from_slice(&[0x64, 0, 0x01 | if privacy { 0x10 } else { 0 }, 0]);
    element(&mut f, 0, SSID);
    element(&mut f, 1, &[0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]);
    element(&mut f, 3, &[6]);
    match kind {
        Kind::Psk {
            wpa2: false,
            group,
            pairwise,
        } => {
            let mut e = vec![0x00, 0x50, 0xF2, 0x01, 1, 0, 0x00, 0x50, 0xF2, group];
            e.extend_from_slice(&[1, 0, 0x00, 0x50, 0xF2, pairwise, 1, 0, 0x00, 0x50, 0xF2, 2]);
            element(&mut f, 221, &e);
        }
        Kind::Psk {
            wpa2: true,
            group,
            pairwise,
        } => {
            let mut e = vec![1, 0, 0x00, 0x0F, 0xAC, group];
            e.extend_from_slice(&[1, 0, 0x00, 0x0F, 0xAC, pairwise, 1, 0, 0x00, 0x0F, 0xAC, 2]);
            e.extend_from_slice(&[0, 0]);
            element(&mut f, 48, &e);
        }
        Kind::Sae {
            h2e, transition, ..
        } => {
            let mut e = vec![1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4];
            if transition {
                e.extend_from_slice(&[2, 0, 0x00, 0x0F, 0xAC, 2, 0x00, 0x0F, 0xAC, 8]);
            } else {
                e.extend_from_slice(&[1, 0, 0x00, 0x0F, 0xAC, 8]);
            }
            e.extend_from_slice(&[0xC0, 0]);
            element(&mut f, 48, &e);
            if h2e {
                element(&mut f, 244, &[0x20]);
            }
        }
        _ => {}
    }
    f
}

/// RFC 3394 key wrap.
fn wrap(kek: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    let aes = Aes::new(kek);
    let n = plain.len() / 8;
    let mut a = [0xA6u8; 8];
    let mut r: Vec<[u8; 8]> = plain.chunks(8).map(|c| c.try_into().unwrap()).collect();
    for j in 0..6 {
        for (i, ri) in r.iter_mut().enumerate() {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(ri);
            aes.encrypt(&mut b);
            let t = (n * j + i + 1) as u64;
            for (k, x) in t.to_be_bytes().iter().enumerate() {
                a[k] = b[k] ^ x;
            }
            ri.copy_from_slice(&b[8..]);
        }
    }
    let mut out = a.to_vec();
    for ri in r {
        out.extend_from_slice(&ri);
    }
    out
}

/// What a fuzzed EAPOL-Key frame is made of.
struct KeyFrame<'a> {
    descriptor: u8,
    info: u16,
    replay: u64,
    nonce: [u8; 32],
    iv: [u8; 16],
    data: &'a [u8],
    /// Encrypt the key data with the KEK.
    encrypt: bool,
    /// Sign with the KCK (of the handshake under way if `pending`).
    sign: bool,
    pending: bool,
    /// Added to the declared lengths.
    skew: (i16, i16),
    version: u16,
}

impl Air {
    fn kck_kek(&self, pending: bool) -> ([u8; 16], [u8; 16]) {
        let ptk = if pending {
            self.keys.pending.or(self.keys.ptk)
        } else {
            self.keys.ptk.or(self.keys.pending)
        }
        .unwrap_or([0; 64]);
        (
            ptk[..16].try_into().unwrap(),
            ptk[16..32].try_into().unwrap(),
        )
    }

    fn key_frame(&self, k: &KeyFrame) -> Vec<u8> {
        let (kck, kek) = self.kck_kek(k.pending);
        let data = if k.encrypt {
            if k.version == 1 {
                let mut key = [0u8; 32];
                key[..16].copy_from_slice(&k.iv);
                key[16..].copy_from_slice(&kek);
                let mut d = k.data.to_vec();
                rc4(&key, 256, &mut d);
                d
            } else {
                let mut d = k.data.to_vec();
                if d.len() < 16 || d.len() % 8 != 0 {
                    d.push(0xDD);
                    while d.len() < 16 || d.len() % 8 != 0 {
                        d.push(0);
                    }
                }
                wrap(&kek, &d)
            }
        } else {
            k.data.to_vec()
        };
        let mut e = vec![0u8; 99];
        e[0] = 2;
        e[1] = 3;
        let body = (95 + data.len()) as i32 + k.skew.0 as i32;
        e[2..4].copy_from_slice(&(body as u16).to_be_bytes());
        e[4] = k.descriptor;
        e[5..7].copy_from_slice(&k.info.to_be_bytes());
        e[7..9].copy_from_slice(&16u16.to_be_bytes());
        e[9..17].copy_from_slice(&k.replay.to_be_bytes());
        e[17..49].copy_from_slice(&k.nonce);
        e[49..65].copy_from_slice(&k.iv);
        let dl = data.len() as i32 + k.skew.1 as i32;
        e[97..99].copy_from_slice(&(dl as u16).to_be_bytes());
        e.extend_from_slice(&data);
        if k.sign {
            let mic = match k.version {
                0 => aes::cmac(&kck, &[&e]),
                2 => hmac_sha1(&kck, &[&e])[..16].try_into().unwrap(),
                _ => hmac_md5(&kck, &[&e]),
            };
            e[81..97].copy_from_slice(&mic);
        }
        let mut body = LLC_EAPOL.to_vec();
        body.extend_from_slice(&e);
        body
    }

    /// A data frame from the access point, protected in software when
    /// `soft` names a key (0 pairwise, else the group key's index).
    fn data(
        &mut self,
        fc0: u8,
        to: &Mac,
        body: &[u8],
        soft: Option<u8>,
        pn: Option<u64>,
    ) -> Vec<u8> {
        let mut f = header(fc0, 0x02, to, &AP, &AP);
        if fc0 & 0x80 != 0 {
            f.extend_from_slice(&[0, 0]);
        }
        f.extend_from_slice(body);
        match soft {
            Some(id) => self.protect(f, id, pn),
            None => f,
        }
    }

    fn protect(&mut self, mut f: Vec<u8>, id: u8, pn: Option<u64>) -> Vec<u8> {
        let group = id != 0;
        let key: [u8; 16] = if group {
            self.keys.gtk.1[..16].try_into().unwrap()
        } else {
            self.tk().unwrap_or([0; 16])
        };
        let counter = if group {
            &mut self.keys.group_pn
        } else {
            &mut self.keys.pn
        };
        *counter += 1;
        let pn = pn.unwrap_or(*counter);
        let len = f.len();
        f.resize(len + ccmp::OVERHEAD, 0);
        let n = ccmp::protect(&key, id & 3, pn, &mut f, len);
        f.truncate(n);
        f
    }

    fn msg1(&mut self) -> Vec<u8> {
        let mut anonce = [0u8; 32];
        for b in anonce.iter_mut() {
            *b = self.next() as u8;
        }
        self.keys.anonce = anonce;
        self.keys.replay += 1;
        let v = self.version();
        let k = KeyFrame {
            descriptor: self.descriptor(),
            info: 0x0008 | 0x0080 | v,
            replay: self.keys.replay,
            nonce: anonce,
            iv: [0; 16],
            data: &[],
            encrypt: false,
            sign: false,
            pending: false,
            skew: (0, 0),
            version: v,
        };
        self.key_frame(&k)
    }

    fn descriptor(&self) -> u8 {
        match self.kind {
            Kind::Psk { wpa2: false, .. } => 0xFE,
            _ => 2,
        }
    }

    fn kdes(&self) -> Vec<u8> {
        let mut d = Vec::new();
        let (id, gtk) = self.keys.gtk;
        let mut g = vec![0x00, 0x0F, 0xAC, 1, id, 0];
        let n = match self.kind {
            Kind::Psk { group: 2, .. } => 32,
            _ => 16,
        };
        g.extend_from_slice(&gtk[..n]);
        element(&mut d, 0xDD, &g);
        if self.sae_kind() {
            let (id, igtk) = self.keys.igtk;
            let mut i = vec![0x00, 0x0F, 0xAC, 9];
            i.extend_from_slice(&id.to_le_bytes());
            i.extend_from_slice(&self.keys.ipn.to_le_bytes()[..6]);
            i.extend_from_slice(&igtk);
            element(&mut d, 0xDD, &i);
        }
        d
    }

    fn msg3(&mut self, extra: &[u8]) -> Vec<u8> {
        self.keys.replay += 1;
        let v = self.version();
        let wpa1 = matches!(self.kind, Kind::Psk { wpa2: false, .. });
        let mut data = if wpa1 { Vec::new() } else { self.kdes() };
        data.extend_from_slice(extra);
        let k = KeyFrame {
            descriptor: self.descriptor(),
            info: 0x0008 | 0x0040 | 0x0080 | 0x0100 | if wpa1 { 0 } else { 0x0200 | 0x1000 } | v,
            replay: self.keys.replay,
            nonce: self.keys.anonce,
            iv: [0; 16],
            data: &data,
            encrypt: !wpa1,
            sign: true,
            pending: true,
            skew: (0, 0),
            version: v,
        };
        self.key_frame(&k)
    }

    fn group(&mut self, index: u8) -> Vec<u8> {
        self.keys.replay += 1;
        self.keys.gtk.0 = index & 3;
        let v = self.version();
        let wpa1 = matches!(self.kind, Kind::Psk { wpa2: false, .. });
        let data = if wpa1 {
            let n = match self.kind {
                Kind::Psk { group: 2, .. } => 32,
                _ => 16,
            };
            self.keys.gtk.1[..n].to_vec()
        } else {
            self.kdes()
        };
        let k = KeyFrame {
            descriptor: self.descriptor(),
            info: ((index as u16 & 3) << 4) | 0x0080 | 0x0100 | 0x0200 | 0x1000 | v,
            replay: self.keys.replay,
            nonce: [0; 32],
            iv: [7; 16],
            data: &data,
            encrypt: true,
            sign: true,
            pending: false,
            skew: (0, 0),
            version: v,
        };
        self.key_frame(&k)
    }

    /// An EAPOL body as a data frame: under the pairwise key on a WPA3
    /// link that has one.
    fn eapol_frame(&mut self, body: &[u8], soft: bool) -> (Vec<u8>, bool) {
        let soft = soft && self.sae_kind() && self.keys.ptk.is_some();
        let f = self.data(0x08, &STA, body, soft.then_some(0), None);
        (f, soft)
    }

    fn sae_commit(&mut self) -> Vec<u8> {
        let Kind::Sae { h2e, .. } = self.kind else {
            return Vec::new();
        };
        let element = if h2e {
            let pt = sae::password_point(SSID, PASSWORD, &[]).unwrap();
            sae::password_element_from_point(&pt, &AP, &STA)
        } else {
            sae::password_element_looping(&AP, &STA, PASSWORD).unwrap()
        };
        let mut rand = [0u8; 32];
        let mut mask = [0u8; 32];
        for b in rand.iter_mut().chain(mask.iter_mut()) {
            *b = self.next() as u8;
        }
        let mut s = Session::new(element, &rand, &mask);
        let mut body = vec![3, 0, 1, 0, if h2e { 126 } else { 0 }, 0];
        body.extend_from_slice(&s.commit().to_bytes());
        if let Some(c) = &self.commit
            && s.process_commit(c).is_ok()
        {
            self.pmk = s.pmk;
        }
        self.sae = Some(s);
        management(0xB0, &body)
    }

    fn sae_confirm(&mut self) -> Vec<u8> {
        let mut body = vec![3, 0, 2, 0, 0, 0, 1, 0];
        let c = self
            .sae
            .as_ref()
            .and_then(|s| s.confirm(1))
            .unwrap_or([0; 32]);
        body.extend_from_slice(&c);
        management(0xB0, &body)
    }

    /// A broadcast management frame signed with BIP.
    fn bip(
        &mut self,
        fc0: u8,
        body: &[u8],
        key_id: Option<u16>,
        ipn: Option<u64>,
        good: bool,
    ) -> Vec<u8> {
        let mut f = header(fc0, 0, &[0xFF; 6], &AP, &AP);
        f.extend_from_slice(body);
        self.keys.ipn += 1;
        let ipn = ipn.unwrap_or(self.keys.ipn);
        f.extend_from_slice(&[76, 16]);
        f.extend_from_slice(&key_id.unwrap_or(self.keys.igtk.0).to_le_bytes());
        f.extend_from_slice(&ipn.to_le_bytes()[..6]);
        f.extend_from_slice(&[0; 8]);
        if good {
            let mic = ccmp::bip_mic(&self.keys.igtk.1, &f);
            let n = f.len();
            f[n - 8..].copy_from_slice(&mic);
        }
        f
    }
}

// ---- getting there ------------------------------------------------------

/// A station and its air, in one state of a connection.
#[derive(Clone)]
pub struct World {
    pub air: Air,
    pub sta: Station,
    buffer: Vec<u8>,
    found: Vec<wifi::ScanResult>,
}

impl World {
    /// Hand over everything queued, as the main loop does.
    fn pump(&mut self, oracle: &mut Oracle) {
        while let Some(rx) = self.air.receive(&mut self.buffer) {
            let len = rx.len;
            let protected = self.buffer[1] & 0x40 != 0;
            if let Some(d) = self.sta.input(&mut self.air, &mut self.buffer, rx) {
                assert!(d.start >= 24 && d.start + d.len <= len, "{d:?} of {len}");
                oracle.check(&self.air, rx.decrypted, protected);
            }
        }
    }

    fn deliver(&mut self, frame: Vec<u8>, oracle: &mut Oracle) {
        self.air.push(frame, false, -50);
        self.pump(oracle);
    }

    fn scan(&mut self, frames: Vec<(Vec<u8>, bool)>, ssid: Option<&[u8]>) {
        for (f, d) in frames {
            self.air.push(f, d, -40);
        }
        let mut found = Vec::new();
        let World {
            air, sta, buffer, ..
        } = self;
        sta.scan(air, ssid, buffer, &mut |r| {
            assert!(r.ssid_len <= 32);
            found.push(*r)
        });
        self.air.rx.clear();
        self.found = found;
    }
}

/// Where the script leaves the station: the number of steps taken.
pub fn script_len(kind: Kind) -> usize {
    script(kind).len()
}

fn script(kind: Kind) -> &'static [Step] {
    use Step::*;
    match kind {
        Kind::Open | Kind::Wep { shared: false, .. } => &[Scan, Join, AuthOk, AssocOk],
        Kind::Wep { shared: true, .. } => &[Scan, Join, Challenge, AuthOk4, AssocOk],
        Kind::Psk { wpa2: false, .. } => &[Scan, Join, AuthOk, AssocOk, Msg1, Msg3, Group],
        Kind::Psk { .. } => &[Scan, Join, AuthOk, AssocOk, Msg1, Msg3],
        Kind::Sae { cached: false, .. } => {
            &[Scan, Join, SaeCommit, SaeConfirm, AssocOk, Msg1, Msg3]
        }
        Kind::Sae { cached: true, .. } => &[
            Scan, Join, SaeCommit, SaeConfirm, AssocOk, Msg1, Msg3, Deauth, Join, AuthOk, AssocOk,
            Msg1, Msg3,
        ],
        Kind::Master => &[SetMode, PeerAuth, PeerAssoc],
    }
}

#[derive(Debug, Clone, Copy)]
enum Step {
    Scan,
    Join,
    AuthOk,
    Challenge,
    AuthOk4,
    AssocOk,
    Msg1,
    Msg3,
    Group,
    SaeCommit,
    SaeConfirm,
    Deauth,
    SetMode,
    PeerAuth,
    PeerAssoc,
}

impl World {
    fn new(kind: Kind) -> World {
        World {
            air: Air::new(kind),
            sta: Station::new(),
            buffer: vec![0; 2400],
            found: Vec::new(),
        }
    }

    fn join(&mut self) {
        let kind = self.air.kind;
        let r = self
            .found
            .iter()
            .find(|r| r.bssid == AP)
            .copied()
            .unwrap_or(wifi::ScanResult {
                ssid: [0; 33],
                ssid_len: 0,
                mac: AP,
                bssid: AP,
                rssi: -40,
                channel: 6,
                rateset: 0xFFF,
                encryption: 0,
            });
        let (key, shared): (&[u8], bool) = match kind {
            Kind::Wep { long, shared } => (if long { WEP104 } else { WEP40 }, shared),
            Kind::Psk { .. } | Kind::Sae { .. } => (&self.air.pmk.clone(), false),
            _ => (&[], false),
        };
        let password: &[u8] = if matches!(kind, Kind::Sae { .. }) {
            PASSWORD
        } else {
            &[]
        };
        let key = key.to_vec();
        self.sta.auth(
            &mut self.air,
            &r.ssid[..r.ssid_len],
            &r.mac,
            &r.bssid,
            r.channel,
            r.rateset,
            shared,
            r.encryption,
            &key,
            password,
        );
    }

    fn step(&mut self, step: Step) {
        let mut o = Oracle::off();
        match step {
            Step::Scan => {
                let b = beacon(self.air.kind);
                self.scan(vec![(b, false)], None);
            }
            Step::Join => self.join(),
            Step::AuthOk => self.deliver(management(0xB0, &[0, 0, 2, 0, 0, 0]), &mut o),
            Step::Challenge => {
                let mut body = vec![1, 0, 2, 0, 0, 0];
                element(&mut body, 16, &[0x5A; 128]);
                self.deliver(management(0xB0, &body), &mut o)
            }
            Step::AuthOk4 => self.deliver(management(0xB0, &[1, 0, 4, 0, 0, 0]), &mut o),
            Step::AssocOk => {
                let f = management(0x10, &[0x01, 0, 0, 0, 1, 0xC0, 1, 1, 0x82]);
                self.deliver(f, &mut o)
            }
            Step::Msg1 => {
                let body = self.air.msg1();
                let (f, _) = self.air.eapol_frame(&body, true);
                self.deliver(f, &mut o)
            }
            Step::Msg3 => {
                let body = self.air.msg3(&[]);
                let (f, _) = self.air.eapol_frame(&body, true);
                self.deliver(f, &mut o)
            }
            Step::Group => {
                let body = self.air.group(2);
                let (f, _) = self.air.eapol_frame(&body, true);
                // WPA: the group message comes encrypted by the stick.
                self.air.push(f, true, -50);
                self.pump(&mut o);
            }
            Step::SaeCommit => {
                let f = self.air.sae_commit();
                self.deliver(f, &mut o)
            }
            Step::SaeConfirm => {
                let f = self.air.sae_confirm();
                self.deliver(f, &mut o)
            }
            Step::Deauth => {
                let f = management(0xC0, &[3, 0]);
                let f = self.air.protect(f, 0, None);
                self.deliver(f, &mut o);
                // A new association starts from scratch.
                self.air.keys.ptk = None;
                self.air.keys.pending = None;
                self.air.keys.pn = 0;
            }
            Step::SetMode => self.sta.set_mode(&mut self.air, true, b"Nabaztag2815\0", 4),
            Step::PeerAuth => {
                let mut f = header(0xB0, 0, &STA, &LAPTOPS[0], &STA);
                f.extend_from_slice(&[0, 0, 1, 0, 0, 0]);
                self.deliver(f, &mut o)
            }
            Step::PeerAssoc => {
                let mut f = header(0x00, 0, &STA, &LAPTOPS[0], &STA);
                f.extend_from_slice(&[1, 0, 10, 0]);
                element(&mut f, 0, b"Nabaztag2815");
                self.deliver(f, &mut o)
            }
        }
    }
}

impl World {
    /// Join the genuine access point again, from a scan, as the
    /// bytecode does when the link is down: whatever came before, this
    /// must end connected.
    fn rejoin(&mut self) {
        let kind = self.air.kind;
        if kind == Kind::Master {
            return;
        }
        if self.sta.mode != wifi::Mode::Managed {
            self.sta.set_mode(&mut self.air, false, &[], 0);
        }
        self.air.rx.clear();
        self.air.keys.ptk = None;
        self.air.keys.pending = None;
        self.air.keys.pn = 0;
        self.air.keys.gtk.0 = 1;
        self.air.auth_alg = None;
        self.step(Step::Scan);
        self.step(Step::Join);
        let mut o = Oracle::off();
        let steps: &[Step] = match kind {
            Kind::Wep { shared: true, .. } => &[Step::Challenge, Step::AuthOk4, Step::AssocOk],
            Kind::Psk { wpa2: false, .. } => &[
                Step::AuthOk,
                Step::AssocOk,
                Step::Msg1,
                Step::Msg3,
                Step::Group,
            ],
            Kind::Psk { .. } => &[Step::AuthOk, Step::AssocOk, Step::Msg1, Step::Msg3],
            Kind::Sae { .. } => {
                if self.air.auth_alg == Some(0) {
                    // The cached key: the access point has forgotten it.
                    self.step(Step::AuthOk);
                    let f = management(0x10, &[0x01, 0, 53, 0, 0, 0]);
                    self.deliver(f, &mut o);
                }
                &[
                    Step::SaeCommit,
                    Step::SaeConfirm,
                    Step::AssocOk,
                    Step::Msg1,
                    Step::Msg3,
                ]
            }
            _ => &[Step::AuthOk, Step::AssocOk],
        };
        for step in steps {
            self.step(*step);
        }
    }
}

/// What may be handed up.
struct Oracle {
    on: bool,
    delivered: usize,
    /// The operation under way sent nothing a key vouches for.
    forged: bool,
}

impl Oracle {
    fn off() -> Self {
        Oracle {
            on: false,
            delivered: 0,
            forged: false,
        }
    }

    /// A frame was handed up: on a keyed link, it must have been
    /// opened by the stick or by the station.
    fn check(&mut self, air: &Air, decrypted: bool, protected: bool) {
        self.delivered += 1;
        if !self.on {
            return;
        }
        match air.kind {
            Kind::Psk { .. } => assert!(decrypted, "WPA: handed up a frame no key opened"),
            Kind::Sae { .. } => assert!(
                protected && !decrypted,
                "WPA3: handed up a frame not opened by the station"
            ),
            Kind::Wep { .. } => {
                assert!(
                    decrypted || !protected,
                    "WEP: handed up a frame still sealed"
                )
            }
            Kind::Open | Kind::Master => assert!(!protected, "open: handed up a sealed frame"),
        }
    }
}

thread_local! {
    static WORLDS: std::cell::RefCell<HashMap<(usize, usize), World>> =
        std::cell::RefCell::new(HashMap::new());
}

/// The world of `kind` after `steps` steps of its script, made once.
pub fn world(kind: usize, steps: usize) -> World {
    let kind = kind % KINDS.len();
    let s = script(KINDS[kind]);
    let steps = steps % (s.len() + 1);
    WORLDS.with(|w| {
        w.borrow_mut()
            .entry((kind, steps))
            .or_insert_with(|| {
                let mut w = World::new(KINDS[kind]);
                for step in &s[..steps] {
                    w.step(*step);
                }
                w
            })
            .clone()
    })
}

// ---- the fuzzed part ----------------------------------------------------

fn mac(input: &mut Input) -> Mac {
    match input.u8() % 6 {
        0 => STA,
        1 => AP,
        2 => [0xFF; 6],
        3 => [0x01, 0x00, 0x5E, 0, 0, 1],
        4 => LAPTOPS[input.u8() as usize % 3],
        _ => input.array(),
    }
}

/// Run one input: a kind, a number of steps, then operations. Returns
/// how many frames were handed up, and the station's state.
pub fn run(data: &[u8]) -> (usize, i32) {
    let mut input = Input::new(data);
    let kind = input.u8() as usize;
    let steps = input.u8() as usize;
    // Joining again at the end takes a scan and a handshake (with SAE,
    // a thousand times a frame's work): one input in two.
    let rejoin = steps & 0x80 != 0;
    let mut w = world(kind, steps & 0x7F);
    w.air.work = 0;
    let mut oracle = Oracle {
        on: true,
        delivered: 0,
        forged: false,
    };
    let mut ops = 0;
    while !input.is_empty() && ops < 64 {
        ops += 1;
        let before = w.sta.net_state();
        oracle.forged = false;
        op(&mut w, &mut input, &mut oracle);
        // WPA3 protects the management frames: nothing unsigned brings
        // the link down.
        if oracle.on
            && oracle.forged
            && matches!(w.air.kind, Kind::Sae { .. })
            && before == wifi::S_CONNECTED
        {
            assert_eq!(
                w.sta.net_state(),
                wifi::S_CONNECTED,
                "WPA3: a forged frame cut the link"
            );
        }
    }
    let state = w.sta.net_state();
    if rejoin && w.air.kind != Kind::Master {
        w.rejoin();
        assert_eq!(
            w.sta.net_state(),
            wifi::S_CONNECTED,
            "the genuine network can no longer be joined"
        );
    }
    (oracle.delivered, state)
}

fn op(w: &mut World, input: &mut Input, oracle: &mut Oracle) {
    match input.u8() % 18 {
        // A frame as it is.
        0 => {
            oracle.forged = true;
            let flags = input.u8();
            let f = input.chunk(true).to_vec();
            if f.len() >= 10 {
                w.air.push(f, flags & 1 != 0, flags as i8);
            }
            w.pump(oracle);
        }
        // A management frame from the access point.
        1 => {
            let fc0 = input.u8() & 0xF0;
            let protect = input.u8();
            let body = input.chunk(false).to_vec();
            let mut f = management(fc0, &body);
            oracle.forged = !(protect & 1 != 0 && w.air.keys.ptk.is_some());
            if protect & 1 != 0 && w.air.keys.ptk.is_some() {
                let pn = (protect & 2 != 0).then(|| input.u32() as u64);
                f = w.air.protect(f, 0, pn);
            }
            w.deliver(f, oracle);
        }
        // A data frame from the access point.
        2 => {
            let fc0 = [0x08, 0x48, 0x88, input.u8()][input.u8() as usize % 4];
            let to = mac(input);
            let how = input.u8();
            let body = input.chunk(true).to_vec();
            let soft = match how % 4 {
                1 => Some(0),
                2 => Some(w.air.keys.gtk.0),
                3 => Some(input.u8() & 3),
                _ => None,
            };
            let pn = (how & 4 != 0).then(|| input.u32() as u64);
            oracle.forged = soft.is_none();
            let f = w.air.data(fc0, &to, &body, soft, pn);
            if f.len() >= 10 {
                w.air.push(f, how & 8 != 0, -50);
            }
            w.pump(oracle);
        }
        // An EAPOL-Key frame of the fuzzer's making, signed or not.
        3 => {
            let flags = input.u8();
            let info = input.u16();
            let replay = match input.u8() % 4 {
                0 => {
                    w.air.keys.replay += 1;
                    w.air.keys.replay
                }
                1 => w.air.keys.replay,
                _ => u64::from_be_bytes(input.array()),
            };
            let nonce = if flags & 2 != 0 {
                input.array()
            } else {
                w.air.keys.anonce
            };
            let skew = if flags & 4 != 0 {
                (input.u8() as i8 as i16, input.u8() as i8 as i16)
            } else {
                (0, 0)
            };
            let iv = input.array();
            let data = input.chunk(false);
            let k = KeyFrame {
                descriptor: [w.air.descriptor(), 2, 0xFE, input.u8()][(flags >> 3) as usize % 4],
                info,
                replay,
                nonce,
                iv,
                data,
                encrypt: flags & 0x20 != 0,
                sign: flags & 0x40 == 0,
                pending: flags & 0x80 != 0,
                skew,
                version: w.air.version(),
            };
            let body = w.air.key_frame(&k);
            let (f, soft) = w.air.eapol_frame(&body, flags & 1 != 0);
            oracle.forged = !soft && !k.sign;
            let decrypted = info & 0x2000 != 0;
            w.air.push(f, decrypted, -50);
            w.pump(oracle);
        }
        // The real messages, to move the handshake along.
        4 => {
            let body = w.air.msg1();
            let (f, _) = w.air.eapol_frame(&body, input.bool());
            w.deliver(f, oracle);
        }
        5 => {
            let extra = input.chunk(false).to_vec();
            let body = w.air.msg3(&extra);
            let (f, _) = w.air.eapol_frame(&body, input.bool());
            w.deliver(f, oracle);
        }
        6 => {
            let index = input.u8();
            let body = w.air.group(index);
            let (f, _) = w.air.eapol_frame(&body, input.bool());
            w.air.push(f, true, -50);
            w.pump(oracle);
        }
        // SAE.
        7 => match input.u8() % 4 {
            0 => {
                let f = w.air.sae_commit();
                w.deliver(f, oracle)
            }
            1 => {
                let f = w.air.sae_confirm();
                w.deliver(f, oracle)
            }
            _ => {
                let seq = input.u16() % 4;
                let status = [0, 126, 76, 1, input.u16()][input.u8() as usize % 5];
                let mut body = vec![3, 0];
                body.extend_from_slice(&seq.to_le_bytes());
                body.extend_from_slice(&status.to_le_bytes());
                body.extend_from_slice(input.chunk(false));
                w.deliver(management(0xB0, &body), oracle)
            }
        },
        // BIP-signed broadcast management.
        8 => {
            let fc0 = [0xC0, 0xA0, 0xD0, input.u8() & 0xF0][input.u8() as usize % 4];
            let flags = input.u8();
            let body = input.chunk(false).to_vec();
            let key_id = (flags & 1 != 0).then(|| input.u16());
            let ipn = (flags & 2 != 0).then(|| input.u32() as u64);
            oracle.forged = flags & 4 != 0;
            let f = w.air.bip(fc0, &body, key_id, ipn, flags & 4 == 0);
            w.deliver(f, oracle);
        }
        // An SA Query, protected.
        9 => {
            let body = [8, input.u8() & 1, input.u8(), input.u8()];
            let f = management(0xD0, &body);
            let f = w.air.protect(f, 0, None);
            w.deliver(f, oracle);
        }
        10 => w.sta.tick(&mut w.air),
        11 => {
            w.air.now = w
                .air
                .now
                .wrapping_add(input.u16() as u32 * input.u8() as u32);
            w.sta.poll(&mut w.air);
        }
        // The bytecode sends.
        12 => {
            let to = mac(input);
            let low = input.bool();
            let data = input.chunk(true).to_vec();
            w.sta.send(&mut w.air, &data, &to, low);
        }
        // A scan, hearing frames.
        13 => {
            let n = input.u8() % 4;
            let mut frames = Vec::new();
            for _ in 0..n {
                if input.bool() {
                    let mut b = beacon(w.air.kind);
                    b[0] = if input.bool() { 0x80 } else { 0x50 };
                    b[10..16].copy_from_slice(&mac(input));
                    b[16..22].copy_from_slice(&mac(input));
                    b.truncate(24 + 12);
                    b.extend_from_slice(input.chunk(true));
                    frames.push((b, false));
                } else {
                    let f = input.chunk(true).to_vec();
                    if f.len() >= 10 {
                        frames.push((f, false));
                    }
                }
            }
            let ssid = input.bool().then(|| input.chunk(false).to_vec());
            w.scan(frames, ssid.as_deref());
            if input.bool() {
                // Join what was heard, as the bytecode would.
                let i = input.u8() as usize;
                if let Some(r) = w.found.get(i % w.found.len().max(1)).copied() {
                    let key = input.chunk(false).to_vec();
                    let password = input.chunk(false).to_vec();
                    oracle.on = false;
                    w.sta.auth(
                        &mut w.air,
                        &r.ssid[..r.ssid_len],
                        &r.mac,
                        &r.bssid,
                        r.channel,
                        r.rateset,
                        input.bool(),
                        r.encryption,
                        &key[..key.len().min(32)],
                        &password[..password.len().min(64)],
                    );
                }
            }
        }
        // The bytecode joins, with what it likes.
        14 => {
            let mac_ = mac(input);
            let bssid = mac(input);
            let channel = input.u8();
            let rateset = input.u16();
            let shared = input.bool();
            let encryption = input.u8();
            let ssid = input.chunk(false).to_vec();
            let key = input.chunk(false).to_vec();
            let password = input.chunk(false).to_vec();
            oracle.on = false;
            w.sta.auth(
                &mut w.air,
                &ssid,
                &mac_,
                &bssid,
                channel,
                rateset,
                shared,
                encryption,
                &key[..key.len().min(32)],
                &password[..password.len().min(64)],
            );
        }
        15 => {
            let master = input.bool();
            let channel = input.u8();
            let ssid = input.chunk(false).to_vec();
            oracle.on = false;
            w.sta.set_mode(&mut w.air, master, &ssid, channel);
        }
        // A frame from a laptop, to the access point.
        16 => {
            let fc0 = input.u8();
            let fc1 = [0, 0x01, input.u8()][input.u8() as usize % 3];
            let from = LAPTOPS[input.u8() as usize % 3];
            let a3 = mac(input);
            let mut f = header(fc0, fc1, &STA, &from, &a3);
            f.extend_from_slice(input.chunk(true));
            oracle.forged = true;
            w.deliver(f, oracle);
        }
        // An association response with a comeback time.
        _ => {
            let status = [0, 30, 53, 1, input.u16()][input.u8() as usize % 5];
            let tu = input.u32();
            let mut body = vec![0x01, 0];
            body.extend_from_slice(&status.to_le_bytes());
            body.extend_from_slice(&[1, 0xC0]);
            element(
                &mut body,
                56,
                &[
                    3,
                    tu as u8,
                    (tu >> 8) as u8,
                    (tu >> 16) as u8,
                    (tu >> 24) as u8,
                ],
            );
            w.deliver(management(0x10, &body), oracle);
            w.sta.poll(&mut w.air);
        }
    }
}
