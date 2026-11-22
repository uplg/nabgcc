//! A WPA3 station written from the standard: the reference for what
//! the rabbit's firmware has to do to join a WPA3 network, and the
//! other end the emulated access point is tested against.
//!
//! It does the password exchange (SAE, by hunting and pecking or by
//! hashing to the curve), associates asking for protected management
//! frames, runs the four-way handshake of key management 8 (AES-CMAC
//! for integrity, SHA-256 for derivation), then exchanges CCMP data.
//! Frames go straight on a [`Radio`]: no emulated processor involved.

use crate::air::{Mac, element};
use crate::crypto::{self, Cipher, Key};
use crate::rt2573::{Radio, TxFrame};
use crate::sae;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    HuntingAndPecking,
    HashToElement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    /// Commit sent.
    Committed,
    /// Confirm sent.
    Confirmed,
    Associating,
    /// Associated, the four-way handshake is running.
    Handshake,
    Connected,
    Failed(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// A deauthentication that could not be trusted was ignored.
    ForgedDeauthIgnored,
    Deauthenticated {
        reason: u16,
    },
    GroupKeyRenewed {
        index: u8,
    },
    /// A frame failed to decrypt or repeated an old packet number.
    Dropped,
}

pub struct Supplicant {
    pub mac: Mac,
    pub ssid: String,
    pub password: String,
    pub method: Method,
    /// Ask for protected management frames, as WPA3 demands. Turning
    /// this off makes a station no WPA3 network should accept.
    pub protect_management: bool,
    pub state: State,
    pub notices: Vec<Notice>,
    /// Ethernet frames received once connected.
    pub received: Vec<Vec<u8>>,
    /// The key the password exchange produced.
    pub pmk: [u8; 32],
    bssid: Mac,
    channel: u8,
    session: Option<sae::Session>,
    pmkid: [u8; 16],
    ptk: [u8; 48],
    snonce: [u8; 32],
    gtk: Option<(u8, [u8; 16])>,
    igtk: Option<[u8; 16]>,
    tx_pn: u64,
    rx_pn: u64,
    group_rx_pn: u64,
    seq: u16,
    rng: u64,
}

const LLC_EAPOL: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];
const INFO_PAIRWISE: u16 = 0x0008;
const INFO_ACK: u16 = 0x0080;
const INFO_MIC: u16 = 0x0100;
const INFO_SECURE: u16 = 0x0200;

impl Supplicant {
    pub fn new(mac: Mac, ssid: &str, password: &str) -> Self {
        Supplicant {
            mac,
            ssid: ssid.into(),
            password: password.into(),
            method: Method::HashToElement,
            protect_management: true,
            state: State::Idle,
            notices: Vec::new(),
            received: Vec::new(),
            pmk: [0; 32],
            bssid: [0; 6],
            channel: 0,
            session: None,
            pmkid: [0; 16],
            ptk: [0; 48],
            snonce: [0; 32],
            gtk: None,
            igtk: None,
            tx_pn: 0,
            rx_pn: 0,
            group_rx_pn: 0,
            seq: 0,
            rng: u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0x3C, 0xC3])
                | 1,
        }
    }

    fn random(&mut self) -> [u8; 32] {
        std::array::from_fn(|_| {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            (self.rng >> 24) as u8
        })
    }

    pub fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    /// The integrity group key was handed over (protected broadcasts).
    pub fn has_integrity_group_key(&self) -> bool {
        self.igtk.is_some()
    }

    /// The RSN element sent in the association request and message 2.
    fn own_element(&self) -> Vec<u8> {
        let capabilities: u16 = if self.protect_management { 0x00C0 } else { 0 };
        let mut e = vec![
            48, 20, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 8,
        ];
        e.extend_from_slice(&capabilities.to_le_bytes());
        e
    }

    fn transmit(
        &mut self,
        radio: &mut Radio,
        fc0: u8,
        fc1: u8,
        a3: Mac,
        body: &[u8],
        protect: bool,
    ) {
        let mut f = vec![fc0, fc1, 0, 0];
        f.extend_from_slice(&self.bssid);
        f.extend_from_slice(&self.mac);
        f.extend_from_slice(&a3);
        f.extend_from_slice(&(self.seq << 4).to_le_bytes());
        self.seq = (self.seq + 1) & 0xFFF;
        f.extend_from_slice(body);
        if protect {
            self.tx_pn += 1;
            let iv = (self.tx_pn as u32 & 0xFFFF) | 0x2000_0000;
            let key = Key {
                cipher: Cipher::Ccmp,
                key: &self.ptk[32..48],
                mic: &[0; 8],
            };
            f = crypto::protect(&key, &f, iv, (self.tx_pn >> 16) as u32);
        }
        radio.tx.push_back(TxFrame {
            data: f,
            channel: self.channel,
        });
    }

    /// Start joining the network at `bssid` on `channel`.
    pub fn connect(&mut self, radio: &mut Radio, bssid: Mac, channel: u8) {
        self.bssid = bssid;
        self.channel = channel;
        let password = self.password.clone();
        let (status, element) = match self.method {
            Method::HuntingAndPecking => (
                0u16,
                sae::password_element_looping(&self.mac, &bssid, password.as_bytes()),
            ),
            Method::HashToElement => {
                let point = sae::password_point(self.ssid.as_bytes(), password.as_bytes(), None);
                (
                    126,
                    sae::password_element_from_point(&point, &self.mac, &bssid),
                )
            }
        };
        let (rand, mask) = (self.random(), self.random());
        let session = sae::Session::new(element, &rand, &mask);
        let mut body = vec![3, 0, 1, 0];
        body.extend_from_slice(&status.to_le_bytes());
        body.extend_from_slice(&session.commit().to_bytes());
        self.session = Some(session);
        self.transmit(radio, 0xB0, 0, bssid, &body, false);
        self.state = State::Committed;
    }

    /// Send an Ethernet frame through the access point.
    pub fn send(&mut self, radio: &mut Radio, eth: &[u8]) {
        if self.state != State::Connected || eth.len() < 14 {
            return;
        }
        let mut body = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];
        body.extend_from_slice(&eth[12..]);
        self.transmit(radio, 0x08, 0x01, eth[..6].try_into().unwrap(), &body, true);
    }

    /// Leave the network, with a deauthentication the access point can
    /// trust.
    pub fn disconnect(&mut self, radio: &mut Radio) {
        let protect = self.state == State::Connected && self.protect_management;
        // Reason 3: the station is leaving.
        self.transmit(radio, 0xC0, 0, self.bssid, &[3, 0], protect);
        self.state = State::Idle;
    }

    /// Handle everything that arrived.
    pub fn poll(&mut self, radio: &mut Radio) {
        while let Some(frame) = radio.rx.pop_front() {
            let f = frame.data;
            if f.len() < 24 || f[10..16] != self.bssid {
                continue;
            }
            let mine = f[4..10] == self.mac;
            let group = f[4] & 1 != 0;
            match f[0] {
                0xB0 if mine => self.on_authentication(radio, &f[24..]),
                0x10 if mine => self.on_association(&f[24..]),
                0xC0 | 0xA0 if mine || group => self.on_deauthentication(&f),
                0x08 if (mine || group) && f[1] & 3 == 2 => self.on_data(radio, &f),
                _ => {}
            }
        }
    }

    fn on_authentication(&mut self, radio: &mut Radio, body: &[u8]) {
        if body.len() < 6 || body[..2] != [3, 0] {
            return;
        }
        let seq = u16::from_le_bytes([body[2], body[3]]);
        let status = u16::from_le_bytes([body[4], body[5]]);
        match (self.state, seq) {
            (State::Committed, 1) => {
                if status != 0 && status != 126 {
                    self.state = State::Failed("the access point refused the commit");
                    return;
                }
                let Some(theirs) = sae::Commit::from_bytes(&body[6..]) else {
                    self.state = State::Failed("not a commit");
                    return;
                };
                let session = self.session.as_mut().unwrap();
                if session.process_commit(&theirs).is_err() {
                    self.state = State::Failed("the access point's commit is not valid");
                    return;
                }
                let mut reply = vec![3, 0, 2, 0, 0, 0, 1, 0];
                reply.extend_from_slice(&session.confirm(1));
                self.transmit(radio, 0xB0, 0, self.bssid, &reply, false);
                self.state = State::Confirmed;
            }
            (State::Confirmed, 2) => {
                let session = self.session.as_ref().unwrap();
                let ok = status == 0
                    && body.len() >= 40
                    && session.check_confirm(u16::from_le_bytes([body[6], body[7]]), &body[8..40]);
                if !ok {
                    self.state = State::Failed("the access point does not know the password");
                    return;
                }
                self.pmk = session.pmk;
                self.pmkid = session.pmkid;
                let mut request = vec![0x31, 0x04, 10, 0, 0, self.ssid.len() as u8];
                request.extend_from_slice(self.ssid.as_bytes());
                request.extend_from_slice(&[1, 4, 0x82, 0x84, 0x8B, 0x96]);
                request.extend_from_slice(&self.own_element());
                self.transmit(radio, 0x00, 0, self.bssid, &request, false);
                self.state = State::Associating;
            }
            _ => {}
        }
    }

    fn on_association(&mut self, body: &[u8]) {
        if self.state != State::Associating || body.len() < 4 {
            return;
        }
        self.state = match u16::from_le_bytes([body[2], body[3]]) {
            0 => State::Handshake,
            31 => State::Failed("refused: management frame protection policy"),
            43 => State::Failed("refused: key management"),
            _ => State::Failed("association refused"),
        };
    }

    fn on_deauthentication(&mut self, frame: &[u8]) {
        let keyed = matches!(self.state, State::Connected) && self.protect_management;
        let mut body = frame[24..].to_vec();
        if keyed {
            // Only the access point holds the key: a clear frame, or one
            // that does not decrypt, is somebody else's.
            let key = Key {
                cipher: Cipher::Ccmp,
                key: &self.ptk[32..48],
                mic: &[0; 8],
            };
            let genuine = frame[1] & 0x40 != 0 && frame[4..10] == self.mac;
            match crypto::unprotect(&key, frame).ok().filter(|_| genuine) {
                Some((clear, iv, eiv)) if self.fresh(iv, eiv, false) => body = clear[24..].to_vec(),
                _ => return self.notices.push(Notice::ForgedDeauthIgnored),
            }
        }
        let reason = body
            .get(..2)
            .map_or(0, |r| u16::from_le_bytes([r[0], r[1]]));
        self.notices.push(Notice::Deauthenticated { reason });
        self.state = State::Idle;
    }

    /// Check and record a received packet number.
    fn fresh(&mut self, iv: u32, eiv: u32, group: bool) -> bool {
        let pn = (eiv as u64) << 16 | (iv & 0xFFFF) as u64;
        let last = if group {
            &mut self.group_rx_pn
        } else {
            &mut self.rx_pn
        };
        if pn <= *last {
            return false;
        }
        *last = pn;
        true
    }

    fn on_data(&mut self, radio: &mut Radio, frame: &[u8]) {
        let group = frame[4] & 1 != 0;
        let clear;
        let mut body = &frame[24..];
        if frame[1] & 0x40 != 0 {
            let key: [u8; 16] = match (group, self.gtk) {
                (true, Some((_, gtk))) => gtk,
                (true, None) => return,
                (false, _) => self.ptk[32..48].try_into().unwrap(),
            };
            let key = Key {
                cipher: Cipher::Ccmp,
                key: &key,
                mic: &[0; 8],
            };
            match crypto::unprotect(&key, frame) {
                Ok((f, iv, eiv)) if self.fresh(iv, eiv, group) => {
                    clear = f;
                    body = &clear[24..];
                }
                _ => return self.notices.push(Notice::Dropped),
            }
        } else if self.state == State::Connected {
            // Nothing travels in clear once the keys are in place.
            return self.notices.push(Notice::Dropped);
        }
        if body.len() >= 8 && body[..8] == LLC_EAPOL {
            return self.on_eapol(radio, &body[8..]);
        }
        if self.state == State::Connected && body.len() >= 8 {
            let mut eth = frame[4..10].to_vec();
            eth.extend_from_slice(&frame[16..22]);
            eth.extend_from_slice(&body[6..]);
            self.received.push(eth);
        }
    }

    /// Build, sign and send an EAPOL-Key frame of key management 8.
    fn send_key(
        &mut self,
        radio: &mut Radio,
        info: u16,
        replay: &[u8],
        nonce: &[u8; 32],
        data: &[u8],
    ) {
        let mut k = vec![2];
        k.extend_from_slice(&info.to_be_bytes());
        k.extend_from_slice(&[0, 0]);
        k.extend_from_slice(replay);
        k.extend_from_slice(nonce);
        k.extend_from_slice(&[0; 16 + 8 + 8 + 16]);
        k.extend_from_slice(&(data.len() as u16).to_be_bytes());
        k.extend_from_slice(data);
        let mut eapol = vec![2, 3];
        eapol.extend_from_slice(&(k.len() as u16).to_be_bytes());
        eapol.extend_from_slice(&k);
        let mic = crypto::aes_cmac(self.ptk[..16].try_into().unwrap(), &eapol);
        eapol[81..97].copy_from_slice(&mic);
        let mut body = LLC_EAPOL.to_vec();
        body.extend_from_slice(&eapol);
        let protect = self.state == State::Connected;
        self.transmit(radio, 0x08, 0x01, self.bssid, &body, protect);
    }

    fn on_eapol(&mut self, radio: &mut Radio, eapol: &[u8]) {
        if eapol.len() < 99 || eapol[1] != 3 {
            return;
        }
        let info = u16::from_be_bytes([eapol[5], eapol[6]]);
        let replay = eapol[9..17].to_vec();
        let data_len = u16::from_be_bytes([eapol[97], eapol[98]]) as usize;
        let Some(data) = eapol.get(99..99 + data_len) else {
            return;
        };
        if info & 7 != 0 || info & INFO_ACK == 0 {
            return;
        }

        if info & INFO_MIC == 0 {
            // Message 1: derive the keys, answer with message 2.
            if self.state != State::Handshake || info & INFO_PAIRWISE == 0 {
                return;
            }
            let anonce = &eapol[17..49];
            self.snonce = self.random();
            let (lo_mac, hi_mac) = if self.bssid < self.mac {
                (self.bssid, self.mac)
            } else {
                (self.mac, self.bssid)
            };
            let snonce = self.snonce;
            let (lo_nonce, hi_nonce) = if anonce < &snonce[..] {
                (anonce, &snonce[..])
            } else {
                (&snonce[..], anonce)
            };
            let mut seed = lo_mac.to_vec();
            seed.extend_from_slice(&hi_mac);
            seed.extend_from_slice(lo_nonce);
            seed.extend_from_slice(hi_nonce);
            self.ptk.copy_from_slice(&crypto::kdf_sha256(
                &self.pmk,
                "Pairwise key expansion",
                &seed,
                384,
            ));
            let own = self.own_element();
            return self.send_key(radio, INFO_PAIRWISE | INFO_MIC, &replay, &snonce, &own);
        }

        let mut unsigned = eapol[..99 + data_len].to_vec();
        unsigned[81..97].fill(0);
        if crypto::aes_cmac(self.ptk[..16].try_into().unwrap(), &unsigned) != eapol[81..97] {
            self.state = State::Failed("message integrity check of the handshake");
            return;
        }
        let Some(plain) = crypto::aes_unwrap(self.ptk[16..32].try_into().unwrap(), data) else {
            self.state = State::Failed("key data does not unwrap");
            return;
        };
        // Key data elements: the group key and the integrity group key.
        let mut gtk = None;
        let mut igtk = None;
        let mut rest = &plain[..];
        while let [id, len, tail @ ..] = rest {
            let Some(body) = tail.get(..*len as usize) else {
                break;
            };
            if *id == 0xDD && body.len() >= 4 && body[..3] == [0x00, 0x0F, 0xAC] {
                match body[3] {
                    1 if body.len() >= 22 => {
                        gtk = Some((body[4] & 3, body[6..22].try_into().unwrap()))
                    }
                    9 if body.len() >= 28 => igtk = Some(body[12..28].try_into().unwrap()),
                    _ => {}
                }
            }
            rest = &tail[*len as usize..];
        }

        if info & INFO_PAIRWISE != 0 {
            // Message 3: the access point proved it has the key too.
            if self.state != State::Handshake {
                return;
            }
            if element(&plain, 48).is_none() || gtk.is_none() {
                self.state =
                    State::Failed("message 3 without the network's element or a group key");
                return;
            }
            self.gtk = gtk;
            self.igtk = igtk;
            self.send_key(
                radio,
                INFO_PAIRWISE | INFO_MIC | INFO_SECURE,
                &replay,
                &[0; 32],
                &[],
            );
            self.state = State::Connected;
        } else if self.state == State::Connected {
            // A new group key.
            if let Some((index, key)) = gtk {
                self.gtk = Some((index, key));
                self.group_rx_pn = 0;
                self.notices.push(Notice::GroupKeyRenewed { index });
            }
            self.send_key(radio, INFO_MIC | INFO_SECURE, &replay, &[0; 32], &[]);
        }
    }
}
