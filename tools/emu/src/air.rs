//! What is on the air around the rabbit: access points.
//!
//! An [`AccessPoint`] behaves like the real thing as far as a station
//! can tell: it beacons, answers probes, authenticates (open system or
//! WEP shared key), associates, runs the WPA and WPA2 pre-shared-key
//! handshakes, encrypts, checks replay counters, renews its group key.
//! Stations' traffic comes out as Ethernet frames on `uplink`; Ethernet
//! frames given to [`AccessPoint::send`] go out to them.
//!
//! Everything it notices goes to `events`, so a test can tell a clean
//! join from one that only happened to work.

use std::collections::{BTreeMap, VecDeque};

use crate::crypto::{self, Cipher, Key};
use crate::rt2573::{DEFAULT_RSSI, Radio, RxFrame};
use crate::sae;

pub type Mac = [u8; 6];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Security {
    Open,
    /// WEP with a 5 or 13 byte key. `shared_auth` demands the shared-key
    /// authentication exchange instead of open system.
    Wep {
        key: Vec<u8>,
        shared_auth: bool,
    },
    /// Pre-shared key. `wpa2` selects RSN over the original WPA.
    Psk {
        wpa2: bool,
        pairwise: Cipher,
        group: Cipher,
        passphrase: String,
    },
}

impl Security {
    /// WPA with TKIP, as first-generation WPA routers ship.
    pub fn wpa(passphrase: &str) -> Self {
        Security::Psk {
            wpa2: false,
            pairwise: Cipher::Tkip,
            group: Cipher::Tkip,
            passphrase: passphrase.into(),
        }
    }

    /// WPA2 with CCMP for everything.
    pub fn wpa2(passphrase: &str) -> Self {
        Security::Psk {
            wpa2: true,
            pairwise: Cipher::Ccmp,
            group: Cipher::Ccmp,
            passphrase: passphrase.into(),
        }
    }

    /// WPA2 with CCMP pairwise and a TKIP group key, as "mixed mode"
    /// routers announce.
    pub fn wpa2_tkip_group(passphrase: &str) -> Self {
        Security::Psk {
            wpa2: true,
            pairwise: Cipher::Ccmp,
            group: Cipher::Tkip,
            passphrase: passphrase.into(),
        }
    }
}

/// How a WPA2 network stands towards WPA3. The simultaneous
/// authentication of equals exchange itself is not implemented yet:
/// what is modelled is what such a network announces, and that it
/// still takes (or refuses) a WPA2 station.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wpa3 {
    Off,
    /// "WPA2/WPA3" as home routers call it: both key managements are
    /// announced, management frame protection is optional.
    Transition,
    /// WPA3 alone: protection required, pre-shared key refused.
    Only,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApEvent {
    Authenticated {
        sta: Mac,
        shared_key: bool,
    },
    AuthRejected {
        sta: Mac,
        status: u16,
    },
    Associated {
        sta: Mac,
    },
    AssocRejected {
        sta: Mac,
        status: u16,
    },
    /// An EAPOL-Key message carried a wrong MIC (wrong passphrase).
    EapolMicFailure {
        sta: Mac,
    },
    /// An EAPOL-Key message did not fit the handshake (stale replay
    /// counter, wrong flags, element differing from the association).
    EapolRejected {
        sta: Mac,
        why: &'static str,
    },
    /// Pairwise keys are in place on both sides.
    HandshakeComplete {
        sta: Mac,
    },
    /// The station acknowledged a group key.
    GroupKeyInstalled {
        sta: Mac,
    },
    /// A new pairwise key is in use, after a handshake on a running link.
    PairwiseKeyRenewed {
        sta: Mac,
    },
    /// The station came back with the key of an earlier password
    /// exchange (PMKSA caching): no SAE this time.
    PmksaCacheUsed {
        sta: Mac,
    },
    /// A protected frame from the station failed to decrypt.
    DecryptFailure {
        sta: Mac,
        error: crypto::CipherError,
    },
    /// A frame arrived with a packet number that was not fresh.
    Replay {
        sta: Mac,
    },
    /// Traffic from a station that has not finished its handshake.
    NotAuthorized {
        sta: Mac,
    },
    /// A frame that had to be encrypted arrived in clear, or the reverse.
    WrongProtection {
        sta: Mac,
    },
    Deauthenticated {
        sta: Mac,
        reason: u16,
        by_ap: bool,
    },
    /// The WPA3 password exchange succeeded.
    SaeComplete {
        sta: Mac,
        hash_to_element: bool,
    },
    /// A WPA3 commit or confirm was refused (wrong password, bad values).
    SaeRejected {
        sta: Mac,
        why: &'static str,
    },
    /// An unprotected deauthentication or disassociation arrived for a
    /// station that protects its management frames; it was ignored.
    UnprotectedDeauthIgnored {
        sta: Mac,
    },
    /// Too many password exchanges were open: the commit was answered
    /// with an anti-clogging token to send back (status 76).
    SaeTokenRequested {
        sta: Mac,
    },
    /// A commit carried a token this access point never gave out; it
    /// was dropped without an answer.
    SaeTokenRejected {
        sta: Mac,
    },
    /// A station protecting its management frames asked to associate
    /// again while its association still stood: refused for now
    /// (status 30) and the station that holds the keys is asked
    /// whether it is still there.
    SaQueryStarted {
        sta: Mac,
    },
    /// The station answered the query, keys and all: it is alive, the
    /// association it holds stays.
    SaQueryAnswered {
        sta: Mac,
    },
    /// Nobody answered within the limit: the next association attempt
    /// is let in.
    SaQueryTimedOut {
        sta: Mac,
    },
    /// A robust action frame arrived in clear from a station that
    /// protects its management frames; it was dropped.
    UnprotectedActionDropped {
        sta: Mac,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Authenticated,
    Associated,
    /// Message 1 sent, waiting for message 2.
    Msg2,
    /// Message 3 sent, waiting for message 4.
    Msg4,
    /// Group message sent after the 4-way handshake (WPA), waiting.
    Group,
    Authorized,
}

struct Station {
    phase: Phase,
    /// The WPA or RSN element of the association request.
    element: Vec<u8>,
    anonce: [u8; 32],
    /// KCK, KEK, TK, then the two Michael keys.
    ptk: [u8; 64],
    keys_installed: bool,
    tx_pn: u64,
    rx_pn: u64,
    rx_started: bool,
    /// Replay counter of the last EAPOL-Key frame sent to this station,
    /// and of the first transmission of that message: a retransmission
    /// takes the next counter (as hostapd), and an answer to any of them
    /// is taken.
    replay: u64,
    replay_first: u64,
    last_eapol: Vec<u8>,
    retries: u32,
    retry_at: u64,
    challenge: Vec<u8>,
    rekeying: bool,
    /// WPA3 exchange in progress, then the key it produced.
    sae: Option<sae::Session>,
    sae_key: Option<([u8; 32], [u8; 16])>,
    /// Key management of the association: 2 pre-shared key, 8 SAE.
    akm: u8,
    /// Management frames are protected on this link.
    pmf: bool,
    /// The password exchange in progress chose hash-to-element.
    sae_h2e: bool,
    /// The station's last commit: the same one again is a
    /// retransmission (it missed our answer), not a new exchange.
    sae_peer: Vec<u8>,
    /// Last packet number of a protected management frame from the
    /// station: a counter of its own, apart from data frames.
    rx_mgmt_pn: u64,
    /// SA Query procedure: transaction identifiers sent so far, when
    /// the first went out, when the next is due.
    sa_query: Vec<[u8; 2]>,
    sa_query_start: u64,
    sa_query_next: u64,
    sa_query_timed_out: bool,
    /// A handshake on a running link: the new keys, once message 2
    /// came, and whether message 4 is awaited.
    rekey: Option<Rekey>,
}

#[derive(Clone, Copy)]
struct Rekey {
    next_ptk: Option<[u8; 64]>,
}

pub struct AccessPoint {
    pub ssid: String,
    pub bssid: Mac,
    pub channel: u8,
    pub security: Security,
    /// Milliseconds between beacons.
    pub beacon_interval: u64,
    /// What a WPA2 network says about WPA3 (see [`Wpa3`]).
    pub wpa3: Wpa3,
    /// When set, beacons carry an empty network name and only probes
    /// naming the network are answered.
    pub hidden: bool,
    /// The raw RSSI byte the stick reports for this network's frames
    /// (the firmwares take 0x79 off for dBm).
    pub rssi: u8,
    pub events: Vec<ApEvent>,
    /// Ethernet frames from authorised stations.
    pub uplink: VecDeque<Vec<u8>>,
    /// Probe requests answered so far.
    pub probes_answered: u32,
    /// Probe requests left unanswered because they had no SSID element.
    pub probes_ignored: u32,
    /// Only take WPA3 stations that derive the password element by
    /// hashing to the curve.
    pub require_h2e: bool,
    /// Say in the beacons that hash-to-element is understood (the RSN
    /// extension element); off, a station hunts and pecks.
    pub offer_h2e: bool,
    /// Open password exchanges from which a new commit has to come
    /// back with an anti-clogging token; 0 demands one every time.
    /// hostapd's default is 5.
    pub anti_clogging_threshold: usize,
    /// How long, in time units of 1024 µs, a station that may have lost
    /// its keys is given to answer an SA Query, and how often it is
    /// asked (hostapd's `assoc_sa_query_max_timeout` and
    /// `assoc_sa_query_retry_timeout`).
    pub sa_query_max_tu: u64,
    pub sa_query_retry_tu: u64,
    /// Messages 4 to lose, as if they never arrived: the access point
    /// sends message 3 again, in clear (it holds no key yet).
    pub lose_message_4: u32,
    /// When set, beacons and probe responses carry these elements in
    /// place of the security elements of `security`: an offer to be
    /// scanned, not joined.
    pub announced: Option<Vec<u8>>,
    psk: [u8; 32],
    comeback_key: [u8; 32],
    igtk_index: u8,
    /// Packet number of the last frame protected with the integrity
    /// group key.
    ipn: u64,
    passphrase: String,
    igtk: [u8; 16],
    gtk: [u8; 32],
    gtk_index: u8,
    group_pn: u64,
    stations: BTreeMap<Mac, Station>,
    /// Keys of past password exchanges, by station: what PMKSA caching
    /// lets a station associate with again, without SAE.
    pmksa: BTreeMap<Mac, ([u8; 32], [u8; 16])>,
    rng: u64,
    seq: u16,
    heard: usize,
    next_beacon: u64,
    now: u64,
}

const MGMT_ASSOC_REQ: u8 = 0x00;
const MGMT_ASSOC_RESP: u8 = 0x10;
const MGMT_REASSOC_REQ: u8 = 0x20;
const MGMT_REASSOC_RESP: u8 = 0x30;
const MGMT_PROBE_REQ: u8 = 0x40;
const MGMT_PROBE_RESP: u8 = 0x50;
const MGMT_BEACON: u8 = 0x80;
const MGMT_DISASSOC: u8 = 0xA0;
const MGMT_AUTH: u8 = 0xB0;
const MGMT_DEAUTH: u8 = 0xC0;
const MGMT_ACTION: u8 = 0xD0;

const LLC_SNAP: [u8; 6] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];
const ETHERTYPE_EAPOL: u16 = 0x888E;

const KEY_INFO_PAIRWISE: u16 = 0x0008;
const KEY_INFO_INSTALL: u16 = 0x0040;
const KEY_INFO_ACK: u16 = 0x0080;
const KEY_INFO_MIC: u16 = 0x0100;
const KEY_INFO_SECURE: u16 = 0x0200;
const KEY_INFO_ENCRYPTED: u16 = 0x1000;

/// Handshake message retransmissions before giving up on a station.
const EAPOL_RETRIES: u32 = 3;
const EAPOL_RETRY_MS: u64 = 1000;

/// Body of the first information element with this id.
pub fn element(mut ies: &[u8], id: u8) -> Option<&[u8]> {
    while let [eid, len, rest @ ..] = ies {
        let body = rest.get(..*len as usize)?;
        if *eid == id {
            return Some(body);
        }
        ies = &rest[*len as usize..];
    }
    None
}

/// The whole WPA (vendor) or RSN element in a list, header included.
fn security_element(mut ies: &[u8], wpa2: bool) -> Option<&[u8]> {
    while let [eid, len, rest @ ..] = ies {
        let total = 2 + *len as usize;
        let body = rest.get(..*len as usize)?;
        let hit = if wpa2 {
            *eid == 48
        } else {
            *eid == 221 && body.starts_with(&[0x00, 0x50, 0xF2, 0x01])
        };
        if hit {
            return Some(&ies[..total]);
        }
        ies = &ies[total..];
    }
    None
}

fn suite(cipher: Cipher) -> u8 {
    match cipher {
        Cipher::Wep => 1,
        Cipher::Tkip => 2,
        Cipher::Ccmp => 4,
    }
}

/// The two IV words of a protected frame for packet number `pn`.
fn iv_words(cipher: Cipher, pn: u64, key_id: u8) -> (u32, u32) {
    let ctl = (key_id as u32) << 30;
    match cipher {
        Cipher::Wep => ((pn as u32 & 0x00FF_FFFF) | ctl, 0),
        Cipher::Tkip => {
            let (lo, hi) = (pn as u32 & 0xFF, (pn >> 8) as u32 & 0xFF);
            (
                hi | ((hi | 0x20) & 0x7F) << 8 | lo << 16 | ctl | 0x2000_0000,
                (pn >> 16) as u32,
            )
        }
        Cipher::Ccmp => ((pn as u32 & 0xFFFF) | ctl | 0x2000_0000, (pn >> 16) as u32),
    }
}

/// Packet number carried by the IV words of a received frame.
fn pn_of(cipher: Cipher, iv: u32, eiv: u32) -> u64 {
    match cipher {
        Cipher::Wep => 0,
        Cipher::Tkip => (eiv as u64) << 16 | ((iv & 0xFF) as u64) << 8 | ((iv >> 16) & 0xFF) as u64,
        Cipher::Ccmp => (eiv as u64) << 16 | (iv & 0xFFFF) as u64,
    }
}

/// A MAC header from `a1`, `a2` and `a3`, numbered with the next value
/// of `seq`.
pub(crate) fn mac_header(fc0: u8, fc1: u8, a1: Mac, a2: Mac, a3: Mac, seq: &mut u16) -> Vec<u8> {
    let mut f = vec![fc0, fc1, 0, 0];
    f.extend_from_slice(&a1);
    f.extend_from_slice(&a2);
    f.extend_from_slice(&a3);
    f.extend_from_slice(&(*seq << 4).to_le_bytes());
    *seq = (*seq + 1) & 0xFFF;
    f
}

/// Bytes from a xorshift generator. The emulated ends draw their nonces
/// from one seeded by their address, so that runs repeat.
pub(crate) fn random_bytes<const N: usize>(rng: &mut u64) -> [u8; N] {
    std::array::from_fn(|_| {
        *rng ^= *rng << 13;
        *rng ^= *rng >> 7;
        *rng ^= *rng << 17;
        (*rng >> 24) as u8
    })
}

/// A unicast frame sealed with CCMP under the temporal key of `ptk`,
/// at key index 0, its packet number counted up first.
pub(crate) fn seal_ccmp(ptk: &[u8], pn: &mut u64, frame: &[u8]) -> Vec<u8> {
    *pn += 1;
    let (iv, eiv) = iv_words(Cipher::Ccmp, *pn, 0);
    let key = Key {
        cipher: Cipher::Ccmp,
        key: &ptk[32..48],
        mic: &[0; 8],
    };
    crypto::protect(&key, frame, iv, eiv)
}

/// The key data of an EAPOL-Key frame at least 99 bytes long, `None`
/// if its length runs past the frame.
pub(crate) fn eapol_key_data(eapol: &[u8]) -> Option<&[u8]> {
    let data_len = u16::from_be_bytes([eapol[97], eapol[98]]) as usize;
    eapol.get(99..99 + data_len)
}

impl AccessPoint {
    pub fn new(ssid: &str, bssid: Mac, channel: u8, security: Security) -> Self {
        let psk = match &security {
            Security::Psk { passphrase, .. } => crypto::wpa_psk(passphrase, ssid),
            _ => [0; 32],
        };
        let mut ap = AccessPoint {
            ssid: ssid.to_string(),
            bssid,
            channel,
            security,
            beacon_interval: 100,
            announced: None,
            hidden: false,
            rssi: DEFAULT_RSSI,
            wpa3: Wpa3::Off,
            events: Vec::new(),
            uplink: VecDeque::new(),
            probes_answered: 0,
            probes_ignored: 0,
            require_h2e: false,
            offer_h2e: true,
            anti_clogging_threshold: 5,
            sa_query_max_tu: 1000,
            sa_query_retry_tu: 201,
            lose_message_4: 0,
            psk,
            comeback_key: [0; 32],
            igtk_index: 4,
            ipn: 0,
            passphrase: String::new(),
            igtk: [0; 16],
            gtk: [0; 32],
            gtk_index: 1,
            group_pn: 0,
            stations: BTreeMap::new(),
            pmksa: BTreeMap::new(),
            rng: u64::from_le_bytes([
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], 0x5A, 0xA5,
            ]) | 1,
            seq: 0,
            heard: 0,
            next_beacon: 0,
            now: 0,
        };
        ap.gtk = ap.random();
        ap.igtk = ap.random();
        ap.comeback_key = ap.random();
        if let Security::Psk { passphrase, .. } = &ap.security {
            ap.passphrase = passphrase.clone();
        }
        ap
    }

    fn random<const N: usize>(&mut self) -> [u8; N] {
        random_bytes(&mut self.rng)
    }

    /// Whether this station completed everything the network demands.
    pub fn is_authorized(&self, sta: Mac) -> bool {
        self.stations
            .get(&sta)
            .is_some_and(|s| s.phase == Phase::Authorized)
    }

    fn psk_params(&self) -> Option<(bool, Cipher, Cipher)> {
        match &self.security {
            Security::Psk {
                wpa2,
                pairwise,
                group,
                ..
            } => Some((*wpa2, *pairwise, *group)),
            _ => None,
        }
    }

    /// The WPA or RSN element this network advertises.
    fn own_element(&self) -> Vec<u8> {
        let Some((wpa2, pairwise, group)) = self.psk_params() else {
            return Vec::new();
        };
        let (g, p) = (suite(group), suite(pairwise));
        if wpa2 {
            let akms: &[u8] = match self.wpa3 {
                Wpa3::Off => &[2],
                Wpa3::Transition => &[2, 8],
                Wpa3::Only => &[8],
            };
            // Management frame protection: capable in transition mode,
            // required when only WPA3 is offered.
            let capabilities: u16 = match self.wpa3 {
                Wpa3::Off => 0,
                Wpa3::Transition => 0x0080,
                Wpa3::Only => 0x00C0,
            };
            let mut e = vec![48, 0, 1, 0, 0x00, 0x0F, 0xAC, g, 1, 0, 0x00, 0x0F, 0xAC, p];
            e.extend_from_slice(&[akms.len() as u8, 0]);
            for akm in akms {
                e.extend_from_slice(&[0x00, 0x0F, 0xAC, *akm]);
            }
            e.extend_from_slice(&capabilities.to_le_bytes());
            e[1] = e.len() as u8 - 2;
            e
        } else {
            let o = [0x00, 0x50, 0xF2];
            let mut e = vec![221, 22, o[0], o[1], o[2], 1, 1, 0];
            e.extend_from_slice(&[
                o[0], o[1], o[2], g, 1, 0, o[0], o[1], o[2], p, 1, 0, o[0], o[1], o[2], 2,
            ]);
            e
        }
    }

    /// The RSN extension element: says hash-to-element is understood.
    fn own_extension(&self) -> Vec<u8> {
        if !self.offer_h2e
            || self.wpa3 == Wpa3::Off
            || self.psk_params().is_none_or(|(wpa2, ..)| !wpa2)
        {
            Vec::new()
        } else {
            vec![244, 1, 0x20]
        }
    }

    fn header(&mut self, fc0: u8, fc1: u8, a1: Mac, a2: Mac, a3: Mac) -> Vec<u8> {
        mac_header(fc0, fc1, a1, a2, a3, &mut self.seq)
    }

    fn mgmt(&mut self, subtype: u8, to: Mac) -> Vec<u8> {
        self.header(subtype, 0, to, self.bssid, self.bssid)
    }

    fn capabilities(&self) -> u16 {
        // ESS, short slot time, privacy unless open.
        0x0401
            | if self.security == Security::Open {
                0
            } else {
                0x0010
            }
    }

    /// Supported rates: 1, 2, 5.5, 11 (basic), 6, 9, 12, 18 Mbit/s.
    const RATES: [u8; 10] = [1, 8, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24];

    /// A beacon or probe response.
    fn announce(&mut self, subtype: u8, to: Mac) -> Vec<u8> {
        let mut f = self.mgmt(subtype, to);
        f.extend_from_slice(&(self.now * 1000).to_le_bytes());
        f.extend_from_slice(&(self.beacon_interval as u16).to_le_bytes());
        f.extend_from_slice(&self.capabilities().to_le_bytes());
        let name: &[u8] = if self.hidden && subtype == MGMT_BEACON {
            &[]
        } else {
            self.ssid.as_bytes()
        };
        f.push(0);
        f.push(name.len() as u8);
        f.extend_from_slice(name);
        f.extend_from_slice(&Self::RATES);
        f.extend_from_slice(&[3, 1, self.channel]);
        match &self.announced {
            Some(elements) => f.extend_from_slice(elements),
            None => {
                f.extend_from_slice(&self.own_element());
                f.extend_from_slice(&self.own_extension());
            }
        }
        f
    }

    fn emit(&self, radio: &mut Radio, frame: Vec<u8>) {
        if radio.channel == self.channel {
            radio.rx.push_back(RxFrame {
                data: frame,
                rssi: self.rssi,
            });
        }
    }

    fn deauth(&mut self, radio: &mut Radio, sta: Mac, reason: u16) {
        // A station that protects its management frames only believes
        // a deauthentication encrypted with its pairwise key.
        self.send_management(radio, MGMT_DEAUTH, sta, &reason.to_le_bytes());
        self.stations.remove(&sta);
        self.events.push(ApEvent::Deauthenticated {
            sta,
            reason,
            by_ap: true,
        });
    }

    /// Lose power and come back: every station forgotten, with its keys
    /// and cached exchanges, and nobody told; new group keys. A station
    /// that goes on talking gets the answer hostapd gives frames from
    /// strangers: a deauthentication, reason 7, in clear.
    pub fn power_cut(&mut self) {
        self.stations.clear();
        self.pmksa.clear();
        self.gtk = self.random();
        self.igtk = self.random();
        self.group_pn = 0;
        self.ipn = 0;
    }

    /// Throw a station out, as an access point does when it restarts or
    /// an administrator kicks a client.
    pub fn kick(&mut self, radio: &mut Radio, sta: Mac, reason: u16) {
        self.deauth(radio, sta, reason);
    }

    /// Live for a moment: handle what was heard, retransmit, beacon.
    pub fn poll(&mut self, radio: &mut Radio, now_ms: u64) {
        self.now = now_ms;
        let fresh: Vec<Vec<u8>> = radio
            .tx
            .iter()
            .skip(self.heard)
            .filter(|f| f.channel == self.channel && f.data.len() >= crypto::HEADER_LEN)
            .map(|f| f.data.clone())
            .collect();
        self.heard = radio.tx.len();
        for frame in fresh {
            match frame[0] & 0x0C {
                0x00 => self.on_management(radio, &frame),
                0x08 if frame[4..10] == self.bssid && frame[1] & 3 == 1 => {
                    self.on_data(radio, &frame)
                }
                _ => {}
            }
        }

        // SA Query: a new request at every retry interval until the
        // procedure times out (hostapd's `ap_sa_query_timer`).
        let querying: Vec<Mac> = self
            .stations
            .iter()
            .filter(|(_, s)| s.sa_query_next != 0 && now_ms >= s.sa_query_next)
            .map(|(m, _)| *m)
            .collect();
        for sta in querying {
            if !self.sa_query_timeout(sta) {
                self.sa_query_round(radio, sta);
            }
        }

        let due: Vec<Mac> = self
            .stations
            .iter()
            .filter(|(_, s)| s.retry_at != 0 && now_ms >= s.retry_at)
            .map(|(m, _)| *m)
            .collect();
        for sta in due {
            let s = self.stations.get_mut(&sta).unwrap();
            if s.retries >= EAPOL_RETRIES {
                // Reason 15: 4-way handshake timeout.
                self.deauth(radio, sta, 15);
            } else {
                s.retries += 1;
                s.retry_at = now_ms + EAPOL_RETRY_MS;
                // The same message under the next replay counter, signed
                // again.
                s.replay += 1;
                let mut again = s.last_eapol.clone();
                again[9..17].copy_from_slice(&s.replay.to_be_bytes());
                let info = u16::from_be_bytes([again[5], again[6]]);
                if info & KEY_INFO_MIC != 0 {
                    let ptk = s.rekey.and_then(|r| r.next_ptk).unwrap_or(s.ptk);
                    again[81..97].fill(0);
                    let mic = Self::eapol_mic(info & 7, &ptk[..16], &again);
                    again[81..97].copy_from_slice(&mic);
                }
                s.last_eapol = again.clone();
                self.send_eapol_raw(radio, sta, &again);
            }
        }

        if now_ms >= self.next_beacon {
            self.next_beacon = now_ms + self.beacon_interval;
            let frame = self.announce(MGMT_BEACON, [0xFF; 6]);
            self.emit(radio, frame);
        }
    }

    fn on_management(&mut self, radio: &mut Radio, frame: &[u8]) {
        let sta: Mac = frame[10..16].try_into().unwrap();
        let body = &frame[crypto::HEADER_LEN..];
        let subtype = frame[0];
        if subtype == MGMT_PROBE_REQ {
            // Like hostapd, only answer probes that carry an SSID element:
            // empty for "anyone", or naming us.
            match element(body, 0) {
                Some(wanted)
                    if wanted == self.ssid.as_bytes() || (wanted.is_empty() && !self.hidden) =>
                {
                    let f = self.announce(MGMT_PROBE_RESP, sta);
                    self.emit(radio, f);
                    self.probes_answered += 1;
                }
                Some(_) => {}
                None => self.probes_ignored += 1,
            }
            return;
        }
        if frame[4..10] != self.bssid {
            return;
        }
        match subtype {
            MGMT_AUTH => self.on_auth(radio, sta, frame),
            MGMT_ASSOC_REQ | MGMT_REASSOC_REQ => self.on_assoc(radio, sta, subtype, body),
            MGMT_DEAUTH | MGMT_DISASSOC => self.on_leave(sta, frame),
            MGMT_ACTION => self.on_action(radio, sta, frame),
            _ => {}
        }
    }

    /// A deauthentication or disassociation from a station.
    fn on_leave(&mut self, sta: Mac, frame: &[u8]) {
        let Some(station) = self.stations.get_mut(&sta) else {
            return;
        };
        let mut body = frame[crypto::HEADER_LEN..].to_vec();
        if station.pmf && station.keys_installed {
            // Anyone can forge the clear version: only the encrypted
            // one counts.
            if frame[1] & 0x40 == 0 {
                self.events.push(ApEvent::UnprotectedDeauthIgnored { sta });
                return;
            }
            let Some(clear) = self.open_management(sta, frame) else {
                return;
            };
            body = clear[crypto::HEADER_LEN..].to_vec();
        }
        self.stations.remove(&sta);
        let reason = body
            .get(..2)
            .map_or(0, |r| u16::from_le_bytes([r[0], r[1]]));
        self.events.push(ApEvent::Deauthenticated {
            sta,
            reason,
            by_ap: false,
        });
    }

    /// A frame of the WPA3 password exchange (authentication algorithm 3).
    fn on_sae(&mut self, radio: &mut Radio, sta: Mac, seq: u16, status: u16, rest: &[u8]) {
        let wpa2 = self.psk_params().is_some_and(|(wpa2, ..)| wpa2);
        if !wpa2 || self.wpa3 == Wpa3::Off {
            self.reply_auth(radio, sta, 3, seq, 13, &[]);
            self.events.push(ApEvent::AuthRejected { sta, status: 13 });
            return;
        }
        match seq {
            1 => {
                // Status 126 announces the hash-to-element method.
                let h2e = status == 126;
                if status != 0 && !h2e {
                    return;
                }
                if self.require_h2e && !h2e {
                    self.reply_auth(radio, sta, 3, 1, 1, &[]);
                    return self.events.push(ApEvent::SaeRejected {
                        sta,
                        why: "hash-to-element is required",
                    });
                }
                // The anti-clogging token: in a container element after
                // the element when hashing to the curve, between the
                // group and the scalar otherwise.
                let (commit, token) = if h2e {
                    let token = rest.get(98..).and_then(|ies| {
                        let mut ies = ies;
                        while let [255, len, rest @ ..] = ies {
                            let body = rest.get(..*len as usize)?;
                            if body.first() == Some(&93) {
                                return Some(body[1..].to_vec());
                            }
                            ies = &rest[*len as usize..];
                        }
                        None
                    });
                    (rest.to_vec(), token)
                } else if rest.len() >= 98 + 32 {
                    let split = rest.len() - 96;
                    let mut commit = rest[..2].to_vec();
                    commit.extend_from_slice(&rest[split..]);
                    (commit, Some(rest[2..split].to_vec()))
                } else {
                    (rest.to_vec(), None)
                };
                if let Some(s) = self.stations.get(&sta).filter(|s| s.sae_peer == commit) {
                    // As hostapd: our own commit again while the
                    // exchange is open, nothing once it is through.
                    if let Some(session) = &s.sae {
                        let ours = session.commit().to_bytes();
                        self.reply_auth(radio, sta, 3, 1, status, &ours);
                    }
                    return;
                }
                let Some(theirs) = sae::Commit::from_bytes(&commit) else {
                    // Status 77: unsupported finite cyclic group.
                    self.reply_auth(radio, sta, 3, 1, 77, &[]);
                    return self.events.push(ApEvent::SaeRejected {
                        sta,
                        why: "not a group 19 commit",
                    });
                };
                if token
                    .as_ref()
                    .is_some_and(|t| *t != self.comeback_token(sta))
                {
                    return self.events.push(ApEvent::SaeTokenRejected { sta });
                }
                // A station already in the middle of an exchange may
                // start it again without a token, as hostapd lets it.
                let restarting = self.stations.get(&sta).is_some_and(|s| s.sae.is_some());
                if token.is_none() && !restarting && self.needs_anti_clogging() {
                    let mut body = sae::GROUP.to_le_bytes().to_vec();
                    let token = self.comeback_token(sta);
                    if h2e {
                        body.extend_from_slice(&[255, 1 + token.len() as u8, 93]);
                    }
                    body.extend_from_slice(&token);
                    self.reply_auth(radio, sta, 3, 1, 76, &body);
                    return self.events.push(ApEvent::SaeTokenRequested { sta });
                }
                let element = if h2e {
                    let point =
                        sae::password_point(self.ssid.as_bytes(), self.passphrase.as_bytes(), None);
                    sae::password_element_from_point(&point, &self.bssid, &sta)
                } else {
                    sae::password_element_looping(&self.bssid, &sta, self.passphrase.as_bytes())
                };
                let (rand, mask) = (self.random(), self.random());
                let mut session = sae::Session::new(element, &rand, &mask);
                if session.process_commit(&theirs).is_err() {
                    return self.events.push(ApEvent::SaeRejected {
                        sta,
                        why: "commit values out of range",
                    });
                }
                let ours = session.commit().to_bytes();
                // A station whose management frames are protected keeps
                // its association and keys while it authenticates again:
                // a clear authentication frame must not be enough to
                // throw it out.
                let keep = self
                    .stations
                    .get(&sta)
                    .is_some_and(|s| s.pmf && s.phase == Phase::Authorized);
                if !keep {
                    self.stations.insert(sta, Self::new_station());
                }
                let s = self.stations.get_mut(&sta).unwrap();
                s.sae = Some(session);
                s.sae_h2e = h2e;
                s.sae_peer = commit;
                self.reply_auth(radio, sta, 3, 1, status, &ours);
            }
            2 => {
                let Some(s) = self.stations.get_mut(&sta) else {
                    return;
                };
                let Some(session) = &s.sae else { return };
                let (Some(counter), Some(value)) = (rest.get(..2), rest.get(2..34)) else {
                    return;
                };
                let counter = u16::from_le_bytes([counter[0], counter[1]]);
                if !session.check_confirm(counter, value) {
                    // Wrong password: nothing is said, the station times out.
                    self.stations.remove(&sta);
                    return self.events.push(ApEvent::SaeRejected {
                        sta,
                        why: "confirm does not match",
                    });
                }
                let mut reply = 1u16.to_le_bytes().to_vec();
                reply.extend_from_slice(&session.confirm(1));
                s.sae_key = Some((session.pmk, session.pmkid));
                self.pmksa.insert(sta, (session.pmk, session.pmkid));
                let s = self.stations.get_mut(&sta).unwrap();
                let hash_to_element = s.sae_h2e;
                s.sae = None;
                self.reply_auth(radio, sta, 3, 2, 0, &reply);
                self.events.push(ApEvent::SaeComplete {
                    sta,
                    hash_to_element,
                });
            }
            _ => {}
        }
    }

    /// The token a station has to send back when the access point is
    /// under load: only this access point can make it, and it is bound
    /// to the station's address.
    fn comeback_token(&self, sta: Mac) -> Vec<u8> {
        crypto::hmac_sha256(&self.comeback_key, &[&sta]).to_vec()
    }

    /// Whether a new commit has to come back with a token: as hostapd,
    /// once as many exchanges are open as the threshold says.
    fn needs_anti_clogging(&self) -> bool {
        let open = self.stations.values().filter(|s| s.sae.is_some()).count();
        open >= self.anti_clogging_threshold
    }

    /// The station holds an association whose management frames are
    /// protected: nothing sent in clear may undo it.
    fn holds_protected_association(&self, sta: Mac) -> bool {
        self.stations
            .get(&sta)
            .is_some_and(|s| s.pmf && s.keys_installed && s.phase == Phase::Authorized)
    }

    fn tu_to_ms(tu: u64) -> u64 {
        tu * 1024 / 1000
    }

    /// hostapd's `check_sa_query`: for a station holding a protected
    /// association, start the SA Query procedure unless it is running,
    /// and say in how many time units to come back; `None` once the
    /// procedure timed out, which lets the association through.
    fn check_sa_query(&mut self, radio: &mut Radio, sta: Mac) -> Option<u64> {
        if !self.holds_protected_association(sta) {
            return None;
        }
        self.sa_query_timeout(sta);
        let s = &self.stations[&sta];
        if s.sa_query_timed_out {
            return None;
        }
        if s.sa_query.is_empty() {
            self.events.push(ApEvent::SaQueryStarted { sta });
            self.sa_query_round(radio, sta);
        }
        let s = &self.stations[&sta];
        let passed = (self.now - s.sa_query_start) * 1000 / 1024;
        let mut tu = self.sa_query_max_tu.saturating_sub(passed);
        if tu < self.sa_query_max_tu {
            // hostapd adds a unit for its own timers.
            tu += 1;
        }
        Some(tu)
    }

    /// End the procedure if its time is up. True when it ended.
    fn sa_query_timeout(&mut self, sta: Mac) -> bool {
        let max = self.sa_query_max_tu;
        let now = self.now;
        let Some(s) = self.stations.get_mut(&sta) else {
            return false;
        };
        if s.sa_query.is_empty() || (now - s.sa_query_start) * 1000 / 1024 <= max {
            return false;
        }
        s.sa_query.clear();
        s.sa_query_next = 0;
        s.sa_query_timed_out = true;
        self.events.push(ApEvent::SaQueryTimedOut { sta });
        true
    }

    /// One SA Query request, protected with the station's pairwise key,
    /// with a fresh transaction identifier.
    fn sa_query_round(&mut self, radio: &mut Radio, sta: Mac) {
        let id: [u8; 2] = self.random();
        let (now, retry) = (self.now, Self::tu_to_ms(self.sa_query_retry_tu));
        let s = self.stations.get_mut(&sta).unwrap();
        if s.sa_query.is_empty() {
            s.sa_query_start = now;
        }
        s.sa_query.push(id);
        s.sa_query_next = now + retry.max(1);
        // Category 8 (SA Query), action 0 (request).
        self.send_management(radio, MGMT_ACTION, sta, &[8, 0, id[0], id[1]]);
    }

    /// A management frame to a station, protected when its management
    /// frames are.
    fn send_management(&mut self, radio: &mut Radio, subtype: u8, sta: Mac, body: &[u8]) {
        let mut f = self.mgmt(subtype, sta);
        f.extend_from_slice(body);
        if let Some(s) = self
            .stations
            .get_mut(&sta)
            .filter(|s| s.pmf && s.keys_installed)
        {
            f = seal_ccmp(&s.ptk, &mut s.tx_pn, &f);
        }
        self.emit(radio, f);
    }

    /// A protected management frame from a station: its clear version,
    /// or why it is refused. Its packet number is checked against the
    /// counter kept for management frames.
    fn open_management(&mut self, sta: Mac, frame: &[u8]) -> Option<Vec<u8>> {
        let station = self.stations.get_mut(&sta)?;
        let key = Key {
            cipher: Cipher::Ccmp,
            key: &station.ptk[32..48],
            mic: &[0; 8],
        };
        match crypto::unprotect(&key, frame) {
            Ok((clear, iv, eiv)) if pn_of(Cipher::Ccmp, iv, eiv) > station.rx_mgmt_pn => {
                station.rx_mgmt_pn = pn_of(Cipher::Ccmp, iv, eiv);
                Some(clear)
            }
            Ok(_) => {
                self.events.push(ApEvent::Replay { sta });
                None
            }
            Err(error) => {
                self.events.push(ApEvent::DecryptFailure { sta, error });
                None
            }
        }
    }

    /// An action frame from a station.
    fn on_action(&mut self, radio: &mut Radio, sta: Mac, frame: &[u8]) {
        let associated = self
            .stations
            .get(&sta)
            .is_some_and(|s| s.phase != Phase::Authenticated);
        let Some(&category) = frame.get(crypto::HEADER_LEN) else {
            return;
        };
        let category = if frame[1] & 0x40 != 0 {
            None
        } else {
            Some(category)
        };
        // Public action frames (category 4) are for anyone; the others
        // only from associated stations.
        if !associated && category != Some(4) {
            return;
        }
        let protects = self
            .stations
            .get(&sta)
            .is_some_and(|s| s.pmf && s.keys_installed);
        let body = if frame[1] & 0x40 != 0 {
            if !protects {
                return;
            }
            let Some(clear) = self.open_management(sta, frame) else {
                return;
            };
            clear[crypto::HEADER_LEN..].to_vec()
        } else {
            // Robust action frames have to be protected on such a link
            // (all categories but public, HT, unprotected WNM,
            // self-protected, unprotected DMG, VHT and vendor-specific).
            let robust = !matches!(category, Some(4 | 7 | 11 | 15 | 20 | 21 | 127));
            if protects && robust {
                return self.events.push(ApEvent::UnprotectedActionDropped { sta });
            }
            frame[crypto::HEADER_LEN..].to_vec()
        };
        match body[..] {
            [8, 0, a, b, ..] => {
                // Somebody checks that we still hold their association.
                self.send_management(radio, MGMT_ACTION, sta, &[8, 1, a, b]);
            }
            [8, 1, a, b, ..] => {
                let Some(s) = self.stations.get_mut(&sta) else {
                    return;
                };
                if s.sa_query.contains(&[a, b]) {
                    s.sa_query.clear();
                    s.sa_query_next = 0;
                    self.events.push(ApEvent::SaQueryAnswered { sta });
                }
            }
            _ => {}
        }
    }

    fn on_auth(&mut self, radio: &mut Radio, sta: Mac, frame: &[u8]) {
        let wep = match &self.security {
            Security::Wep { key, shared_auth } => Some((key.clone(), *shared_auth)),
            _ => None,
        };
        // The third frame of a shared-key exchange is WEP-encrypted.
        let clear;
        let mut body = &frame[crypto::HEADER_LEN..];
        if frame[1] & 0x40 != 0 {
            let Some((key, _)) = &wep else { return };
            match crypto::unprotect(
                &Key {
                    cipher: Cipher::Wep,
                    key,
                    mic: &[0; 8],
                },
                frame,
            ) {
                Ok((f, _, _)) => {
                    clear = f;
                    body = &clear[crypto::HEADER_LEN..];
                }
                Err(error) => {
                    self.events.push(ApEvent::DecryptFailure { sta, error });
                    self.reply_auth(radio, sta, 1, 4, 15, &[]);
                    self.events.push(ApEvent::AuthRejected { sta, status: 15 });
                    return;
                }
            }
        }
        if body.len() < 6 {
            return;
        }
        let word = |i: usize| u16::from_le_bytes([body[i], body[i + 1]]);
        let (algorithm, seq) = (word(0), word(2));
        if algorithm == 3 {
            return self.on_sae(radio, sta, seq, word(4), &body[6..]);
        }
        let demands_shared = wep.as_ref().is_some_and(|(_, shared)| *shared);
        match (algorithm, seq) {
            (0, 1) if !demands_shared => {
                if !self.holds_protected_association(sta) {
                    self.stations.insert(sta, Self::new_station());
                }
                self.reply_auth(radio, sta, 0, 2, 0, &[]);
                self.events.push(ApEvent::Authenticated {
                    sta,
                    shared_key: false,
                });
            }
            (1, 1) if wep.is_some() => {
                let challenge: [u8; 128] = self.random();
                let mut s = Self::new_station();
                s.challenge = challenge.to_vec();
                self.stations.insert(sta, s);
                let mut ie = vec![16, 128];
                ie.extend_from_slice(&challenge);
                self.reply_auth(radio, sta, 1, 2, 0, &ie);
            }
            (1, 3) if wep.is_some() => {
                let expected = self
                    .stations
                    .get(&sta)
                    .map(|s| s.challenge.clone())
                    .unwrap_or_default();
                let ok = !expected.is_empty() && element(&body[6..], 16) == Some(&expected[..]);
                let status = if ok { 0 } else { 15 };
                self.reply_auth(radio, sta, 1, 4, status, &[]);
                if ok {
                    self.events.push(ApEvent::Authenticated {
                        sta,
                        shared_key: true,
                    });
                } else {
                    self.stations.remove(&sta);
                    self.events.push(ApEvent::AuthRejected { sta, status });
                }
            }
            (_, seq) => {
                // Status 13: authentication algorithm not supported.
                self.reply_auth(radio, sta, algorithm, seq + 1, 13, &[]);
                self.events.push(ApEvent::AuthRejected { sta, status: 13 });
            }
        }
    }

    fn new_station() -> Station {
        Station {
            phase: Phase::Authenticated,
            element: Vec::new(),
            anonce: [0; 32],
            ptk: [0; 64],
            keys_installed: false,
            tx_pn: 0,
            rx_pn: 0,
            rx_started: false,
            replay: 0,
            replay_first: 0,
            last_eapol: Vec::new(),
            retries: 0,
            retry_at: 0,
            challenge: Vec::new(),
            rekeying: false,
            sae: None,
            sae_key: None,
            akm: 2,
            pmf: false,
            sae_h2e: false,
            sae_peer: Vec::new(),
            rx_mgmt_pn: 0,
            sa_query: Vec::new(),
            sa_query_start: 0,
            sa_query_next: 0,
            sa_query_timed_out: false,
            rekey: None,
        }
    }

    fn reply_auth(
        &mut self,
        radio: &mut Radio,
        sta: Mac,
        algorithm: u16,
        seq: u16,
        status: u16,
        ies: &[u8],
    ) {
        let mut f = self.mgmt(MGMT_AUTH, sta);
        for v in [algorithm, seq, status] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(ies);
        self.emit(radio, f);
    }

    /// Judge the WPA or RSN element of an association request: the key
    /// management chosen and whether management frames get protected,
    /// or the status code to refuse with.
    fn judge_element(
        &self,
        element: Option<&[u8]>,
        wpa2: bool,
        pairwise: Cipher,
        group: Cipher,
        did_sae: bool,
    ) -> Result<(u8, bool), u16> {
        // Status 40: invalid element; 41 group cipher, 42 pairwise
        // cipher, 43 key management not valid here; 31 management
        // frame protection policy.
        let Some(element) = element else {
            return Err(40);
        };
        if !wpa2 {
            return if element == self.own_element() {
                Ok((2, false))
            } else {
                Err(40)
            };
        }
        let body = &element[2..];
        let suite_at = |at: usize| {
            body.get(at..at + 4)
                .filter(|s| s[..3] == [0x00, 0x0F, 0xAC])
                .map(|s| s[3])
        };
        if body.len() < 18 || body[..2] != [1, 0] || body[6..8] != [1, 0] || body[12..14] != [1, 0]
        {
            return Err(40);
        }
        if suite_at(2) != Some(suite(group)) {
            return Err(41);
        }
        if suite_at(8) != Some(suite(pairwise)) {
            return Err(42);
        }
        let akm = match suite_at(14) {
            Some(2) if self.wpa3 != Wpa3::Only => 2,
            Some(8) if self.wpa3 != Wpa3::Off && did_sae => 8,
            _ => return Err(43),
        };
        let capabilities = body
            .get(18..20)
            .map_or(0, |c| u16::from_le_bytes([c[0], c[1]]));
        let (capable, required) = (capabilities & 0x80 != 0, capabilities & 0x40 != 0);
        let we_can = self.wpa3 != Wpa3::Off;
        let we_require = self.wpa3 == Wpa3::Only;
        // WPA3 never goes without protection.
        if (required && !we_can) || ((we_require || akm == 8) && !capable) {
            return Err(31);
        }
        Ok((akm, capable && we_can))
    }

    fn on_assoc(&mut self, radio: &mut Radio, sta: Mac, subtype: u8, body: &[u8]) {
        let fixed = if subtype == MGMT_REASSOC_REQ { 10 } else { 4 };
        let Some(ies) = body.get(fixed..) else { return };
        let psk = self.psk_params();
        let wanted = psk.and_then(|(wpa2, ..)| security_element(ies, wpa2));
        let mut chosen = (2u8, false);
        let status: u16 = if !self.stations.contains_key(&sta) {
            // The station skipped authentication: unspecified failure.
            1
        } else if element(ies, 0) != Some(self.ssid.as_bytes()) {
            1
        } else if self.stations[&sta].sae_h2e
            && element(ies, 244).is_none_or(|x| x.first().is_none_or(|b| b & 0x20 == 0))
        {
            // After a hash-to-element exchange the station says so in
            // its RSN extension element (802.11-2020 12.4.2): otherwise
            // a downgrade to hunting and pecking would go unseen.
            40
        } else if let Some((wpa2, pairwise, group)) = psk {
            let mut did_sae = self.stations[&sta].sae_key.is_some();
            // Open authentication then SAE's key management: only with the
            // PMKID of a cached exchange (status 53 otherwise, as hostapd).
            let asks_sae =
                wpa2 && wanted.is_some_and(|e| e.get(16..20) == Some(&[0x00, 0x0F, 0xAC, 8]));
            let mut cache_miss = false;
            if asks_sae && !did_sae && self.wpa3 != Wpa3::Off {
                let pmkid = wanted.and_then(|e| {
                    let body = &e[2..];
                    (body.get(20..22) == Some(&[1, 0]))
                        .then(|| body.get(22..38))
                        .flatten()
                });
                match (self.pmksa.get(&sta), pmkid) {
                    (Some(&(pmk, id)), Some(given)) if given == id => {
                        self.stations.get_mut(&sta).unwrap().sae_key = Some((pmk, id));
                        self.events.push(ApEvent::PmksaCacheUsed { sta });
                        did_sae = true;
                    }
                    _ => cache_miss = true,
                }
            }
            if cache_miss {
                53
            } else {
                match self.judge_element(wanted, wpa2, pairwise, group, did_sae) {
                    Ok(found) => {
                        chosen = found;
                        0
                    }
                    Err(status) => status,
                }
            }
        } else {
            0
        };
        // The association stands while its keys may still be in use:
        // status 30, come back later, and ask the holder of the keys.
        let comeback = if status == 0 {
            self.check_sa_query(radio, sta)
        } else {
            None
        };
        let status = if comeback.is_some() { 30 } else { status };
        let reply = if subtype == MGMT_REASSOC_REQ {
            MGMT_REASSOC_RESP
        } else {
            MGMT_ASSOC_RESP
        };
        let mut f = self.mgmt(reply, sta);
        f.extend_from_slice(&self.capabilities().to_le_bytes());
        f.extend_from_slice(&status.to_le_bytes());
        f.extend_from_slice(&0xC001u16.to_le_bytes());
        f.extend_from_slice(&Self::RATES);
        if let Some(tu) = comeback {
            // Timeout interval element, type 3: association comeback time.
            f.extend_from_slice(&[56, 5, 3]);
            f.extend_from_slice(&(tu as u32).to_le_bytes());
        }
        self.emit(radio, f);
        if status != 0 {
            self.events.push(ApEvent::AssocRejected { sta, status });
            return;
        }
        let element = wanted.map(|e| e.to_vec()).unwrap_or_default();
        let s = self.stations.get_mut(&sta).unwrap();
        let sae_key = s.sae_key;
        *s = Self::new_station();
        s.element = element;
        s.sae_key = sae_key;
        (s.akm, s.pmf) = chosen;
        s.phase = if psk.is_some() {
            Phase::Associated
        } else {
            Phase::Authorized
        };
        self.events.push(ApEvent::Associated { sta });
        if psk.is_some() {
            self.send_message_1(radio, sta);
        }
    }

    // ---- data path ----------------------------------------------------

    fn on_data(&mut self, radio: &mut Radio, frame: &[u8]) {
        let sta: Mac = frame[10..16].try_into().unwrap();
        let Some(station) = self.stations.get(&sta) else {
            // Reason 7: class 3 frame from a station that is not associated.
            return self.deauth(radio, sta, 7);
        };
        if station.phase == Phase::Authenticated {
            return self.deauth(radio, sta, 7);
        }
        if frame[0] & 0x40 != 0 {
            // Null function frames carry nothing.
            return;
        }
        let protected = frame[1] & 0x40 != 0;
        let clear;
        let mut body = &frame[crypto::HEADER_LEN..];
        if protected {
            let unprotected = match &self.security {
                Security::Open => {
                    self.events.push(ApEvent::WrongProtection { sta });
                    return;
                }
                Security::Wep { key, .. } => crypto::unprotect(
                    &Key {
                        cipher: Cipher::Wep,
                        key,
                        mic: &[0; 8],
                    },
                    frame,
                ),
                Security::Psk { pairwise, .. } => {
                    let mic: [u8; 8] = station.ptk[56..64].try_into().unwrap();
                    crypto::unprotect(
                        &Key {
                            cipher: *pairwise,
                            key: &station.ptk[32..48],
                            mic: &mic,
                        },
                        frame,
                    )
                }
            };
            match unprotected {
                Ok((f, iv, eiv)) => {
                    if let Some((_, pairwise, _)) = self.psk_params() {
                        let pn = pn_of(pairwise, iv, eiv);
                        let station = self.stations.get_mut(&sta).unwrap();
                        // As Linux access points do: a CCMP counter must
                        // exceed the last one, starting from 0, while the
                        // first TKIP frame is taken whatever its counter.
                        let first_tkip = pairwise == Cipher::Tkip && !station.rx_started;
                        if pn <= station.rx_pn && !first_tkip {
                            self.events.push(ApEvent::Replay { sta });
                            return;
                        }
                        station.rx_pn = pn;
                        station.rx_started = true;
                    }
                    clear = f;
                    body = &clear[crypto::HEADER_LEN..];
                }
                Err(error) => {
                    self.events.push(ApEvent::DecryptFailure { sta, error });
                    return;
                }
            }
        }
        if body.len() < 8 || body[..6] != LLC_SNAP {
            return;
        }
        let ethertype = u16::from_be_bytes([body[6], body[7]]);
        let payload = &body[8..];
        if ethertype == ETHERTYPE_EAPOL {
            return self.on_eapol(radio, sta, payload);
        }
        let station = &self.stations[&sta];
        let must_protect = self.security != Security::Open;
        // As hostapd: the port opens with the pairwise keys, at the end
        // of the 4-way handshake; with WPA the group key handshake that
        // follows does not hold traffic back.
        if !matches!(station.phase, Phase::Authorized | Phase::Group) {
            self.events.push(ApEvent::NotAuthorized { sta });
            return;
        }
        if protected != must_protect {
            self.events.push(ApEvent::WrongProtection { sta });
            return;
        }
        let mut eth = frame[16..22].to_vec();
        eth.extend_from_slice(&sta);
        eth.extend_from_slice(&body[6..]);
        self.uplink.push_back(eth);
    }

    /// Send an Ethernet frame (destination, source, type, payload) to
    /// the station it is addressed to, or to all of them.
    pub fn send(&mut self, radio: &mut Radio, eth: &[u8]) {
        if eth.len() < 14 {
            return;
        }
        let dst: Mac = eth[..6].try_into().unwrap();
        let src: Mac = eth[6..12].try_into().unwrap();
        let mut body = LLC_SNAP.to_vec();
        body.extend_from_slice(&eth[12..]);
        if dst[0] & 1 != 0 {
            if self.stations.values().any(|s| s.phase == Phase::Authorized) {
                self.send_data(radio, dst, src, &body, true, true);
            }
        } else if self
            .stations
            .get(&dst)
            .is_some_and(|s| matches!(s.phase, Phase::Authorized | Phase::Group))
        {
            self.send_data(radio, dst, src, &body, true, false);
        }
    }

    /// One data frame from the distribution system. `protect` asks for
    /// the link's encryption; the first handshake messages go in clear.
    fn send_data(
        &mut self,
        radio: &mut Radio,
        to: Mac,
        from: Mac,
        body: &[u8],
        protect: bool,
        group: bool,
    ) {
        let mut frame = self.header(0x08, 0x02, to, self.bssid, from);
        frame.extend_from_slice(body);
        let security = self.security.clone();
        let out = match (&security, protect) {
            (Security::Open, _) | (_, false) => frame,
            (Security::Wep { key, .. }, true) => {
                let iv: [u8; 3] = self.random();
                let iv = u32::from_le_bytes([iv[0], iv[1], iv[2], 0]);
                crypto::protect(
                    &Key {
                        cipher: Cipher::Wep,
                        key,
                        mic: &[0; 8],
                    },
                    &frame,
                    iv,
                    0,
                )
            }
            (
                Security::Psk {
                    pairwise,
                    group: group_cipher,
                    ..
                },
                true,
            ) => {
                if group {
                    self.group_pn += 1;
                    let (iv, eiv) = iv_words(*group_cipher, self.group_pn, self.gtk_index);
                    let mic: [u8; 8] = self.gtk[16..24].try_into().unwrap();
                    crypto::protect(
                        &Key {
                            cipher: *group_cipher,
                            key: &self.gtk[..16],
                            mic: &mic,
                        },
                        &frame,
                        iv,
                        eiv,
                    )
                } else {
                    let Some(s) = self.stations.get_mut(&to) else {
                        return;
                    };
                    s.tx_pn += 1;
                    let (iv, eiv) = iv_words(*pairwise, s.tx_pn, 0);
                    let mic: [u8; 8] = s.ptk[48..56].try_into().unwrap();
                    crypto::protect(
                        &Key {
                            cipher: *pairwise,
                            key: &s.ptk[32..48],
                            mic: &mic,
                        },
                        &frame,
                        iv,
                        eiv,
                    )
                }
            }
        };
        self.emit(radio, out);
    }

    // ---- WPA handshakes -----------------------------------------------

    /// Key descriptor version of a station's handshake: 1 for TKIP, 2
    /// for CCMP, 0 when the key management defines everything (SAE).
    fn key_version(&self, sta: Mac) -> u16 {
        if self.stations.get(&sta).is_some_and(|s| s.akm == 8) {
            return 0;
        }
        match self.psk_params() {
            Some((_, Cipher::Ccmp, _)) => 2,
            _ => 1,
        }
    }

    fn key_len(cipher: Cipher) -> u16 {
        if cipher == Cipher::Tkip { 32 } else { 16 }
    }

    /// Build an EAPOL-Key frame, sign it if a key is given, remember it
    /// for retransmission and send it.
    #[allow(clippy::too_many_arguments)]
    fn send_key_frame(
        &mut self,
        radio: &mut Radio,
        sta: Mac,
        info: u16,
        key_len: u16,
        nonce: &[u8; 32],
        key_iv: &[u8; 16],
        rsc: u64,
        data: &[u8],
    ) {
        let (wpa2, ..) = self.psk_params().unwrap();
        let version = self.key_version(sta);
        let station = self.stations.get_mut(&sta).unwrap();
        station.replay += 1;
        station.replay_first = station.replay;
        let mut k = vec![if wpa2 { 2 } else { 254 }];
        k.extend_from_slice(&(info | version).to_be_bytes());
        k.extend_from_slice(&key_len.to_be_bytes());
        k.extend_from_slice(&station.replay.to_be_bytes());
        k.extend_from_slice(nonce);
        k.extend_from_slice(key_iv);
        k.extend_from_slice(&rsc.to_le_bytes());
        k.extend_from_slice(&[0; 8]);
        k.extend_from_slice(&[0; 16]);
        k.extend_from_slice(&(data.len() as u16).to_be_bytes());
        k.extend_from_slice(data);
        let mut eapol = vec![if wpa2 { 2 } else { 1 }, 3];
        eapol.extend_from_slice(&(k.len() as u16).to_be_bytes());
        eapol.extend_from_slice(&k);
        if info & KEY_INFO_MIC != 0 {
            let ptk = station
                .rekey
                .and_then(|r| r.next_ptk)
                .unwrap_or(station.ptk);
            let mic = Self::eapol_mic(version, &ptk[..16], &eapol);
            eapol[81..97].copy_from_slice(&mic);
        }
        station.last_eapol = eapol.clone();
        station.retries = 0;
        station.retry_at = self.now + EAPOL_RETRY_MS;
        self.send_eapol_raw(radio, sta, &eapol);
    }

    fn send_eapol_raw(&mut self, radio: &mut Radio, sta: Mac, eapol: &[u8]) {
        let mut body = LLC_SNAP.to_vec();
        body.extend_from_slice(&ETHERTYPE_EAPOL.to_be_bytes());
        body.extend_from_slice(eapol);
        let protect = self.stations.get(&sta).is_some_and(|s| s.keys_installed);
        self.send_data(radio, sta, self.bssid, &body, protect, false);
    }

    fn eapol_mic(version: u16, kck: &[u8], eapol: &[u8]) -> [u8; 16] {
        if version == 0 {
            crypto::aes_cmac(kck.try_into().unwrap(), eapol)
        } else if version == 1 {
            crypto::hmac_md5(kck, &[eapol])
        } else {
            crypto::hmac_sha1(kck, &[eapol])[..16].try_into().unwrap()
        }
    }

    /// Encrypt EAPOL key data with the key encryption key.
    fn wrap_key_data(&mut self, sta: Mac, mut data: Vec<u8>) -> (Vec<u8>, [u8; 16]) {
        let s = &self.stations[&sta];
        let ptk = s.rekey.and_then(|r| r.next_ptk).unwrap_or(s.ptk);
        let kek: [u8; 16] = ptk[16..32].try_into().unwrap();
        if self.key_version(sta) != 1 {
            if !data.len().is_multiple_of(8) || data.len() < 16 {
                data.push(0xDD);
                while !data.len().is_multiple_of(8) || data.len() < 16 {
                    data.push(0);
                }
            }
            (crypto::aes_wrap(&kek, &data), [0; 16])
        } else {
            let iv: [u8; 16] = self.random();
            let mut seed = iv.to_vec();
            seed.extend_from_slice(&kek);
            crypto::rc4(&seed, 256, &mut data);
            (data, iv)
        }
    }

    fn send_message_1(&mut self, radio: &mut Radio, sta: Mac) {
        let (_, pairwise, _) = self.psk_params().unwrap();
        self.stations.get_mut(&sta).unwrap().phase = Phase::Msg2;
        self.send_anonce(radio, sta, pairwise);
    }

    /// Message 1 of a pairwise handshake, with a fresh nonce.
    fn send_anonce(&mut self, radio: &mut Radio, sta: Mac, pairwise: Cipher) {
        let anonce = self.random();
        let s = self.stations.get_mut(&sta).unwrap();
        s.anonce = anonce;
        // After SAE, message 1 names the key both ends just derived.
        let mut data = Vec::new();
        if let Some((_, pmkid)) = s.sae_key.filter(|_| s.akm == 8) {
            data.extend_from_slice(&[0xDD, 20, 0x00, 0x0F, 0xAC, 0x04]);
            data.extend_from_slice(&pmkid);
        }
        self.send_key_frame(
            radio,
            sta,
            KEY_INFO_PAIRWISE | KEY_INFO_ACK,
            Self::key_len(pairwise),
            &anonce,
            &[0; 16],
            0,
            &data,
        );
    }

    /// The group key as key data for this network's flavour of WPA.
    fn group_key_data(&self, group: Cipher, wpa2: bool) -> Vec<u8> {
        let gtk = &self.gtk[..Self::key_len(group) as usize];
        if wpa2 {
            let mut kde = vec![
                0xDD,
                6 + gtk.len() as u8,
                0x00,
                0x0F,
                0xAC,
                0x01,
                self.gtk_index & 3,
                0,
            ];
            kde.extend_from_slice(gtk);
            kde
        } else {
            gtk.to_vec()
        }
    }

    fn send_group_message(&mut self, radio: &mut Radio, sta: Mac) {
        let (wpa2, _, group) = self.psk_params().unwrap();
        let mut plain = self.group_key_data(group, wpa2);
        if self.stations[&sta].pmf {
            plain.extend_from_slice(&self.igtk_kde());
        }
        let (data, iv) = self.wrap_key_data(sta, plain);
        let mut info = KEY_INFO_ACK | KEY_INFO_MIC | KEY_INFO_SECURE;
        info |= if wpa2 {
            KEY_INFO_ENCRYPTED
        } else {
            (self.gtk_index as u16 & 3) << 4
        };
        let zero = [0; 32];
        self.send_key_frame(
            radio,
            sta,
            info,
            Self::key_len(group),
            &zero,
            &iv,
            self.group_pn,
            &data,
        );
    }

    /// Replace the group key and hand the new one to every station, as
    /// access points do on a timer.
    pub fn rekey_group(&mut self, radio: &mut Radio) {
        if self.psk_params().is_none() {
            return;
        }
        self.gtk = self.random();
        self.gtk_index = if self.gtk_index == 1 { 2 } else { 1 };
        self.group_pn = 0;
        // The integrity group key is renewed with it, under the other
        // of its two identifiers (as hostapd's `wpa_gtk_update`).
        if self.wpa3 != Wpa3::Off {
            self.igtk = self.random();
            self.igtk_index = if self.igtk_index == 4 { 5 } else { 4 };
            self.ipn = 0;
        }
        let authorised: Vec<Mac> = self
            .stations
            .iter()
            .filter(|(_, s)| s.phase == Phase::Authorized)
            .map(|(m, _)| *m)
            .collect();
        for sta in authorised {
            self.stations.get_mut(&sta).unwrap().rekeying = true;
            self.send_group_message(radio, sta);
        }
    }

    /// IGTK key data element: identifier, packet number, key.
    fn igtk_kde(&self) -> Vec<u8> {
        let mut kde = vec![0xDD, 28, 0x00, 0x0F, 0xAC, 0x09, self.igtk_index, 0];
        kde.extend_from_slice(&self.ipn.to_le_bytes()[..6]);
        kde.extend_from_slice(&self.igtk);
        kde
    }

    /// Protect a group-addressed management frame with BIP-CMAC-128:
    /// the frame stays readable, a management MIC element (76) is
    /// appended.
    fn bip_protect(&mut self, mut frame: Vec<u8>) -> Vec<u8> {
        self.ipn += 1;
        frame.extend_from_slice(&[76, 16, self.igtk_index, 0]);
        frame.extend_from_slice(&self.ipn.to_le_bytes()[..6]);
        frame.extend_from_slice(&[0; 8]);
        let mic = crypto::bip_mic(&self.igtk, &frame);
        let n = frame.len();
        frame[n - 8..].copy_from_slice(&mic);
        frame
    }

    /// Stop, as hostapd does when it is shut down: every station is
    /// told to leave by a deauthentication to everyone (reason 3),
    /// protected by BIP when the network offers management frame
    /// protection, and forgotten. The access point then has to be taken
    /// off the air by the caller.
    pub fn shut_down(&mut self, radio: &mut Radio) {
        let mut f = self.mgmt(MGMT_DEAUTH, [0xFF; 6]);
        f.extend_from_slice(&3u16.to_le_bytes());
        if self.wpa3 != Wpa3::Off && self.psk_params().is_some() {
            f = self.bip_protect(f);
        }
        self.emit(radio, f);
        let gone: Vec<Mac> = self.stations.keys().copied().collect();
        self.stations.clear();
        for sta in gone {
            self.events.push(ApEvent::Deauthenticated {
                sta,
                reason: 3,
                by_ap: true,
            });
        }
    }

    /// Message 3: the access point's element and the group keys, under
    /// the handshake's key encryption key.
    fn send_message_3(
        &mut self,
        radio: &mut Radio,
        sta: Mac,
        wpa2: bool,
        pairwise: Cipher,
        group: Cipher,
    ) {
        let anonce = self.stations[&sta].anonce;
        let mut info = KEY_INFO_PAIRWISE | KEY_INFO_INSTALL | KEY_INFO_ACK | KEY_INFO_MIC;
        let (data, iv) = if wpa2 {
            info |= KEY_INFO_SECURE | KEY_INFO_ENCRYPTED;
            let mut plain = self.own_element();
            plain.extend_from_slice(&self.own_extension());
            plain.extend_from_slice(&self.group_key_data(group, true));
            if self.stations[&sta].pmf {
                // The integrity group key, for protected broadcasts.
                plain.extend_from_slice(&self.igtk_kde());
            }
            self.wrap_key_data(sta, plain)
        } else {
            (self.own_element(), [0; 16])
        };
        let rsc = if wpa2 { self.group_pn } else { 0 };
        self.send_key_frame(
            radio,
            sta,
            info,
            Self::key_len(pairwise),
            &anonce,
            &iv,
            rsc,
            &data,
        );
    }

    /// The pairwise handshake again on a running link (hostapd's
    /// `wpa_ptk_rekey`): message 1 goes out under the current key, the
    /// new one is used from message 4 on.
    pub fn rekey_pairwise(&mut self, radio: &mut Radio, sta: Mac) {
        let Some((_, pairwise, _)) = self.psk_params() else {
            return;
        };
        let Some(s) = self.stations.get_mut(&sta) else {
            return;
        };
        if s.phase != Phase::Authorized || !s.keys_installed {
            return;
        }
        s.rekey = Some(Rekey { next_ptk: None });
        self.send_anonce(radio, sta, pairwise);
    }

    #[allow(clippy::too_many_arguments)]
    fn on_rekey(
        &mut self,
        radio: &mut Radio,
        sta: Mac,
        rekey: Rekey,
        ptk: [u8; 64],
        data: &[u8],
        wpa2: bool,
        pairwise: Cipher,
        group: Cipher,
    ) {
        if rekey.next_ptk.is_none() {
            // Message 2 of the rekey.
            if security_element(data, wpa2) != Some(&self.stations[&sta].element[..]) {
                self.reject(sta, "element differs from the association request");
                return self.deauth(radio, sta, 17);
            }
            self.stations.get_mut(&sta).unwrap().rekey = Some(Rekey {
                next_ptk: Some(ptk),
            });
            self.send_message_3(radio, sta, wpa2, pairwise, group);
        } else {
            // Message 4: the new key takes over, packet numbers start again.
            let s = self.stations.get_mut(&sta).unwrap();
            s.ptk = ptk;
            s.rekey = None;
            s.tx_pn = 0;
            s.rx_pn = 0;
            s.rx_started = false;
            s.retry_at = 0;
            self.events.push(ApEvent::PairwiseKeyRenewed { sta });
        }
    }

    fn reject(&mut self, sta: Mac, why: &'static str) {
        self.events.push(ApEvent::EapolRejected { sta, why });
    }

    fn on_eapol(&mut self, radio: &mut Radio, sta: Mac, eapol: &[u8]) {
        let Some((wpa2, pairwise, group)) = self.psk_params() else {
            return;
        };
        // EAPOL header (4), then the key descriptor up to its data (95).
        if eapol.len() < 99 || eapol[1] != 3 {
            return;
        }
        let total = 4 + u16::from_be_bytes([eapol[2], eapol[3]]) as usize;
        let Some(eapol) = eapol.get(..total) else {
            return;
        };
        let info = u16::from_be_bytes([eapol[5], eapol[6]]);
        let replay = u64::from_be_bytes(eapol[9..17].try_into().unwrap());
        let Some(data) = eapol_key_data(eapol) else {
            return;
        };
        let version = self.key_version(sta);
        let station = &self.stations[&sta];
        let phase = station.phase;

        if info & 7 != version {
            return self.reject(sta, "key descriptor version");
        }
        if info & KEY_INFO_MIC == 0 || info & KEY_INFO_ACK != 0 {
            return self.reject(sta, "flags of a message from a supplicant");
        }
        if replay < station.replay_first || replay > station.replay {
            return self.reject(sta, "replay counter");
        }

        // Message 2 is the one that lets us derive the keys.
        let rekey = station
            .rekey
            .filter(|_| phase == Phase::Authorized && info & KEY_INFO_PAIRWISE != 0);
        let mut ptk = rekey.and_then(|r| r.next_ptk).unwrap_or(station.ptk);
        if phase == Phase::Msg2 || rekey.is_some_and(|r| r.next_ptk.is_none()) {
            let snonce = &eapol[17..49];
            let (lo_mac, hi_mac) = if self.bssid < sta {
                (self.bssid, sta)
            } else {
                (sta, self.bssid)
            };
            let anonce = &station.anonce[..];
            let (lo_nonce, hi_nonce) = if anonce < snonce {
                (anonce, snonce)
            } else {
                (snonce, anonce)
            };
            let mut seed = lo_mac.to_vec();
            seed.extend_from_slice(&hi_mac);
            seed.extend_from_slice(lo_nonce);
            seed.extend_from_slice(hi_nonce);
            match station.sae_key.filter(|_| station.akm == 8) {
                // SAE: SHA-256 all the way, 384 bits of keys.
                Some((pmk, _)) => {
                    let keys = crypto::kdf_sha256(&pmk, "Pairwise key expansion", &seed, 384);
                    ptk[..48].copy_from_slice(&keys);
                }
                None => ptk.copy_from_slice(&crypto::prf(
                    &self.psk,
                    "Pairwise key expansion",
                    &seed,
                    64,
                )),
            }
        }
        let mut unsigned = eapol.to_vec();
        unsigned[81..97].fill(0);
        if Self::eapol_mic(version, &ptk[..16], &unsigned) != eapol[81..97] {
            self.events.push(ApEvent::EapolMicFailure { sta });
            return;
        }

        if let Some(r) = rekey {
            return self.on_rekey(radio, sta, r, ptk, data, wpa2, pairwise, group);
        }
        match phase {
            Phase::Msg2 => {
                if info & KEY_INFO_PAIRWISE == 0 {
                    return self.reject(sta, "message 2 is not a pairwise message");
                }
                if security_element(data, wpa2) != Some(&station.element[..]) {
                    self.reject(sta, "element differs from the association request");
                    // Reason 17: element in the handshake differs.
                    return self.deauth(radio, sta, 17);
                }
                let s = self.stations.get_mut(&sta).unwrap();
                s.ptk = ptk;
                s.phase = Phase::Msg4;
                self.send_message_3(radio, sta, wpa2, pairwise, group);
            }
            Phase::Msg4 => {
                if info & KEY_INFO_PAIRWISE == 0 {
                    return self.reject(sta, "message 4 is not a pairwise message");
                }
                if self.lose_message_4 > 0 {
                    // Lost on the way: message 3 goes again.
                    self.lose_message_4 -= 1;
                    return;
                }
                let s = self.stations.get_mut(&sta).unwrap();
                s.keys_installed = true;
                s.retry_at = 0;
                self.events.push(ApEvent::HandshakeComplete { sta });
                if wpa2 {
                    s.phase = Phase::Authorized;
                } else {
                    s.phase = Phase::Group;
                    self.send_group_message(radio, sta);
                }
            }
            Phase::Group | Phase::Authorized => {
                if info & KEY_INFO_PAIRWISE != 0 {
                    return self.reject(sta, "pairwise message outside a handshake");
                }
                let s = self.stations.get_mut(&sta).unwrap();
                if phase == Phase::Authorized && !s.rekeying {
                    return self.reject(sta, "group message nobody asked for");
                }
                s.phase = Phase::Authorized;
                s.rekeying = false;
                s.retry_at = 0;
                self.events.push(ApEvent::GroupKeyInstalled { sta });
            }
            Phase::Authenticated | Phase::Associated => {
                self.reject(sta, "handshake message before message 1")
            }
        }
    }
}
