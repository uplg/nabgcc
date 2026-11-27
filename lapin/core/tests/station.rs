//! The station of `lapin_core::wifi` against the emulator's access
//! point, on the host: no processor emulated, the stick's own
//! encryption imitated with the emulator's cipher code. Quick to run;
//! the same code is then checked on the emulated rabbit.

use lapin_core::wifi::{self, HwCipher, Link, Rx, Station, Tx};
use nabemu::air::{AccessPoint, ApEvent, Security, Wpa3};
use nabemu::crypto::{self, Cipher, Key};
use nabemu::rt2573::{Radio, TxFrame};

const BSSID: [u8; 6] = [0x02, 0, 0, 0, 0, 0xA1];
const STA: [u8; 6] = [0x00, 0x19, 0xDB, 0x9C, 0x28, 0x15];
const PASSPHRASE: &str = "carotte-violette";

struct Slot {
    cipher: HwCipher,
    key: Vec<u8>,
    tx_mic: [u8; 8],
    rx_mic: [u8; 8],
}

struct World {
    radio: Radio,
    aps: Vec<AccessPoint>,
    now: u64,
    keys: [Option<Slot>; 4],
    channel: u8,
    cipher_errors: u32,
    seq: u16,
    rng: u64,
    /// Someone on the air changing what the station hears (before the
    /// stick sees it), or keeping what it sends from the access point.
    rewrite: Option<fn(&mut Vec<u8>)>,
    lose: Option<fn(&[u8]) -> bool>,
}

fn emu_cipher(c: HwCipher) -> Option<Cipher> {
    match c {
        HwCipher::None => None,
        HwCipher::Wep40 | HwCipher::Wep104 => Some(Cipher::Wep),
        HwCipher::Tkip => Some(Cipher::Tkip),
        HwCipher::Ccmp => Some(Cipher::Ccmp),
    }
}

impl World {
    fn new(security: Security, wpa3: Wpa3) -> World {
        let mut ap = AccessPoint::new("Terrier", BSSID, 6, security);
        ap.wpa3 = wpa3;
        World {
            radio: Radio {
                channel: 1,
                mac: STA,
                rx_enabled: true,
                ..Radio::default()
            },
            aps: vec![ap],
            now: 0,
            keys: [None, None, None, None],
            channel: 1,
            cipher_errors: 0,
            seq: 0,
            rng: 0x1234_5678_9ABC_DEF1,
            rewrite: None,
            lose: None,
        }
    }

    fn step(&mut self) {
        self.now += 1;
        for ap in self.aps.iter_mut() {
            ap.poll(&mut self.radio, self.now);
        }
    }

    fn ap(&self) -> &AccessPoint {
        &self.aps[0]
    }
}

impl Link for World {
    fn mac(&self) -> [u8; 6] {
        STA
    }
    fn millis(&self) -> u32 {
        self.now as u32
    }
    fn transmit(&mut self, frame: &[u8], tx: &Tx) -> bool {
        let mut f = frame.to_vec();
        // The stick numbers the frames.
        f[22..24].copy_from_slice(&(self.seq << 4).to_le_bytes());
        self.seq = (self.seq + 1) & 0xFFF;
        if let Some(cipher) = emu_cipher(tx.cipher) {
            let Some(slot) = &self.keys[tx.key as usize] else {
                panic!("transmit with an empty key slot");
            };
            let key = Key {
                cipher,
                key: &slot.key,
                mic: &slot.tx_mic,
            };
            f = crypto::protect(&key, &f, tx.iv, tx.eiv);
        }
        if self.lose.is_some_and(|lose| lose(&f)) {
            return true;
        }
        self.radio.tx.push_back(TxFrame {
            data: f,
            channel: self.channel,
        });
        true
    }
    fn receive(&mut self, buffer: &mut [u8]) -> Option<Rx> {
        loop {
            let mut f = self.radio.rx.pop_front()?.data;
            if let Some(rewrite) = self.rewrite {
                rewrite(&mut f);
            }
            let to = &f[4..10];
            if !(to == STA || to[0] & 1 != 0) {
                continue;
            }
            let protected = f.len() > 28 && f[1] & 0x40 != 0 && f[0] & 0x0C == 0x08;
            let mut out = f.clone();
            let mut decrypted = false;
            let (mut iv, mut eiv) = (0, 0);
            if protected {
                let index = (f[27] >> 6) as usize;
                if let Some(slot) = &self.keys[index] {
                    let key = Key {
                        cipher: emu_cipher(slot.cipher).unwrap(),
                        key: &slot.key,
                        mic: &slot.rx_mic,
                    };
                    match crypto::unprotect(&key, &f) {
                        Ok((clear, i, e)) => {
                            out = clear;
                            decrypted = true;
                            (iv, eiv) = (i, e);
                        }
                        Err(_) => {
                            self.cipher_errors += 1;
                            continue;
                        }
                    }
                }
            }
            buffer[..out.len()].copy_from_slice(&out);
            return Some(Rx {
                len: out.len(),
                rssi: -50,
                decrypted,
                iv,
                eiv,
            });
        }
    }
    fn set_channel(&mut self, channel: u8) {
        self.channel = channel;
        self.radio.channel = channel;
    }
    fn set_bssid(&mut self, _: &[u8; 6]) {}
    fn set_key(
        &mut self,
        index: u8,
        cipher: HwCipher,
        key: &[u8],
        tx_mic: &[u8; 8],
        rx_mic: &[u8; 8],
    ) {
        self.keys[index as usize] = (cipher != HwCipher::None).then(|| Slot {
            cipher,
            key: key.to_vec(),
            tx_mic: *tx_mic,
            rx_mic: *rx_mic,
        });
    }
    fn set_beacon(&mut self, _: Option<&[u8]>) {}
    fn set_answer_rates(&mut self, _: u16) {}
    fn pause(&mut self) {
        self.step();
    }
    fn random(&mut self, out: &mut [u8]) {
        for b in out {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            *b = (self.rng >> 24) as u8;
        }
    }
}

/// The main loop of the firmware, in short: frames in, the timer every
/// 200 ms. Returns what was handed up.
fn run(w: &mut World, sta: &mut Station, ms: u64, up: &mut Vec<Vec<u8>>) {
    let mut buf = vec![0u8; 2400];
    for _ in 0..ms {
        w.step();
        sta.poll(w);
        while let Some(rx) = w.receive(&mut buf) {
            if let Some(d) = sta.input(w, &mut buf, rx) {
                up.push(buf[d.start..d.start + d.len].to_vec());
            }
        }
        if w.now % 200 == 0 {
            sta.tick(w);
        }
    }
}

fn scan(w: &mut World, sta: &mut Station) -> Vec<wifi::ScanResult> {
    let mut found = Vec::new();
    let mut buf = vec![0u8; 2400];
    sta.scan(w, None, &mut buf, &mut |r| found.push(*r));
    found
}

fn join(w: &mut World, sta: &mut Station, key: &[u8], password: &[u8]) -> Vec<Vec<u8>> {
    let found = scan(w, sta);
    let r = found
        .iter()
        .find(|r| r.bssid == BSSID)
        .unwrap_or_else(|| panic!("not found: {found:?}"));
    sta.auth(
        w,
        &r.ssid[..r.ssid_len],
        &r.mac,
        &r.bssid,
        r.channel,
        r.rateset,
        false,
        r.encryption,
        key,
        password,
    );
    let mut up = Vec::new();
    run(w, sta, 3000, &mut up);
    up
}

fn dhcp_like(sta: &mut Station, w: &mut World) {
    // An IP frame from its LLC header on, to everyone.
    let mut data = vec![0xAA, 0xAA, 0x03, 0, 0, 0, 0x08, 0x00];
    data.extend_from_slice(&[0x45; 40]);
    assert!(sta.send(w, &data, &[0xFF; 6], false));
    run(w, sta, 20, &mut Vec::new());
}

fn ethernet(dst: [u8; 6], src: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut f = dst.to_vec();
    f.extend_from_slice(&src);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(payload);
    f
}

fn pmk() -> [u8; 32] {
    lapin_core::sha1::passphrase_to_pmk(PASSPHRASE.as_bytes(), b"Terrier", &mut |_| {})
}

fn talks(w: &mut World, sta: &mut Station) {
    dhcp_like(sta, w);
    assert!(
        w.ap().uplink.iter().any(|f| f[12..14] == [0x08, 0x00]),
        "nothing came up: {:?}",
        w.ap().events
    );
    let mut up = Vec::new();
    w.aps[0].send(&mut w.radio, &ethernet(STA, [2, 0, 0, 0, 0, 1], b"bonjour"));
    w.aps[0].send(
        &mut w.radio,
        &ethernet([0xFF; 6], [2, 0, 0, 0, 0, 1], b"tout le monde"),
    );
    run(w, sta, 50, &mut up);
    assert!(up.iter().any(|f| f.ends_with(b"bonjour")), "{up:?}");
    assert!(up.iter().any(|f| f.ends_with(b"tout le monde")), "{up:?}");
    assert_eq!(w.cipher_errors, 0);
}

fn trouble(w: &World) -> Vec<&ApEvent> {
    w.ap()
        .events
        .iter()
        .filter(|e| {
            !matches!(
                e,
                ApEvent::Authenticated { .. }
                    | ApEvent::Associated { .. }
                    | ApEvent::HandshakeComplete { .. }
                    | ApEvent::GroupKeyInstalled { .. }
                    | ApEvent::SaeComplete { .. }
                    | ApEvent::PairwiseKeyRenewed { .. }
                    | ApEvent::PmksaCacheUsed { .. }
            )
        })
        .collect()
}

#[test]
fn scan_reports_the_network_as_the_c_driver_did() {
    let mut w = World::new(Security::wpa2(PASSPHRASE), Wpa3::Off);
    let mut sta = Station::new();
    let found = scan(&mut w, &mut sta);
    let r = found.iter().find(|r| r.bssid == BSSID).unwrap();
    assert_eq!(&r.ssid[..r.ssid_len], b"Terrier");
    assert_eq!(r.channel, 6);
    assert_eq!(r.encryption, 0x40 | 0x08 | 0x02);
    assert_eq!(sta.net_state(), wifi::S_IDLE);
}

#[test]
fn joins_an_open_network() {
    let mut w = World::new(Security::Open, Wpa3::Off);
    let mut sta = Station::new();
    join(&mut w, &mut sta, &[], &[]);
    assert_eq!(sta.net_state(), wifi::S_CONNECTED);
    talks(&mut w, &mut sta);
}

#[test]
fn joins_wpa2() {
    let mut w = World::new(Security::wpa2(PASSPHRASE), Wpa3::Off);
    let mut sta = Station::new();
    join(&mut w, &mut sta, &pmk(), &[]);
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    assert!(!sta.is_wpa3());
    talks(&mut w, &mut sta);
    assert_eq!(trouble(&w), Vec::<&ApEvent>::new());
}

/// A frame the access point sent, recorded and sent again by someone
/// else: the stick opens it a second time without a word, and the
/// station handed it up twice.
#[test]
fn a_frame_sent_again_goes_up_once() {
    for security in [Security::wpa2(PASSPHRASE), Security::wpa(PASSPHRASE)] {
        let mut w = World::new(security, Wpa3::Off);
        let mut sta = Station::new();
        join(&mut w, &mut sta, &pmk(), &[]);
        assert_eq!(sta.net_state(), wifi::S_CONNECTED);
        for to in [STA, [0xFF; 6]] {
            w.aps[0].send(&mut w.radio, &ethernet(to, [2, 0, 0, 0, 0, 1], b"une fois"));
            let recorded = w.radio.rx.back().unwrap().clone();
            w.radio.rx.push_back(recorded);
            let mut up = Vec::new();
            run(&mut w, &mut sta, 20, &mut up);
            let n = up.iter().filter(|f| f.ends_with(b"une fois")).count();
            assert_eq!(n, 1, "to {to:x?}");
        }
    }
}

#[test]
fn joins_wpa_tkip() {
    let mut w = World::new(Security::wpa(PASSPHRASE), Wpa3::Off);
    let mut sta = Station::new();
    join(&mut w, &mut sta, &pmk(), &[]);
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    talks(&mut w, &mut sta);
    assert_eq!(trouble(&w), Vec::<&ApEvent>::new());
}

#[test]
fn joins_mixed_mode() {
    let mut w = World::new(Security::wpa2_tkip_group(PASSPHRASE), Wpa3::Off);
    let mut sta = Station::new();
    join(&mut w, &mut sta, &pmk(), &[]);
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    talks(&mut w, &mut sta);
    assert_eq!(trouble(&w), Vec::<&ApEvent>::new());
}

#[test]
fn joins_wep_104() {
    let key = b"thirteenchars".to_vec();
    let mut w = World::new(
        Security::Wep {
            key: key.clone(),
            shared_auth: false,
        },
        Wpa3::Off,
    );
    let mut sta = Station::new();
    join(&mut w, &mut sta, &key, &[]);
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    talks(&mut w, &mut sta);
}

#[test]
fn joins_wep_shared_key() {
    let key = b"carot".to_vec();
    let mut w = World::new(
        Security::Wep {
            key: key.clone(),
            shared_auth: true,
        },
        Wpa3::Off,
    );
    let mut sta = Station::new();
    let found = scan(&mut w, &mut sta);
    let r = found.iter().find(|r| r.bssid == BSSID).unwrap();
    sta.auth(
        &mut w,
        b"Terrier",
        &r.mac,
        &r.bssid,
        r.channel,
        r.rateset,
        true,
        r.encryption,
        &key,
        &[],
    );
    run(&mut w, &mut sta, 2000, &mut Vec::new());
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    talks(&mut w, &mut sta);
    assert!(w.ap().events.contains(&ApEvent::Authenticated {
        sta: STA,
        shared_key: true
    }));
}

fn joins_wpa3(wpa3: Wpa3) -> (World, Station) {
    let mut w = World::new(Security::wpa2(PASSPHRASE), wpa3);
    let mut sta = Station::new();
    join(&mut w, &mut sta, &pmk(), PASSPHRASE.as_bytes());
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    assert!(sta.is_wpa3());
    assert!(
        w.ap()
            .events
            .iter()
            .any(|e| matches!(e, ApEvent::SaeComplete { .. }))
    );
    talks(&mut w, &mut sta);
    assert_eq!(trouble(&w), Vec::<&ApEvent>::new());
    (w, sta)
}

#[test]
fn joins_wpa3_only() {
    joins_wpa3(Wpa3::Only);
}

#[test]
fn prefers_wpa3_on_a_transition_network() {
    joins_wpa3(Wpa3::Transition);
}

/// A transition network (WPA2 and WPA3) whose beacons and probe
/// responses someone rewrites to offer WPA2 alone: the station, which
/// holds the password, joined with the pre-shared key, as told. The
/// RSN element of message 3 cannot be forged: it differs, the attempt
/// ends there, and the next one runs WPA3 (802.11-2020 12.7.6.4).
#[test]
fn a_transition_network_made_to_look_wpa2_only_is_joined_with_wpa3() {
    let mut w = World::new(Security::wpa2(PASSPHRASE), Wpa3::Transition);
    w.rewrite = Some(|f| {
        if f[0] != 0x80 && f[0] != 0x50 {
            return;
        }
        // The same element with PSK alone, no protection, and no RSN
        // extension element.
        let at = 24 + 12;
        let mut out = f[..at].to_vec();
        let mut ies = &f[at..];
        while let [id, len, rest @ ..] = ies {
            let body = &rest[..*len as usize];
            match id {
                48 => out.extend_from_slice(&[
                    48, 20, 1, 0, 0, 0x0F, 0xAC, 4, 1, 0, 0, 0x0F, 0xAC, 4, 1, 0, 0, 0x0F, 0xAC, 2,
                    0, 0,
                ]),
                244 => {}
                _ => {
                    out.extend_from_slice(&[*id, *len]);
                    out.extend_from_slice(body);
                }
            }
            ies = &rest[*len as usize..];
        }
        *f = out;
    });
    let mut sta = Station::new();
    join(&mut w, &mut sta, &pmk(), PASSPHRASE.as_bytes());
    assert!(!sta.is_wpa3() || sta.net_state() != wifi::S_CONNECTED);
    assert_ne!(sta.net_state(), wifi::S_CONNECTED, "joined with WPA2");
    join(&mut w, &mut sta, &pmk(), PASSPHRASE.as_bytes());
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    assert!(sta.is_wpa3());
    talks(&mut w, &mut sta);
}

/// After hashing the password to the curve, the association request
/// carries the RSN extension element that says so: without it, the
/// access point cannot tell a downgrade to hunting and pecking, and
/// (as the emulated one, after 802.11) refuses the association.
#[test]
fn wpa3_says_it_hashed_to_the_curve() {
    let (w, sta) = joins_wpa3(Wpa3::Only);
    assert!(sta.is_wpa3());
    let request = w
        .radio
        .tx
        .iter()
        .find(|f| f.data[0] == 0x00)
        .expect("no association request");
    assert!(request.data.windows(3).any(|e| e == [244, 1, 0x20]));
}

/// A message 1 with the largest replay counter, from someone else,
/// just before the access point's own: the station took its counter as
/// the last one seen, and dropped the genuine message 1 and every one
/// the access point sent again. The handshake could never finish.
#[test]
fn a_forged_message_1_does_not_lock_the_handshake_out() {
    let mut w = World::new(Security::wpa2(PASSPHRASE), Wpa3::Off);
    let mut sta = Station::new();
    let found = scan(&mut w, &mut sta);
    let r = *found.iter().find(|r| r.bssid == BSSID).unwrap();
    sta.auth(
        &mut w,
        &r.ssid[..r.ssid_len],
        &r.mac,
        &r.bssid,
        r.channel,
        r.rateset,
        false,
        r.encryption,
        &pmk(),
        &[],
    );
    // Up to the association response, which the access point sends
    // with its message 1.
    let mut buf = vec![0u8; 2400];
    for _ in 0..1000 {
        w.step();
        if w.radio.rx.iter().any(|f| f.data[0] == 0x10) {
            break;
        }
        while let Some(rx) = w.receive(&mut buf) {
            sta.input(&mut w, &mut buf, rx);
        }
    }
    let mut forged = vec![0x08, 0x02, 0, 0];
    forged.extend_from_slice(&STA);
    forged.extend_from_slice(&BSSID);
    forged.extend_from_slice(&BSSID);
    forged.extend_from_slice(&[0, 0]);
    forged.extend_from_slice(&wifi::LLC_EAPOL);
    let mut e = vec![2, 3, 0, 95, 2, 0x00, 0x8A, 0, 16];
    e.extend_from_slice(&[0xFF; 8]);
    e.extend_from_slice(&[0x99; 32]);
    e.resize(99, 0);
    forged.extend_from_slice(&e);
    let at = w.radio.rx.iter().position(|f| f.data[0] == 0x10).unwrap();
    w.radio
        .rx
        .insert(at + 1, nabemu::rt2573::RxFrame::new(forged));
    run(&mut w, &mut sta, 4000, &mut Vec::new());
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    talks(&mut w, &mut sta);
}

#[test]
fn stays_on_wpa2_without_a_password() {
    let mut w = World::new(Security::wpa2(PASSPHRASE), Wpa3::Transition);
    let mut sta = Station::new();
    join(&mut w, &mut sta, &pmk(), &[]);
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    assert!(!sta.is_wpa3());
}

#[test]
fn wpa3_survives_a_group_rekey_and_ignores_a_forged_deauthentication() {
    let (mut w, mut sta) = joins_wpa3(Wpa3::Only);
    w.aps[0].rekey_group(&mut w.radio);
    run(&mut w, &mut sta, 100, &mut Vec::new());
    // Someone else, in clear, with the access point's address.
    let mut forged = vec![0xC0, 0, 0, 0];
    forged.extend_from_slice(&STA);
    forged.extend_from_slice(&BSSID);
    forged.extend_from_slice(&BSSID);
    forged.extend_from_slice(&[0, 0, 7, 0]);
    w.radio.rx.push_back(nabemu::rt2573::RxFrame::new(forged));
    run(&mut w, &mut sta, 20, &mut Vec::new());
    assert_eq!(sta.net_state(), wifi::S_CONNECTED);
    let mut up = Vec::new();
    w.aps[0].send(
        &mut w.radio,
        &ethernet([0xFF; 6], [2, 0, 0, 0, 0, 1], b"apres"),
    );
    run(&mut w, &mut sta, 20, &mut up);
    assert!(up.iter().any(|f| f.ends_with(b"apres")), "{up:?}");
    // The real thing, signed: believed.
    w.aps[0].shut_down(&mut w.radio);
    run(&mut w, &mut sta, 20, &mut Vec::new());
    assert_eq!(sta.net_state(), wifi::S_IDLE);
}

#[test]
fn wpa3_after_a_restart_waits_for_the_sa_query() {
    let (mut w, _) = joins_wpa3(Wpa3::Only);
    // The rabbit restarts: everything forgotten, the access point not told.
    let mut sta = Station::new();
    join(&mut w, &mut sta, &pmk(), PASSPHRASE.as_bytes());
    run(&mut w, &mut sta, 2000, &mut Vec::new());
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    assert!(
        w.ap()
            .events
            .iter()
            .any(|e| matches!(e, ApEvent::SaQueryTimedOut { .. })),
        "{:?}",
        w.ap().events
    );
    talks(&mut w, &mut sta);
}

/// The access point loses power and comes back, the rabbit forgotten.
/// To the rabbit's protected frames it answers, as hostapd does, with a
/// deauthentication in clear (reason 7): ignored, as anyone could send
/// it, and the beacons kept the link "up" for ever. Now the station asks
/// the access point under the keys (SA Query); no answer within a
/// second, the link is down, and the station joins again.
#[test]
fn wpa3_notices_an_access_point_that_forgot_it() {
    let (mut w, mut sta) = joins_wpa3(Wpa3::Only);
    w.aps[0].power_cut();
    // The rabbit talks; the access point says it does not know it.
    let mut data = vec![0xAA, 0xAA, 0x03, 0, 0, 0, 0x08, 0x00];
    data.extend_from_slice(&[0x45; 40]);
    sta.send(&mut w, &data, &[0xFF; 6], false);
    run(&mut w, &mut sta, 500, &mut Vec::new());
    assert!(
        w.ap()
            .events
            .iter()
            .any(|e| matches!(e, ApEvent::Deauthenticated { reason: 7, .. })),
        "{:?}",
        w.ap().events
    );
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "too soon");
    run(&mut w, &mut sta, 1000, &mut Vec::new());
    assert_eq!(sta.net_state(), wifi::S_IDLE);
    join(&mut w, &mut sta, &pmk(), PASSPHRASE.as_bytes());
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    w.aps[0].uplink.clear();
    talks(&mut w, &mut sta);
}

/// The same deauthentication in clear, but from someone else while the
/// access point still holds the association: it answers the query, and
/// the link stays.
#[test]
fn wpa3_keeps_the_link_when_the_access_point_answers_the_query() {
    let (mut w, mut sta) = joins_wpa3(Wpa3::Only);
    let mut forged = vec![0xC0, 0, 0, 0];
    forged.extend_from_slice(&STA);
    forged.extend_from_slice(&BSSID);
    forged.extend_from_slice(&BSSID);
    forged.extend_from_slice(&[0, 0, 6, 0]);
    w.radio.rx.push_back(nabemu::rt2573::RxFrame::new(forged));
    run(&mut w, &mut sta, 3000, &mut Vec::new());
    assert_eq!(sta.net_state(), wifi::S_CONNECTED);
    let queries = w
        .radio
        .tx
        .iter()
        .filter(|f| f.data[0] == 0xD0)
        .count();
    assert!(queries >= 1);
    w.aps[0].uplink.clear();
    talks(&mut w, &mut sta);
}

/// Message 4 lost: the access point sends message 3 again, in clear (it
/// has no key yet). The WPA3 station, keys in place, dropped everything
/// in clear, the access point gave up (reason 15, in clear: ignored
/// too), and the rabbit stayed "connected" to an access point that no
/// longer knew it. Now message 3 again is answered, nothing installed
/// again.
#[test]
fn a_lost_message_4_is_sent_again() {
    for wpa3 in [Wpa3::Only, Wpa3::Off] {
        let mut w = World::new(Security::wpa2(PASSPHRASE), wpa3);
        w.aps[0].lose_message_4 = 1;
        let mut sta = Station::new();
        let password: &[u8] = if wpa3 == Wpa3::Only {
            PASSPHRASE.as_bytes()
        } else {
            &[]
        };
        join(&mut w, &mut sta, &pmk(), password);
        assert_eq!(sta.net_state(), wifi::S_CONNECTED);
        assert!(w.ap().is_authorized(STA), "{:?}", w.ap().events);
        talks(&mut w, &mut sta);
        assert_eq!(trouble(&w), Vec::<&ApEvent>::new());
    }
}

#[test]
fn access_point_mode_lets_a_station_in() {
    let mut w = World::new(Security::Open, Wpa3::Off);
    w.aps.clear();
    let mut sta = Station::new();
    sta.set_mode(&mut w, true, b"Nabaztag2815\0", 4);
    assert_eq!(sta.net_state(), wifi::S_MASTER);
    // A laptop: authenticates, associates, sends a frame.
    let laptop = [0x02, 0, 0, 0, 0, 0x77];
    let mgmt = |fc: u8, body: &[u8]| {
        let mut f = vec![fc, 0, 0, 0];
        f.extend_from_slice(&STA);
        f.extend_from_slice(&laptop);
        f.extend_from_slice(&STA);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(body);
        nabemu::rt2573::RxFrame::new(f)
    };
    w.radio.rx.push_back(mgmt(0xB0, &[0, 0, 1, 0, 0, 0]));
    w.radio.rx.push_back(mgmt(0x00, &[1, 0, 10, 0, 0, 0]));
    let mut data = vec![0x08, 0x01, 0, 0];
    data.extend_from_slice(&STA);
    data.extend_from_slice(&laptop);
    data.extend_from_slice(&[0xFF; 6]);
    data.extend_from_slice(&[0, 0, 0xAA, 0xAA, 3, 0, 0, 0, 0x08, 0x00, 1, 2, 3]);
    w.radio.rx.push_back(nabemu::rt2573::RxFrame::new(data));
    let mut up = Vec::new();
    run(&mut w, &mut sta, 10, &mut up);
    assert_eq!(up, vec![vec![0xAA, 0xAA, 3, 0, 0, 0, 0x08, 0x00, 1, 2, 3]]);
    let sent: Vec<u8> = w.radio.tx.iter().map(|f| f.data[0]).collect();
    assert_eq!(sent, vec![0xB0, 0x10]);
}

fn rekeys_and_talks(w: &mut World, sta: &mut Station) {
    w.aps[0].rekey_pairwise(&mut w.radio, STA);
    run(w, sta, 200, &mut Vec::new());
    assert!(
        w.ap()
            .events
            .contains(&ApEvent::PairwiseKeyRenewed { sta: STA }),
        "{:?}",
        w.ap().events
    );
    assert_eq!(sta.net_state(), wifi::S_CONNECTED);
    w.aps[0].uplink.clear();
    talks(w, sta);
    assert_eq!(trouble(w), Vec::<&ApEvent>::new());
}

#[test]
fn wpa2_takes_a_new_pairwise_key_on_the_run() {
    let mut w = World::new(Security::wpa2(PASSPHRASE), Wpa3::Off);
    let mut sta = Station::new();
    join(&mut w, &mut sta, &pmk(), &[]);
    rekeys_and_talks(&mut w, &mut sta);
}

#[test]
fn wpa_tkip_takes_a_new_pairwise_key_on_the_run() {
    let mut w = World::new(Security::wpa(PASSPHRASE), Wpa3::Off);
    let mut sta = Station::new();
    join(&mut w, &mut sta, &pmk(), &[]);
    rekeys_and_talks(&mut w, &mut sta);
}

#[test]
fn wpa3_takes_a_new_pairwise_key_on_the_run() {
    let (mut w, mut sta) = joins_wpa3(Wpa3::Only);
    rekeys_and_talks(&mut w, &mut sta);
}

#[test]
fn wpa3_comes_back_without_a_new_password_exchange() {
    let (mut w, mut sta) = joins_wpa3(Wpa3::Only);
    w.aps[0].kick(&mut w.radio, STA, 3);
    run(&mut w, &mut sta, 50, &mut Vec::new());
    assert_eq!(sta.net_state(), wifi::S_IDLE);
    join(&mut w, &mut sta, &pmk(), PASSPHRASE.as_bytes());
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    let events = &w.ap().events;
    assert!(
        events.contains(&ApEvent::PmksaCacheUsed { sta: STA }),
        "{events:?}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, ApEvent::SaeComplete { .. }))
            .count(),
        1
    );
    w.aps[0].uplink.clear();
    talks(&mut w, &mut sta);
}

#[test]
fn wpa3_runs_the_exchange_again_when_the_access_point_forgot() {
    let (mut w, mut sta) = joins_wpa3(Wpa3::Only);
    w.aps[0].kick(&mut w.radio, STA, 3);
    run(&mut w, &mut sta, 50, &mut Vec::new());
    // The access point restarts: its cache is gone.
    let mut fresh = AccessPoint::new("Terrier", BSSID, 6, Security::wpa2(PASSPHRASE));
    fresh.wpa3 = Wpa3::Only;
    // (It reads what was sent from where it last stopped: a new one
    // starts on an empty air.)
    w.radio.tx.clear();
    w.aps[0] = fresh;
    join(&mut w, &mut sta, &pmk(), PASSPHRASE.as_bytes());
    assert_eq!(sta.net_state(), wifi::S_CONNECTED, "{:?}", w.ap().events);
    let events = &w.ap().events;
    assert!(
        events.contains(&ApEvent::AssocRejected {
            sta: STA,
            status: 53
        }),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ApEvent::SaeComplete { .. }))
    );
    talks(&mut w, &mut sta);
}
