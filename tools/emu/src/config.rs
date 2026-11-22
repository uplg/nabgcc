//! The rabbit's settings, as the boot bytecode keeps them in the last
//! flash sector (`CONF_*` in `mtl/boot/boot.0.0.0.13.mtl`).

use crate::crypto;

pub const OFFSET: usize = 0x1F000;
pub const LENGTH: usize = 208;

const SERVER_URL: usize = 0;
const DHCP: usize = 41;
const NETMASK: usize = 46;
const SSID: usize = 58;
const AUTH: usize = 90;
const CRYPT: usize = 91;
const KEY: usize = 92;
const PMK: usize = 175;
const MAGIC: usize = 207;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wifi {
    Open,
    /// The key as typed in the setup page: 5 or 13 characters, or hex.
    Wep {
        key: String,
        shared_auth: bool,
    },
    Wpa {
        passphrase: String,
    },
    Wpa2 {
        passphrase: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Host and path the bytecode is fetched from, without `http://`.
    pub server: String,
    pub ssid: String,
    pub wifi: Wifi,
}

impl Config {
    pub fn new(ssid: &str, wifi: Wifi) -> Self {
        Config {
            server: "r.nabaztag.com/vl".into(),
            ssid: ssid.into(),
            wifi,
        }
    }

    /// The 208 bytes the setup page would have saved.
    pub fn to_bytes(&self) -> [u8; LENGTH] {
        let mut c = [b'-'; LENGTH];
        let mut text = |at: usize, room: usize, s: &str| {
            let n = s.len().min(room - 1);
            c[at..at + n].copy_from_slice(&s.as_bytes()[..n]);
            c[at + n] = 0;
        };
        text(SERVER_URL, 41, &self.server);
        text(SSID, 32, &self.ssid);
        let (crypt, auth, key, pmk) = match &self.wifi {
            Wifi::Open => (0, 0, "", None),
            Wifi::Wep { key, shared_auth } => (16, *shared_auth as u8, key.as_str(), None),
            Wifi::Wpa { passphrase } => (32, 0, passphrase.as_str(), Some(passphrase)),
            Wifi::Wpa2 { passphrase } => (64, 0, passphrase.as_str(), Some(passphrase)),
        };
        text(KEY, 64, key);
        // DHCP on, addresses blank, the default netmask.
        c[DHCP] = 1;
        c[DHCP + 1..SSID].fill(0);
        c[NETMASK..NETMASK + 3].fill(255);
        c[AUTH] = auth;
        c[CRYPT] = crypt;
        // Proxy off, no login, no password.
        c[156..PMK].fill(0);
        if let Some(passphrase) = pmk {
            // The setup page stores the derived key, not the passphrase.
            c[PMK..PMK + 32].copy_from_slice(&crypto::wpa_psk(passphrase, &self.ssid));
        }
        c[MAGIC] = 0x47;
        c
    }

    /// Put the settings in a flash image, as if the rabbit had been set
    /// up through its configuration page.
    pub fn install(&self, flash: &mut [u8]) {
        flash[OFFSET..OFFSET + LENGTH].copy_from_slice(&self.to_bytes());
    }
}
