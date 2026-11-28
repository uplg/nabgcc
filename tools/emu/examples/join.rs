//! Join an access point and print what both sides saw.
//! usage: join <firmware> <open|wep|wepshared|wpa|wpa2|mixed> [ms]
mod common;

use nabemu::air::{AccessPoint, Security};
use nabemu::config::{Config, Wifi};

fn main() {
    let mut args = common::Args::new();
    let mut m = args.machine();
    let kind = args.word().unwrap_or_else(|| "wpa2".into());
    let ms = args.number(10_000);
    let pass = "carotte-violette";
    let (wifi, security) = match kind.as_str() {
        "open" => (Wifi::Open, Security::Open),
        "wep" => (
            Wifi::Wep {
                key: "abcde".into(),
                shared_auth: false,
            },
            Security::Wep {
                key: b"abcde".to_vec(),
                shared_auth: false,
            },
        ),
        "wepshared" => (
            Wifi::Wep {
                key: "abcde".into(),
                shared_auth: true,
            },
            Security::Wep {
                key: b"abcde".to_vec(),
                shared_auth: true,
            },
        ),
        "wpa" => (
            Wifi::Wpa {
                passphrase: pass.into(),
            },
            Security::wpa(pass),
        ),
        "mixed" => (
            Wifi::Wpa2 {
                passphrase: pass.into(),
            },
            Security::wpa2_tkip_group(pass),
        ),
        _ => (
            Wifi::Wpa2 {
                passphrase: pass.into(),
            },
            Security::wpa2(pass),
        ),
    };
    Config::new("Terrier", wifi).install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        security,
    ));
    m.lan = Some(nabemu::lan::Lan::new());
    m.run_until_ms(ms);
    for line in m.console().lines().filter(|l| !l.starts_with("0000")) {
        println!("| {line}");
    }
    for e in &m.air[0].events {
        println!("ap: {e:?}");
    }
    for f in &m.air[0].uplink {
        println!("uplink: {} bytes, type {:02x}{:02x}", f.len(), f[12], f[13]);
    }
    let lan = m.lan.as_ref().unwrap();
    println!(
        "dhcp {:?} leased {:?} dns {:?}",
        lan.dhcp_messages, lan.leased_to, lan.dns_queries
    );
    for r in &lan.requests {
        println!(
            "http: {} {} | {}",
            r.method,
            r.target,
            r.headers.replace("\r\n", " | ")
        );
    }
    let radio = m.radio.borrow();
    println!(
        "cipher errors {:?}, dropped {}",
        radio.rx_cipher_errors, radio.rx_dropped
    );
    for f in radio.tx.iter().filter(|f| f.data[0] != 0x40).take(0) {
        let hex: String = f.data.iter().map(|b| format!("{b:02x}")).collect();
        println!("tx {:4} {hex}", f.data.len());
    }
}
