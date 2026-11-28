//! The boot bytecode on both machines.

use lapin_metal_cref::{World, boot_bytecode, garenne, run_both, served};

/// The boot bytecode downloads garenne, which then runs for three
/// minutes of board time.
#[test]
fn garenne_runs_the_same() {
    let Some(app) = garenne() else {
        eprintln!("skipped: no garenne build around");
        return;
    };
    let bc = boot_bytecode();
    // The build is already in its envelope.
    let c = run_both(|| World::new(app.clone()), &bc, 3600);
    let console = String::from_utf8_lossy(&c.world.console);
    println!("{console}");
    assert!(console.contains("BOOT DONE"), "{console}");
    let mut kinds = std::collections::BTreeMap::new();
    for l in &c.world.log {
        *kinds
            .entry(l.split(' ').next().unwrap().to_string())
            .or_insert(0) += 1;
    }
    println!("{} turns, {} ms, calls {kinds:?}", c.turns, c.world.now_ms);
}

/// WEP and WPA2 settings: the key the boot bytecode hands the driver.
#[test]
fn boot_with_keys() {
    use nabemu::config::Wifi;
    let bc = boot_bytecode();
    for (wifi, crypt) in [
        (
            Wifi::Wpa2 {
                passphrase: "carotte-violette".into(),
            },
            0x40,
        ),
        (
            Wifi::Wpa {
                passphrase: "carotte-violette".into(),
            },
            0x40,
        ),
        (
            Wifi::Wep {
                key: "0123456789".into(),
                shared_auth: true,
            },
            0x10,
        ),
        (
            Wifi::Wep {
                key: "lapin".into(),
                shared_auth: false,
            },
            0x12,
        ),
    ] {
        let c = run_both(
            || World::with_wifi(served(&bc), wifi.clone(), crypt),
            &bc,
            200,
        );
        let auth: Vec<_> = c
            .world
            .log
            .iter()
            .filter(|l| l.starts_with("auth"))
            .collect();
        assert_eq!(auth.len(), 1, "{:?}", c.world.log);
        println!("{}", auth[0]);
    }
}

#[test]
fn the_boot_bytecode_is_found() {
    let bc = boot_bytecode();
    assert!(bc.len() > 20_000, "{}", bc.len());
}

#[test]
fn boot_up_to_the_download() {
    let bc = boot_bytecode();
    let body = served(&bc);
    let c = run_both(|| World::new(body.clone()), &bc, 400);
    println!("{}", String::from_utf8_lossy(&c.world.console));
}
