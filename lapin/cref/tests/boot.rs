//! The boot bytecode on both machines.

use lapin_metal_cref::{Outcome, World, boot_bytecode, garenne, run_c, run_rust, served};

/// Fail on the first difference between the two runs.
fn same(c: &Outcome, r: &Outcome) {
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
    if let Some(i) = (0..c.heap.len()).find(|&i| c.heap[i] != r.heap[i]) {
        panic!(
            "memory differs from word {i}: C {:08x}, Rust {:08x}",
            c.heap[i], r.heap[i]
        );
    }
    assert_eq!(c.fifo, r.fifo, "audio buffer");
    assert_eq!(c.turns, r.turns);
}

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
    let body = app;
    let c = run_c(World::new(body.clone()), &bc, 3600);
    let r = run_rust(World::new(body), &bc, 3600);
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
    same(&c, &r);
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
        let world = || World::with_wifi(served(&bc), wifi.clone(), crypt);
        let c = run_c(world(), &bc, 200);
        let r = run_rust(world(), &bc, 200);
        let auth: Vec<_> = c
            .world
            .log
            .iter()
            .filter(|l| l.starts_with("auth"))
            .collect();
        assert_eq!(auth.len(), 1, "{:?}", c.world.log);
        println!("{}", auth[0]);
        same(&c, &r);
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
    let mut w = World::new(body.clone());
    w.stop_at = None;
    let c = run_c(w, &bc, 400);
    let r = run_rust(World::new(body), &bc, 400);
    println!("{}", String::from_utf8_lossy(&c.world.console));
    same(&c, &r);
}
