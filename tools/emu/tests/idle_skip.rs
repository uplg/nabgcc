//! The emulator skips the turns of a loop that changes nothing
//! (`Machine::skip_idle`). Whatever a firmware does, it must see and do
//! the same with it as without: the same bytes on its serial port, the
//! same frames on the air, the same restarts, the same requests.

use nabemu::Machine;
use nabemu::air::{AccessPoint, Security};
use nabemu::config::{Config, Wifi};
use nabemu::lan::{Lan, Response};
use nabemu::metal;

struct Seen {
    console: Vec<u8>,
    air: Vec<Vec<u8>>,
    events: String,
    requests: usize,
}

fn run(image: &[u8], skip: bool) -> (Seen, u64) {
    let mut m = Machine::from_file(image).0;
    m.skip_idle = skip;
    Config::new("Terrier", Wifi::Open).install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::Open,
    ));
    let mut lan = Lan::new();
    let served = metal::boot_response(&metal::print_number(4242));
    lan.handler = Box::new(move |_| Response::ok(served.clone()));
    m.lan = Some(lan);
    m.run_until_ms(25_000);
    let seen = Seen {
        console: m.soc.uart_tx.clone(),
        air: m.radio.borrow().tx.iter().map(|t| t.data.clone()).collect(),
        events: format!("{:?}", m.events),
        requests: m.lan.as_ref().unwrap().requests.len(),
    };
    (seen, m.skipped)
}

fn same_with_and_without(path: &str) {
    let Ok(image) = std::fs::read(path) else {
        eprintln!("skipped: {path} not there");
        return;
    };
    let ((a, _), (b, skipped)) = (run(&image, false), run(&image, true));
    eprintln!("{path}: {skipped} cycles skipped");
    assert!(skipped > 0, "nothing skipped: the test lost its point");
    assert_eq!(
        String::from_utf8_lossy(&a.console),
        String::from_utf8_lossy(&b.console)
    );
    assert_eq!(a.events, b.events);
    assert_eq!(a.requests, b.requests);
    assert_eq!(a.air.len(), b.air.len(), "frames sent");
    assert!(a.air == b.air, "the frames differ");
}

#[test]
fn r3_sees_the_same() {
    same_with_and_without(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../artifacts/Nab-wpa23-gtk-r3.sim"
    ));
}

#[test]
fn lapin_sees_the_same() {
    same_with_and_without(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../lapin/target/lapin-full.bin"
    ));
}
