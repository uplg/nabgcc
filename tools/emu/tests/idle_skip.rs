//! The emulator skips the turns of a loop that changes nothing
//! (`Machine::skip_idle`). Whatever a firmware does, it must see and do
//! the same with it as without: the same bytes on its serial port, the
//! same frames on the air, the same restarts, the same requests.

mod common;

use nabemu::metal;

struct Seen {
    console: Vec<u8>,
    air: Vec<Vec<u8>>,
    events: String,
    requests: usize,
}

fn run(image: &[u8], skip: bool) -> (Seen, u64) {
    let mut m = common::serving(image, &metal::print_number(4242));
    m.skip_idle = skip;
    m.run_until_ms(25_000);
    let seen = Seen {
        console: m.soc.uart_tx.clone(),
        air: m.radio.borrow().tx.iter().map(|t| t.data.clone()).collect(),
        events: format!("{:?}", m.events),
        requests: m.lan.as_ref().unwrap().requests.len(),
    };
    (seen, m.skipped)
}

fn same_with_and_without(name: &str, image: &[u8]) {
    // With the interrupt line seen late the emulator does not skip.
    if std::env::var_os("NABEMU_IRQ_LAG").is_some() {
        return;
    }
    let ((a, _), (b, skipped)) = (run(image, false), run(image, true));
    eprintln!("{name}: {skipped} cycles skipped");
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
    same_with_and_without("r3", &common::r3());
}

#[test]
fn lapin_sees_the_same() {
    let Some(lapin) = common::lapin() else { return };
    same_with_and_without("lapin", &lapin);
}
