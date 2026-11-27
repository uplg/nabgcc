//! A bench for the rabbit's processor: it replays the WPA3 password exchange of the
//! standard's test vector on the rabbit's processor and reports on the
//! serial port, so the emulator can time each step.

#![no_std]
#![no_main]

use lapin_core::sae::{self, vector};
use lapin_fw::{clock, halt, uart};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    lapin_fw::panicked()
}

fn verdict(name: &[u8], ok: bool) {
    uart::write(name);
    uart::write(if ok { b" ok\n" } else { b" WRONG\n" });
}

#[unsafe(no_mangle)]
extern "C" fn main() -> ! {
    lapin_fw::start::link();
    // The chip starts on its ring oscillator: the timings mean nothing
    // before the PLL gives the 32 MHz the firmware runs at.
    clock::init();
    uart::init();
    uart::write(b"lapin bench\n");

    uart::write(b"> hunting\n");
    let element = sae::password_element_looping(&vector::ADDR1, &vector::ADDR2, vector::PASSWORD);
    uart::write(b"> commit\n");
    let mut session = element.map(|e| sae::Session::new(e, &vector::RAND, &vector::MASK));
    let commit_ok = session
        .as_ref()
        .is_some_and(|s| s.commit().to_bytes() == vector::LOCAL_COMMIT);
    uart::write(b"> shared\n");
    let peer = sae::Commit::from_bytes(&vector::PEER_COMMIT);
    let keys_ok = match (&mut session, &peer) {
        (Some(s), Some(p)) => {
            s.process_commit(p).is_ok() && s.pmk == vector::PMK && s.pmkid == vector::PMKID
        }
        _ => false,
    };
    uart::write(b"> confirm\n");
    let confirm = session.as_ref().and_then(|s| s.confirm(1));
    uart::write(b"> point\n");
    let point = sae::password_point(vector::SSID, vector::PASSWORD, vector::IDENTIFIER);
    uart::write(b"> element\n");
    let h2e = point.map(|p| sae::password_element_from_point(&p, &vector::ADDR1B, &vector::ADDR2B));
    let h2e_ok = h2e.and_then(|e| e.to_bytes()) == Some(vector::ELEMENT);
    uart::write(b"> done\n");

    verdict(b"commit", commit_ok);
    verdict(b"keys", keys_ok);
    verdict(b"confirm", confirm.is_some());
    verdict(b"hash-to-element", h2e_ok);
    uart::write(b"end\n");
    halt()
}
