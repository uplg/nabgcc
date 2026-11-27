//! What the fuzz targets share: an air for the station, with an access
//! point that knows the keys (so that fuzzed frames get past the
//! integrity checks and into the parsers behind them), and a board for
//! the bytecode machine.
//!
//! The targets, run from this directory:
//!
//! - `station`: the 802.11 station in every state of a connection
//!   (open, WEP, WPA, WPA2, WPA3, cached WPA3) and the access point
//!   mode, fed frames, timers and the bytecode's calls;
//! - `sae`, `ccmp`, `lz`: the parsers and ciphers on their own;
//! - `vm`: the bytecode machine booting anything (built with `-O`: its
//!   arithmetic wraps on purpose, as the C's does);
//! - `vm_diff`: the Rust machine against the C one, on programs the C
//!   one runs within its memory (`--features cref`).
//!
//! ```text
//! cargo fuzz run station -- -max_total_time=600
//! cargo fuzz run -O vm -- -timeout=20 -max_len=65536
//! cargo fuzz run -O --features cref vm_diff
//! ```
//!
//! What they found is pinned by the crates' own tests; the corpus and
//! the artifacts stay out of the repository.

pub mod input;
pub mod program;
pub mod station;
pub mod vm;

/// Run `f`, and come back from a stop the board itself asked for
/// (`Stop`, raised with `panic_any`): a reboot, a firmware flashed, the
/// budget of instructions spent. Any other panic goes on to the fuzzer.
pub fn stoppable<R>(f: impl FnOnce() -> R) -> Option<R> {
    quiet_stops();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => Some(r),
        Err(e) if e.downcast_ref::<Stop>().is_some() => None,
        Err(e) => std::panic::resume_unwind(e),
    }
}

/// The board stopped the machine.
#[derive(Debug)]
pub struct Stop;

fn quiet_stops() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let loud = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if info.payload().downcast_ref::<Stop>().is_none() {
                loud(info)
            }
        }));
    });
}
