//! What every example starts with: the firmware named first on the
//! command line, then whatever else it takes, in order.

// Each example is its own crate and takes only what it needs of this.
#![allow(dead_code)]

use nabemu::Machine;

pub struct Args(std::iter::Skip<std::env::Args>);

impl Args {
    pub fn new() -> Self {
        Args(std::env::args().skip(1))
    }

    /// The next argument, a file, read whole: `what` names it in the
    /// error.
    pub fn file(&mut self, what: &str) -> Vec<u8> {
        let path = self.0.next().unwrap_or_else(|| panic!("{what} path"));
        std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    /// The next argument, a firmware file, on a fresh board.
    pub fn machine(&mut self) -> Machine {
        Machine::from_file(&self.file("firmware")).0
    }

    /// The next argument as a number, or `default`.
    pub fn number(&mut self, default: u64) -> u64 {
        self.0
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(default)
    }

    /// The next argument, if there is one.
    pub fn word(&mut self) -> Option<String> {
        self.0.next()
    }
}
