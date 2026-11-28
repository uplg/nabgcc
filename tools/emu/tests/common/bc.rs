//! Bytecodes the tests assemble by hand: the interpreter's opcodes, the
//! globals and functions of a bytecode, and the pieces several tests'
//! programs share.

use nabemu::metal;
use op::*;

/// The interpreter's opcodes the tests use, by the C's names.
pub mod op {
    // Each test binary uses a part of them.
    #[allow(unused_imports)]
    pub use nabemu::metal::{
        OP_DROP as DROP, OP_GETGLOBALB as GETGLOBALB, OP_IECHOLN as IECHOLN, OP_RET as RET,
        OP_SECHOLN as SECHOLN,
    };
    pub const NIL: u8 = 4;
    pub const DUP: u8 = 6;
    pub const GETLOCALB: u8 = 7;
    pub const ADD: u8 = 9;
    pub const SUB: u8 = 10;
    pub const AND: u8 = 14;
    pub const NEG: u8 = 19;
    pub const EQ: u8 = 22;
    pub const LT: u8 = 24;
    pub const GT: u8 = 25;
    pub const GOTO: u8 = 28;
    pub const ELSE: u8 = 29;
    pub const DEFTABB: u8 = 32;
    pub const SETGLOBAL: u8 = 42;
    pub const HD: u8 = 45;
    pub const TIME_MS: u8 = 53;
    pub const TIME: u8 = 61;
    pub const STRCPY: u8 = 64;
    pub const STRLEN: u8 = 68;
    pub const STRGET: u8 = 69;
    pub const PLAYSTART: u8 = 79;
    pub const PLAYFEED: u8 = 80;
    pub const GC: u8 = 87;
    pub const BYTECODE: u8 = 93;
    pub const LOOPCB: u8 = 94;
    pub const ENVGET: u8 = 98;
    pub const ENVSET: u8 = 99;
    pub const SNDVOL: u8 = 100;
    pub const NETCB: u8 = 103;
    pub const NETSEND: u8 = 104;
    pub const NETSTATE: u8 = 105;
    pub const NETSETMODE: u8 = 108;
    pub const NETSCAN: u8 = 109;
    pub const NETAUTH: u8 = 110;
    pub const REBOOT: u8 = 136;
    pub const STRCMP: u8 = 137;
    pub const ADP2WAV: u8 = 138;
    pub const WAV2ADP: u8 = 139;
    pub const ALAW2WAV: u8 = 140;
    pub const WAV2ALAW: u8 = 141;
    pub const NETPMK: u8 = 142;
}

/// A global, as a bytecode's globals hold it.
pub enum Global<'a> {
    /// A string.
    Str(&'a [u8]),
    /// A word as it is: the integer 0 is 0, nil `u32::MAX`.
    Word(u32),
}

/// A bytecode with `globals` and `functions` (whole, their headers
/// included), the first run when loaded.
pub fn assemble(globals: &[Global], functions: &[&[u8]]) -> Vec<u8> {
    let mut words = Vec::new();
    for g in globals {
        match g {
            Global::Str(s) => {
                words.extend(((s.len() as u32) << 2 | 1).to_le_bytes());
                words.extend_from_slice(s);
            }
            Global::Word(w) => words.extend(w.to_le_bytes()),
        }
    }
    // The same without globals, then the globals in their place.
    let mut bc = metal::bytecode_functions(&[], functions);
    let size = (words.len() as u32 + 4).to_le_bytes();
    bc.splice(0..4, size.into_iter().chain(words));
    bc
}

/// A function taking `args` arguments, with `locals` locals more.
pub fn function(args: u8, locals: u16, code: &[u8]) -> Vec<u8> {
    let mut f = vec![args];
    f.extend(locals.to_le_bytes());
    f.extend_from_slice(code);
    f
}

/// Point the jump whose operand is at `at` of `code` to the end of
/// `code`, which starts at byte `base` of its function (from after the
/// function's header, where jumps count from).
pub fn land_here(code: &mut [u8], at: usize, base: usize) {
    let here = ((base + code.len()) as u16).to_le_bytes();
    code[at..at + 2].copy_from_slice(&here);
}

/// A loop that keeps the bytecode busy `ms` on the rabbit's clock, at
/// byte `base` of its function, for as long as `cond` (code that leaves
/// a value) is true too: an empty `cond` is always true.
pub fn pause_while(base: usize, ms: i32, cond: &[u8]) -> Vec<u8> {
    let mut b = vec![TIME_MS];
    b.extend(metal::int(ms));
    b.push(ADD);
    let top = (base + b.len()) as u16;
    let mut exits = Vec::new();
    for test in [&[DUP, TIME_MS, GT][..], cond] {
        if !test.is_empty() {
            b.extend_from_slice(test);
            b.extend([ELSE, 0, 0]);
            exits.push(b.len() - 2);
        }
    }
    b.push(GOTO);
    b.extend(top.to_le_bytes());
    let end = b.len();
    for at in exits {
        land_here(&mut b[..end], at, base);
    }
    b.push(DROP);
    b
}

/// The same, all `ms` long.
pub fn pause(base: usize, ms: i32) -> Vec<u8> {
    pause_while(base, ms, &[])
}

/// The start of a main function that sets `g<table> = [name bssid bssid
/// -40 6 255 WPA2+CCMP]`: what a scan says of the home network, from
/// the globals `name` and `bssid`.
pub fn main_with_home_network(table: i32, name: u8, bssid: u8) -> Vec<u8> {
    let mut b = metal::FUNCTION_HEADER.to_vec();
    b.extend(metal::int(table));
    b.extend([GETGLOBALB, name, GETGLOBALB, bssid, GETGLOBALB, bssid]);
    for v in [-40, 6, 255, 0x4A] {
        b.extend(metal::int(v));
    }
    b.extend([DEFTABB, 7, SETGLOBAL, DROP]);
    b
}

/// `loopcb #<function>`, then the end of the main function.
pub fn loop_callback(function: i32) -> Vec<u8> {
    let mut b = metal::int(function);
    b.extend([LOOPCB, DROP]);
    b.extend(metal::int(0));
    b.push(RET);
    b
}

/// The loop callback that joins the home network again whenever the
/// link is idle, as the rabbit's bytecode does: `if netState == IDLE
/// then netAuth g<table> 0 WPA2 <key>`, `key` the code that pushes the
/// key (nil: the passphrase's, derived again).
pub fn rejoin(table: u8, key: &[u8]) -> Vec<u8> {
    let mut b = vec![NETSTATE];
    b.extend(metal::int(1));
    b.extend([EQ, ELSE, 0, 0]);
    let skip = b.len() - 2;
    b.extend([GETGLOBALB, table]);
    b.extend(metal::int(0));
    b.extend(metal::int(0x40));
    b.extend_from_slice(key);
    b.extend([NETAUTH, DROP]);
    land_here(&mut b, skip, 0);
    b.extend(metal::int(0));
    b.push(RET);
    function(0, 0, &b)
}
