//! The two ears: a motor each, and an encoder wheel with seventeen
//! teeth and a gap that marks the reference position.
//!
//! Timers 2 to 5 drive the motor bridges by pulse width; timers 0 and
//! 1 are clocked by the encoders and count their teeth.

use crate::reg;

reg! {
    FTM0GR: u16 = 0xB7F0_0010;
    FTM1GR: u16 = 0xB7F0_0030;
    FTMEN: u8 = 0xB7F0_00C0;
}

const TIMERS: usize = 0xB7F0_0000;
const CONTROL: usize = 0x00;
const COUNTER: usize = 0x08;
const COMPARE: usize = 0x10;
const OUTPUT_LEVEL: usize = 0x14;

fn timer8(n: usize, offset: usize) -> crate::reg::Reg<u8> {
    // SAFETY: a register of one of the six flexible timers.
    unsafe { crate::reg::Reg::at(TIMERS + n * 0x20 + offset) }
}

fn timer16(n: usize, offset: usize) -> crate::reg::Reg<u16> {
    // SAFETY: as above.
    unsafe { crate::reg::Reg::at(TIMERS + n * 0x20 + offset) }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Turn {
    Stop,
    Forward,
    Backward,
}

pub fn init() {
    for n in 0..6 {
        // Timers 0 and 1 capture on the encoders' rising edges, the
        // others generate the pulses.
        timer8(n, CONTROL).write(if n < 2 { 0x1E } else { 0x10 });
        timer8(n, OUTPUT_LEVEL).write(1);
        timer16(n, COUNTER).write(0);
    }
    for n in 2..6 {
        timer16(n, COMPARE).write(0);
    }
    FTMEN.write(0x3F);
}

/// Run or stop an ear (0 or 1) at full speed.
pub fn turn(ear: usize, turn: Turn) {
    let forward = 2 + (ear & 1) * 2;
    let (f, b) = match turn {
        Turn::Stop => (0, 0),
        Turn::Forward => (0xFFFF, 0),
        Turn::Backward => (0, 0xFFFF),
    };
    // Never both sides of the bridge at once: off first.
    timer16(forward, COMPARE).write(0);
    timer16(forward + 1, COMPARE).write(0);
    timer16(forward, COMPARE).write(f);
    timer16(forward + 1, COMPARE).write(b);
}

/// Teeth seen by an ear's encoder since power-on, modulo 65536.
pub fn teeth(ear: usize) -> u16 {
    if ear & 1 == 0 {
        FTM0GR.read()
    } else {
        FTM1GR.read()
    }
}
