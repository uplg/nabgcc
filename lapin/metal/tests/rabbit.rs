//! What the machine does the way the rabbit's processor does it, where
//! the C machine built for another processor would not show it (the
//! rest is checked against the C machine in `../cref`).

mod kit;

use kit::asm::{Fun, bytecode};
use kit::{Board, memory};
use lapin_metal::Vm;
use lapin_metal::op::*;

/// A program of one function, `f`, printing what it leaves, one value
/// per `IECHOLN`, with `strings` as globals.
fn run(strings: &[&[u8]], f: &mut Fun) -> String {
    f.op(NIL_).op(RET);
    let mut mem = memory();
    let mut vm = Vm::new(Board::default(), &mut mem);
    vm.boot(&bytecode(strings, &[f]));
    String::from_utf8(vm.into_host().console).unwrap()
}

/// Print `a o b`.
fn binary(f: &mut Fun, a: i32, o: i32, b: i32) {
    f.int(a).int(b).op(o).show();
}

#[test]
fn dividing_by_zero_gives_what_libgcc_gives() {
    // __aeabi_idiv: the largest number of the dividend's sign, cut to
    // the machine's 31 bits; __aeabi_idivmod leaves a zero remainder.
    let mut f = Fun::new(0, 0);
    for a in [5, -5, 0] {
        binary(&mut f, a, DIV, 0);
        binary(&mut f, a, MOD, 0);
    }
    assert_eq!(run(&[], &mut f), "-1\r\n0\r\n0\r\n0\r\n0\r\n0\r\n");
}

#[test]
fn shifts_by_32_and_more_shift_everything_out() {
    // The ARM shifts by the low byte of the count. (1 << 31 is 0 once
    // cut to the machine's 31 bits.)
    let mut f = Fun::new(0, 0);
    for b in [31, 32, 33, 255, 256, 257] {
        binary(&mut f, 1, SHL, b);
        binary(&mut f, -8, SHR, b);
    }
    assert_eq!(
        run(&[], &mut f),
        "0\r\n-1\r\n0\r\n-1\r\n0\r\n-1\r\n0\r\n-1\r\n1\r\n-8\r\n2\r\n-4\r\n"
    );
}

#[test]
fn a_checksum_from_an_odd_offset_reads_rotated_halfwords() {
    // From an odd address the ARM7TDMI loads the halfword below, rotated
    // by a byte across the 32-bit register.
    let mut f = Fun::new(0, 0);
    f.b(GETGLOBALB, 0).int(1).int(2).int(0).op(NETCHK).show();
    // Bytes 0 and 1 are 0x12 0x34: loaded as 0x3412 then rotated to
    // 0x12000034, folded to 0x1234, swapped to 0x3412.
    assert_eq!(
        run(&[&[0x12, 0x34, 0x56, 0x78]], &mut f),
        format!("{}\r\n", 0x3412)
    );
}

#[test]
fn i2c_read_returns_what_the_device_said() {
    let mut f = Fun::new(0, 0);
    f.int(0x42).int(3).op(I2CREAD).shows();
    assert_eq!(run(&[], &mut f), "abc\r\n");
}
