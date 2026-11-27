//! The boot bytecode's unpacker on any stream, into any room.

#![no_main]

use lapin_fuzz::input::Input;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let room = input.u16() as usize;
    let packed = input.bytes(usize::MAX);
    let mut out = vec![0u8; room];
    let n = lapin_core::lz::unpack(packed, &mut out);
    assert!(n <= room);
});
