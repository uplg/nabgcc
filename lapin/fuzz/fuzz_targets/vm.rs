//! The machine boots any bytecode, then runs a few turns of the main
//! loop, a budget of instructions in all (a bytecode may loop forever,
//! as on the C machine: the watchdog's business). Nothing may panic or
//! break the board's contract.

#![no_main]

use lapin_fuzz::input::Input;
use lapin_fuzz::vm::{Board, assemble, memory};
use lapin_metal::Vm;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let how = input.u8();
    let turns = input.u8() % 8;
    // The machine calls it every 256 instructions.
    let board = Board::new(256_000, &mut input);
    let bytecode = if how & 1 == 0 {
        assemble(&mut input)
    } else {
        input.bytes(usize::MAX).to_vec()
    };
    let debug = std::env::var_os("LAPIN_FUZZ_DEBUG").is_some();
    if !lapin_fuzz::vm::globals_ok(&bytecode) {
        if debug {
            eprintln!("malformed globals");
        }
        return;
    }
    let mut mem = memory();
    let mut vm = Vm::new(board, &mut mem);
    lapin_fuzz::stoppable(|| {
        vm.boot(&bytecode);
        for _ in 0..turns {
            vm.main_loop_once();
        }
    });
    if debug {
        let console = &vm.host.console;
        eprintln!(
            "{}",
            String::from_utf8_lossy(&console[..console.len().min(2000)])
        );
    }
});
