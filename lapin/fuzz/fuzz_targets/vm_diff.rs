//! The Rust machine against the C one (`lapin/cref`) on random
//! programs the C machine runs within its memory: the same console,
//! the same calls to the board, the same registers and memory, word
//! for word.

#![no_main]

use lapin_fuzz::input::Input;
use lapin_metal_cref::{Outcome, World, run_c, run_rust};

fn same(c: &Outcome, r: &Outcome) {
    assert_eq!(
        String::from_utf8_lossy(&c.world.console),
        String::from_utf8_lossy(&r.world.console)
    );
    assert_eq!(c.world.log, r.world.log);
    assert_eq!(c.registers, r.registers, "stack, heap index, heap start");
    if let Some(i) = (0..c.heap.len()).find(|&i| c.heap[i] != r.heap[i]) {
        panic!(
            "memory differs from word {i}: C {:08x}, Rust {:08x}",
            c.heap[i], r.heap[i]
        );
    }
    assert_eq!(c.fifo, r.fifo);
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let bc = lapin_fuzz::program::program(&mut input);
    if std::env::var_os("LAPIN_FUZZ_DEBUG").is_some() {
        eprintln!("{} bytes of bytecode", bc.len());
    }
    let c = run_c(World::new(Vec::new()), &bc, 1);
    let r = run_rust(World::new(Vec::new()), &bc, 1);
    same(&c, &r);
});
