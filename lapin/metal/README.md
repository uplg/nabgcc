# lapin-metal

The Metal virtual machine, the one that runs the rabbit's bytecode: a
port of the C firmware's (`src/vm/*.c`, and the half of
`src/hal/audio.c` that calls back into the bytecode). `no_std`, no
allocation.

The boot bytecode and every program served to rabbits were written
against the C machine, so this one keeps its behaviour down to its
accidents: the same memory layout word for word, a collector that runs
and moves blocks exactly when the C one does, the same results for
out-of-range indexes, and the same bugs where bytecode can see them.
Where the C reads or writes outside its memory, this one reads zero
and writes nothing.

## Using it

```rust
static mut MEMORY: Memory = Memory::new();     // 804 KB: external RAM
let mut vm = Vm::new(board, &mut MEMORY);       // board: impl Host
vm.boot(BOOT_BYTECODE);                         // as main() does
loop {
    vm.main_loop_once();                        // one turn of main()'s loop
}
```

`Host` is the board: one method per C function the machine calls
(`set_led`, `vlsi_read_sci`, `rt2501_send`, …). `main_loop_once` does
what the C main loop does: the loop callback, then for 50 ms the
codec, the recorder and received frames (`net_pending`, `net_take`,
which run the bytecode's network callback), and `net_timer` every
fourth turn. `reboot` and `flash_firmware` do not return.

## How it is checked

`../cref` builds the C machine, unchanged, for the machine running the
tests, and runs it beside this one on the same simulated board (a
settings sector, a codec with a 2 KB buffer, a Wi-Fi driver, and the
emulator's network: DHCP, DNS, HTTP). Each test compares what both
printed, every call they made to the board, and their whole memory,
word for word:

- the boot bytecode taken from the r3 image: open, WEP (both lengths,
  shared key), WPA and WPA2 settings; DHCP, DNS, the download, then the
  downloaded bytecode taking over;
- garenne, when its build is around, for three minutes of board time;
- one program per family of instructions: arithmetic, strings and
  conversions, tables, calls, closures and tail calls, the collector
  under load, running out of memory, sound conversions, play and
  record streams, the board's natives, a change of bytecode carrying
  its environment.

`tests/rabbit.rs` pins what the host's processor cannot show, where the
rabbit's ARM7 and its libgcc decide: division by zero, shifts by 32 or
more, halfwords loaded from odd addresses.

    cargo test                       # here
    (cd ../cref && cargo test --release)

## Where it differs from the C, on purpose

- `i2cRead`: the C reads into a null pointer and returns the first
  bytes of the flash; this returns what the device sent.
- A change of bytecode carries an environment of at most 4 KB, the
  audio buffer it travels through. The C copies a longer one past the
  buffer, over whatever follows it.
- Malformed memory (a block header of size zero) stops the collector's
  walk; the C loops until the watchdog resets the board.
- The memory accessors are out of line: 2.6 KB less flash for a call
  per access. Inlined, the machine takes 22.8 KB.

## Size

20.2 KB of flash on `thumbv4t-none-eabi` at `opt-level = "z"`, the
machine and a stub board together (the C machine and its audio half:
about 19.3 KB).
