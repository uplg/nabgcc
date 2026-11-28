//! Just enough of the Metal virtual machine's bytecode format to write
//! small test programs by hand (see `src/vm/vloader.c`, `inc/vm/vbc.h`).
//!
//! A bytecode is: the globals (preceded by their total length), the
//! code (preceded by its length), then the function table. Function 0
//! runs when the bytecode is loaded.
//!
//! A bytecode the server sends (started by the boot bytecode's
//! `OPbytecode`) loses its last global on r3 once its main function has
//! returned (lapin keeps it): the stack's top is then one past it, and
//! a callback's frame lands on it. A test that reads its globals in a
//! callback on both firmwares keeps a spare one last (see
//! `tests/observable.rs`, `the_last_global_of_a_served_bytecode_is_kept`).

pub const OP_RET: u8 = 1;
pub const OP_INT: u8 = 3;
pub const OP_GETGLOBALB: u8 = 36;
pub const OP_IECHOLN: u8 = 95;
pub const OP_SECHOLN: u8 = 96;
pub const OP_RFID_GET: u8 = 101;
pub const OP_RFID_READ: u8 = 148;
pub const OP_RFID_WRITE: u8 = 149;
pub const OP_DROP: u8 = 5;
pub const OP_FLASH_FIRMWARE: u8 = 143;

/// Start of a function taking no argument and using no local.
pub const FUNCTION_HEADER: [u8; 3] = [0, 0, 0];

/// `OP_INT` with its operand.
pub fn int(value: i32) -> Vec<u8> {
    let mut code = vec![OP_INT];
    code.extend_from_slice(&value.to_le_bytes());
    code
}

/// Assemble a bytecode with one function and string globals.
pub fn bytecode(strings: &[&[u8]], function: &[u8]) -> Vec<u8> {
    bytecode_functions(strings, &[function])
}

/// The same with several functions, numbered from 0 in that order
/// (the first runs at load).
pub fn bytecode_functions(strings: &[&[u8]], functions: &[&[u8]]) -> Vec<u8> {
    let mut globals = Vec::new();
    for s in strings {
        globals.extend_from_slice(&((s.len() as u32) << 2 | 1).to_le_bytes());
        globals.extend_from_slice(s);
    }
    let mut bc = (globals.len() as u32 + 4).to_le_bytes().to_vec();
    bc.extend_from_slice(&globals);
    let code: Vec<u8> = functions.concat();
    bc.extend_from_slice(&(code.len() as u32).to_le_bytes());
    bc.extend_from_slice(&code);
    bc.extend_from_slice(&(functions.len() as u16).to_le_bytes());
    let mut at = 0u32;
    for f in functions {
        bc.extend_from_slice(&at.to_le_bytes());
        at += f.len() as u32;
    }
    bc
}

/// A program that prints `number` on the serial console.
pub fn print_number(number: i32) -> Vec<u8> {
    let mut f = FUNCTION_HEADER.to_vec();
    f.extend(int(number));
    f.extend([OP_IECHOLN, OP_RET]);
    bytecode(&[], &f)
}

/// A program that writes `image` over the firmware and reboots.
pub fn flash_firmware(image: &[u8]) -> Vec<u8> {
    let mut f = FUNCTION_HEADER.to_vec();
    f.extend([OP_GETGLOBALB, 0]);
    // The two magic numbers `OPflashFirmware` demands.
    f.extend(int(0x13FB_6754));
    f.extend(int(0x0407_FE58));
    f.extend([OP_FLASH_FIRMWARE, OP_RET]);
    bytecode(&[image], &f)
}

/// What the server answers to `bc.jsp`: the bytecode in its envelope.
pub fn boot_response(bytecode: &[u8]) -> Vec<u8> {
    let mut body = format!("amber{:08x}", bytecode.len()).into_bytes();
    body.extend_from_slice(bytecode);
    body.extend_from_slice(b"Mind");
    body
}
