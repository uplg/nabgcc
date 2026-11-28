//! Bytecode for the tests, assembled: functions with labels for their
//! jumps, and the bytecode that holds them. Shared by this crate's tests
//! and by `../cref`'s, each using its part.
#![allow(dead_code)]

use lapin_metal::op::{DROP, IECHOLN, INT, NIL_, SECHOLN};

/// A function being assembled, with labels for its jumps.
#[derive(Default)]
pub struct Fun {
    narg: u8,
    nloc: u16,
    /// The code so far, open to raw bytes.
    pub code: Vec<u8>,
    labels: Vec<Option<u16>>,
    fixups: Vec<(usize, usize)>,
}

impl Fun {
    pub fn new(narg: u8, nloc: u16) -> Self {
        Fun {
            narg,
            nloc,
            ..Default::default()
        }
    }
    pub fn op(&mut self, o: i32) -> &mut Self {
        self.code.push(o as u8);
        self
    }
    pub fn b(&mut self, o: i32, v: u8) -> &mut Self {
        self.code.extend([o as u8, v]);
        self
    }
    pub fn int(&mut self, v: i32) -> &mut Self {
        self.code.push(INT as u8);
        self.code.extend(v.to_le_bytes());
        self
    }
    pub fn label(&mut self) -> usize {
        self.labels.push(None);
        self.labels.len() - 1
    }
    pub fn here(&mut self, l: usize) -> &mut Self {
        self.labels[l] = Some(self.code.len() as u16);
        self
    }
    pub fn jump(&mut self, o: i32, l: usize) -> &mut Self {
        self.code.push(o as u8);
        self.fixups.push((self.code.len(), l));
        self.code.extend([0, 0]);
        self
    }
    /// An integer, or nil for a negative one: the natives' optional
    /// arguments.
    pub fn int_or_nil(&mut self, v: i32) -> &mut Self {
        if v < 0 { self.op(NIL_) } else { self.int(v) }
    }
    /// Print the top of the stack as a number and drop it.
    pub fn show(&mut self) -> &mut Self {
        self.op(IECHOLN).op(DROP)
    }
    /// Print the top of the stack as a string and drop it.
    pub fn shows(&mut self) -> &mut Self {
        self.op(SECHOLN).op(DROP)
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut code = self.code.clone();
        for &(at, l) in &self.fixups {
            let to = self.labels[l].expect("label placed");
            code[at..at + 2].copy_from_slice(&to.to_le_bytes());
        }
        let mut out = vec![self.narg];
        out.extend(self.nloc.to_le_bytes());
        out.extend(code);
        out
    }
}

/// A bytecode: string globals, then functions (the first runs).
pub fn bytecode(strings: &[&[u8]], funs: &[&Fun]) -> Vec<u8> {
    bytecode_with(strings, &[], funs)
}

/// The same, with integer globals after the strings.
pub fn bytecode_with(strings: &[&[u8]], ints: &[i32], funs: &[&Fun]) -> Vec<u8> {
    let mut globals = Vec::new();
    for s in strings {
        globals.extend(((s.len() as u32) << 2 | 1).to_le_bytes());
        globals.extend_from_slice(s);
    }
    for i in ints {
        globals.extend((i << 1).to_le_bytes());
    }
    let mut bc = (globals.len() as u32 + 4).to_le_bytes().to_vec();
    bc.extend(globals);
    let mut code = Vec::new();
    let mut starts = Vec::new();
    for f in funs {
        starts.push(code.len() as u32);
        code.extend(f.bytes());
    }
    bc.extend((code.len() as u32).to_le_bytes());
    bc.extend(code);
    bc.extend((funs.len() as u16).to_le_bytes());
    for s in starts {
        bc.extend(s.to_le_bytes());
    }
    bc
}
