//! Programs for comparing the two machines: random, but such that the
//! C machine stays inside its memory (it reads and writes wherever a
//! bytecode points it, which this one does not, by design).
//!
//! The main function works on sixteen typed locals: integers,
//! strings, tables of known sizes, and values of unknown kind (what a
//! table held), which are only printed as numbers or stored. Indexes
//! and lengths are small constants; every other value may be
//! anything. Blocks are skipped by `ELSE` or repeated by a counted
//! loop; inside them, locals keep their kind.

use lapin_metal::op::*;

use crate::input::Input;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Int,
    Str,
    /// A table of this many words.
    Tab(u8),
    /// A function of two integers with this many of them fixed
    /// (`FIXARG`): one or two.
    Fun(u8),
    Any,
}

const LOCALS: usize = 16;

struct Gen<'a, 'b> {
    input: &'a mut Input<'b>,
    code: Vec<u8>,
    locals: [Kind; LOCALS],
    /// Locals a loop counts with: not to be written.
    reserved: u32,
    depth: u32,
    globals: usize,
    /// This function's number, and how many there are: a function
    /// calls only those after it (no recursion, so no end to wait for).
    fun: usize,
    funs: usize,
}

const INTS: [i32; 12] = [
    0,
    1,
    -1,
    2,
    7,
    -7,
    255,
    0x3FFF_FFFF,
    -0x4000_0000,
    12345,
    31,
    48,
];

impl Gen<'_, '_> {
    fn op(&mut self, o: i32) {
        self.code.push(o as u8);
    }

    fn int(&mut self, v: i32) {
        if (0..256).contains(&v) {
            self.code.extend([INTB as u8, v as u8]);
        } else {
            self.code.push(INT as u8);
            self.code.extend(v.to_le_bytes());
        }
    }

    fn get(&mut self, i: usize) {
        self.code.extend([GETLOCALB as u8, i as u8]);
    }

    fn set(&mut self, i: usize) {
        self.code.extend([SETLOCALB as u8, i as u8]);
    }

    /// A small number, for an index or a length.
    fn small(&mut self) -> i32 {
        match self.input.u8() % 8 {
            0 => -1,
            1 => 0,
            2 => 1,
            _ => self.input.u8() as i32 % 40,
        }
    }

    /// A small number pushed.
    fn push_small(&mut self) {
        let n = self.small();
        self.int(n);
    }

    /// A small number pushed, or none (nil, for an optional length).
    fn push_small_or_nil(&mut self) {
        if self.input.bool() {
            self.op(NIL_);
        } else {
            self.push_small();
        }
    }

    /// Any number pushed.
    fn push_any(&mut self) {
        let v = self.any_int();
        self.int(v);
    }

    fn any_int(&mut self) -> i32 {
        let b = self.input.u8();
        if b < 192 {
            INTS[b as usize % INTS.len()]
        } else {
            (self.input.u32() as i32) >> 1
        }
    }

    /// The first local that `fits`, from one the input names.
    fn search(&mut self, fits: impl Fn(&Self, usize) -> bool) -> Option<usize> {
        let start = self.input.u8() as usize;
        (0..LOCALS)
            .map(|k| (start + k) % LOCALS)
            .find(|&i| fits(self, i))
    }

    /// A local of `kind` (any table for `Tab(0)`), if there is one.
    fn pick(&mut self, want: fn(Kind) -> bool) -> Option<usize> {
        self.search(|g, i| want(g.locals[i]))
    }

    /// Where a result of `kind` goes: a local free to take it.
    fn dest(&mut self, kind: Kind) -> Option<usize> {
        self.search(|g, i| g.reserved & 1 << i == 0 && (g.depth == 0 || g.locals[i] == kind))
    }

    fn store(&mut self, kind: Kind) {
        match self.dest(kind) {
            Some(i) => {
                self.set(i);
                self.locals[i] = kind;
            }
            None => self.op(DROP),
        }
    }

    fn int_local(&mut self) -> Option<usize> {
        self.pick(|k| k == Kind::Int)
    }

    fn str_local(&mut self) -> Option<usize> {
        self.pick(|k| k == Kind::Str)
    }

    /// An integer local's value, or `v` if there is none.
    fn int_or(&mut self, v: i32) {
        match self.int_local() {
            Some(a) => self.get(a),
            None => self.int(v),
        }
    }

    /// Any local's value (local 0's if none has one).
    fn get_any_local(&mut self) {
        let v = self.pick(|_| true).unwrap_or(0);
        self.get(v);
    }

    /// `body`, skipped by an `ELSE` unless local `c` holds true.
    fn unless_zero(&mut self, c: usize, body: impl FnOnce(&mut Self)) {
        self.get(c);
        self.op(ELSE);
        let at = self.code.len();
        self.code.extend([0, 0]);
        body(self);
        let to = self.code.len() as u16;
        self.code[at..at + 2].copy_from_slice(&to.to_le_bytes());
    }

    /// A few statements, one level deeper.
    fn nested(&mut self) {
        self.depth += 1;
        for _ in 0..self.input.u8() % 6 {
            self.statement();
        }
        self.depth -= 1;
    }

    fn statement(&mut self) {
        let choice = self.input.u8() % 60;
        match choice {
            0 => {
                self.push_any();
                self.store(Kind::Int);
            }
            1..=4 => {
                let (Some(a), Some(b)) = (self.int_local(), self.int_local()) else {
                    return;
                };
                const OPS: [i32; 14] = [
                    ADD, SUB, MUL, AND, OR, EOR, EQ, NE, LT, GT, LE, GE, MAX, MIN,
                ];
                let o = OPS[self.input.u8() as usize % OPS.len()];
                self.get(a);
                self.get(b);
                self.op(o);
                self.store(Kind::Int);
            }
            5 => {
                let Some(a) = self.int_local() else { return };
                self.get(a);
                // By zero (or by more than 31) the host differs from the
                // rabbit: lapin-metal's own tests pin those.
                let o = self.input.u8() as usize % 4;
                let by = if o < 2 {
                    [3, -2, 7, 1000, -1][self.input.u8() as usize % 5]
                } else {
                    self.input.u8() as i32 % 32
                };
                self.int(by);
                self.op([DIV, MOD, SHL, SHR][o]);
                self.store(Kind::Int);
            }
            6 => {
                let Some(a) = self.int_local() else { return };
                self.get(a);
                let o = [NEG, NOT, NON, ABS][self.input.u8() as usize % 4];
                self.op(o);
                self.store(Kind::Int);
            }
            // Printing.
            7 | 8 => {
                let Some(a) = self.pick(|k| matches!(k, Kind::Int | Kind::Any)) else {
                    return;
                };
                self.get(a);
                self.op(if choice == 7 { IECHOLN } else { IECHO });
                self.op(DROP);
            }
            9 | 10 => {
                let Some(a) = self.str_local() else { return };
                self.get(a);
                self.op(if choice == 9 { SECHOLN } else { SECHO });
                self.op(DROP);
            }
            // Strings.
            11 => {
                let Some(a) = self.int_local() else { return };
                self.get(a);
                let o = [ITOA, CTOA, ITOH, CTOH, ITOBIN2][self.input.u8() as usize % 5];
                self.op(o);
                self.store(Kind::Str);
            }
            12 => {
                let n = self.input.u16() as i32 % 600 - 2;
                self.int(n);
                self.op(STRNEW);
                self.store(Kind::Str);
            }
            13 => {
                let Some(a) = self.str_local() else { return };
                self.get(a);
                self.op(STRLEN);
                self.store(Kind::Int);
            }
            14 => {
                let Some(a) = self.str_local() else { return };
                self.get(a);
                self.push_small();
                self.op(STRGET);
                self.store(Kind::Int);
            }
            15 => {
                let Some(a) = self.str_local() else { return };
                let v = self.int_local();
                self.get(a);
                self.push_small();
                match v {
                    Some(v) => self.get(v),
                    None => self.int(65),
                }
                self.op(STRSET);
                self.op(DROP);
            }
            16 => {
                let Some(a) = self.str_local() else { return };
                self.get(a);
                self.push_small();
                self.push_small_or_nil();
                self.op(STRSUB);
                self.store(Kind::Str);
            }
            17 => {
                let (Some(a), Some(b)) = (self.str_local(), self.str_local()) else {
                    return;
                };
                self.get(a);
                self.get(b);
                let o = if self.input.bool() { STRCAT } else { STRCMP };
                self.op(o);
                let k = if self.code.last() == Some(&(STRCAT as u8)) {
                    Kind::Str
                } else {
                    Kind::Int
                };
                self.store(k);
            }
            18 => {
                // p, index, q, start, len.
                let (Some(a), Some(b)) = (self.str_local(), self.str_local()) else {
                    return;
                };
                let o = [STRCPY, VSTRCMP, STRFIND, STRFINDREV][self.input.u8() as usize % 4];
                self.get(a);
                let i = self.small();
                if o == STRFINDREV && self.input.bool() {
                    self.op(NIL_);
                } else {
                    self.int(i);
                }
                self.get(b);
                self.push_small();
                // VSTRCMP's default length reads past the shorter
                // string, in the C as here: within the heap, unless
                // the length itself is large.
                if o != VSTRCMP && self.input.bool() {
                    self.op(NIL_);
                } else {
                    self.push_small();
                }
                self.op(o);
                self.store(if o == STRCPY { Kind::Str } else { Kind::Int });
            }
            19 => {
                let Some(a) = self.str_local() else { return };
                self.get(a);
                let o = if self.input.bool() { ATOI } else { HTOI };
                self.op(o);
                self.store(Kind::Int);
            }
            20 => {
                let Some(a) = self.str_local() else { return };
                self.get(a);
                self.push_small();
                if self.input.bool() {
                    self.op(STRGETWORD);
                    self.store(Kind::Int);
                } else {
                    self.push_any();
                    self.op(STRPUTWORD);
                    self.op(DROP);
                }
            }
            // Tables.
            21 if self.depth == 0 => {
                let n = self.input.u8() % 12;
                if self.input.bool() {
                    self.code.extend([MKTABB as u8, n]);
                } else {
                    self.get_any_local();
                    self.int(n as i32);
                    self.op(TABNEW);
                }
                self.store(Kind::Tab(n));
            }
            22 => {
                let Some(t) = self.pick(|k| matches!(k, Kind::Tab(_))) else {
                    return;
                };
                self.get(t);
                self.push_small();
                self.op(FETCH);
                self.store(Kind::Any);
            }
            23 => {
                let Some(t) = self.pick(|k| matches!(k, Kind::Tab(n) if n > 0)) else {
                    return;
                };
                let Kind::Tab(n) = self.locals[t] else { return };
                let v = self.pick(|_| true).unwrap_or(0);
                self.get(t);
                let i = self.input.u8() % n;
                self.int(i as i32);
                self.get(v);
                self.op(STORE);
                self.op(DROP);
            }
            24 => {
                let Some(t) = self.pick(|k| matches!(k, Kind::Tab(_))) else {
                    return;
                };
                self.get(t);
                self.op(TABLEN);
                self.store(Kind::Int);
            }
            25 => {
                self.op(GC);
                self.store(Kind::Int);
            }
            26 => {
                if self.input.bool() {
                    self.op(RAND);
                } else {
                    self.push_any();
                    self.op(SRAND);
                }
                self.store(Kind::Int);
            }
            27 if self.globals > 0 => {
                let g = self.input.u8() as usize % self.globals;
                self.code.extend([GETGLOBALB as u8, g as u8]);
                self.store(Kind::Str);
            }
            // The board.
            28 => {
                self.push_small();
                self.push_any();
                let o = [LED, MOTORSET][self.input.u8() as usize & 1];
                self.op(o);
                self.op(DROP);
            }
            // A block skipped, or not.
            29 | 30 if self.depth < 3 => {
                let Some(c) = self.int_local() else { return };
                self.unless_zero(c, Self::nested);
            }
            // A block repeated.
            31 if self.depth < 2 => {
                let Some(c) = self.dest(Kind::Int) else {
                    return;
                };
                let n = self.input.u8() as i32 % 40;
                self.int(n);
                self.set(c);
                self.locals[c] = Kind::Int;
                let top = self.code.len() as u16;
                self.unless_zero(c, |g| {
                    g.reserved |= 1 << c;
                    g.nested();
                    g.reserved &= !(1 << c);
                    g.get(c);
                    g.int(1);
                    g.op(SUB);
                    g.set(c);
                    g.op(GOTO);
                    g.code.extend(top.to_le_bytes());
                });
            }
            // A call: two integers, an integer back.
            32 | 33 if self.fun + 1 < self.funs => {
                let (Some(a), Some(b)) = (self.int_local(), self.int_local()) else {
                    return;
                };
                let f = self.fun + 1 + self.input.u8() as usize % (self.funs - self.fun - 1);
                self.get(a);
                self.get(b);
                self.int(f as i32);
                self.op(EXEC);
                self.store(Kind::Int);
            }
            34 => {
                let Some(a) = self.str_local() else { return };
                self.get(a);
                self.push_small();
                self.push_small_or_nil();
                // The key, then the alpha.
                self.push_any();
                self.push_any();
                let o = if self.input.bool() { CRYPT } else { UNCRYPT };
                self.op(o);
                self.store(Kind::Int);
            }
            // A tuple of integers, and its parts.
            35 => {
                let n = 1 + self.input.u8() % 4;
                for _ in 0..n {
                    self.int_or(0);
                }
                self.code.extend([DEFTABB as u8, n]);
                self.store(Kind::Tab(n));
            }
            36 => {
                let Some(t) = self.pick(|k| matches!(k, Kind::Tab(n) if n >= 2)) else {
                    return;
                };
                let Kind::Tab(n) = self.locals[t] else { return };
                self.get(t);
                match self.input.u8() % 3 {
                    0 => self.op(HD),
                    1 => self.op(TL),
                    _ => {
                        let k = self.input.u8() % n;
                        self.code.extend([FETCHB as u8, k]);
                    }
                }
                self.store(Kind::Any);
            }
            // The other ways to call: through the stack (CALLRB, CALLR),
            // with the arguments in a tuple (CALL), a nil function.
            37 | 38 if self.fun + 1 < self.funs => {
                let (Some(a), Some(b)) = (self.int_local(), self.int_local()) else {
                    return;
                };
                let f = self.later_fun();
                let how = self.input.u8() % 4;
                if how == 3 && self.input.bool() {
                    self.op(NIL_);
                } else {
                    self.int(f);
                }
                self.get(a);
                self.get(b);
                match how {
                    0 => self.code.extend([CALLRB as u8, 2]),
                    1 => {
                        self.int(2);
                        self.op(CALLR);
                    }
                    _ => {
                        self.code.extend([DEFTABB as u8, 2]);
                        self.op(CALL);
                    }
                }
                // A nil function gives nil.
                self.store(Kind::Any);
            }
            // A closure: a function with an argument fixed, or two.
            39 if self.fun + 1 < self.funs => {
                let Some(a) = self.int_local() else { return };
                let fixed = match self.pick(|k| k == Kind::Fun(1)) {
                    Some(c) if self.input.bool() => {
                        self.get(c);
                        2
                    }
                    _ => {
                        let f = self.later_fun();
                        self.int(f);
                        1
                    }
                };
                self.get(a);
                self.op(FIXARG);
                self.store(Kind::Fun(fixed));
            }
            40 => {
                let Some(c) = self.pick(|k| matches!(k, Kind::Fun(_))) else {
                    return;
                };
                let Kind::Fun(fixed) = self.locals[c] else {
                    return;
                };
                let free = 2 - fixed;
                self.get(c);
                for _ in 0..free {
                    self.int_or(3);
                }
                match self.input.u8() % 3 {
                    0 if free == 0 => self.op(EXEC),
                    1 => {
                        self.int(free as i32);
                        self.op(CALLR);
                    }
                    _ => self.code.extend([CALLRB as u8, free]),
                }
                self.store(Kind::Int);
            }
            // The stack and the locals, by number.
            41 => {
                // Not of an empty table: both machines would read the
                // next block's header, and hand it on as a value.
                let Some(t) = self.pick(|k| matches!(k, Kind::Tab(n) if n > 0)) else {
                    return;
                };
                self.get(t);
                self.op(FIRST);
                self.store(Kind::Any);
                self.op(DROP);
            }
            42 => {
                let Some(a) = self.pick(|_| true) else { return };
                let kind = self.locals[a];
                self.get(a);
                self.op(DUP);
                self.store(kind);
                self.op(DROP);
            }
            43 => {
                let a = self.input.u8() as usize % LOCALS;
                let kind = self.locals[a];
                self.int(a as i32);
                self.op(GETLOCAL);
                self.store(kind);
            }
            44 | 45 => {
                let Some(v) = self.pick(|_| true) else { return };
                let kind = self.locals[v];
                let Some(d) = self.dest(kind) else { return };
                if choice == 44 {
                    self.get(v);
                    self.int(d as i32);
                    self.op(SETLOCAL);
                } else {
                    self.int(d as i32);
                    self.get(v);
                    self.op(SETLOCAL2);
                    self.op(DROP);
                }
                self.locals[d] = kind;
            }
            // Globals by number: strings stay strings.
            46 if self.globals > 0 => {
                let g = self.input.u8() as usize % self.globals;
                if self.input.bool() {
                    self.int(g as i32);
                    self.op(GETGLOBAL);
                    self.store(Kind::Str);
                } else {
                    let Some(a) = self.str_local() else { return };
                    self.int(g as i32);
                    self.get(a);
                    self.op(SETGLOBAL);
                    self.op(DROP);
                }
            }
            // Tables sized from the stack, and stores into them.
            47 if self.depth == 0 => {
                let n = self.input.u8() % 12;
                self.int(n as i32);
                self.op(MKTAB);
                self.store(Kind::Tab(n));
            }
            48 => {
                let n = 1 + self.input.u8() % 4;
                for _ in 0..n {
                    self.get_any_local();
                }
                self.int(n as i32);
                self.op(DEFTAB);
                self.store(Kind::Tab(n));
            }
            49 => {
                let Some(t) = self.pick(|k| matches!(k, Kind::Tab(n) if n > 0)) else {
                    return;
                };
                let Kind::Tab(n) = self.locals[t] else {
                    return;
                };
                let v = self.pick(|_| true).unwrap_or(0);
                // In bounds: the C stores wherever the index points.
                let i = self.input.u8() % n;
                self.get(t);
                self.get(v);
                if self.input.bool() {
                    self.code.extend([SETSTRUCTB as u8, i]);
                } else {
                    self.int(i as i32);
                    self.op(SETSTRUCT);
                }
                self.op(DROP);
            }
            // Lists: of strings joined, of pairs looked up.
            50 => {
                let n = self.input.u8() % 4;
                for _ in 0..n {
                    match self.str_local() {
                        Some(a) => self.get(a),
                        None => self.op(NIL_),
                    }
                }
                self.op(NIL_);
                for _ in 0..n {
                    self.code.extend([DEFTABB as u8, 2]);
                }
                self.op(STRCATLIST);
                self.store(Kind::Str);
            }
            51 | 52 => {
                let strings = choice == 52;
                let n = self.input.u8() % 4;
                for _ in 0..n {
                    let key = if strings {
                        self.str_local()
                    } else {
                        self.int_local()
                    };
                    match key {
                        Some(k) => self.get(k),
                        None => self.op(NIL_),
                    }
                    let v = self.int_local().unwrap_or(0);
                    self.get(v);
                    self.code.extend([DEFTABB as u8, 2]);
                }
                self.op(NIL_);
                for _ in 0..n {
                    self.code.extend([DEFTABB as u8, 2]);
                }
                let key = if strings {
                    self.str_local()
                } else {
                    self.int_local()
                };
                match key {
                    Some(k) if !self.input.u8().is_multiple_of(5) => self.get(k),
                    _ => self.op(NIL_),
                }
                self.op(if strings { LISTSWITCHSTR } else { LISTSWITCH });
                self.store(Kind::Any);
            }
            // The clocks.
            53 => {
                let o = if self.input.bool() { TIME } else { TIME_MS };
                self.op(o);
                self.store(Kind::Int);
            }
            // The environment kept across bytecodes.
            54 => {
                if self.input.bool() {
                    self.op(ENVGET);
                    self.store(Kind::Any);
                } else {
                    let Some(a) = self.str_local() else { return };
                    self.get(a);
                    self.op(ENVSET);
                    self.op(DROP);
                }
            }
            // Tags: the one in front, the list, a block read or written.
            55 => {
                let o = if self.input.bool() {
                    RFIDGET
                } else {
                    RFIDGETLIST
                };
                self.op(o);
                self.store(Kind::Any);
            }
            56 => {
                // The C reads eight bytes of identifier and four of
                // data, whatever the strings' lengths: strings that long.
                self.int(8);
                self.op(STRNEW);
                self.push_small();
                if self.input.bool() {
                    self.op(RFIDREAD);
                } else {
                    self.int(4);
                    self.op(STRNEW);
                    self.op(RFIDWRITE);
                }
                self.store(Kind::Any);
            }
            // The network: a frame sent, a checksum, the link.
            57 => {
                let (Some(a), Some(m)) = (self.str_local(), self.str_local()) else {
                    return;
                };
                self.get(a);
                self.push_small();
                self.push_small_or_nil();
                self.get(m);
                self.push_small();
                self.push_small();
                self.op(NETSEND);
                self.store(Kind::Any);
            }
            58 => {
                let Some(a) = self.str_local() else { return };
                self.get(a);
                // From an even index: at an odd one the C reads its
                // half-words unaligned, which the rabbit's processor
                // turns round (as lapin-metal does) and the host does
                // not.
                let i = self.small();
                self.int(if i > 0 { i & !1 } else { i });
                self.push_small_or_nil();
                self.push_any();
                self.op(NETCHK);
                self.store(Kind::Int);
            }
            59 => {
                let o = [NETSTATE, NETRSSI, NETMAC][self.input.u8() as usize % 3];
                self.op(o);
                self.store(if o == NETMAC { Kind::Str } else { Kind::Int });
            }
            _ => {}
        }
    }

    /// A function after this one, to call.
    fn later_fun(&mut self) -> i32 {
        (self.fun + 1 + self.input.u8() as usize % (self.funs - self.fun - 1)) as i32
    }

    /// Start the locals from `from` on as something of their kind.
    fn init(&mut self, from: usize) {
        for i in from..LOCALS {
            let kind = match i % 4 {
                0 | 1 => Kind::Int,
                2 => Kind::Str,
                _ => Kind::Tab(2),
            };
            match kind {
                Kind::Int => self.int(INTS[i % INTS.len()]),
                Kind::Str => {
                    self.int(i as i32);
                    self.op(ITOA);
                }
                _ => self.code.extend([MKTABB as u8, 2]),
            }
            self.set(i);
            self.locals[i] = kind;
        }
    }
}

/// A whole bytecode: string globals, then one function.
pub fn program(input: &mut Input) -> Vec<u8> {
    let mut globals = Vec::new();
    let nglobals = input.u8() as usize % 4;
    for _ in 0..nglobals {
        let s = input.chunk(false);
        let s = &s[..s.len().min(64)];
        globals.extend(((s.len() as u32) << 2 | 1).to_le_bytes());
        globals.extend_from_slice(s);
    }
    // The main function, then functions of two integers, made last
    // first (the main one takes what is left of the input).
    let funs = 1 + input.u8() as usize % 4;
    let mut lengths: Vec<usize> = (1..funs).map(|_| input.u8() as usize % 40).collect();
    lengths.insert(0, 400);
    let mut made = Vec::new();
    for (fun, &statements) in lengths.iter().enumerate().rev() {
        let narg = if fun == 0 { 0 } else { 2 };
        let mut g = Gen {
            input: &mut *input,
            code: Vec::new(),
            locals: [Kind::Int; LOCALS],
            reserved: 0,
            depth: 0,
            globals: nglobals,
            fun,
            funs,
        };
        g.init(narg);
        let mut n = 0;
        while !g.input.is_empty() && n < statements && g.code.len() < 30_000 {
            g.statement();
            n += 1;
        }
        if fun == 0 {
            g.op(NIL_);
        } else {
            let r = g.int_local().unwrap_or(0);
            g.get(r);
        }
        g.op(RET);
        let mut f = vec![narg as u8];
        f.extend(((LOCALS - narg) as u16).to_le_bytes());
        // Jumps count from the function's first instruction, after
        // its header.
        f.extend(&g.code);
        made.push((fun, f));
    }
    made.sort_by_key(|(fun, _)| *fun);
    let mut code = Vec::new();
    let mut table = Vec::new();
    for (_, f) in made {
        table.extend((code.len() as u32).to_le_bytes());
        code.extend(f);
    }
    let mut bc = (globals.len() as u32 + 4).to_le_bytes().to_vec();
    bc.extend(globals);
    bc.extend((code.len() as u32).to_le_bytes());
    bc.extend(code);
    bc.extend((funs as u16).to_le_bytes());
    bc.extend(table);
    bc
}
