//! The interpreter (`src/vm/vinterp.c`).
//!
//! A call frame on the stack, from the top: the four words saved by the
//! call (return pc, pc base, caller frame, caller result slot), the
//! locals, the arguments. `callstack` indexes the first argument;
//! positive, it says the frame is the outermost of this run, and `ret`
//! then ends the run.

use crate::op::*;
use crate::{
    GC_THRESHOLD, HEADER_LENGTH, Host, NIL, SYS_CBLOOP, SYS_CBPLAY, SYS_CBREC, SYS_CBTCP, SYS_ENV,
    VMEM_LENGTH, Vm, int, pnt, val,
};

/// `<<` as the ARM shifts: by the low byte of the count, nothing left
/// from 32 on.
fn shl(a: i32, b: i32) -> i32 {
    let s = (b as u32) & 0xFF;
    if s >= 32 { 0 } else { a << s }
}

/// `>>`, arithmetic: from 32 on, only the sign is left.
fn shr(a: i32, b: i32) -> i32 {
    let s = (b as u32) & 0xFF;
    if s >= 32 { a >> 31 } else { a >> s }
}

/// `/` as libgcc divides on the rabbit: by zero, the largest number of
/// the dividend's sign, or zero.
fn div(a: i32, b: i32) -> i32 {
    if b == 0 {
        return match a {
            0 => 0,
            a if a > 0 => i32::MAX,
            _ => i32::MIN,
        };
    }
    a.wrapping_div(b)
}

/// `%`: libgcc's remainder by zero is zero.
fn rem(a: i32, b: i32) -> i32 {
    if b == 0 { 0 } else { a.wrapping_rem(b) }
}

/// Where a run is: the registers of `interpGo` besides the stack.
pub(crate) struct Regs {
    pc: i32,
    pcbase: i32,
    callstack: i32,
    callstackres: i32,
}

/// What the cold side tells the hot loop.
pub(crate) enum Flow {
    /// Fetch the next opcode.
    Next,
    /// Run this opcode now, without a fetch.
    Again(i32),
    /// The run is over.
    Return,
}

impl<H: Host> Vm<'_, H> {
    /// `interpGo`: run the function on top of the stack, its arguments
    /// below it, until it returns.
    ///
    /// The opcodes that make up most of any program run here, on local
    /// copies of the stack pointer and of the memory's address that stay
    /// in registers; the others go to [`Self::cold`], with the machine's
    /// registers brought up to date before and read back after. Memory
    /// is reached with one bounds check per access, as elsewhere:
    /// outside it, reads give zero and writes are dropped.
    #[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
    pub fn interp_go(&mut self) {
        let (mut pc, mut pcbase, mut callstack, mut callstackres) = (-1i32, -1i32, 1i32, 1i32);
        let mut op = EXEC;
        if self.broken {
            return;
        }
        const LEN: u32 = VMEM_LENGTH as u32;
        let mut sp = self.stack;
        let mut hi = self.heapindex;
        let mut heap = self.mem.heap.as_mut_ptr();
        // The watchdog is fed every 256 opcodes rather than at each.
        let mut feed: u8 = 0;

        // Word `i` of the memory.
        macro_rules! w {
            ($i:expr) => {{
                let i = $i as u32;
                // SAFETY: `i` is inside the memory `heap` points to.
                if i < LEN {
                    unsafe { *heap.add(i as usize) }
                } else {
                    0
                }
            }};
        }
        macro_rules! set {
            ($i:expr, $v:expr) => {{
                let i = $i as u32;
                let v = $v;
                if i < LEN {
                    // SAFETY: as above.
                    unsafe { *heap.add(i as usize) = v }
                }
            }};
        }
        // Byte `o` of the memory (the bytecode lives there).
        macro_rules! b {
            ($o:expr) => {{
                let o = $o as u32;
                // SAFETY: `o` is inside the memory's bytes.
                if o < 4 * LEN {
                    unsafe { *heap.cast::<u8>().add(o as usize) as i32 }
                } else {
                    0
                }
            }};
        }
        macro_rules! short {
            ($o:expr) => {{
                let o = $o;
                b!(o) | b!(o.wrapping_add(1)) << 8
            }};
        }
        // The stack, from its top; a frame's slots.
        macro_rules! get {
            ($n:expr) => {
                w!((LEN as i32).wrapping_add(sp).wrapping_add($n))
            };
        }
        macro_rules! put {
            ($n:expr, $v:expr) => {
                set!((LEN as i32).wrapping_add(sp).wrapping_add($n), $v)
            };
        }
        macro_rules! cget {
            ($off:expr, $n:expr) => {
                w!((LEN as i32).wrapping_add($off).wrapping_sub($n))
            };
        }
        macro_rules! cset {
            ($off:expr, $n:expr, $v:expr) => {
                set!((LEN as i32).wrapping_add($off).wrapping_sub($n), $v)
            };
        }
        // Bring the machine's registers up to date, run `$e`, take them
        // back: around anything that is not this loop's own.
        macro_rules! outside {
            ($e:expr) => {{
                self.stack = sp;
                self.currentop = op;
                let out = $e;
                self.currentop = -1;
                sp = self.stack;
                hi = self.heapindex;
                heap = self.mem.heap.as_mut_ptr();
                out
            }};
        }
        // `vmemPush`: store, then check for room, collecting if short.
        macro_rules! push {
            ($v:expr) => {{
                let v = $v;
                sp = sp.wrapping_sub(1);
                set!((LEN as i32).wrapping_add(sp), v);
                if (LEN as i32).wrapping_add(sp).wrapping_sub(hi) < GC_THRESHOLD {
                    outside!(self.check_slow(0));
                }
            }};
        }

        loop {
            // One opcode; `Again` from the cold side runs another in its
            // place, without a fetch.
            loop {
                match op {
                    INTB => {
                        let v = b!(pc);
                        pc = pc.wrapping_add(1);
                        push!(int(v));
                    }
                    INT => {
                        let v = short!(pc.wrapping_add(2)) << 16 | short!(pc);
                        pc = pc.wrapping_add(4);
                        push!(int(v));
                    }
                    NIL_ => push!(NIL),
                    DROP => sp = sp.wrapping_add(1),
                    DUP => push!(get!(0)),
                    GETLOCALB => {
                        let i = b!(pc);
                        pc = pc.wrapping_add(1);
                        push!(cget!(callstack, i));
                    }
                    SETLOCALB => {
                        let i = b!(pc);
                        pc = pc.wrapping_add(1);
                        let v = get!(0);
                        sp = sp.wrapping_add(1);
                        cset!(callstack, i, v);
                    }
                    GETGLOBALB => {
                        let i = b!(pc);
                        pc = pc.wrapping_add(1);
                        push!(cget!(self.global_start, i));
                    }
                    ADD..=SHR => {
                        let (a, c) = (val(get!(1)), val(get!(0)));
                        let v = match op {
                            ADD => a.wrapping_add(c),
                            SUB => a.wrapping_sub(c),
                            MUL => a.wrapping_mul(c),
                            DIV => div(a, c),
                            MOD => rem(a, c),
                            AND => a & c,
                            OR => a | c,
                            EOR => a ^ c,
                            SHL => shl(a, c),
                            _ => shr(a, c),
                        };
                        put!(1, int(v));
                        sp = sp.wrapping_add(1);
                    }
                    NEG => put!(0, int(val(get!(0)).wrapping_neg())),
                    NOT => put!(0, int(!val(get!(0)))),
                    NON => put!(0, int((val(get!(0)) == 0) as i32)),
                    EQ | NE => {
                        let same = get!(1) == get!(0);
                        put!(1, int((same == (op == EQ)) as i32));
                        sp = sp.wrapping_add(1);
                    }
                    LT..=GE => {
                        let (a, c) = (val(get!(1)), val(get!(0)));
                        let v = match op {
                            LT => a < c,
                            GT => a > c,
                            LE => a <= c,
                            _ => a >= c,
                        };
                        put!(1, int(v as i32));
                        sp = sp.wrapping_add(1);
                    }
                    GOTO => pc = pcbase.wrapping_add(short!(pc)),
                    ELSE => {
                        let v = get!(0);
                        sp = sp.wrapping_add(1);
                        if v == 0 {
                            pc = pcbase.wrapping_add(short!(pc));
                        } else {
                            pc = pc.wrapping_add(2);
                        }
                    }
                    FETCHB => {
                        let i = b!(pc);
                        pc = pc.wrapping_add(1);
                        let p = get!(0);
                        if p != NIL {
                            put!(0, w!(val(p).wrapping_add(HEADER_LENGTH).wrapping_add(i)));
                        }
                    }
                    HD | TL => {
                        let p = get!(0);
                        if p != NIL {
                            let i = (op == TL) as i32;
                            put!(0, w!(val(p).wrapping_add(HEADER_LENGTH).wrapping_add(i)));
                        }
                    }
                    STORE => {
                        let v = get!(0);
                        let i = get!(1);
                        sp = sp.wrapping_add(2);
                        let p = get!(0);
                        // `i >= 0 || i < size`, as the C: false only for a
                        // negative index into a header of -1280 or less.
                        if p != NIL
                            && i != NIL
                            && (val(i) >= 0 || val(i) < ((w!(val(p)) >> 8) + 4) >> 2)
                        {
                            set!(val(p).wrapping_add(HEADER_LENGTH).wrapping_add(val(i)), v);
                        }
                        put!(0, v);
                    }
                    FIRST => {
                        let p = get!(0);
                        let v = if p != NIL {
                            w!(val(p).wrapping_add(HEADER_LENGTH))
                        } else {
                            NIL
                        };
                        push!(v);
                    }
                    SETGLOBAL => {
                        let v = get!(0);
                        cset!(self.global_start, val(get!(1)), v);
                        put!(1, v);
                        sp = sp.wrapping_add(1);
                    }
                    TIME_MS => {
                        let t = self.host.time_ms() as i32;
                        push!(int(t));
                    }
                    CALLRB | CALLR => {
                        let n = if op == CALLRB {
                            let n = b!(pc);
                            pc = pc.wrapping_add(1);
                            n
                        } else {
                            let n = val(get!(0));
                            sp = sp.wrapping_add(1);
                            n
                        };
                        let valn = get!(n);
                        if valn == NIL {
                            sp = sp.wrapping_add(n);
                        } else {
                            let mut i = n;
                            while i > 0 {
                                put!(i, get!(i - 1));
                                i -= 1;
                            }
                            put!(0, valn);
                            op = EXEC;
                            continue;
                        }
                    }
                    // A call of a function by its number; a closure goes to
                    // the cold side, which comes back here with its number.
                    EXEC if get!(0) & 1 == 0 => {
                        let fun = val(get!(0));
                        sp = sp.wrapping_add(1);
                        if fun < 0 {
                            op = fun.wrapping_neg();
                            continue;
                        }
                        let at = self.tabfun.wrapping_add(fun << 2);
                        let mut npc = short!(at.wrapping_add(2)) << 16 | short!(at);
                        let narg = b!(npc);
                        let nloc = short!(npc.wrapping_add(1));
                        npc = npc.wrapping_add(3);
                        // `TFCtest`: only jumps to a `ret` after the call?
                        let tail = callstack <= 0 && {
                            let mut q = pc;
                            loop {
                                match b!(q) {
                                    RET => break true,
                                    GOTO => q = pcbase.wrapping_add(short!(q.wrapping_add(1))),
                                    _ => break false,
                                }
                            }
                        };
                        if tail {
                            pc = val(cget!(callstackres, -3));
                            pcbase = val(cget!(callstackres, -2));
                            let ncall = val(cget!(callstackres, -1));
                            callstackres = val(cget!(callstackres, 0));
                            for i in 0..narg {
                                cset!(callstack, i, get!(narg - i - 1));
                            }
                            sp = callstack - narg + 1;
                            callstack = ncall;
                        }
                        for _ in 0..nloc {
                            push!(NIL);
                        }
                        push!(int(pc));
                        push!(int(pcbase));
                        push!(int(callstack));
                        push!(int(callstackres));
                        callstack = sp + 3 + nloc + narg;
                        callstackres = sp;
                        pc = npc;
                        pcbase = npc;
                    }
                    RET => {
                        pc = val(get!(4));
                        pcbase = val(get!(3));
                        let ncall = val(get!(2));
                        callstackres = val(get!(1));
                        cset!(callstack, 0, get!(0));
                        sp = callstack;
                        callstack = ncall;
                    }
                    _ => {
                        let mut r = Regs {
                            pc,
                            pcbase,
                            callstack,
                            callstackres,
                        };
                        let flow = outside!(self.cold(op, &mut r));
                        (pc, pcbase, callstack, callstackres) =
                            (r.pc, r.pcbase, r.callstack, r.callstackres);
                        match flow {
                            Flow::Next => {}
                            Flow::Again(next) => {
                                op = next;
                                continue;
                            }
                            Flow::Return => return,
                        }
                    }
                }
                break;
            }
            if callstack > 0 {
                self.stack = sp;
                return;
            }
            op = b!(pc);
            pc = pc.wrapping_add(1);
            feed = feed.wrapping_add(1);
            if feed == 0 {
                self.host.watchdog();
            }
        }
    }

    /// Every opcode the hot loop of [`Self::interp_go`] leaves out, as
    /// the C runs it, on the machine's own registers (`self.stack`). The
    /// hot loop's own opcodes never come here.
    #[inline(never)]
    fn cold(&mut self, op: i32, r: &mut Regs) -> Flow {
        match op {
            // A closure, `[fun args]`: its arguments go on the stack in
            // its place, then the hot loop calls the function by its
            // number, which takes the slot the list's nil leaves.
            EXEC => {
                let p = val(self.sget(0));
                let fun = val(self.fetch(p, 0));
                self.sset(0, self.fetch(p, 1));
                while self.sget(0) != NIL {
                    self.push(self.fetch(val(self.sget(0)), 1));
                    self.sset(1, self.fetch(val(self.sget(1)), 0));
                }
                self.sset(0, int(fun));
                return Flow::Again(EXEC);
            }
            GETLOCAL => {
                let v = self.cget(r.callstack, val(self.sget(0)));
                self.sset(0, v);
            }
            MKTABB | MKTAB => {
                let n = if op == MKTABB {
                    self.operand(r)
                } else {
                    val(self.pull())
                };
                let p = self.alloc_tab_clear(n);
                self.push(pnt(p));
            }
            DEFTABB | DEFTAB => {
                let n = if op == DEFTABB {
                    self.operand(r)
                } else {
                    val(self.pull())
                };
                self.stack_to_tab(n);
            }
            FETCH => {
                let i = self.pull();
                let p = self.sget(0);
                if p == NIL || i == NIL {
                    self.sset(0, NIL);
                } else {
                    let (i, p) = (val(i), val(p));
                    if i < 0 || i >= self.size_tab(p) {
                        self.sset(0, NIL);
                    } else {
                        self.sset(0, self.fetch(p, i));
                    }
                }
            }
            GETGLOBAL => {
                let v = self.cget(self.global_start, val(self.sget(0)));
                self.sset(0, v);
            }
            SECHO | SECHOLN => self.secho(self.sget(0), op == SECHOLN),
            IECHO | IECHOLN => self.iecho(self.sget(0), op == IECHOLN),
            SETLOCAL => {
                let i = val(self.pull());
                let v = self.pull();
                self.cset(r.callstack, i, v);
            }
            SETSTRUCTB => {
                // The C checks `i >= 0 || i < size`, which always
                // holds: the store happens whatever the index.
                let i = self.operand(r);
                let v = self.pull();
                let p = self.sget(0);
                if p != NIL {
                    self.store(val(p), i, v);
                }
            }
            SETSTRUCT => {
                let i = self.pull();
                let v = self.pull();
                let p = self.sget(0);
                if p != NIL && i != NIL && self.indexable(val(p), val(i)) {
                    self.store(val(p), val(i), v);
                }
            }
            SETLOCAL2 => {
                self.cset(r.callstack, val(self.sget(1)), self.sget(0));
                self.sset(1, self.sget(0));
                self.pull();
            }
            CALL => {
                let p = self.sget(0);
                if p == NIL {
                    self.sset(1, NIL);
                    self.pull();
                } else {
                    let n = self.size_tab(val(p));
                    if n == 0 {
                        self.pull();
                    } else {
                        for _ in 1..n {
                            self.push(NIL);
                        }
                        let p = val(self.sget(n - 1));
                        for i in 0..n {
                            self.sset(n - 1 - i, self.fetch(p, i));
                        }
                    }
                    self.push(int(n));
                    return Flow::Again(CALLR);
                }
            }
            TABNEW => {
                let v = self.pull();
                if v == NIL {
                    self.sset(0, NIL);
                } else {
                    let v = val(v);
                    let p = self.alloc_tab(v);
                    let v0 = self.sget(0);
                    for i in 0..v {
                        self.store(p, i, v0);
                    }
                    self.sset(0, pnt(p));
                }
            }
            FIXARG => {
                let v = self.sget(1);
                if v == NIL {
                    self.pull();
                } else {
                    if v & 1 != 0 {
                        self.push(self.fetch(val(v), 1));
                        self.sset(2, self.fetch(val(self.sget(2)), 0));
                    } else {
                        self.push(NIL);
                    }
                    self.stack_to_tab(2);
                    self.stack_to_tab(2);
                }
            }
            ABS => {
                let v = val(self.sget(0));
                self.sset(0, int(if v < 0 { v.wrapping_neg() } else { v }));
            }
            MAX | MIN => {
                let v = val(self.pull());
                let w = val(self.sget(0));
                let r = if op == MAX {
                    if v < w { w } else { v }
                } else if v > w {
                    w
                } else {
                    v
                };
                self.sset(0, int(r));
            }
            RAND => {
                let r = self.rand();
                self.push(int(r));
            }
            SRAND => self.srand(val(self.sget(0))),
            TIME => {
                let t = self.host.time_s() as i32;
                self.push(int(t));
            }
            STRNEW => {
                let n = val(self.sget(0));
                if n < 0 {
                    self.sset(0, NIL);
                } else {
                    let p = self.alloc_bin(n);
                    self.sset(0, pnt(p));
                }
            }
            STRSET => {
                let v = val(self.pull());
                let n = val(self.pull());
                let p = val(self.sget(0));
                if p != NIL && n >= 0 && n < self.size_bin(p) {
                    self.set_b(Self::start_bin(p) + n, v as u8);
                }
            }
            STRCPY => {
                if let Ok(s) = self.pull_two() {
                    let len = val_or(s.len, s.lq.wrapping_sub(s.start));
                    self.sys_cpy(s.p, val(s.index), s.lp, s.q, s.start, s.lq, len);
                }
            }
            VSTRCMP => {
                let r = match self.pull_two() {
                    Ok(s) => {
                        let index = val(s.index);
                        let rest = s.lq.wrapping_sub(s.start).max(s.lp.wrapping_sub(index));
                        let len = val_or(s.len, rest);
                        self.sys_cmp(s.p, index, s.lp, s.q, s.start, s.lq, len)
                    }
                    Err((p, q)) => nil_order(p, q),
                };
                self.sset(0, int(r));
            }
            STRFIND | STRFINDREV => {
                let r = match self.pull_two() {
                    Ok(s) => {
                        let len = val_or(s.len, s.lq.wrapping_sub(s.start));
                        let forward = op == STRFIND;
                        let index = if forward {
                            val(s.index)
                        } else {
                            val_or(s.index, s.lp - 1)
                        };
                        self.sys_find(s.p, index, s.lp, s.q, s.start, s.lq, len, forward)
                    }
                    Err(_) => NIL,
                };
                self.sset(0, r);
            }
            STRLEN => {
                let p = val(self.sget(0));
                if p != NIL {
                    self.sset(0, int(self.size_bin(p)));
                }
            }
            STRGET => {
                let n = val(self.pull());
                let p = val(self.sget(0));
                if p == NIL || n < 0 || n >= self.size_bin(p) {
                    self.sset(0, NIL);
                } else {
                    let c = self.b(Self::start_bin(p) + n);
                    self.sset(0, int(c as i32));
                }
            }
            STRSUB => {
                let len = self.pull();
                let start = val(self.pull());
                let q = val(self.sget(0));
                let v = match self.sub_len(q, start, len) {
                    Some(len) => {
                        let p = self.alloc_bin(len);
                        let from = Self::start_bin(val(self.sget(0))) + start;
                        self.copy_bytes(Self::start_bin(p), from, len);
                        pnt(p)
                    }
                    None => NIL,
                };
                self.sset(0, v);
            }
            STRCAT => {
                let q = val(self.sget(0));
                let p = val(self.sget(1));
                let mut len = 0;
                if p != NIL {
                    len += self.size_bin(p);
                }
                if q != NIL {
                    len += self.size_bin(q);
                }
                let r = self.alloc_bin(len);
                let q = val(self.pull());
                let p = val(self.sget(0));
                let mut len = 0;
                if p != NIL {
                    len = self.size_bin(p);
                    self.copy_bytes(Self::start_bin(r), Self::start_bin(p), len);
                }
                if q != NIL {
                    let lq = self.size_bin(q);
                    self.copy_bytes(Self::start_bin(r) + len, Self::start_bin(q), lq);
                }
                self.sset(0, pnt(r));
            }
            TABLEN => {
                let p = val(self.sget(0));
                if p != NIL {
                    self.sset(0, int(self.size_tab(p)));
                }
            }
            STRCATLIST => {
                let mut len = 0;
                let mut p = val(self.sget(0));
                while p != NIL {
                    let q = val(self.fetch(p, 0));
                    if q != NIL {
                        len += self.size_bin(q);
                    }
                    p = val(self.fetch(p, 1));
                }
                let r = self.alloc_bin(len);
                if r < 0 {
                    return Flow::Return;
                }
                let mut len = 0;
                let mut p = val(self.sget(0));
                while p != NIL {
                    let q = val(self.fetch(p, 0));
                    if q != NIL {
                        let lq = self.size_bin(q);
                        self.copy_bytes(Self::start_bin(r) + len, Self::start_bin(q), lq);
                        len += lq;
                    }
                    p = val(self.fetch(p, 1));
                }
                self.sset(0, pnt(r));
            }
            LED => {
                self.host
                    .led(val(self.sget(1)) as u8, val(self.sget(0)) as u32);
                self.pull();
            }
            MOTORSET => {
                self.motor_set(val(self.sget(1)), val(self.sget(0)));
                self.pull();
            }
            MOTORGET => {
                let m = 1 + (val(self.sget(0)) & 1) as u8;
                let v = self.host.motor_position(m) as i32;
                self.sset(0, int(v));
            }
            BUTTON2 => {
                let v = self.host.button() as i32;
                self.push(int(v));
            }
            BUTTON3 => {
                let v = 255 - self.host.adc() as i32;
                self.push(int(v));
            }
            PLAYSTART => {
                let cb = self.pull();
                self.cset(self.sys_start, SYS_CBPLAY, cb);
                let k = val(self.pull());
                self.push(int(0));
                self.play_start(k);
            }
            PLAYFEED => {
                let len = self.pull();
                let start = val(self.pull());
                let q = val(self.sget(0));
                let v = if q == NIL {
                    self.play_feed(None);
                    NIL
                } else if let Some(len) = self.sub_len(q, start, len) {
                    int(self.play_feed(Some((Self::start_bin(q) + start, len))))
                } else {
                    NIL
                };
                self.sset(0, v);
            }
            PLAYSTOP => {
                self.play_stop();
                self.push(int(0));
            }
            RECSTART => {
                let cb = self.pull();
                self.cset(self.sys_start, SYS_CBREC, cb);
                let gain = val(self.pull());
                let freq = val(self.pull());
                self.push(int(0));
                self.rec_start(freq, gain);
            }
            RECSTOP => {
                self.rec_stop();
                self.push(int(0));
            }
            RECVOL => {
                let start = val(self.pull());
                let q = val(self.sget(0));
                if q != NIL {
                    let v = self.rec_vol(Self::start_bin(q), self.size_bin(q), start);
                    self.sset(0, int(v));
                }
            }
            LOAD | SAVE => {
                let v = match self.pull_two() {
                    Ok(s) => {
                        let index = val(s.index);
                        let len = val_or(s.len, s.lp.wrapping_sub(index));
                        int(if op == LOAD {
                            self.sys_load(s.p, index, s.lp, s.start, len)
                        } else {
                            self.sys_save(s.p, index, s.lp, s.start, len)
                        })
                    }
                    Err(_) => NIL,
                };
                self.sset(0, v);
            }
            GC => {
                self.gc();
                let used = self.used_percent();
                self.push(int(used));
            }
            BYTECODE => {
                if self.sget(0) != NIL {
                    let mut env = -1;
                    let p = val(self.cget(self.sys_start, SYS_ENV));
                    self.play_stop();
                    self.rec_stop();
                    if p != NIL {
                        // The C copies the whole environment into
                        // the 4 KB audio buffer; this keeps what
                        // fits.
                        env = self.size_bin(p).min(crate::AUDIO_FIFOPLAY as i32);
                        let from = Self::start_bin(p);
                        for k in 0..env.max(0) {
                            self.mem.fifo[k as usize] = self.b(from + k);
                        }
                    }
                    let q = Self::start_bin(val(self.sget(0)));
                    self.load_heap(q);
                    if env >= 0 {
                        let p = self.alloc_bin(env);
                        for k in 0..env {
                            let v = self.mem.fifo[k as usize];
                            self.set_b(Self::start_bin(p) + k, v);
                        }
                        self.cset(self.sys_start, SYS_ENV, pnt(p));
                    }
                    self.push(int(0));
                    self.interp_go();
                    self.pull();
                    return Flow::Return;
                }
            }
            LOOPCB => self.cset(self.sys_start, SYS_CBLOOP, self.sget(0)),
            ENVGET => {
                self.push(self.cget(self.sys_start, SYS_ENV));
            }
            ENVSET => self.cset(self.sys_start, SYS_ENV, self.sget(0)),
            SNDVOL => self.volume(val(self.sget(0))),
            RFIDGET => match self.host.rfid_first() {
                None => {
                    self.push(NIL);
                }
                Some(id) => self.push_str(&id),
            },
            PLAYTIME => {
                let t = self.play_time();
                self.push(int(t));
            }
            NETCB => self.cset(self.sys_start, SYS_CBTCP, self.sget(0)),
            NETSEND => {
                let speed = val(self.pull());
                let indmac = val(self.pull());
                let q = val(self.pull());
                let r = match self.pull_span() {
                    Some(s) if q != NIL => {
                        let (mac, lmac) = (Self::start_bin(q), self.size_bin(q));
                        let r =
                            self.net_send(s.at, s.index, s.len, s.size, mac, indmac, lmac, speed);
                        int(r)
                    }
                    _ => NIL,
                };
                self.sset(0, r);
            }
            NETSTATE => {
                let s = self.host.net_state();
                self.push(int(s));
            }
            NETMAC => {
                let mac = self.host.net_mac();
                self.push_str(&mac);
            }
            NETCHK => {
                let v = val(self.pull());
                let r = match self.pull_span() {
                    Some(s) => self.net_chk(s.at, s.index, s.len, s.size, v as u32) as i32,
                    None => v,
                };
                self.sset(0, int(r));
            }
            NETSETMODE => {
                let chn = val(self.pull());
                let p = val(self.pull());
                let md = val(self.sget(0));
                let heap = crate::bytes(&self.mem.heap);
                let ssid = (p != NIL).then(|| crate::natives::cstr(heap, Self::start_bin(p)));
                self.host.net_set_mode(md, ssid, chn as u8);
            }
            NETSCAN => {
                let p = val(self.pull());
                self.net_scan(p);
            }
            NETAUTH => {
                let key = val(self.pull());
                let encrypt = val(self.pull());
                let authmode = val(self.pull());
                let scan = val(self.sget(0));
                self.net_auth(scan, authmode, encrypt, key);
            }
            NETSEQADD => {
                let inc = val(self.pull());
                let seq = val(self.pull());
                if seq == NIL || self.size_bin(seq) < 4 {
                    self.push(NIL);
                } else {
                    self.net_seq_add(Self::start_bin(seq), inc);
                }
            }
            STRGETWORD => {
                let ind = val(self.pull());
                let src = val(self.sget(0));
                if src != NIL {
                    let v = self.strgetword(Self::start_bin(src), self.size_bin(src), ind);
                    self.sset(0, int(v));
                }
            }
            STRPUTWORD => {
                let v = val(self.pull());
                let ind = val(self.pull());
                let src = val(self.sget(0));
                if src != NIL {
                    self.strputword(Self::start_bin(src), self.size_bin(src), ind, v);
                }
            }
            ATOI | HTOI => {
                let src = val(self.sget(0));
                if src != NIL {
                    let v = if op == ATOI {
                        self.atoi(Self::start_bin(src))
                    } else {
                        self.htoi(Self::start_bin(src))
                    };
                    self.sset(0, int(v));
                }
            }
            ITOA | CTOA | ITOH | CTOH | ITOBIN2 => {
                let v = val(self.pull());
                match op {
                    ITOA => self.itoa(v),
                    CTOA => self.ctoa(v),
                    ITOH => self.itoh(v),
                    CTOH => self.ctoh(v),
                    _ => self.itobin2(v),
                }
            }
            LISTSWITCH | LISTSWITCHSTR => {
                let key = self.pull();
                let p = val(self.sget(0));
                let v = if op == LISTSWITCH || key == NIL {
                    self.listswitch(p, key)
                } else {
                    self.listswitchstr(p, Self::start_bin(val(key)))
                };
                self.sset(0, v);
            }
            SNDREFRESH => {
                self.play_check(false);
                self.rec_check();
                self.push(NIL);
            }
            SNDWRITE => {
                let v = val(self.pull());
                let reg = val(self.sget(0));
                self.host.codec_write(reg as u8, v as u16);
            }
            SNDREAD => {
                let reg = val(self.sget(0));
                let v = if reg == -1 {
                    self.host.codec_ready() as i32
                } else {
                    self.host.codec_read(reg as u8) as i32
                };
                self.sset(0, int(v));
            }
            SNDFEED => {
                let len = self.pull();
                let start = val_or(self.pull(), 0);
                let q = val(self.sget(0));
                let v = match self.sub_len(q, start, len) {
                    Some(len) => {
                        let heap = crate::bytes(&self.mem.heap);
                        let data = crate::natives::clip(heap, Self::start_bin(q) + start, len);
                        int(self.host.codec_feed(data) as i32)
                    }
                    None => NIL,
                };
                self.sset(0, v);
            }
            SNDAMPLI => {
                let on = val(self.sget(0)) as u8;
                self.host.amplifier(on != 0);
            }
            COREPP => {
                self.push(int(self.stack));
            }
            COREPUSH => {
                self.push(self.sget(0));
            }
            COREPULL => {
                self.sset(1, self.sget(0));
                self.pull();
            }
            COREBIT0 => {
                let v = val(self.pull());
                self.sset(0, (self.sget(0) & !1) | (v & 1));
            }
            REBOOT => {
                let w = val(self.pull());
                let v = val(self.sget(0));
                if v == 0x0407FE58 && w == 0x13fb6754 {
                    self.host.reboot();
                }
            }
            STRCMP => {
                let q = val(self.pull());
                let p = val(self.sget(0));
                let r = if p != NIL && q != NIL {
                    let (pl, ql) = (self.size_bin(p), self.size_bin(q));
                    self.memcmp(Self::start_bin(p), Self::start_bin(q), pl.max(ql))
                } else {
                    nil_order(p, q)
                };
                self.sset(0, int(r));
            }
            ADP2WAV | WAV2ADP | ALAW2WAV | WAV2ALAW => {
                let mu = (op == ALAW2WAV || op == WAV2ALAW) && val(self.pull()) != 0;
                if let Ok(s) = self.pull_two() {
                    let (dp, index, lp, dq, start, lq) =
                        (s.p, val(s.index), s.lp, s.q, s.start, s.lq);
                    let len = val_or(s.len, lq.wrapping_sub(start));
                    match op {
                        ADP2WAV => self.adp2wav(dp, index, lp, dq, start, lq, len),
                        WAV2ADP => self.wav2adp(dp, index, lp, dq, start, lq, len),
                        ALAW2WAV => self.alaw2wav(dp, index, lp, dq, start, lq, len, mu),
                        _ => self.wav2alaw(dp, index, lp, dq, start, lq, len, mu),
                    }
                }
            }
            NETPMK => {
                let key = val(self.pull());
                let ssid = val(self.pull());
                if key == NIL || ssid == NIL {
                    self.push(NIL);
                } else {
                    let heap = crate::bytes(&self.mem.heap);
                    let ssid = crate::natives::cstr(heap, Self::start_bin(ssid));
                    let key = crate::natives::cstr(heap, Self::start_bin(key));
                    let pmk = self.host.net_pmk(ssid, key);
                    self.push_str(&pmk);
                }
            }
            FLASHFIRMWARE => {
                let w = val(self.pull());
                let v = val(self.pull());
                let firmware = val(self.sget(0));
                if firmware != NIL && v == 0x13fb6754 && w == 0x0407FE58 {
                    let len = self.size_bin(firmware);
                    self.flash_firmware(Self::start_bin(firmware), len);
                }
            }
            CRYPT | UNCRYPT => {
                let alpha = val(self.pull());
                let key = val(self.pull());
                let r = match self.pull_span() {
                    Some(s) => {
                        let decode = op == UNCRYPT;
                        int(self.crypt(s.at, s.index, s.len, s.size, key, alpha, decode))
                    }
                    None => NIL,
                };
                self.sset(0, r);
            }
            NETRSSI => {
                let r = self.host.net_rssi();
                self.push(int(r));
            }
            RFIDGETLIST => self.rfid_list(),
            RFIDREAD => {
                let block = val(self.pull());
                let p = val(self.pull());
                if p != NIL {
                    self.rfid_read(Self::start_bin(p), block);
                } else {
                    self.push(NIL);
                }
            }
            RFIDWRITE => {
                let q = val(self.pull());
                let block = val(self.pull());
                let p = val(self.pull());
                if p != NIL && q != NIL {
                    let id = self.slice_padded::<8>(Self::start_bin(p));
                    let data = self.slice_padded::<4>(Self::start_bin(q));
                    let r = self.host.rfid_write(&id, block, &data);
                    self.push(int(r));
                } else {
                    self.push(NIL);
                }
            }
            I2CREAD => {
                let size = val(self.pull());
                let address = val(self.pull()) as u8;
                self.i2c_read(address, size);
            }
            I2CWRITE => {
                let len = val(self.pull());
                let data = val(self.pull());
                let address = val(self.pull()) as u8;
                self.i2c_write(address, Self::start_bin(data), len);
            }
            // Unknown, or one of the opcodes this firmware never
            // implemented (udp*, tcp*): nothing happens.
            _ => {}
        }
        Flow::Next
    }

    /// The byte after the opcode.
    fn operand(&self, r: &mut Regs) -> i32 {
        let v = self.b(r.pc) as i32;
        r.pc = r.pc.wrapping_add(1);
        v
    }

    /// Pull `len` and `index`, the arguments of the natives on a part of
    /// a string; the string stays on the stack for the result. None when
    /// it is nil.
    fn pull_span(&mut self) -> Option<Span> {
        let len = self.pull();
        let index = val(self.pull());
        let p = val(self.sget(0));
        (p != NIL).then(|| {
            let size = self.size_bin(p);
            Span {
                at: Self::start_bin(p),
                size,
                index,
                len: val_or(len, size.wrapping_sub(index)),
            }
        })
    }

    /// Pull `index q start len`, the arguments of the natives from one
    /// string to another; the first string stays on the stack for the
    /// result. Both strings, as blocks, when either is nil.
    fn pull_two(&mut self) -> Result<Two, (i32, i32)> {
        let len = self.pull();
        let start = val(self.pull());
        let q = val(self.pull());
        let index = self.pull();
        let p = val(self.sget(0));
        if p == NIL || q == NIL {
            return Err((p, q));
        }
        Ok(Two {
            p: Self::start_bin(p),
            lp: self.size_bin(p),
            index,
            q: Self::start_bin(q),
            lq: self.size_bin(q),
            start,
            len,
        })
    }

    /// How many bytes `strsub` and the sound natives take from the string
    /// `q` at `start`: `len`, or the rest when nil, cut at its end. None
    /// for a nil string, or a part that starts before it or ends before
    /// it starts.
    fn sub_len(&self, q: i32, start: i32, len: i32) -> Option<i32> {
        if q == NIL {
            return None;
        }
        let lq = self.size_bin(q);
        let mut len = val_or(len, lq.wrapping_sub(start));
        if start.wrapping_add(len) > lq {
            len = lq - start;
        }
        (start >= 0 && len >= 0).then_some(len)
    }
}

/// A part of a string, from [`Vm::pull_span`]: the string's first byte
/// and its size, the index and the length asked for (nil already read
/// as the rest).
struct Span {
    at: i32,
    size: i32,
    index: i32,
    len: i32,
}

/// Two strings and where in them, from [`Vm::pull_two`]: each string's
/// first byte and size, then the other arguments. The index and the
/// length are as the stack holds them: what nil stands for there is the
/// native's business.
struct Two {
    p: i32,
    lp: i32,
    index: i32,
    q: i32,
    lq: i32,
    start: i32,
    len: i32,
}

/// The integer a word holds, or `nil` when the word is nil: the natives'
/// optional arguments.
fn val_or(v: i32, nil: i32) -> i32 {
    if v == NIL { nil } else { val(v) }
}

/// The order of two strings when one is nil (`p` and `q` are blocks): a
/// string comes after nil.
fn nil_order(p: i32, q: i32) -> i32 {
    if p != NIL {
        1
    } else if q != NIL {
        -1
    } else {
        0
    }
}
