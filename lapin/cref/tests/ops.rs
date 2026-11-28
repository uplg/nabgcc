//! Small programs, one family of instructions each, on both machines:
//! same console, same calls, same memory to the word.

use lapin_metal::op::*;
use lapin_metal_cref::{Outcome, World, assert_same_memory, run_both, run_c, run_rust};

/// A function being assembled, with labels for its jumps.
#[derive(Default)]
struct Fun {
    narg: u8,
    nloc: u16,
    code: Vec<u8>,
    labels: Vec<Option<u16>>,
    fixups: Vec<(usize, usize)>,
}

impl Fun {
    fn new(narg: u8, nloc: u16) -> Self {
        Fun {
            narg,
            nloc,
            ..Default::default()
        }
    }
    fn op(&mut self, o: i32) -> &mut Self {
        self.code.push(o as u8);
        self
    }
    fn b(&mut self, o: i32, v: u8) -> &mut Self {
        self.code.extend([o as u8, v]);
        self
    }
    fn int(&mut self, v: i32) -> &mut Self {
        self.code.push(INT as u8);
        self.code.extend(v.to_le_bytes());
        self
    }
    fn label(&mut self) -> usize {
        self.labels.push(None);
        self.labels.len() - 1
    }
    fn here(&mut self, l: usize) -> &mut Self {
        self.labels[l] = Some(self.code.len() as u16);
        self
    }
    fn jump(&mut self, o: i32, l: usize) -> &mut Self {
        self.code.push(o as u8);
        self.fixups.push((self.code.len(), l));
        self.code.extend([0, 0]);
        self
    }
    /// An integer, or nil for a negative one: the natives' optional
    /// arguments.
    fn int_or_nil(&mut self, v: i32) -> &mut Self {
        if v < 0 { self.op(NIL_) } else { self.int(v) }
    }
    /// Print the top of the stack as a number and drop it.
    fn show(&mut self) -> &mut Self {
        self.op(IECHOLN).op(DROP)
    }
    /// Print the top of the stack as a string and drop it.
    fn shows(&mut self) -> &mut Self {
        self.op(SECHOLN).op(DROP)
    }
    fn bytes(&self) -> Vec<u8> {
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
fn bytecode(strings: &[&[u8]], funs: &[&Fun]) -> Vec<u8> {
    bytecode_with(strings, &[], funs)
}

/// The same, with integer globals after the strings.
fn bytecode_with(strings: &[&[u8]], ints: &[i32], funs: &[&Fun]) -> Vec<u8> {
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

/// Run on both, compare, give back what the C printed.
fn both(bc: &[u8]) -> String {
    let c = run_both(World::quiet, bc, 3);
    String::from_utf8_lossy(&c.world.console).into_owned()
}

fn main_fun() -> Fun {
    Fun::new(0, 4)
}

fn end(f: &mut Fun) {
    f.op(NIL_).op(RET);
}

#[test]
fn arithmetic() {
    let values = [
        0,
        1,
        -1,
        2,
        7,
        -7,
        13,
        0x3FFF_FFFF,
        -0x4000_0000,
        12345,
        -98765,
        31,
        30,
    ];
    let mut f = main_fun();
    for &a in &values {
        for &b in &values {
            for o in [
                ADD, SUB, MUL, AND, OR, EOR, EQ, NE, LT, GT, LE, GE, MAX, MIN,
            ] {
                f.int(a).int(b).op(o).show();
            }
            // By zero and by more than 31 the host's processor differs
            // from the rabbit's; the unit tests of lapin-metal pin those.
            if b != 0 {
                f.int(a).int(b).op(DIV).show();
                f.int(a).int(b).op(MOD).show();
            }
            if (0..32).contains(&b) {
                f.int(a).int(b).op(SHL).show();
                f.int(a).int(b).op(SHR).show();
            }
        }
        for o in [NEG, NOT, NON, ABS] {
            f.int(a).op(o).show();
        }
    }
    f.op(NIL_).op(NON).show();
    f.op(NIL_).op(NIL_).op(EQ).show();
    f.b(INTB, 200).show();
    f.op(RAND)
        .show()
        .int(42)
        .op(SRAND)
        .op(DROP)
        .op(RAND)
        .show()
        .op(RAND)
        .show();
    f.op(TIME_MS).show().op(TIME).show();
    end(&mut f);
    let out = both(&bytecode(&[], &[&f]));
    assert!(out.lines().count() > 2000, "{out}");
}

#[test]
fn strings() {
    let mut f = main_fun();
    let g = |f: &mut Fun, i: u8| {
        f.b(GETGLOBALB, i);
    };
    // strsub, out of range and nil lengths.
    for (start, len) in [(0, 3), (2, -1), (4, 100), (-1, 2), (10, 1), (3, 0)] {
        g(&mut f, 0);
        f.int(start).int_or_nil(len).op(STRSUB).shows();
    }
    // strcat with nil on either side.
    g(&mut f, 0);
    g(&mut f, 1);
    f.op(STRCAT).shows();
    f.op(NIL_);
    g(&mut f, 1);
    f.op(STRCAT).shows();
    g(&mut f, 0);
    f.op(NIL_).op(STRCAT).shows();
    // strfind, strfindrev.
    for (from, len) in [(0, -1), (3, -1), (0, 2), (20, 1)] {
        for o in [STRFIND, STRFINDREV] {
            g(&mut f, 0);
            f.int(from);
            g(&mut f, 2);
            f.int(0).int_or_nil(len).op(o).show();
        }
    }
    g(&mut f, 0);
    f.op(NIL_);
    g(&mut f, 2);
    f.int(0).op(NIL_).op(STRFINDREV).show();
    // Comparisons.
    for (a, b) in [(0, 1), (1, 0), (0, 0), (2, 3), (3, 2)] {
        g(&mut f, a);
        g(&mut f, b);
        f.op(STRCMP).show();
        g(&mut f, a);
        f.int(0);
        g(&mut f, b);
        f.int(0).op(NIL_).op(VSTRCMP).show();
    }
    g(&mut f, 0);
    f.op(NIL_).op(STRCMP).show();
    // strget, strlen, strnew, strset, strcpy.
    for i in [-1, 0, 5, 9, 10] {
        g(&mut f, 0);
        f.int(i).op(STRGET).show();
    }
    g(&mut f, 0);
    f.op(STRLEN).show();
    f.int(6).op(STRNEW).b(SETLOCALB, 0);
    for (i, c) in [(0, 65), (5, 66), (6, 67), (-1, 68)] {
        f.b(GETLOCALB, 0).int(i).int(c).op(STRSET).op(DROP);
    }
    f.b(GETLOCALB, 0).int(1);
    g(&mut f, 0);
    f.int(2).int(3).op(STRCPY).shows();
    f.b(GETLOCALB, 0).int(4);
    g(&mut f, 0);
    f.int(0).op(NIL_).op(STRCPY).shows();
    // Conversions.
    for s in [3u8, 4, 5, 6] {
        g(&mut f, s);
        f.op(ATOI).show();
        g(&mut f, s);
        f.op(HTOI).show();
    }
    for v in [0, 1, -1, 123456, -0x4000_0000, 0x3FFF_FFFF, 255, 4096] {
        f.int(v).op(ITOA).shows();
        f.int(v).op(ITOH).shows();
        f.int(v).op(CTOH).shows();
        f.int(v).op(CTOA).shows();
        f.int(v).op(ITOBIN2).shows();
    }
    // Words.
    for i in [-1, 0, 4, 9] {
        g(&mut f, 0);
        f.int(i).op(STRGETWORD).show();
    }
    f.b(GETLOCALB, 0).int(2).int(0x4142).op(STRPUTWORD).shows();
    // Lists of pairs.
    f.int(1)
        .int(10)
        .b(DEFTABB, 2)
        .int(2)
        .int(20)
        .b(DEFTABB, 2)
        .op(NIL_)
        .b(DEFTABB, 2)
        .b(DEFTABB, 2);
    f.b(SETLOCALB, 1);
    for k in [1, 2, 3] {
        f.b(GETLOCALB, 1).int(k).op(LISTSWITCH).show();
    }
    g(&mut f, 0);
    f.int(7).b(DEFTABB, 2);
    g(&mut f, 1);
    f.int(8)
        .b(DEFTABB, 2)
        .op(NIL_)
        .b(DEFTABB, 2)
        .b(DEFTABB, 2)
        .b(SETLOCALB, 2);
    for s in [0, 1, 2] {
        f.b(GETLOCALB, 2);
        g(&mut f, s);
        f.op(LISTSWITCHSTR).show();
    }
    f.b(GETLOCALB, 2).op(NIL_).op(LISTSWITCHSTR).show();
    // crypt and uncrypt, there and back.
    g(&mut f, 0);
    f.int(0).op(NIL_).int(0x47).int(47).op(CRYPT).show();
    g(&mut f, 0);
    f.shows();
    g(&mut f, 0);
    f.int(0).op(NIL_).int(0x47).int(47).op(UNCRYPT).show();
    g(&mut f, 0);
    f.shows();
    g(&mut f, 0);
    f.int(5).int(20).int(1).int(2).op(CRYPT).show();
    // Checksums and sequence numbers.
    // Even offsets only: from an odd one the rabbit's processor loads a
    // rotated halfword, the host's does not (pinned in lapin-metal).
    for (i, l) in [(0, -1), (2, -1), (0, 7), (4, 4), (-1, 2)] {
        g(&mut f, 0);
        f.int(i).int_or_nil(l).int(0x1234).op(NETCHK).show();
    }
    g(&mut f, 0);
    f.int(-5).op(NETSEQADD).shows();
    g(&mut f, 2);
    f.int(1).op(NETSEQADD).op(SECHOLN).op(DROP);
    end(&mut f);
    let strings: &[&[u8]] = &[
        b"carottes!!",
        b"-violettes",
        b"ot",
        b"-1234x",
        b"ffzz",
        b"99999999999",
        b"",
        b"abc",
    ];
    let out = both(&bytecode(strings, &[&f]));
    assert!(out.contains("carottes!!-violettes"), "{out}");
}

#[test]
fn tables_and_calls() {
    // f(a, b) = a * b + 1
    let mut mul = Fun::new(2, 0);
    mul.b(GETLOCALB, 0)
        .b(GETLOCALB, 1)
        .op(MUL)
        .int(1)
        .op(ADD)
        .op(RET);
    // Both recursions start with: if n == 0 then 0 else ...
    let zero_or = || {
        let mut f = Fun::new(1, 0);
        let rec = f.label();
        f.b(GETLOCALB, 0)
            .int(0)
            .op(EQ)
            .jump(ELSE, rec)
            .int(0)
            .op(RET)
            .here(rec);
        f
    };
    // g(n) = g(n - 1): a tail call, so it runs in constant stack.
    let mut g = zero_or();
    g.b(GETLOCALB, 0).int(1).op(SUB).int(2).op(EXEC).op(RET);
    // h(n) = n + h(n - 1), not a tail call.
    let mut h = zero_or();
    h.b(GETLOCALB, 0)
        .b(GETLOCALB, 0)
        .int(1)
        .op(SUB)
        .int(3)
        .op(EXEC)
        .op(ADD)
        .op(RET);

    let mut f = main_fun();
    f.int(6).int(7).int(1).op(EXEC).show();
    f.int(100_000).int(2).op(EXEC).show();
    f.int(300).int(3).op(EXEC).show();
    // A closure: [fun [b nil]] given a.
    f.int(5)
        .int(1)
        .int(9)
        .op(NIL_)
        .b(DEFTABB, 2)
        .b(DEFTABB, 2)
        .op(EXEC)
        .show();
    // callrb: function under its arguments.
    f.int(1).int(3).int(4).b(CALLRB, 2).show();
    f.op(NIL_).int(3).int(4).b(CALLRB, 2).show();
    // call: a tuple [fun a b].
    f.int(1).int(8).int(9).b(DEFTABB, 3).op(CALL).show();
    // Tables.
    f.b(MKTABB, 3).b(SETLOCALB, 0);
    for i in [0, 2, 3, -1] {
        f.b(GETLOCALB, 0).int(i).int(i * 11).op(STORE).show();
        f.b(GETLOCALB, 0).int(i).op(FETCH).show();
    }
    f.b(GETLOCALB, 0).op(TABLEN).show();
    f.b(GETLOCALB, 0)
        .op(HD)
        .show()
        .b(GETLOCALB, 0)
        .op(TL)
        .show();
    f.b(GETLOCALB, 0).b(FETCHB, 2).show();
    f.b(GETLOCALB, 0)
        .int(77)
        .b(SETSTRUCTB, 1)
        .b(FETCHB, 1)
        .show();
    f.int(4).op(MKTAB).op(TABLEN).show();
    f.int(9).int(5).op(TABNEW).b(FETCHB, 4).show();
    f.int(1).int(2).int(3).int(3).op(DEFTAB).b(FETCHB, 2).show();
    f.op(NIL_).op(HD).show().op(NIL_).int(1).op(FETCH).show();
    f.b(GETLOCALB, 0).op(FIRST).show().op(DROP);
    // Globals: the first one is a string here.
    f.b(GETGLOBALB, 0).op(STRLEN).show();
    f.int(0)
        .int(12)
        .op(SETGLOBAL)
        .show()
        .b(GETGLOBALB, 0)
        .show();
    f.int(0).op(GETGLOBAL).show();
    // Locals by number, stack words.
    f.int(3).int(1).op(SETLOCAL).int(1).op(GETLOCAL).show();
    f.int(2).int(6).op(SETLOCAL2).show().b(GETLOCALB, 2).show();
    f.op(COREPP).show();
    f.int(5).op(COREPUSH).show().show();
    f.int(5).int(6).op(COREPULL).show();
    f.int(8).int(1).op(COREBIT0).op(IECHOLN).op(DROP);
    // Strings of tables.
    f.b(GETGLOBALB, 0)
        .op(NIL_)
        .b(DEFTABB, 2)
        .op(STRCATLIST)
        .op(STRLEN)
        .show();
    end(&mut f);
    let out = both(&bytecode(&[b"lapin"], &[&f, &mul, &g, &h]));
    assert!(out.starts_with("43\r\n0\r\n45150\r\n"), "{out}");
}

#[test]
fn the_collector_moves_everything_the_same() {
    // Keep a list of strings, make garbage in between, many times over
    // the size of the memory.
    let mut f = main_fun();
    let (top, out) = (f.label(), f.label());
    f.int(0).b(SETLOCALB, 0).op(NIL_).b(SETLOCALB, 1);
    f.here(top)
        .b(GETLOCALB, 0)
        .int(30_000)
        .op(LT)
        .jump(ELSE, out);
    f.int(40).op(STRNEW).op(DROP);
    f.int(3).op(MKTAB).op(DROP);
    f.b(GETLOCALB, 0).int(7).op(MOD).int(0).op(EQ);
    let skip = f.label();
    f.jump(ELSE, skip);
    f.b(GETLOCALB, 0)
        .op(ITOA)
        .b(GETLOCALB, 1)
        .b(DEFTABB, 2)
        .b(SETLOCALB, 1);
    f.here(skip);
    // Drop half the list now and then.
    f.b(GETLOCALB, 0).int(5000).op(MOD).int(4999).op(EQ);
    let keep = f.label();
    f.jump(ELSE, keep)
        .b(GETLOCALB, 1)
        .op(TL)
        .op(TL)
        .b(SETLOCALB, 1)
        .here(keep);
    f.b(GETLOCALB, 0)
        .int(1)
        .op(ADD)
        .b(SETLOCALB, 0)
        .jump(GOTO, top);
    f.here(out).op(GC).show();
    f.b(GETLOCALB, 1).op(HD).shows();
    end(&mut f);
    let out = both(&bytecode(&[], &[&f]));
    assert!(out.matches("#GC").count() > 3, "{out}");
}

#[test]
fn out_of_memory_breaks_both_the_same_way() {
    let mut f = main_fun();
    let top = f.label();
    f.op(NIL_).b(SETLOCALB, 1);
    f.here(top)
        .int(100)
        .op(STRNEW)
        .b(GETLOCALB, 1)
        .b(DEFTABB, 2)
        .b(SETLOCALB, 1)
        .jump(GOTO, top);
    end(&mut f);
    let c = run_both(World::quiet, &bytecode(&[], &[&f]), 2);
    assert!(c.world.log.contains(&"reboot".to_string()));
}

#[test]
fn sound_conversions() {
    // 505 samples of a saw, as 16-bit little-endian.
    let pcm: Vec<u8> = (0..505i32)
        .flat_map(|i| (((i * 397) % 20000 - 10000) as i16).to_le_bytes())
        .collect();
    let mut f = main_fun();
    // wav2adp then adp2wav.
    f.int(256).op(STRNEW).b(SETLOCALB, 0);
    f.b(GETLOCALB, 0)
        .int(0)
        .b(GETGLOBALB, 0)
        .int(0)
        .op(NIL_)
        .op(WAV2ADP)
        .shows();
    f.int(1010).op(STRNEW).b(SETLOCALB, 1);
    f.b(GETLOCALB, 1)
        .int(0)
        .b(GETLOCALB, 0)
        .int(0)
        .op(NIL_)
        .op(ADP2WAV)
        .shows();
    f.b(GETLOCALB, 0).int(0).op(RECVOL).show();
    // A-law and mu-law, both ways.
    for mu in [0, 1] {
        f.int(505).op(STRNEW).b(SETLOCALB, 2);
        f.b(GETLOCALB, 2)
            .int(0)
            .b(GETGLOBALB, 0)
            .int(0)
            .op(NIL_)
            .int(mu)
            .op(WAV2ALAW)
            .shows();
        f.int(1010).op(STRNEW).b(SETLOCALB, 3);
        f.b(GETLOCALB, 3)
            .int(0)
            .b(GETLOCALB, 2)
            .int(0)
            .op(NIL_)
            .int(mu)
            .op(ALAW2WAV)
            .shows();
    }
    // Bad lengths do nothing.
    f.b(GETLOCALB, 0)
        .int(0)
        .b(GETGLOBALB, 0)
        .int(0)
        .int(1000)
        .op(WAV2ADP)
        .op(STRLEN)
        .show();
    f.b(GETLOCALB, 1)
        .int(0)
        .b(GETLOCALB, 0)
        .int(1)
        .int(255)
        .op(ADP2WAV)
        .op(STRLEN)
        .show();
    end(&mut f);
    both(&bytecode(&[&pcm], &[&f]));
}

#[test]
fn sound_streams() {
    // play: the callback feeds the same 300 bytes again and again.
    let mut feed = Fun::new(1, 0);
    feed.b(GETGLOBALB, 0).int(0).op(NIL_).op(PLAYFEED).op(RET);
    // rec: the callback prints how much it got.
    let mut got = Fun::new(1, 0);
    got.b(GETLOCALB, 0).op(STRLEN).op(IECHOLN).op(RET);
    // The loop callback stops the sound on its 20th turn and records.
    let mut tick = Fun::new(0, 0);
    let later = tick.label();
    tick.int(1)
        .b(GETGLOBALB, 1)
        .int(1)
        .op(ADD)
        .op(SETGLOBAL)
        .op(DROP);
    tick.b(GETGLOBALB, 1).int(20).op(EQ).jump(ELSE, later);
    tick.op(PLAYSTOP)
        .op(DROP)
        .int(8000)
        .int(0)
        .int(2)
        .op(RECSTART)
        .op(DROP);
    tick.here(later).op(SNDREFRESH).op(RET);
    let mut f = main_fun();
    f.int(512).int(1).op(PLAYSTART).op(DROP);
    f.op(SNDREFRESH).op(DROP).op(PLAYTIME).show();
    f.int(3).op(LOOPCB).op(DROP);
    end(&mut f);
    let pcm: Vec<u8> = (0..300u32).map(|i| (i * 7) as u8).collect();
    let bc = bytecode_with(&[&pcm], &[0], &[&f, &feed, &got, &tick]);
    let c = run_both(World::quiet, &bc, 40);
    assert!(c.world.codec_fed > 4000, "{}", c.world.codec_fed);
    assert!(String::from_utf8_lossy(&c.world.console).contains("256"));
}

#[test]
fn the_board() {
    let mut f = main_fun();
    for (led, color) in [(0, 0xFF0000), (4, 0x00FF00), (300, 0x123456)] {
        f.int(led).int(color).op(LED).op(DROP);
    }
    for (m, s) in [(0, 1), (1, -1), (2, 0), (3, 5)] {
        f.int(m).int(s).op(MOTORSET).op(DROP);
        f.int(m).op(MOTORGET).show();
    }
    f.op(BUTTON2).show().op(BUTTON3).show();
    f.op(RFIDGET)
        .op(SECHOLN)
        .op(DROP)
        .op(RFIDGETLIST)
        .op(SECHOLN)
        .op(DROP);
    f.b(GETGLOBALB, 0).int(3).op(RFIDREAD).op(SECHOLN).op(DROP);
    f.b(GETGLOBALB, 0)
        .int(3)
        .b(GETGLOBALB, 1)
        .op(RFIDWRITE)
        .show();
    f.int(3).op(SNDVOL).op(DROP).int(250).op(SNDVOL).op(DROP);
    f.int(11)
        .int(0x2020)
        .op(SNDWRITE)
        .op(DROP)
        .int(11)
        .op(SNDREAD)
        .show()
        .int(-1)
        .op(SNDREAD)
        .show();
    f.int(1)
        .op(SNDAMPLI)
        .op(DROP)
        .int(256)
        .op(SNDAMPLI)
        .op(DROP);
    f.b(GETGLOBALB, 1).int(0).op(NIL_).op(SNDFEED).show();
    f.op(PLAYTIME).show();
    // Settings: read, write, read back.
    f.int(16).op(STRNEW).b(SETLOCALB, 0);
    f.b(GETLOCALB, 0)
        .int(0)
        .b(GETGLOBALB, 0)
        .int(58)
        .op(NIL_)
        .op(LOAD)
        .show();
    f.b(GETLOCALB, 0).shows();
    f.b(GETGLOBALB, 1)
        .int(0)
        .b(GETGLOBALB, 0)
        .int(4090)
        .op(NIL_)
        .op(SAVE)
        .show();
    f.b(GETLOCALB, 0)
        .int(2)
        .b(GETGLOBALB, 0)
        .int(4090)
        .int(8)
        .op(LOAD)
        .show();
    f.b(GETLOCALB, 0).shows();
    // The network natives that need no network.
    f.op(NETSTATE).show().op(NETMAC).shows().op(NETRSSI).show();
    f.int(1).b(GETGLOBALB, 2).int(11).op(NETSETMODE).show();
    f.int(0).op(NIL_).int(0).op(NETSETMODE).show();
    f.op(NIL_).op(NETSCAN).op(HD).b(SETLOCALB, 1);
    f.b(GETLOCALB, 1).b(FETCHB, 0).shows();
    f.b(GETGLOBALB, 2).b(GETGLOBALB, 3).op(NETPMK).shows();
    f.b(GETLOCALB, 1)
        .int(0)
        .int(64)
        .b(GETGLOBALB, 3)
        .op(NETAUTH)
        .op(DROP);
    f.b(GETGLOBALB, 3)
        .int(0)
        .op(NIL_)
        .b(GETGLOBALB, 4)
        .int(0)
        .int(1)
        .op(NETSEND)
        .show();
    // Wrong keys: no reboot, no flash.
    f.int(1).int(2).op(REBOOT).op(DROP);
    f.b(GETGLOBALB, 1).int(1).int(2).op(FLASHFIRMWARE).op(DROP);
    f.b(GETGLOBALB, 1)
        .int(0x13fb6754)
        .int(0x0407FE58)
        .op(FLASHFIRMWARE)
        .op(DROP);
    // Opcodes the firmware never implemented do nothing.
    f.int(9).op(UDPSTART).op(TCPOPEN).op(TCPENABLE).show();
    end(&mut f);
    let strings: &[&[u8]] = &[
        b"12345678",
        b"abcd",
        b"Terrier",
        b"carotte-violette",
        &[255; 6],
    ];
    let out = both(&bytecode(strings, &[&f]));
    assert!(out.contains("Terrier"), "{out}");
}

#[test]
fn a_new_bytecode_takes_over_with_its_environment() {
    // The second program prints its environment.
    let mut second = main_fun();
    second.op(ENVGET).shows();
    end(&mut second);
    let inner = bytecode(&[b"second"], &[&second]);
    let mut f = main_fun();
    f.b(GETGLOBALB, 1).op(ENVSET).op(DROP);
    f.b(GETGLOBALB, 0).op(BYTECODE);
    end(&mut f);
    let out = both(&bytecode(&[&inner, b"the environment"], &[&f]));
    assert!(out.contains("the environment"), "{out}");
}

/// What a run left, without the world's handlers (which stay on their
/// thread).
#[derive(Debug, PartialEq)]
struct Left {
    console: Vec<u8>,
    log: String,
    registers: (i32, i32, i32),
    heap: Vec<i32>,
    fifo: Vec<u8>,
}

fn left(o: &Outcome) -> Left {
    Left {
        console: o.world.console.clone(),
        log: format!("{:?}", o.world.log),
        registers: o.registers,
        heap: o.heap.to_vec(),
        fifo: o.fifo.to_vec(),
    }
}

/// Run the Rust machine on a thread, or say it never finished: a hang
/// in the collector must fail the test, not stall it.
fn rust_within(bc: &[u8], runs: usize, secs: u64) -> Left {
    let bc = bc.to_vec();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(left(&run_rust(World::quiet(), &bc, runs)));
    });
    rx.recv_timeout(std::time::Duration::from_secs(secs))
        .expect("the Rust machine never finished")
}

const LEN: i32 = lapin_metal::VMEM_LENGTH as i32;

#[test]
fn a_store_at_a_negative_index_into_a_negative_header_is_skipped_as_in_c() {
    for op in [STORE, SETSTRUCT] {
        let mut m = main_fun();
        // A table whose first slot holds -1000 (a header of -2000 seen
        // from the pointer made to it): VSIZE is negative there.
        m.int(-1000)
            .b(DEFTABB, 1)
            .op(DUP)
            .b(INTB, 3)
            .op(ADD)
            .b(INTB, 1)
            .op(COREBIT0);
        if op == STORE {
            m.int(-1).b(INTB, 77).op(STORE);
        } else {
            m.b(INTB, 77).int(-1).op(SETSTRUCT);
        }
        m.op(DROP);
        end(&mut m);
        run_both(World::quiet, &bytecode(&[], &[&m]), 0);
    }
}

/// A recording whose push collects: the samples land in the block
/// where it moved, as the C (which reads it back from the stack).
#[test]
fn a_recording_block_moved_by_its_own_push_gets_the_samples() {
    let prog = |x: i32| {
        let mut m = main_fun();
        m.int(8000)
            .b(INTB, 0)
            .b(INTB, 1)
            .op(RECSTART)
            .op(DROP)
            .int(x)
            .op(STRNEW)
            .op(DROP);
        end(&mut m);
        let mut cb = Fun::new(1, 0);
        cb.b(GETLOCALB, 0)
            .op(STRLEN)
            .op(IECHOLN)
            .op(DROP)
            .b(GETLOCALB, 0)
            .op(SECHOLN)
            .op(RET);
        bytecode(&[], &[&m, &cb])
    };
    let (stack, heapindex, _) = run_c(World::quiet(), &prog(0), 0).registers;
    // 16 words left after the recording's block: its push collects.
    let want = LEN + stack - heapindex + 4 - 84;
    let mut collected = 0;
    for dw in -3..=3 {
        let bc = prog((want + dw - 3) * 4 - 4);
        let c = run_both(World::quiet, &bc, 1);
        collected += String::from_utf8_lossy(&c.world.console)
            .matches("#GC")
            .count();
    }
    assert!(collected > 0, "no collection met: the test lost its point");
}

/// A word that looks like a pointer outside the memory, on the stack
/// at a collection: the C chains it in the RAM beside the heap and
/// finishes; so must this one, with the same memory.
#[test]
fn the_collector_finishes_with_a_pointer_outside_the_memory() {
    for k in [-5i32, LEN + 1000, LEN - 2] {
        let mut m = main_fun();
        // Words 1 and 2 of the memory (the code's bytes 4..12) zero.
        let l = m.label();
        m.jump(GOTO, l);
        m.code.extend([0; 12]);
        m.here(l);
        m.int(k)
            .b(INTB, 1)
            .op(COREBIT0)
            .op(GC)
            .op(IECHOLN)
            .op(DROP)
            .b(INTB, 42)
            .op(IECHOLN)
            .op(DROP);
        end(&mut m);
        let bc = bytecode(&[], &[&m]);
        let r = rust_within(&bc, 0, 10);
        if k == LEN - 2 {
            // Its first word inside, its chaining word outside: the C's
            // mark would land in the heap's last word. Finishing is
            // what matters here.
            assert!(String::from_utf8_lossy(&r.console).contains("42"));
        } else {
            let c = left(&run_c(World::quiet(), &bc, 0));
            assert_eq!(
                String::from_utf8_lossy(&c.console),
                String::from_utf8_lossy(&r.console)
            );
            assert_eq!(c.registers, r.registers, "k {k}");
            assert_eq!(c.log, r.log, "k {k}");
            assert_same_memory(&c.heap, &r.heap, &format!("k {k}: "));
            assert_eq!(c.fifo, r.fifo, "k {k}");
        }
    }
}

/// A bytecode whose code size makes the C's unsigned `(n + 3) >> 2`
/// huge: the Rust machine must neither copy below its memory nor hang.
#[test]
fn a_bytecode_with_an_absurd_size_is_survived() {
    let n: i32 = 1_073_741_804;
    let mut m = main_fun();
    let first = m.label();
    m.op(RAND)
        .jump(ELSE, first)
        .int(n)
        .op(STRNEW)
        .op(DROP)
        .int(n)
        .op(STRNEW)
        .op(DROP)
        .b(MKTABB, 1)
        .op(GC)
        .op(IECHOLN)
        .op(DROP)
        .b(INTB, 42)
        .op(IECHOLN)
        .op(RET);
    m.here(first)
        .b(INTB, 16)
        .op(STRNEW)
        .b(INTB, 0)
        .int(0x0400)
        .op(STRPUTWORD)
        .b(INTB, 4)
        .int(0xFCFF)
        .op(STRPUTWORD)
        .b(INTB, 6)
        .int(0xFF7F)
        .op(STRPUTWORD)
        .op(BYTECODE)
        .op(RET);
    let bc = bytecode(&[], &[&m]);
    rust_within(&bc, 0, 10);
}
