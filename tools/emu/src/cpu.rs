//! ARM7TDMI interpreter (ARMv4T, ARM and Thumb states).
//!
//! Instruction-accurate, not cycle-accurate: the machine charges a flat
//! cost per instruction. No coprocessor, as on the real core.

pub trait Bus {
    fn read8(&mut self, addr: u32) -> u8;
    fn read16(&mut self, addr: u32) -> u16;
    fn read32(&mut self, addr: u32) -> u32;
    fn write8(&mut self, addr: u32, val: u8);
    fn write16(&mut self, addr: u32, val: u16);
    fn write32(&mut self, addr: u32, val: u32);
}

pub const MODE_USR: u32 = 0x10;
pub const MODE_FIQ: u32 = 0x11;
pub const MODE_IRQ: u32 = 0x12;
pub const MODE_SVC: u32 = 0x13;
pub const MODE_ABT: u32 = 0x17;
pub const MODE_UND: u32 = 0x1B;
pub const MODE_SYS: u32 = 0x1F;

pub const FLAG_N: u32 = 1 << 31;
pub const FLAG_Z: u32 = 1 << 30;
pub const FLAG_C: u32 = 1 << 29;
pub const FLAG_V: u32 = 1 << 28;
pub const FLAG_I: u32 = 1 << 7;
pub const FLAG_F: u32 = 1 << 6;
pub const FLAG_T: u32 = 1 << 5;

/// Why the core left the straight path on the last step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trap {
    None,
    Undefined { addr: u32, opcode: u32 },
    Swi { addr: u32, number: u32 },
    Irq,
    Fiq,
}

#[derive(Clone)]
pub struct Cpu {
    /// r[15] is the address of the next instruction to fetch.
    pub r: [u32; 16],
    pub cpsr: u32,
    bank_hi: [[u32; 5]; 2],
    bank_sp_lr: [[u32; 2]; 6],
    spsr: [u32; 6],
    pub irq_line: bool,
    pub fiq_line: bool,
    pub last_trap: Trap,
}

fn bank_of(mode: u32) -> usize {
    match mode & 0x1F {
        MODE_FIQ => 1,
        MODE_IRQ => 2,
        MODE_SVC => 3,
        MODE_ABT => 4,
        MODE_UND => 5,
        _ => 0,
    }
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

impl Cpu {
    pub fn new() -> Self {
        let mut c = Cpu {
            r: [0; 16],
            cpsr: MODE_SVC | FLAG_I | FLAG_F,
            bank_hi: [[0; 5]; 2],
            bank_sp_lr: [[0; 2]; 6],
            spsr: [0; 6],
            irq_line: false,
            fiq_line: false,
            last_trap: Trap::None,
        };
        c.reset();
        c
    }

    pub fn reset(&mut self) {
        self.set_cpsr(MODE_SVC | FLAG_I | FLAG_F);
        self.r[15] = 0;
        self.last_trap = Trap::None;
    }

    #[inline]
    pub fn thumb(&self) -> bool {
        self.cpsr & FLAG_T != 0
    }

    #[inline]
    pub fn mode(&self) -> u32 {
        self.cpsr & 0x1F
    }

    /// Address of the instruction about to run.
    #[inline]
    pub fn pc(&self) -> u32 {
        self.r[15]
    }

    pub fn set_cpsr(&mut self, new: u32) {
        let old_mode = self.cpsr & 0x1F;
        let new_mode = new & 0x1F;
        if old_mode != new_mode {
            let (ob, nb) = (bank_of(old_mode), bank_of(new_mode));
            if ob != nb {
                self.bank_sp_lr[ob] = [self.r[13], self.r[14]];
                let (of, nf) = ((ob == 1) as usize, (nb == 1) as usize);
                if of != nf {
                    self.bank_hi[of].copy_from_slice(&self.r[8..13]);
                    let hi = self.bank_hi[nf];
                    self.r[8..13].copy_from_slice(&hi);
                }
                self.r[13] = self.bank_sp_lr[nb][0];
                self.r[14] = self.bank_sp_lr[nb][1];
            }
        }
        self.cpsr = new;
    }

    pub fn spsr(&self) -> u32 {
        match bank_of(self.mode()) {
            0 => self.cpsr,
            b => self.spsr[b],
        }
    }

    fn set_spsr(&mut self, v: u32) {
        let b = bank_of(self.mode());
        if b != 0 {
            self.spsr[b] = v;
        }
    }

    fn user_reg(&self, n: usize) -> u32 {
        let b = bank_of(self.mode());
        match n {
            8..=12 if b == 1 => self.bank_hi[0][n - 8],
            13 | 14 if b != 0 => self.bank_sp_lr[0][n - 13],
            _ => self.r[n],
        }
    }

    fn set_user_reg(&mut self, n: usize, v: u32) {
        let b = bank_of(self.mode());
        match n {
            8..=12 if b == 1 => self.bank_hi[0][n - 8] = v,
            13 | 14 if b != 0 => self.bank_sp_lr[0][n - 13] = v,
            _ => self.r[n] = v,
        }
    }

    /// Register as an instruction sees it: r15 reads two instructions ahead.
    #[inline]
    fn reg(&self, n: usize) -> u32 {
        if n == 15 {
            self.r[15].wrapping_add(if self.thumb() { 2 } else { 4 })
        } else {
            self.r[n]
        }
    }

    #[inline]
    fn flag(&self, f: u32) -> bool {
        self.cpsr & f != 0
    }

    #[inline]
    fn set_nz(&mut self, v: u32) {
        self.cpsr =
            (self.cpsr & !(FLAG_N | FLAG_Z)) | (v & FLAG_N) | if v == 0 { FLAG_Z } else { 0 };
    }

    #[inline]
    fn set_c(&mut self, c: bool) {
        self.cpsr = (self.cpsr & !FLAG_C) | if c { FLAG_C } else { 0 };
    }

    #[inline]
    fn set_nzcv(&mut self, v: u32, c: bool, o: bool) {
        self.cpsr = (self.cpsr & 0x0FFF_FFFF)
            | (v & FLAG_N)
            | if v == 0 { FLAG_Z } else { 0 }
            | if c { FLAG_C } else { 0 }
            | if o { FLAG_V } else { 0 };
    }

    fn cond(&self, c: u32) -> bool {
        let (n, z, cf, v) = (
            self.flag(FLAG_N),
            self.flag(FLAG_Z),
            self.flag(FLAG_C),
            self.flag(FLAG_V),
        );
        match c {
            0x0 => z,
            0x1 => !z,
            0x2 => cf,
            0x3 => !cf,
            0x4 => n,
            0x5 => !n,
            0x6 => v,
            0x7 => !v,
            0x8 => cf && !z,
            0x9 => !cf || z,
            0xA => n == v,
            0xB => n != v,
            0xC => !z && n == v,
            0xD => z || n != v,
            0xE => true,
            _ => false,
        }
    }

    fn exception(&mut self, vector: u32, mode: u32, lr: u32) {
        let old = self.cpsr;
        let mut new = (old & !0x3F) | mode | FLAG_I;
        if mode == MODE_FIQ {
            new |= FLAG_F;
        }
        self.set_cpsr(new);
        self.set_spsr(old);
        self.r[14] = lr;
        self.r[15] = vector;
    }

    /// Run one instruction, or take one pending interrupt.
    /// Run one instruction, or take one pending interrupt. Returns the
    /// number of clock cycles it took on a real core without wait states.
    pub fn step<B: Bus>(&mut self, bus: &mut B) -> u32 {
        self.last_trap = Trap::None;
        if self.fiq_line && !self.flag(FLAG_F) {
            let lr = self.r[15].wrapping_add(4);
            self.exception(0x1C, MODE_FIQ, lr);
            self.last_trap = Trap::Fiq;
            return 3;
        }
        if self.irq_line && !self.flag(FLAG_I) {
            let lr = self.r[15].wrapping_add(4);
            self.exception(0x18, MODE_IRQ, lr);
            self.last_trap = Trap::Irq;
            return 3;
        }
        if self.thumb() {
            let pc = self.r[15] & !1;
            let op = bus.read16(pc) as u32;
            let cycles = self.thumb_cycles(op);
            self.r[15] = pc.wrapping_add(2);
            self.exec_thumb(bus, op, pc);
            cycles
        } else {
            let pc = self.r[15] & !3;
            let op = bus.read32(pc);
            self.r[15] = pc.wrapping_add(4);
            if !self.cond(op >> 28) {
                return 1;
            }
            let cycles = self.arm_cycles(op);
            self.exec_arm(bus, op, pc);
            cycles
        }
    }

    // ---- timing -------------------------------------------------------
    //
    // Cycle counts from the ARM7TDMI data sheet, with every sequential,
    // non-sequential and internal cycle taken as one clock period.

    /// Internal cycles of a multiplication: the core stops early when
    /// the upper bytes of the multiplier are all zeros (or all ones,
    /// for signed operations).
    fn multiplier_cycles(multiplier: u32, signed: bool) -> u32 {
        let fits = |bits: u32| {
            let top = multiplier >> bits;
            top == 0 || (signed && top == u32::MAX >> bits)
        };
        if fits(8) {
            1
        } else if fits(16) {
            2
        } else if fits(24) {
            3
        } else {
            4
        }
    }

    fn arm_cycles(&self, op: u32) -> u32 {
        let rd_is_pc = (op >> 12) & 15 == 15;
        let load = op & (1 << 20) != 0;
        match (op >> 25) & 7 {
            0b000 | 0b001 => {
                let immediate = op & (1 << 25) != 0;
                if !immediate && op & 0x0FFF_FFF0 == 0x012F_FF10 {
                    3
                } else if !immediate && op & 0x90 == 0x90 {
                    if op & 0x60 != 0 {
                        // Halfword and signed byte transfers.
                        if load { 3 + 2 * rd_is_pc as u32 } else { 2 }
                    } else {
                        let rs = self.r[((op >> 8) & 15) as usize];
                        let accumulate = (op >> 21) & 1;
                        match (op >> 23) & 3 {
                            0 => 1 + Self::multiplier_cycles(rs, true) + accumulate,
                            1 => 2 + Self::multiplier_cycles(rs, op & (1 << 22) != 0) + accumulate,
                            _ => 4,
                        }
                    }
                } else if op & 0x0190_0000 == 0x0100_0000 {
                    1
                } else {
                    let register_shift = !immediate && op & 0x10 != 0;
                    let compare = (0x8..=0xB).contains(&((op >> 21) & 15));
                    1 + register_shift as u32 + 2 * (rd_is_pc && !compare) as u32
                }
            }
            0b010 | 0b011 => {
                if load {
                    3 + 2 * rd_is_pc as u32
                } else {
                    2
                }
            }
            0b100 => {
                let n = (op & 0xFFFF).count_ones().max(1);
                if load {
                    n + 2 + 2 * (op >> 15 & 1)
                } else {
                    n + 1
                }
            }
            0b101 => 3,
            _ => {
                if op & (1 << 24) != 0 {
                    3
                } else {
                    4
                }
            }
        }
    }

    fn thumb_cycles(&self, op: u32) -> u32 {
        let load = op & (1 << 11) != 0;
        match op >> 11 {
            0b00000..=0b00111 => 1,
            0b01000 => {
                if op & (1 << 10) == 0 {
                    match (op >> 6) & 15 {
                        // Shifts by a register amount.
                        2 | 3 | 4 | 7 => 2,
                        0xD => 1 + Self::multiplier_cycles(self.r[(op & 7) as usize], true),
                        _ => 1,
                    }
                } else if (op >> 8) & 3 == 3 {
                    3
                } else {
                    let to_pc = (op & 7) | ((op >> 4) & 8) == 15;
                    1 + 2 * (to_pc && (op >> 8) & 3 != 1) as u32
                }
            }
            0b01001 => 3,
            0b01010 | 0b01011 => {
                if (op >> 9) & 7 <= 2 {
                    2
                } else {
                    3
                }
            }
            0b01100..=0b10011 => {
                if load {
                    3
                } else {
                    2
                }
            }
            0b10100 | 0b10101 => 1,
            0b10110 | 0b10111 => {
                let n = (op & 0x1FF).count_ones();
                match (op >> 8) & 15 {
                    0x4 | 0x5 => n + 1,
                    0xC | 0xD => n + 2 + 2 * (op >> 8 & 1),
                    _ => 1,
                }
            }
            0b11000 | 0b11001 => {
                let n = (op & 0xFF).count_ones().max(1);
                if load { n + 2 } else { n + 1 }
            }
            0b11010 | 0b11011 => {
                let c = (op >> 8) & 15;
                if c == 0xF || self.cond(c) { 3 } else { 1 }
            }
            0b11100 | 0b11111 => 3,
            _ => 1,
        }
    }

    fn undefined(&mut self, addr: u32, opcode: u32) {
        let lr = self.r[15];
        self.exception(0x04, MODE_UND, lr);
        self.last_trap = Trap::Undefined { addr, opcode };
    }

    fn swi(&mut self, addr: u32, number: u32) {
        let lr = self.r[15];
        self.exception(0x08, MODE_SVC, lr);
        self.last_trap = Trap::Swi { addr, number };
    }

    fn branch(&mut self, target: u32) {
        self.r[15] = if self.thumb() {
            target & !1
        } else {
            target & !3
        };
    }

    fn bx(&mut self, target: u32) {
        if target & 1 != 0 {
            self.cpsr |= FLAG_T;
            self.r[15] = target & !1;
        } else {
            self.cpsr &= !FLAG_T;
            self.r[15] = target & !3;
        }
    }

    // ---- shifts -------------------------------------------------------

    /// Shift by an immediate amount (ARM encoding: 0 has special meanings).
    fn shift_imm(&self, kind: u32, v: u32, amount: u32) -> (u32, bool) {
        let c = self.flag(FLAG_C);
        match kind {
            0 => {
                if amount == 0 {
                    (v, c)
                } else {
                    (v << amount, v & (1 << (32 - amount)) != 0)
                }
            }
            1 => {
                if amount == 0 {
                    (0, v >> 31 != 0)
                } else {
                    (v >> amount, v & (1 << (amount - 1)) != 0)
                }
            }
            2 => {
                if amount == 0 {
                    (((v as i32) >> 31) as u32, v >> 31 != 0)
                } else {
                    (((v as i32) >> amount) as u32, v & (1 << (amount - 1)) != 0)
                }
            }
            _ => {
                if amount == 0 {
                    ((v >> 1) | ((c as u32) << 31), v & 1 != 0)
                } else {
                    (v.rotate_right(amount), v & (1 << (amount - 1)) != 0)
                }
            }
        }
    }

    /// Shift by a register amount (0..=255).
    fn shift_reg(&self, kind: u32, v: u32, amount: u32) -> (u32, bool) {
        let c = self.flag(FLAG_C);
        if amount == 0 {
            return (v, c);
        }
        match kind {
            0 => match amount {
                1..=31 => (v << amount, v & (1 << (32 - amount)) != 0),
                32 => (0, v & 1 != 0),
                _ => (0, false),
            },
            1 => match amount {
                1..=31 => (v >> amount, v & (1 << (amount - 1)) != 0),
                32 => (0, v >> 31 != 0),
                _ => (0, false),
            },
            2 => match amount {
                1..=31 => (((v as i32) >> amount) as u32, v & (1 << (amount - 1)) != 0),
                _ => (((v as i32) >> 31) as u32, v >> 31 != 0),
            },
            _ => {
                let a = amount & 31;
                if a == 0 {
                    (v, v >> 31 != 0)
                } else {
                    (v.rotate_right(a), v & (1 << (a - 1)) != 0)
                }
            }
        }
    }

    #[inline]
    fn adc(a: u32, b: u32, c: bool) -> (u32, bool, bool) {
        let wide = a as u64 + b as u64 + c as u64;
        let res = wide as u32;
        (res, wide >> 32 != 0, (!(a ^ b) & (a ^ res)) >> 31 != 0)
    }

    /// Halfword load. At an odd address the core returns the aligned
    /// halfword rotated by a byte.
    #[inline]
    fn load_half<B: Bus>(bus: &mut B, addr: u32) -> u32 {
        (bus.read16(addr & !1) as u32).rotate_right((addr & 1) * 8)
    }

    /// Signed halfword load. At an odd address the core sign-extends the
    /// byte there instead.
    #[inline]
    fn load_half_signed<B: Bus>(bus: &mut B, addr: u32) -> u32 {
        if addr & 1 != 0 {
            bus.read8(addr) as i8 as i32 as u32
        } else {
            bus.read16(addr) as i16 as i32 as u32
        }
    }

    // ---- ARM ----------------------------------------------------------

    fn exec_arm<B: Bus>(&mut self, bus: &mut B, op: u32, pc: u32) {
        match (op >> 25) & 7 {
            0b000 => {
                if op & 0x0FFF_FFF0 == 0x012F_FF10 {
                    let t = self.reg((op & 15) as usize);
                    self.bx(t);
                } else if op & 0x90 == 0x90 {
                    if op & 0x60 == 0 {
                        match (op >> 23) & 3 {
                            0 => self.arm_mul(op),
                            1 => self.arm_mull(op),
                            _ => self.arm_swp(bus, op),
                        }
                    } else {
                        self.arm_halfword(bus, op);
                    }
                } else if op & 0x0190_0000 == 0x0100_0000 {
                    self.arm_psr(op, pc);
                } else {
                    self.arm_data(op);
                }
            }
            0b001 => {
                if op & 0x0190_0000 == 0x0100_0000 {
                    self.arm_psr(op, pc);
                } else {
                    self.arm_data(op);
                }
            }
            0b010 => self.arm_ldr_str(bus, op),
            0b011 => {
                if op & 0x10 != 0 {
                    self.undefined(pc, op);
                } else {
                    self.arm_ldr_str(bus, op);
                }
            }
            0b100 => self.arm_ldm_stm(bus, op),
            0b101 => {
                let off = (((op & 0x00FF_FFFF) << 8) as i32 >> 6) as u32;
                let target = self.reg(15).wrapping_add(off);
                if op & (1 << 24) != 0 {
                    self.r[14] = self.r[15];
                }
                self.branch(target);
            }
            0b110 => self.undefined(pc, op),
            _ => {
                if op & (1 << 24) != 0 {
                    self.swi(pc, op & 0x00FF_FFFF);
                } else {
                    self.undefined(pc, op);
                }
            }
        }
    }

    fn arm_data(&mut self, op: u32) {
        let imm = op & (1 << 25) != 0;
        let s = op & (1 << 20) != 0;
        let opc = (op >> 21) & 15;
        let rn = ((op >> 16) & 15) as usize;
        let rd = ((op >> 12) & 15) as usize;
        let reg_shift = !imm && op & 0x10 != 0;
        // With a register-specified shift the PC reads one more word ahead.
        let pc_extra = if reg_shift { 4 } else { 0 };

        let (b, sh_c) = if imm {
            let v = op & 0xFF;
            let rot = ((op >> 8) & 15) * 2;
            if rot == 0 {
                (v, self.flag(FLAG_C))
            } else {
                let v = v.rotate_right(rot);
                (v, v >> 31 != 0)
            }
        } else {
            let rm = (op & 15) as usize;
            let mut v = self.reg(rm);
            if rm == 15 {
                v = v.wrapping_add(pc_extra);
            }
            let kind = (op >> 5) & 3;
            if reg_shift {
                let amount = self.reg(((op >> 8) & 15) as usize) & 0xFF;
                self.shift_reg(kind, v, amount)
            } else {
                self.shift_imm(kind, v, (op >> 7) & 31)
            }
        };
        let mut a = self.reg(rn);
        if rn == 15 {
            a = a.wrapping_add(pc_extra);
        }
        let cin = self.flag(FLAG_C);

        let (res, c, v, logical) = match opc {
            0x0 | 0x8 => (a & b, sh_c, false, true),
            0x1 | 0x9 => (a ^ b, sh_c, false, true),
            0x2 | 0xA => {
                let (r, c, v) = Self::adc(a, !b, true);
                (r, c, v, false)
            }
            0x3 => {
                let (r, c, v) = Self::adc(b, !a, true);
                (r, c, v, false)
            }
            0x4 | 0xB => {
                let (r, c, v) = Self::adc(a, b, false);
                (r, c, v, false)
            }
            0x5 => {
                let (r, c, v) = Self::adc(a, b, cin);
                (r, c, v, false)
            }
            0x6 => {
                let (r, c, v) = Self::adc(a, !b, cin);
                (r, c, v, false)
            }
            0x7 => {
                let (r, c, v) = Self::adc(b, !a, cin);
                (r, c, v, false)
            }
            0xC => (a | b, sh_c, false, true),
            0xD => (b, sh_c, false, true),
            0xE => (a & !b, sh_c, false, true),
            _ => (!b, sh_c, false, true),
        };
        let test_only = (0x8..=0xB).contains(&opc);

        if s {
            if rd == 15 {
                let spsr = self.spsr();
                self.set_cpsr(spsr);
            } else if logical {
                self.set_nz(res);
                self.set_c(c);
            } else {
                self.set_nzcv(res, c, v);
            }
        }
        if !test_only {
            if rd == 15 {
                self.branch(res);
            } else {
                self.r[rd] = res;
            }
        }
    }

    fn arm_psr(&mut self, op: u32, pc: u32) {
        let use_spsr = op & (1 << 22) != 0;
        if op & 0x0FBF_0FFF == 0x010F_0000 {
            let rd = ((op >> 12) & 15) as usize;
            self.r[rd] = if use_spsr { self.spsr() } else { self.cpsr };
            return;
        }
        let val = if op & 0x0FB0_FFF0 == 0x0120_F000 {
            self.reg((op & 15) as usize)
        } else if op & 0x0FB0_F000 == 0x0320_F000 {
            (op & 0xFF).rotate_right(((op >> 8) & 15) * 2)
        } else {
            self.undefined(pc, op);
            return;
        };
        let mut mask = 0u32;
        if op & (1 << 19) != 0 {
            mask |= 0xFF00_0000;
        }
        if op & (1 << 16) != 0 {
            mask |= 0x0000_00FF;
        }
        if use_spsr {
            let cur = self.spsr();
            self.set_spsr((cur & !mask) | (val & mask));
        } else {
            if self.mode() == MODE_USR {
                mask &= 0xFF00_0000;
            }
            // The T bit cannot be changed through MSR.
            mask &= !FLAG_T;
            let new = (self.cpsr & !mask) | (val & mask);
            self.set_cpsr(new);
        }
    }

    fn arm_mul(&mut self, op: u32) {
        let rd = ((op >> 16) & 15) as usize;
        let rn = ((op >> 12) & 15) as usize;
        let rs = ((op >> 8) & 15) as usize;
        let rm = (op & 15) as usize;
        let mut res = self.reg(rm).wrapping_mul(self.reg(rs));
        if op & (1 << 21) != 0 {
            res = res.wrapping_add(self.reg(rn));
        }
        self.r[rd] = res;
        if op & (1 << 20) != 0 {
            self.set_nz(res);
        }
    }

    fn arm_mull(&mut self, op: u32) {
        let rdhi = ((op >> 16) & 15) as usize;
        let rdlo = ((op >> 12) & 15) as usize;
        let rs = self.reg(((op >> 8) & 15) as usize);
        let rm = self.reg((op & 15) as usize);
        let mut res = if op & (1 << 22) != 0 {
            (rm as i32 as i64).wrapping_mul(rs as i32 as i64) as u64
        } else {
            (rm as u64).wrapping_mul(rs as u64)
        };
        if op & (1 << 21) != 0 {
            res = res.wrapping_add(((self.r[rdhi] as u64) << 32) | self.r[rdlo] as u64);
        }
        self.r[rdlo] = res as u32;
        self.r[rdhi] = (res >> 32) as u32;
        if op & (1 << 20) != 0 {
            self.cpsr = (self.cpsr & !(FLAG_N | FLAG_Z))
                | if res >> 63 != 0 { FLAG_N } else { 0 }
                | if res == 0 { FLAG_Z } else { 0 };
        }
    }

    fn arm_swp<B: Bus>(&mut self, bus: &mut B, op: u32) {
        let rn = ((op >> 16) & 15) as usize;
        let rd = ((op >> 12) & 15) as usize;
        let rm = (op & 15) as usize;
        let addr = self.reg(rn);
        let src = self.reg(rm);
        if op & (1 << 22) != 0 {
            let old = bus.read8(addr);
            bus.write8(addr, src as u8);
            self.r[rd] = old as u32;
        } else {
            let old = bus.read32(addr & !3).rotate_right((addr & 3) * 8);
            bus.write32(addr & !3, src);
            self.r[rd] = old;
        }
    }

    fn arm_halfword<B: Bus>(&mut self, bus: &mut B, op: u32) {
        let pre = op & (1 << 24) != 0;
        let up = op & (1 << 23) != 0;
        let wb = op & (1 << 21) != 0;
        let load = op & (1 << 20) != 0;
        let rn = ((op >> 16) & 15) as usize;
        let rd = ((op >> 12) & 15) as usize;
        let off = if op & (1 << 22) != 0 {
            ((op >> 4) & 0xF0) | (op & 0xF)
        } else {
            self.reg((op & 15) as usize)
        };
        let base = self.reg(rn);
        let moved = if up {
            base.wrapping_add(off)
        } else {
            base.wrapping_sub(off)
        };
        let addr = if pre { moved } else { base };
        let writeback = !pre || wb;
        if load {
            let v = match (op >> 5) & 3 {
                1 => Self::load_half(bus, addr),
                2 => bus.read8(addr) as i8 as i32 as u32,
                _ => Self::load_half_signed(bus, addr),
            };
            if writeback && rn != 15 {
                self.r[rn] = moved;
            }
            if rd == 15 {
                self.branch(v);
            } else {
                self.r[rd] = v;
            }
        } else {
            let mut v = self.reg(rd);
            if rd == 15 {
                v = v.wrapping_add(4);
            }
            bus.write16(addr & !1, v as u16);
            if writeback && rn != 15 {
                self.r[rn] = moved;
            }
        }
    }

    fn arm_ldr_str<B: Bus>(&mut self, bus: &mut B, op: u32) {
        let pre = op & (1 << 24) != 0;
        let up = op & (1 << 23) != 0;
        let byte = op & (1 << 22) != 0;
        let wb = op & (1 << 21) != 0;
        let load = op & (1 << 20) != 0;
        let rn = ((op >> 16) & 15) as usize;
        let rd = ((op >> 12) & 15) as usize;
        let off = if op & (1 << 25) != 0 {
            let v = self.reg((op & 15) as usize);
            self.shift_imm((op >> 5) & 3, v, (op >> 7) & 31).0
        } else {
            op & 0xFFF
        };
        let base = self.reg(rn);
        let moved = if up {
            base.wrapping_add(off)
        } else {
            base.wrapping_sub(off)
        };
        let addr = if pre { moved } else { base };
        let writeback = !pre || wb;
        if load {
            let v = if byte {
                bus.read8(addr) as u32
            } else {
                bus.read32(addr & !3).rotate_right((addr & 3) * 8)
            };
            if writeback && rn != 15 {
                self.r[rn] = moved;
            }
            if rd == 15 {
                self.branch(v);
            } else {
                self.r[rd] = v;
            }
        } else {
            let mut v = self.reg(rd);
            if rd == 15 {
                v = v.wrapping_add(4);
            }
            if byte {
                bus.write8(addr, v as u8);
            } else {
                bus.write32(addr & !3, v);
            }
            if writeback && rn != 15 {
                self.r[rn] = moved;
            }
        }
    }

    fn arm_ldm_stm<B: Bus>(&mut self, bus: &mut B, op: u32) {
        let pre = op & (1 << 24) != 0;
        let up = op & (1 << 23) != 0;
        let psr = op & (1 << 22) != 0;
        let wb = op & (1 << 21) != 0;
        let load = op & (1 << 20) != 0;
        let rn = ((op >> 16) & 15) as usize;
        let mut list = op & 0xFFFF;
        // An empty list transfers r15 alone, yet moves the base as if
        // all sixteen registers had gone through.
        let empty = list == 0;
        if empty {
            list = 0x8000;
        }
        let n = if empty { 0x40 } else { list.count_ones() * 4 };
        let base = self.r[rn];
        let new_base = if up {
            base.wrapping_add(n)
        } else {
            base.wrapping_sub(n)
        };
        let mut addr = match (up, pre) {
            (true, false) => base,
            (true, true) => base.wrapping_add(4),
            (false, false) => base.wrapping_sub(n).wrapping_add(4),
            (false, true) => base.wrapping_sub(n),
        } & !3;
        let has_pc = list & 0x8000 != 0;
        let user_bank = psr && !(load && has_pc);

        if load {
            if wb {
                self.r[rn] = new_base;
            }
            for i in 0..16usize {
                if list & (1 << i) == 0 {
                    continue;
                }
                let v = bus.read32(addr);
                addr = addr.wrapping_add(4);
                if i == 15 {
                    if psr {
                        let spsr = self.spsr();
                        self.set_cpsr(spsr);
                    }
                    self.branch(v);
                } else if user_bank {
                    self.set_user_reg(i, v);
                } else {
                    self.r[i] = v;
                }
            }
        } else {
            let mut first = true;
            for i in 0..16usize {
                if list & (1 << i) == 0 {
                    continue;
                }
                let v = if i == rn {
                    if first { base } else { new_base }
                } else if i == 15 {
                    self.reg(15).wrapping_add(4)
                } else if user_bank {
                    self.user_reg(i)
                } else {
                    self.r[i]
                };
                bus.write32(addr, v);
                addr = addr.wrapping_add(4);
                first = false;
            }
            if wb {
                self.r[rn] = new_base;
            }
        }
    }

    // ---- Thumb --------------------------------------------------------

    fn exec_thumb<B: Bus>(&mut self, bus: &mut B, op: u32, pc: u32) {
        let rd = (op & 7) as usize;
        let rs = ((op >> 3) & 7) as usize;
        match op >> 11 {
            0b00000..=0b00010 => {
                let (v, c) = self.shift_imm(op >> 11, self.r[rs], (op >> 6) & 31);
                self.r[rd] = v;
                self.set_nz(v);
                self.set_c(c);
            }
            0b00011 => {
                let n = (op >> 6) & 7;
                let b = if op & (1 << 10) != 0 {
                    n
                } else {
                    self.r[n as usize]
                };
                let a = self.r[rs];
                let (r, c, v) = if op & (1 << 9) != 0 {
                    Self::adc(a, !b, true)
                } else {
                    Self::adc(a, b, false)
                };
                self.r[rd] = r;
                self.set_nzcv(r, c, v);
            }
            0b00100..=0b00111 => {
                let rd = ((op >> 8) & 7) as usize;
                let imm = op & 0xFF;
                let a = self.r[rd];
                match (op >> 11) & 3 {
                    0 => {
                        self.r[rd] = imm;
                        self.set_nz(imm);
                    }
                    1 => {
                        let (r, c, v) = Self::adc(a, !imm, true);
                        self.set_nzcv(r, c, v);
                    }
                    2 => {
                        let (r, c, v) = Self::adc(a, imm, false);
                        self.r[rd] = r;
                        self.set_nzcv(r, c, v);
                    }
                    _ => {
                        let (r, c, v) = Self::adc(a, !imm, true);
                        self.r[rd] = r;
                        self.set_nzcv(r, c, v);
                    }
                }
            }
            0b01000 => {
                if op & (1 << 10) == 0 {
                    self.thumb_alu(op);
                } else {
                    self.thumb_hi(op);
                }
            }
            0b01001 => {
                let rd = ((op >> 8) & 7) as usize;
                let addr = (self.reg(15) & !2).wrapping_add((op & 0xFF) * 4);
                self.r[rd] = bus.read32(addr);
            }
            0b01010 | 0b01011 => {
                let addr = self.r[rs].wrapping_add(self.r[((op >> 6) & 7) as usize]);
                match (op >> 9) & 7 {
                    0 => bus.write32(addr & !3, self.r[rd]),
                    1 => bus.write16(addr & !1, self.r[rd] as u16),
                    2 => bus.write8(addr, self.r[rd] as u8),
                    3 => self.r[rd] = bus.read8(addr) as i8 as i32 as u32,
                    4 => self.r[rd] = bus.read32(addr & !3).rotate_right((addr & 3) * 8),
                    5 => self.r[rd] = Self::load_half(bus, addr),
                    6 => self.r[rd] = bus.read8(addr) as u32,
                    _ => self.r[rd] = Self::load_half_signed(bus, addr),
                }
            }
            0b01100 | 0b01101 => {
                let addr = self.r[rs].wrapping_add(((op >> 6) & 31) * 4);
                if op & (1 << 11) != 0 {
                    self.r[rd] = bus.read32(addr & !3).rotate_right((addr & 3) * 8);
                } else {
                    bus.write32(addr & !3, self.r[rd]);
                }
            }
            0b01110 | 0b01111 => {
                let addr = self.r[rs].wrapping_add((op >> 6) & 31);
                if op & (1 << 11) != 0 {
                    self.r[rd] = bus.read8(addr) as u32;
                } else {
                    bus.write8(addr, self.r[rd] as u8);
                }
            }
            0b10000 | 0b10001 => {
                let addr = self.r[rs].wrapping_add(((op >> 6) & 31) * 2);
                if op & (1 << 11) != 0 {
                    self.r[rd] = Self::load_half(bus, addr);
                } else {
                    bus.write16(addr & !1, self.r[rd] as u16);
                }
            }
            0b10010 | 0b10011 => {
                let rd = ((op >> 8) & 7) as usize;
                let addr = self.r[13].wrapping_add((op & 0xFF) * 4);
                if op & (1 << 11) != 0 {
                    self.r[rd] = bus.read32(addr & !3).rotate_right((addr & 3) * 8);
                } else {
                    bus.write32(addr & !3, self.r[rd]);
                }
            }
            0b10100 | 0b10101 => {
                let rd = ((op >> 8) & 7) as usize;
                let base = if op & (1 << 11) != 0 {
                    self.r[13]
                } else {
                    self.reg(15) & !2
                };
                self.r[rd] = base.wrapping_add((op & 0xFF) * 4);
            }
            0b10110 | 0b10111 => self.thumb_misc(bus, op, pc),
            0b11000 | 0b11001 if op & 0xFF == 0 => {
                // Empty list: r15 alone is transferred, the base moves
                // by sixteen words.
                let rb = ((op >> 8) & 7) as usize;
                let addr = self.r[rb] & !3;
                if op & (1 << 11) != 0 {
                    let t = bus.read32(addr);
                    self.branch(t);
                } else {
                    bus.write32(addr, self.reg(15).wrapping_add(2));
                }
                self.r[rb] = self.r[rb].wrapping_add(0x40);
            }
            0b11000 | 0b11001 => {
                let rb = ((op >> 8) & 7) as usize;
                let list = op & 0xFF;
                let mut addr = self.r[rb] & !3;
                let end = self.r[rb].wrapping_add(list.count_ones() * 4);
                if op & (1 << 11) != 0 {
                    for i in 0..8usize {
                        if list & (1 << i) != 0 {
                            self.r[i] = bus.read32(addr);
                            addr = addr.wrapping_add(4);
                        }
                    }
                    if list & (1 << rb) == 0 {
                        self.r[rb] = end;
                    }
                } else {
                    let mut first = true;
                    for i in 0..8usize {
                        if list & (1 << i) != 0 {
                            let v = if i == rb && !first { end } else { self.r[i] };
                            bus.write32(addr, v);
                            addr = addr.wrapping_add(4);
                            first = false;
                        }
                    }
                    self.r[rb] = end;
                }
            }
            0b11010 | 0b11011 => {
                let c = (op >> 8) & 15;
                match c {
                    0xF => self.swi(pc, op & 0xFF),
                    0xE => self.undefined(pc, op),
                    _ => {
                        if self.cond(c) {
                            let off = ((op & 0xFF) as i8 as i32 as u32) << 1;
                            let t = self.reg(15).wrapping_add(off);
                            self.branch(t);
                        }
                    }
                }
            }
            0b11100 => {
                let off = (((op & 0x7FF) << 21) as i32 >> 20) as u32;
                let t = self.reg(15).wrapping_add(off);
                self.branch(t);
            }
            0b11110 => {
                let off = (((op & 0x7FF) << 21) as i32 >> 9) as u32;
                self.r[14] = self.reg(15).wrapping_add(off);
            }
            0b11111 => {
                let ret = self.r[15] | 1;
                let t = self.r[14].wrapping_add((op & 0x7FF) << 1);
                self.branch(t);
                self.r[14] = ret;
            }
            _ => self.undefined(pc, op),
        }
    }

    fn thumb_alu(&mut self, op: u32) {
        let rd = (op & 7) as usize;
        let a = self.r[rd];
        let b = self.r[((op >> 3) & 7) as usize];
        let cin = self.flag(FLAG_C);
        match (op >> 6) & 15 {
            0x0 => {
                self.r[rd] = a & b;
                self.set_nz(a & b);
            }
            0x1 => {
                self.r[rd] = a ^ b;
                self.set_nz(a ^ b);
            }
            k @ (0x2 | 0x3 | 0x4 | 0x7) => {
                let kind = match k {
                    0x2 => 0,
                    0x3 => 1,
                    0x4 => 2,
                    _ => 3,
                };
                let (v, c) = self.shift_reg(kind, a, b & 0xFF);
                self.r[rd] = v;
                self.set_nz(v);
                self.set_c(c);
            }
            0x5 => {
                let (r, c, v) = Self::adc(a, b, cin);
                self.r[rd] = r;
                self.set_nzcv(r, c, v);
            }
            0x6 => {
                let (r, c, v) = Self::adc(a, !b, cin);
                self.r[rd] = r;
                self.set_nzcv(r, c, v);
            }
            0x8 => self.set_nz(a & b),
            0x9 => {
                let (r, c, v) = Self::adc(0, !b, true);
                self.r[rd] = r;
                self.set_nzcv(r, c, v);
            }
            0xA => {
                let (r, c, v) = Self::adc(a, !b, true);
                self.set_nzcv(r, c, v);
            }
            0xB => {
                let (r, c, v) = Self::adc(a, b, false);
                self.set_nzcv(r, c, v);
            }
            0xC => {
                self.r[rd] = a | b;
                self.set_nz(a | b);
            }
            0xD => {
                let r = a.wrapping_mul(b);
                self.r[rd] = r;
                self.set_nz(r);
            }
            0xE => {
                self.r[rd] = a & !b;
                self.set_nz(a & !b);
            }
            _ => {
                self.r[rd] = !b;
                self.set_nz(!b);
            }
        }
    }

    fn thumb_hi(&mut self, op: u32) {
        let rd = ((op & 7) | ((op >> 4) & 8)) as usize;
        let rs = ((op >> 3) & 15) as usize;
        let b = self.reg(rs);
        match (op >> 8) & 3 {
            0 => {
                let r = self.reg(rd).wrapping_add(b);
                if rd == 15 {
                    self.branch(r);
                } else {
                    self.r[rd] = r;
                }
            }
            1 => {
                let (r, c, v) = Self::adc(self.reg(rd), !b, true);
                self.set_nzcv(r, c, v);
            }
            2 => {
                if rd == 15 {
                    self.branch(b);
                } else {
                    self.r[rd] = b;
                }
            }
            _ => self.bx(b),
        }
    }

    fn thumb_misc<B: Bus>(&mut self, bus: &mut B, op: u32, pc: u32) {
        match (op >> 8) & 15 {
            0x0 => {
                let off = (op & 0x7F) * 4;
                self.r[13] = if op & 0x80 != 0 {
                    self.r[13].wrapping_sub(off)
                } else {
                    self.r[13].wrapping_add(off)
                };
            }
            0x4 | 0x5 => {
                let list = op & 0xFF;
                let lr = op & 0x100 != 0;
                let n = (list.count_ones() + lr as u32) * 4;
                let mut addr = self.r[13].wrapping_sub(n);
                self.r[13] = addr;
                for i in 0..8usize {
                    if list & (1 << i) != 0 {
                        bus.write32(addr & !3, self.r[i]);
                        addr = addr.wrapping_add(4);
                    }
                }
                if lr {
                    bus.write32(addr & !3, self.r[14]);
                }
            }
            0xC | 0xD => {
                let list = op & 0xFF;
                let mut addr = self.r[13];
                for i in 0..8usize {
                    if list & (1 << i) != 0 {
                        self.r[i] = bus.read32(addr & !3);
                        addr = addr.wrapping_add(4);
                    }
                }
                if op & 0x100 != 0 {
                    let t = bus.read32(addr & !3);
                    addr = addr.wrapping_add(4);
                    self.branch(t);
                }
                self.r[13] = addr;
            }
            _ => self.undefined(pc, op),
        }
    }
}
