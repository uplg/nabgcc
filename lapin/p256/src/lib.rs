//! The NIST P-256 curve, as much of it as SAE needs: field arithmetic
//! modulo the prime, points, scalar multiplication, square roots.
//!
//! Numbers are eight 32-bit limbs, least significant first, and field
//! elements are kept in Montgomery form. The multiplication is the hot
//! spot of the whole WPA3 exchange: on the rabbit it is compiled as
//! ARM code, the only instruction set of its processor that multiplies
//! 32 bits by 32 into 64.
//!
//! The crate is built for speed, and its callers for size: what runs a
//! few times per exchange (conversions, square roots, the checks of a
//! point) is kept out of line, so that it is not copied into each
//! caller, and the byte conversions are built small.

#![no_std]

pub type Limbs = [u32; 8];

const fn limbs(hex: &[u8; 64]) -> Limbs {
    let mut out = [0u32; 8];
    let mut i = 0;
    while i < 64 {
        let c = hex[i];
        let digit = if c <= b'9' {
            c - b'0'
        } else {
            (c | 0x20) - b'a' + 10
        } as u32;
        out[7 - i / 8] = out[7 - i / 8] << 4 | digit;
        i += 1;
    }
    out
}

/// The field prime.
pub const P: Limbs = limbs(b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
/// The order of the group.
pub const N: Limbs = limbs(b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
const B: Limbs = limbs(b"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
const GX: Limbs = limbs(b"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
const GY: Limbs = limbs(b"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

#[inline(never)]
pub fn from_bytes(bytes: &[u8; 32]) -> Limbs {
    // A byte at a time: the processor has no instruction to swap them.
    let mut out = [0u32; 8];
    for (i, byte) in bytes.iter().enumerate() {
        out[7 - i / 4] = out[7 - i / 4] << 8 | *byte as u32;
    }
    out
}

#[inline(never)]
#[optimize(size)]
pub fn to_bytes(n: &Limbs) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (n[7 - i / 4] >> (24 - 8 * (i % 4))) as u8;
    }
    out
}

/// Whether `a < b`: the borrow out of `a - b`, every limb looked at
/// whatever the numbers.
pub const fn less(a: &Limbs, b: &Limbs) -> bool {
    // The whole difference kept, or the optimiser makes the borrow a
    // comparison that stops at the first limb that differs.
    core::hint::black_box(sub_raw(a, b)).1
}

/// Whether `a` is zero, every limb looked at.
pub fn is_zero(a: &Limbs) -> bool {
    a.iter().fold(0, |acc, l| acc | l) == 0
}

/// `a` where `mask` is all ones, `b` where it is zero.
const fn pick(a: &Limbs, b: &Limbs, mask: u32) -> Limbs {
    let mut out = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        out[i] = (a[i] & mask) | (b[i] & !mask);
        i += 1;
    }
    out
}

/// All ones for true, zero for false. Hidden from the optimiser, which
/// otherwise sees through the mask and turns `pick` back into a branch.
const fn mask(b: bool) -> u32 {
    core::hint::black_box((b as u32).wrapping_neg())
}

const fn add_raw(a: &Limbs, b: &Limbs) -> (Limbs, bool) {
    let mut out = [0u32; 8];
    let mut carry = 0u64;
    let mut i = 0;
    while i < 8 {
        let v = a[i] as u64 + b[i] as u64 + carry;
        out[i] = v as u32;
        carry = v >> 32;
        i += 1;
    }
    (out, carry != 0)
}

const fn sub_raw(a: &Limbs, b: &Limbs) -> (Limbs, bool) {
    let mut out = [0u32; 8];
    let mut borrow = 0i64;
    let mut i = 0;
    while i < 8 {
        let v = a[i] as i64 - b[i] as i64 - borrow;
        out[i] = v as u32;
        borrow = (v < 0) as i64;
        i += 1;
    }
    (out, borrow != 0)
}

/// `a + b mod m`, for `a` and `b` below `m`. The subtraction of `m` is
/// always made, and kept or not by a mask: no branch on the numbers.
#[inline(never)]
pub const fn add_mod(a: &Limbs, b: &Limbs, m: &Limbs) -> Limbs {
    let (sum, carry) = add_raw(a, b);
    let (diff, borrow) = sub_raw(&sum, m);
    pick(&diff, &sum, mask(carry | !borrow))
}

/// `a - b mod m`, for `a` and `b` below `m`: `m` added under a mask.
#[inline(never)]
pub fn sub_mod(a: &Limbs, b: &Limbs, m: &Limbs) -> Limbs {
    let (diff, borrow) = sub_raw(a, b);
    let back = pick(m, &[0; 8], mask(borrow));
    add_raw(&diff, &back).0
}

/// Bring any 256-bit number below `m` (for the two moduli used here,
/// both above 2^255, one subtraction is enough), without a branch.
#[inline(never)]
pub fn reduce(a: &Limbs, m: &Limbs) -> Limbs {
    let (diff, borrow) = sub_raw(a, m);
    pick(a, &diff, mask(borrow))
}

/// `2^(256 * times) mod p`, by doubling.
const fn power_of_r(times: u32) -> Limbs {
    let mut v = [1, 0, 0, 0, 0, 0, 0, 0];
    let mut i = 0;
    while i < 256 * times {
        v = add_mod(&v, &v, &P);
        i += 1;
    }
    v
}

/// `v * 2^256 mod p` for `v` below p, by doubling: a number's
/// Montgomery form, computed when the firmware is built.
const fn to_mont(v: &Limbs) -> Limbs {
    let mut v = *v;
    let mut i = 0;
    while i < 256 {
        v = add_mod(&v, &v, &P);
        i += 1;
    }
    v
}

/// The curve's constant b, ready for use.
const B_MONT: Limbs = to_mont(&B);

/// One in Montgomery form, and the factor that brings a number into it.
const R: Limbs = power_of_r(1);
const R2: Limbs = power_of_r(2);

/// Montgomery product modulo the field prime: `a * b / 2^256`.
///
/// Written with plain loops and no call: it is compiled as ARM code,
/// into which the compiler will not inline the library's (Thumb)
/// iterators. The reduction needs no multiplication, because the prime
/// is `2^256 - 2^224 + 2^192 + 2^96 - 1`: the quotient digit is the low
/// limb itself, and adding it times the prime is five additions.
/// The instructions run do not depend on the operands. One thing does,
/// below the code: the ARM7TDMI's multiplier stops early when the top
/// bytes of one of its operands (the register the compiler puts in
/// `Rs`) are zeros, a cycle saved per byte, so a product's time varies
/// by a few cycles with the limbs. Nothing in the instruction set avoids
/// it; it is a residual leak, small against the noise of a radio
/// exchange, and is accepted.
#[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
#[inline(never)]
fn mont_mul(a: &Limbs, b: &Limbs) -> Limbs {
    let mut t = [0u32; 10];
    let mut i = 0;
    while i < 8 {
        let bi = b[i] as u64;
        let mut carry = 0u64;
        let mut j = 0;
        while j < 8 {
            let v = t[j] as u64 + a[j] as u64 * bi + carry;
            t[j] = v as u32;
            carry = v >> 32;
            j += 1;
        }
        let v = t[8] as u64 + carry;
        t[8] = v as u32;
        t[9] = (v >> 32) as u32;

        // Add q times the prime and drop the low limb, which is now zero.
        let q = t[0] as i64;
        let mut v = t[1] as i64;
        t[0] = v as u32;
        v = t[2] as i64 + (v >> 32);
        t[1] = v as u32;
        v = t[3] as i64 + q + (v >> 32);
        t[2] = v as u32;
        v = t[4] as i64 + (v >> 32);
        t[3] = v as u32;
        v = t[5] as i64 + (v >> 32);
        t[4] = v as u32;
        v = t[6] as i64 + q + (v >> 32);
        t[5] = v as u32;
        v = t[7] as i64 - q + (v >> 32);
        t[6] = v as u32;
        v = t[8] as i64 + q + (v >> 32);
        t[7] = v as u32;
        v = t[9] as i64 + (v >> 32);
        t[8] = v as u32;
        i += 1;
    }
    // One conditional subtraction of the prime, without a branch.
    let mut reduced = [0u32; 8];
    let mut borrow = 0i64;
    let mut j = 0;
    while j < 8 {
        let v = t[j] as i64 - P[j] as i64 - borrow;
        reduced[j] = v as u32;
        borrow = (v < 0) as i64;
        j += 1;
    }
    // Keep the difference when the sum overflowed or was at least p.
    let keep = (((t[8] != 0) as u32) | ((borrow == 0) as u32)).wrapping_neg();
    let mut out = [0u32; 8];
    let mut j = 0;
    while j < 8 {
        out[j] = (reduced[j] & keep) | (t[j] & !keep);
        j += 1;
    }
    out
}

/// An element of the field, in Montgomery form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fe(Limbs);

impl Fe {
    pub const ZERO: Fe = Fe([0; 8]);

    /// The number one.
    pub fn one() -> Fe {
        Fe(R)
    }

    /// From a plain number, reduced modulo p first.
    #[inline(never)]
    pub fn new(n: &Limbs) -> Fe {
        Fe(mont_mul(&reduce(n, &P), &R2))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
        Fe::new(&from_bytes(bytes))
    }

    /// A number wider than the field: `hi * 2^256 + lo`, reduced.
    pub fn from_wide(hi: &Limbs, lo: &Limbs) -> Fe {
        // Multiplying by R2 in Montgomery form multiplies by 2^256.
        Fe::new(hi).mul(&Fe(R2)).add(&Fe::new(lo))
    }

    pub fn from_u32(n: u32) -> Fe {
        let mut l = [0u32; 8];
        l[0] = n;
        Fe::new(&l)
    }

    /// Back to a plain number below p.
    pub fn value(&self) -> Limbs {
        mont_mul(&self.0, &[1, 0, 0, 0, 0, 0, 0, 0])
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        to_bytes(&self.value())
    }

    pub fn is_zero(&self) -> bool {
        is_zero(&self.0)
    }

    /// Take `other`'s value where `mask` is all ones, keep ours where
    /// it is zero.
    pub fn select(&mut self, other: &Fe, mask: u32) {
        let mut i = 0;
        while i < 8 {
            self.0[i] = (other.0[i] & mask) | (self.0[i] & !mask);
            i += 1;
        }
    }

    /// All ones if both are the same element, zero otherwise, from
    /// every limb (the derived `==` may stop at the first difference).
    pub fn equal_mask(&self, other: &Fe) -> u32 {
        let mut d = 0;
        let mut i = 0;
        while i < 8 {
            d |= self.0[i] ^ other.0[i];
            i += 1;
        }
        mask(d == 0)
    }

    pub fn is_odd(&self) -> bool {
        self.value()[0] & 1 != 0
    }

    pub fn add(&self, o: &Fe) -> Fe {
        Fe(add_mod(&self.0, &o.0, &P))
    }

    pub fn sub(&self, o: &Fe) -> Fe {
        Fe(sub_mod(&self.0, &o.0, &P))
    }

    pub fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    pub fn mul(&self, o: &Fe) -> Fe {
        Fe(mont_mul(&self.0, &o.0))
    }

    pub fn square(&self) -> Fe {
        self.mul(self)
    }

    fn pow(&self, exponent: &Limbs) -> Fe {
        let mut result = Fe::one();
        for i in (0..256).rev() {
            result = result.square();
            if exponent[i / 32] >> (i % 32) & 1 != 0 {
                result = result.mul(self);
            }
        }
        result
    }

    /// The inverse, or zero for zero (Fermat: `a^(p-2)`).
    #[inline(never)]
    pub fn invert(&self) -> Fe {
        let mut e = P;
        e[0] -= 2;
        self.pow(&e)
    }

    /// Whether the element is a square (zero counts as one).
    pub fn is_square(&self) -> bool {
        // Euler: a^((p-1)/2) is 1 for squares, p-1 otherwise.
        let mut e = P;
        e[0] -= 1;
        let half = shift_right(&e);
        let l = self.pow(&half);
        l == Fe::one() || l.is_zero()
    }

    /// A square root, if there is one. p is 3 mod 4: `a^((p+1)/4)`.
    #[inline(never)]
    pub fn sqrt(&self) -> Option<Fe> {
        let (root, found) = self.sqrt_masked();
        (found != 0).then_some(root)
    }

    /// `a^((p+1)/4)`, and all ones if it is a square root of `a`, zero
    /// otherwise: for callers that must not branch on the answer.
    #[inline(never)]
    pub fn sqrt_masked(&self) -> (Fe, u32) {
        // p + 1 still fits in 256 bits.
        let (p1, _) = add_raw(&P, &[1, 0, 0, 0, 0, 0, 0, 0]);
        let e = shift_right(&shift_right(&p1));
        let root = self.pow(&e);
        (root, root.square().equal_mask(self))
    }
}

fn shift_right(a: &Limbs) -> Limbs {
    core::array::from_fn(|i| a[i] >> 1 | if i < 7 { a[i + 1] << 31 } else { 0 })
}

/// `x^3 - 3x + b`, the right-hand side of the curve equation.
#[inline(never)]
pub fn curve_rhs(x: &Fe) -> Fe {
    let three = Fe::from_u32(3);
    x.square().mul(x).sub(&three.mul(x)).add(&Fe(B_MONT))
}

/// A point of the curve in projective coordinates (x/z, y/z);
/// infinity is (0 : 1 : 0).
#[derive(Debug, Clone, Copy)]
pub struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl Point {
    pub fn infinity() -> Point {
        Point {
            x: Fe::ZERO,
            y: Fe::one(),
            z: Fe::ZERO,
        }
    }

    pub fn generator() -> Point {
        Point {
            x: Fe::new(&GX),
            y: Fe::new(&GY),
            z: Fe::one(),
        }
    }

    /// A point from affine coordinates; `None` if it is not on the curve.
    #[inline(never)]
    pub fn from_affine(x: &Fe, y: &Fe) -> Option<Point> {
        (y.square().equal_mask(&curve_rhs(x)) != 0).then(|| Point {
            x: *x,
            y: *y,
            z: Fe::one(),
        })
    }

    /// From 64 bytes, x then y, each big-endian and below p.
    #[inline(never)]
    #[optimize(size)]
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Point> {
        let mut half = [0u8; 32];
        half.copy_from_slice(&bytes[..32]);
        let x = from_bytes(&half);
        half.copy_from_slice(&bytes[32..]);
        let y = from_bytes(&half);
        if !less(&x, &P) || !less(&y, &P) {
            return None;
        }
        Point::from_affine(&Fe::new(&x), &Fe::new(&y))
    }

    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Affine coordinates; `None` for infinity.
    #[inline(never)]
    #[optimize(size)]
    pub fn affine(&self) -> Option<(Fe, Fe)> {
        if self.is_infinity() {
            return None;
        }
        let zi = self.z.invert();
        Some((self.x.mul(&zi), self.y.mul(&zi)))
    }

    /// 64 bytes, x then y; `None` for infinity.
    #[inline(never)]
    #[optimize(size)]
    pub fn to_bytes(&self) -> Option<[u8; 64]> {
        let (x, y) = self.affine()?;
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&x.to_bytes());
        out[32..].copy_from_slice(&y.to_bytes());
        Some(out)
    }

    pub fn neg(&self) -> Point {
        Point {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// The sum of two points, by the complete formulas of Renes,
    /// Costello and Batina (2016) for curves with a = -3: one sequence
    /// of operations whatever the points, be they equal, opposite or
    /// infinity. No branch here nor in the field operations under it
    /// (additions and subtractions correct by masks, the product
    /// reduces by one), so the time does not depend on the points; but
    /// see `mont_mul` for what the ARM7's multiplier does.
    pub fn add(&self, o: &Point) -> Point {
        let b = Fe(B_MONT);
        let triple = |v: &Fe| v.add(v).add(v);
        let x1x2 = self.x.mul(&o.x);
        let y1y2 = self.y.mul(&o.y);
        let z1z2 = self.z.mul(&o.z);
        // Cross terms, each by one product instead of two.
        let xy = self
            .x
            .add(&self.y)
            .mul(&o.x.add(&o.y))
            .sub(&x1x2)
            .sub(&y1y2);
        let xz = self
            .x
            .add(&self.z)
            .mul(&o.x.add(&o.z))
            .sub(&x1x2)
            .sub(&z1z2);
        let yz = self
            .y
            .add(&self.z)
            .mul(&o.y.add(&o.z))
            .sub(&y1y2)
            .sub(&z1z2);

        let bz = triple(&b.mul(&z1z2));
        let xz3 = triple(&xz);
        let low = y1y2.add(&xz3).sub(&bz);
        let high = y1y2.sub(&xz3).add(&bz);
        let z3 = triple(&z1z2);
        let u = triple(&b.mul(&xz)).sub(&triple(&x1x2)).sub(&triple(&z3));
        let w = triple(&x1x2).sub(&z3);
        Point {
            x: xy.mul(&low).sub(&yz.mul(&u)),
            y: high.mul(&low).add(&w.mul(&u)),
            z: yz.mul(&high).add(&xy.mul(&w)),
        }
    }

    pub fn double(&self) -> Point {
        self.add(self)
    }

    /// `scalar` times the point, four bits at a time, with the same
    /// operations and the same memory accesses whatever the scalar.
    pub fn mul(&self, scalar: &Limbs) -> Point {
        // 0P, 1P, ... 15P.
        let mut table = [Point::infinity(); 16];
        let mut i = 1;
        while i < 16 {
            table[i] = table[i - 1].add(self);
            i += 1;
        }
        let mut result = Point::infinity();
        let mut nibble = 64;
        while nibble > 0 {
            nibble -= 1;
            result = result.double().double().double().double();
            let digit = (scalar[nibble / 8] >> (4 * (nibble % 8))) & 15;
            // Read the whole table and keep one entry.
            let mut chosen = Point::infinity();
            let mut k = 0;
            while k < 16 {
                let mask = ((k as u32 == digit) as u32).wrapping_neg();
                chosen.x.select(&table[k].x, mask);
                chosen.y.select(&table[k].y, mask);
                chosen.z.select(&table[k].z, mask);
                k += 1;
            }
            result = result.add(&chosen);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn hex(s: &str) -> [u8; 32] {
        core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn the_generator_is_on_the_curve_and_has_order_n() {
        let g = Point::generator();
        let (x, y) = g.affine().unwrap();
        assert!(Point::from_affine(&x, &y).is_some());
        assert!(g.mul(&N).is_infinity());
        let mut n1 = N;
        n1[0] -= 1;
        let (mx, my) = g.mul(&n1).affine().unwrap();
        assert_eq!((mx, my), (x, y.neg()));
    }

    #[test]
    fn small_multiples_match_the_published_ones() {
        let g = Point::generator();
        let two = g.double().to_bytes().unwrap();
        assert_eq!(
            two[..32],
            hex("7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978")
        );
        assert_eq!(
            two[32..],
            hex("07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1")
        );
        let mut three = [0u32; 8];
        three[0] = 3;
        let by_mul = g.mul(&three).to_bytes().unwrap();
        let by_add = g.double().add(&g).to_bytes().unwrap();
        assert_eq!(by_mul, by_add);
        assert_eq!(
            by_mul[..32],
            hex("5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C")
        );
    }

    #[test]
    fn the_formulas_handle_every_special_case() {
        let g = Point::generator();
        let o = Point::infinity();
        let same = |a: &Point, b: &Point| a.to_bytes() == b.to_bytes();
        assert!(same(&g.add(&o), &g));
        assert!(same(&o.add(&g), &g));
        assert!(o.add(&o).is_infinity());
        assert!(g.add(&g.neg()).is_infinity());
        assert!(same(&g.add(&g), &g.mul(&[2, 0, 0, 0, 0, 0, 0, 0])));
        // Associativity on unrelated multiples.
        let (a, b, c) = (
            g.mul(&[5, 7, 0, 0, 0, 0, 0, 1]),
            g.mul(&[0, 0, 9, 0, 0, 3, 0, 0]),
            g.mul(&N).add(&g),
        );
        assert!(same(&a.add(&b).add(&c), &a.add(&b.add(&c))));
        // (n - 1)G + 2G = G, through the top of the scalar range.
        let mut n1 = N;
        n1[0] -= 1;
        assert!(same(&g.mul(&n1).add(&g.double()), &g));
    }

    #[test]
    fn field_inverse_and_roots() {
        let a = Fe::from_u32(123_456_789);
        assert_eq!(a.mul(&a.invert()), Fe::one());
        let sq = a.square();
        assert!(sq.is_square());
        let root = sq.sqrt().unwrap();
        assert!(root == a || root == a.neg());
        assert_eq!(Fe::from_u32(7).to_bytes()[31], 7);
        // p - 1 reduces to itself, p to zero.
        assert!(Fe::new(&P).is_zero());
    }

    #[test]
    fn points_off_the_curve_are_refused() {
        let mut bytes = Point::generator().to_bytes().unwrap();
        bytes[63] ^= 1;
        assert!(Point::from_bytes(&bytes).is_none());
        assert!(Point::from_bytes(&[0xFF; 64]).is_none());
    }
}
