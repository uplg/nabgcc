//! The NIST P-256 curve, as much of it as SAE needs: field arithmetic
//! modulo the prime, points, scalar multiplication, square roots.
//!
//! Written for clarity and for a 32-bit target, not for speed or
//! constant time: numbers are eight 32-bit limbs, least significant
//! first, and field elements are kept in Montgomery form.

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

pub fn from_bytes(bytes: &[u8; 32]) -> Limbs {
    std::array::from_fn(|i| u32::from_be_bytes(bytes[28 - 4 * i..32 - 4 * i].try_into().unwrap()))
}

pub fn to_bytes(n: &Limbs) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in n.iter().enumerate() {
        out[28 - 4 * i..32 - 4 * i].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

pub fn less(a: &Limbs, b: &Limbs) -> bool {
    for i in (0..8).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

pub fn is_zero(a: &Limbs) -> bool {
    a.iter().all(|l| *l == 0)
}

fn add_raw(a: &Limbs, b: &Limbs) -> (Limbs, bool) {
    let mut out = [0u32; 8];
    let mut carry = 0u64;
    for i in 0..8 {
        let v = a[i] as u64 + b[i] as u64 + carry;
        out[i] = v as u32;
        carry = v >> 32;
    }
    (out, carry != 0)
}

fn sub_raw(a: &Limbs, b: &Limbs) -> (Limbs, bool) {
    let mut out = [0u32; 8];
    let mut borrow = 0i64;
    for i in 0..8 {
        let v = a[i] as i64 - b[i] as i64 - borrow;
        out[i] = v as u32;
        borrow = (v < 0) as i64;
    }
    (out, borrow != 0)
}

/// `a + b mod m`, for `a` and `b` below `m`.
pub fn add_mod(a: &Limbs, b: &Limbs, m: &Limbs) -> Limbs {
    let (sum, carry) = add_raw(a, b);
    if carry || !less(&sum, m) {
        sub_raw(&sum, m).0
    } else {
        sum
    }
}

/// `a - b mod m`, for `a` and `b` below `m`.
pub fn sub_mod(a: &Limbs, b: &Limbs, m: &Limbs) -> Limbs {
    let (diff, borrow) = sub_raw(a, b);
    if borrow { add_raw(&diff, m).0 } else { diff }
}

/// Bring any 256-bit number below `m` (for the two moduli used here,
/// both above 2^255, one subtraction is enough).
pub fn reduce(a: &Limbs, m: &Limbs) -> Limbs {
    if less(a, m) { *a } else { sub_raw(a, m).0 }
}

/// `-1 / m mod 2^32`, the constant of Montgomery reduction.
const fn mont_constant(m0: u32) -> u32 {
    let mut inv = 1u32;
    let mut i = 0;
    while i < 5 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(m0.wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
}

const P_CONSTANT: u32 = mont_constant(P[0]);

/// Montgomery product modulo the field prime: `a * b / 2^256`.
fn mont_mul(a: &Limbs, b: &Limbs) -> Limbs {
    let mut t = [0u32; 10];
    for bi in b {
        let mut carry = 0u64;
        for j in 0..8 {
            let v = t[j] as u64 + a[j] as u64 * *bi as u64 + carry;
            t[j] = v as u32;
            carry = v >> 32;
        }
        let v = t[8] as u64 + carry;
        t[8] = v as u32;
        t[9] = (v >> 32) as u32;

        let q = t[0].wrapping_mul(P_CONSTANT) as u64;
        let mut carry = (t[0] as u64 + q * P[0] as u64) >> 32;
        for j in 1..8 {
            let v = t[j] as u64 + q * P[j] as u64 + carry;
            t[j - 1] = v as u32;
            carry = v >> 32;
        }
        let v = t[8] as u64 + carry;
        t[7] = v as u32;
        t[8] = t[9] + (v >> 32) as u32;
    }
    let out: Limbs = t[..8].try_into().unwrap();
    if t[8] != 0 || !less(&out, &P) {
        sub_raw(&out, &P).0
    } else {
        out
    }
}

/// An element of the field, in Montgomery form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fe(Limbs);

impl Fe {
    pub const ZERO: Fe = Fe([0; 8]);

    /// 2^256 mod p: the number one in Montgomery form.
    pub fn one() -> Fe {
        let mut one = [0u32; 8];
        one[0] = 1;
        // 2^256 mod p by doubling 1 that many times.
        for _ in 0..256 {
            one = add_mod(&one, &one, &P);
        }
        Fe(one)
    }

    /// From a plain number, reduced modulo p first.
    pub fn new(n: &Limbs) -> Fe {
        // To Montgomery form: multiply by 2^512 mod p.
        let mut r2 = Fe::one().0;
        for _ in 0..256 {
            r2 = add_mod(&r2, &r2, &P);
        }
        Fe(mont_mul(&reduce(n, &P), &r2))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
        Fe::new(&from_bytes(bytes))
    }

    /// A number wider than the field: `hi * 2^256 + lo`, reduced.
    pub fn from_wide(hi: &Limbs, lo: &Limbs) -> Fe {
        // In Montgomery form `one` is 2^256, which is the factor needed.
        Fe::new(hi).mul(&Fe::new(&Fe::one().0)).add(&Fe::new(lo))
    }

    pub fn from_u32(n: u32) -> Fe {
        let mut l = [0u32; 8];
        l[0] = n;
        Fe::new(&l)
    }

    /// Back to a plain number below p.
    pub fn value(&self) -> Limbs {
        let mut one = [0u32; 8];
        one[0] = 1;
        mont_mul(&self.0, &one)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        to_bytes(&self.value())
    }

    pub fn is_zero(&self) -> bool {
        is_zero(&self.0)
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
    pub fn sqrt(&self) -> Option<Fe> {
        let (p1, _) = add_raw(&P, &{
            let mut one = [0u32; 8];
            one[0] = 1;
            one
        });
        // p + 1 overflows 256 bits by nothing here: p ends in ...FFFF,
        // so the sum is exact in 256 bits.
        let e = shift_right(&shift_right(&p1));
        let root = self.pow(&e);
        (root.square() == *self).then_some(root)
    }
}

fn shift_right(a: &Limbs) -> Limbs {
    std::array::from_fn(|i| a[i] >> 1 | if i < 7 { a[i + 1] << 31 } else { 0 })
}

/// `x^3 - 3x + b`, the right-hand side of the curve equation.
pub fn curve_rhs(x: &Fe) -> Fe {
    let three = Fe::from_u32(3);
    x.square().mul(x).sub(&three.mul(x)).add(&Fe::new(&B))
}

/// A point of the curve, in Jacobian coordinates; `z` zero is infinity.
#[derive(Debug, Clone, Copy)]
pub struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl Point {
    pub fn infinity() -> Point {
        Point {
            x: Fe::one(),
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
    pub fn from_affine(x: &Fe, y: &Fe) -> Option<Point> {
        (y.square() == curve_rhs(x)).then(|| Point {
            x: *x,
            y: *y,
            z: Fe::one(),
        })
    }

    /// From 64 bytes, x then y, each big-endian and below p.
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Point> {
        let x = from_bytes(bytes[..32].try_into().unwrap());
        let y = from_bytes(bytes[32..].try_into().unwrap());
        if !less(&x, &P) || !less(&y, &P) {
            return None;
        }
        Point::from_affine(&Fe::new(&x), &Fe::new(&y))
    }

    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Affine coordinates; `None` for infinity.
    pub fn affine(&self) -> Option<(Fe, Fe)> {
        if self.is_infinity() {
            return None;
        }
        let zi = self.z.invert();
        let zi2 = zi.square();
        Some((self.x.mul(&zi2), self.y.mul(&zi2).mul(&zi)))
    }

    /// 64 bytes, x then y; `None` for infinity.
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

    pub fn double(&self) -> Point {
        if self.is_infinity() {
            return *self;
        }
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x.mul(&gamma);
        let t = self.x.sub(&delta).mul(&self.x.add(&delta));
        let alpha = t.add(&t).add(&t);
        let beta4 = beta.add(&beta).add(&beta).add(&beta);
        let x = alpha.square().sub(&beta4).sub(&beta4);
        let z = self.y.add(&self.z).square().sub(&gamma).sub(&delta);
        let gamma2 = gamma.square();
        let gamma8 = (0..3).fold(gamma2, |g, _| g.add(&g));
        let y = alpha.mul(&beta4.sub(&x)).sub(&gamma8);
        Point { x, y, z }
    }

    pub fn add(&self, o: &Point) -> Point {
        if self.is_infinity() {
            return *o;
        }
        if o.is_infinity() {
            return *self;
        }
        let z1z1 = self.z.square();
        let z2z2 = o.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = o.x.mul(&z1z1);
        let s1 = self.y.mul(&o.z).mul(&z2z2);
        let s2 = o.y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&u1);
        let r = s2.sub(&s1);
        if h.is_zero() {
            return if r.is_zero() {
                self.double()
            } else {
                Point::infinity()
            };
        }
        let hh = h.square();
        let hhh = h.mul(&hh);
        let v = u1.mul(&hh);
        let x = r.square().sub(&hhh).sub(&v).sub(&v);
        let y = r.mul(&v.sub(&x)).sub(&s1.mul(&hhh));
        let z = self.z.mul(&o.z).mul(&h);
        Point { x, y, z }
    }

    /// `scalar` times the point.
    pub fn mul(&self, scalar: &Limbs) -> Point {
        let mut result = Point::infinity();
        for i in (0..256).rev() {
            result = result.double();
            if scalar[i / 32] >> (i % 32) & 1 != 0 {
                result = result.add(self);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> [u8; 32] {
        std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
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
