//! Simultaneous Authentication of Equals, the password exchange of
//! WPA3 (IEEE 802.11-2020, 12.4), over group 19 (NIST P-256).
//!
//! Both ends run the same thing: turn the password into a secret point
//! of the curve (the password element), exchange a commit (a scalar
//! and a point that hide a random number), derive the same key from
//! what they sent and received, and prove it with a confirm.
//!
//! The password element can be found by hunting and pecking, the
//! original method, or by hashing to the curve ("H2E"), which newer
//! equipment asks for.

use crate::crypto::{hkdf_expand_sha256, hmac_sha256, kdf_sha256};
use crate::p256::{self, Fe, Limbs, Point};

pub const GROUP: u16 = 19;
pub type Mac = [u8; 6];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaeError {
    /// The peer's scalar is not between 2 and the group order.
    BadScalar,
    /// The peer's element is not a point of the curve.
    BadElement,
    /// The peer sent our own commit back.
    Reflection,
    /// The two commits lead to no shared key.
    NoSharedKey,
}

fn ordered(a: &Mac, b: &Mac) -> [u8; 12] {
    let (hi, lo) = if a > b { (a, b) } else { (b, a) };
    let mut out = [0u8; 12];
    out[..6].copy_from_slice(hi);
    out[6..].copy_from_slice(lo);
    out
}

/// The password element by hunting and pecking: try counters until
/// one hashes to the x coordinate of a point.
pub fn password_element_looping(a: &Mac, b: &Mac, password: &[u8]) -> Point {
    let addresses = ordered(a, b);
    let prime = p256::to_bytes(&p256::P);
    let mut found: Option<Point> = None;
    // Forty rounds whatever happens, so the time taken tells nothing.
    for counter in 1..=40u8 {
        let seed = hmac_sha256(&addresses, &[password, &[counter]]);
        let value: [u8; 32] = kdf_sha256(&seed, "SAE Hunting and Pecking", &prime, 256)
            .try_into()
            .unwrap();
        let x = p256::from_bytes(&value);
        if found.is_some() || !p256::less(&x, &p256::P) {
            continue;
        }
        let x = Fe::new(&x);
        if let Some(mut y) = p256::curve_rhs(&x).sqrt() {
            if y.is_odd() != (seed[31] & 1 != 0) {
                y = y.neg();
            }
            found = Point::from_affine(&x, &y);
        }
    }
    found.expect("forty counters and not one point: one chance in 2^40")
}

/// Simplified SWU map of a field element to a point (RFC 9380, 6.6.2).
fn map_to_curve(u: &Fe) -> Point {
    let a = Fe::from_u32(3).neg();
    let b = p256::curve_rhs(&Fe::ZERO);
    let z = Fe::from_u32(10).neg();
    let zu2 = z.mul(&u.square());
    let t = zu2.square().add(&zu2).invert();
    let x1 = if t.is_zero() {
        b.mul(&z.mul(&a).invert())
    } else {
        b.neg().mul(&a.invert()).mul(&Fe::one().add(&t))
    };
    let gx1 = p256::curve_rhs(&x1);
    let x2 = zu2.mul(&x1);
    let (x, mut y) = match gx1.sqrt() {
        Some(y) => (x1, y),
        None => (
            x2,
            p256::curve_rhs(&x2)
                .sqrt()
                .expect("one of the two candidates is on the curve"),
        ),
    };
    if u.is_odd() != y.is_odd() {
        y = y.neg();
    }
    Point::from_affine(&x, &y).expect("the map lands on the curve")
}

/// The network's secret point for hash-to-element: it depends on the
/// network name and the password only, and can be computed once.
pub fn password_point(ssid: &[u8], password: &[u8], identifier: Option<&[u8]>) -> Point {
    // HKDF-Extract with the network name as salt.
    let seed = hmac_sha256(ssid, &[password, identifier.unwrap_or(&[])]);
    let half = |label: &str| {
        // 48 bytes, reduced modulo p, so the result is close to uniform.
        let wide = hkdf_expand_sha256(&seed, label.as_bytes(), 48);
        let mut hi = [0u8; 32];
        hi[16..].copy_from_slice(&wide[..16]);
        let lo: [u8; 32] = wide[16..].try_into().unwrap();
        map_to_curve(&Fe::from_wide(
            &p256::from_bytes(&hi),
            &p256::from_bytes(&lo),
        ))
    };
    half("SAE Hash to Element u1 P1").add(&half("SAE Hash to Element u2 P2"))
}

/// The password element for one pair of stations, from the network's
/// secret point.
pub fn password_element_from_point(point: &Point, a: &Mac, b: &Mac) -> Point {
    let value = hmac_sha256(&[0; 32], &[&ordered(a, b)]);
    // Into 1..=n-1.
    let mut order_less_one = p256::N;
    order_less_one[0] -= 1;
    let scalar = p256::add_mod(
        &p256::reduce(&p256::from_bytes(&value), &order_less_one),
        &p256::ONE,
        &p256::N,
    );
    point.mul(&scalar)
}

/// What a station sends first: a scalar and an element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub scalar: [u8; 32],
    pub element: [u8; 64],
}

impl Commit {
    /// The body of the authentication frame: group, scalar, element.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = GROUP.to_le_bytes().to_vec();
        out.extend_from_slice(&self.scalar);
        out.extend_from_slice(&self.element);
        out
    }

    /// Parse a frame body; `None` if it is not a group 19 commit.
    pub fn from_bytes(bytes: &[u8]) -> Option<Commit> {
        if bytes.len() < 98 || bytes[..2] != GROUP.to_le_bytes() {
            return None;
        }
        Some(Commit {
            scalar: bytes[2..34].try_into().unwrap(),
            element: bytes[34..98].try_into().unwrap(),
        })
    }
}

/// One run of the exchange, for one end.
pub struct Session {
    element: Point,
    rand: Limbs,
    own: Commit,
    peer: Option<Commit>,
    kck: [u8; 32],
    /// The pairwise master key, once the peer's commit was processed.
    pub pmk: [u8; 32],
    pub pmkid: [u8; 16],
}

fn below_two(n: &Limbs) -> bool {
    n[1..].iter().all(|l| *l == 0) && n[0] < 2
}

/// Bring 32 random bytes into 2..n.
fn private_number(bytes: &[u8; 32]) -> Limbs {
    let mut n = p256::reduce(&p256::from_bytes(bytes), &p256::N);
    if below_two(&n) {
        n[0] += 2;
    }
    n
}

impl Session {
    /// Start a run with the password element and two fresh random
    /// numbers (`rand` stays secret, `mask` hides it in the commit).
    pub fn new(element: Point, rand: &[u8; 32], mask: &[u8; 32]) -> Session {
        let rand = private_number(rand);
        let mask = private_number(mask);
        let scalar = p256::add_mod(&rand, &mask, &p256::N);
        let hidden = element
            .mul(&mask)
            .neg()
            .to_bytes()
            .expect("a multiple of a point of prime order");
        Session {
            element,
            rand,
            own: Commit {
                scalar: p256::to_bytes(&scalar),
                element: hidden,
            },
            peer: None,
            kck: [0; 32],
            pmk: [0; 32],
            pmkid: [0; 16],
        }
    }

    pub fn commit(&self) -> &Commit {
        &self.own
    }

    /// Take the peer's commit and derive the keys.
    pub fn process_commit(&mut self, peer: &Commit) -> Result<(), SaeError> {
        if *peer == self.own {
            return Err(SaeError::Reflection);
        }
        let scalar = p256::from_bytes(&peer.scalar);
        if below_two(&scalar) || !p256::less(&scalar, &p256::N) {
            return Err(SaeError::BadScalar);
        }
        let element = Point::from_bytes(&peer.element).ok_or(SaeError::BadElement)?;
        let shared = self.element.mul(&scalar).add(&element).mul(&self.rand);
        let (k, _) = shared.affine().ok_or(SaeError::NoSharedKey)?;

        let keyseed = hmac_sha256(&[0; 32], &[&k.to_bytes()]);
        let sum = p256::to_bytes(&p256::add_mod(
            &p256::from_bytes(&self.own.scalar),
            &scalar,
            &p256::N,
        ));
        let keys = kdf_sha256(&keyseed, "SAE KCK and PMK", &sum, 512);
        self.kck.copy_from_slice(&keys[..32]);
        self.pmk.copy_from_slice(&keys[32..]);
        self.pmkid.copy_from_slice(&sum[..16]);
        self.peer = Some(peer.clone());
        Ok(())
    }

    fn confirm_value(&self, counter: u16, first: &Commit, second: &Commit) -> [u8; 32] {
        hmac_sha256(
            &self.kck,
            &[
                &counter.to_le_bytes(),
                &first.scalar,
                &first.element,
                &second.scalar,
                &second.element,
            ],
        )
    }

    /// Our confirm for the given send-confirm counter. Call after
    /// [`Session::process_commit`].
    pub fn confirm(&self, counter: u16) -> [u8; 32] {
        let peer = self.peer.as_ref().expect("the peer's commit comes first");
        self.confirm_value(counter, &self.own, peer)
    }

    /// Whether the peer's confirm proves it holds the same key.
    pub fn check_confirm(&self, counter: u16, value: &[u8]) -> bool {
        self.peer
            .as_ref()
            .is_some_and(|peer| self.confirm_value(counter, peer, &self.own)[..] == *value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::hex;

    // IEEE Std 802.11-2020, Annex J.10, as carried by hostapd's tests.
    const ADDR1: Mac = [0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87];
    const ADDR2: Mac = [0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c];
    const PASSWORD: &[u8] = b"mekmitasdigoat";

    #[test]
    fn hunting_and_pecking_matches_the_ieee_vector() {
        let rand: [u8; 32] =
            hex("992465fd3daa3c60aa6565b7f62a2a7f2e12dd12f198faf4fbed89d7ff1ace94")
                .try_into()
                .unwrap();
        let mask: [u8; 32] =
            hex("9507a90f777a044d6a0830b91ea3d5dd70bece44e1acffb86983b5e1bf9fb322")
                .try_into()
                .unwrap();
        let element = password_element_looping(&ADDR1, &ADDR2, PASSWORD);
        let mut session = Session::new(element, &rand, &mask);
        assert_eq!(
            session.commit().to_bytes(),
            hex(
                "1300 2e2c0f0db52440ad146d967114ce005ce1eab0aa2c2e5c2871b774f6c2575c65
                 d5ad9e00829707aa36ba8b859738fc961d08243505f47c035376d7ac4bc8d7b9
                 5083bf43827d0fc31ed778dd3671fd21a46d1091d64b6f9a1e127262132 5dbe1"
            )
        );
        let peer = Commit::from_bytes(&hex(
            "1300 591b96f3397fb945100848e7b550543b6720d88337ee93fc49fd6df7e08b5223
             e71b9bb048d3873f20556953a96c91536fd8ee6ca9b4a68a148b056a909be03e
             83ae208f60f8ef5537858074db0668703239986299 9b511e0a1552a5fea317c2",
        ))
        .unwrap();
        session.process_commit(&peer).unwrap();
        assert_eq!(
            session.kck.to_vec(),
            hex("1e733f6d9bd5325628730433883 1b09a39406d121017073a5c30db36f36cb81a")
        );
        assert_eq!(
            session.pmk.to_vec(),
            hex("4e4dfab1a2dd8ac1a91790f953faaa452ae5c6873ab75b63605ba663f8a7fe59")
        );
        assert_eq!(
            session.pmkid.to_vec(),
            hex("8747a600eea3f9f22475df58ca1e5498")
        );
    }

    #[test]
    fn hash_to_element_matches_the_ieee_vector() {
        let point = password_point(b"byteme", PASSWORD, Some(b"psk4internet"));
        let a = [0x00, 0x09, 0x5b, 0x66, 0xec, 0x1e];
        let b = [0x00, 0x0b, 0x6b, 0xd9, 0x02, 0x46];
        let element = password_element_from_point(&point, &a, &b)
            .to_bytes()
            .unwrap();
        assert_eq!(
            element[..32],
            hex("c93049b9e64000f848201649e999f2b5c22dea69b5632c9df4d633b8aa1f6c1e")[..]
        );
        assert_eq!(
            element[32..],
            hex("73634e94b53d82e7383a8d258199d9dc1a5ee8269d060382ccbf33e614ff59a0")[..]
        );
    }

    #[test]
    fn two_ends_agree_and_a_wrong_password_does_not() {
        let (a, b) = ([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]);
        let run = |pass_a: &[u8], pass_b: &[u8]| {
            let mut x = Session::new(password_element_looping(&a, &b, pass_a), &[7; 32], &[9; 32]);
            let mut y = Session::new(
                password_element_looping(&b, &a, pass_b),
                &[11; 32],
                &[13; 32],
            );
            x.process_commit(&y.commit().clone()).unwrap();
            y.process_commit(&x.commit().clone()).unwrap();
            (x, y)
        };
        let (x, y) = run(b"carotte", b"carotte");
        assert_eq!(x.pmk, y.pmk);
        assert_eq!(x.pmkid, y.pmkid);
        assert!(y.check_confirm(1, &x.confirm(1)));
        assert!(x.check_confirm(1, &y.confirm(1)));
        assert!(
            !x.check_confirm(2, &y.confirm(1)),
            "the counter is part of the proof"
        );

        let (x, y) = run(b"carotte", b"navet");
        assert_ne!(x.pmk, y.pmk);
        assert!(!y.check_confirm(1, &x.confirm(1)));
    }

    #[test]
    fn bad_commits_are_refused() {
        let element = password_element_looping(&ADDR1, &ADDR2, PASSWORD);
        let mut s = Session::new(element, &[7; 32], &[9; 32]);
        let own = s.commit().clone();
        assert_eq!(s.process_commit(&own), Err(SaeError::Reflection));
        let mut zero = own.clone();
        zero.scalar = [0; 32];
        assert_eq!(s.process_commit(&zero), Err(SaeError::BadScalar));
        let mut off = own.clone();
        off.scalar[31] ^= 1;
        off.element[63] ^= 1;
        assert_eq!(s.process_commit(&off), Err(SaeError::BadElement));
    }
}
