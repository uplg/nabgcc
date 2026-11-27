//! Simultaneous Authentication of Equals, the password exchange of
//! WPA3 (IEEE 802.11-2020, 12.4), over group 19 (NIST P-256).
//!
//! Both ends turn the password into a secret point of the curve (the
//! password element), exchange a commit (a scalar and a point that
//! hide a random number), derive the same key from what they sent and
//! received, and prove it with a confirm.

use crate::ccmp::constant_eq;
use crate::p256::{self, Fe, Limbs, Point};
use crate::sha256::{hkdf_expand, hmac, kdf};

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

/// The password element by hunting and pecking: try counters until one
/// hashes to the x coordinate of a point. `None` has one chance in
/// 2^40 of happening.
pub fn password_element_looping(a: &Mac, b: &Mac, password: &[u8]) -> Option<Point> {
    let addresses = ordered(a, b);
    let prime = p256::to_bytes(&p256::P);
    let mut found_x = Fe::ZERO;
    let mut found_y = Fe::ZERO;
    let mut found = 0u32;
    // Forty rounds whatever happens, each doing the same work, so that
    // neither the count nor the time tells which counter gave the point:
    // the first that does is kept by masks, not by a branch.
    for counter in 1..=40u8 {
        let seed = hmac(&addresses, &[password, &[counter]]);
        let mut value = [0u8; 32];
        kdf(&seed, b"SAE Hunting and Pecking", &prime, &mut value);
        let x = p256::from_bytes(&value);
        let in_field = (p256::less(&x, &p256::P) as u32).wrapping_neg();
        let x = Fe::new(&x);
        let (mut y, root) = p256::curve_rhs(&x).sqrt_masked();
        let flip = ((y.is_odd() != (seed[31] & 1 != 0)) as u32).wrapping_neg();
        let negated = y.neg();
        y.select(&negated, flip);
        let take = in_field & root & !found;
        found_x.select(&x, take);
        found_y.select(&y, take);
        found |= take;
    }
    if found == 0 {
        return None;
    }
    Point::from_affine(&found_x, &found_y)
}

/// Simplified SWU map of a field element to a point (RFC 9380, 6.6.2).
fn map_to_curve(u: &Fe) -> Option<Point> {
    let a = Fe::from_u32(3).neg();
    let b = p256::curve_rhs(&Fe::ZERO);
    let z = Fe::from_u32(10).neg();
    let zu2 = z.mul(&u.square());
    let t = zu2.square().add(&zu2).invert();
    // Zero only for two values of u in 2^256: the branch is never
    // taken in practice, and the test of it looks at every limb.
    let x1 = if t.is_zero() {
        b.mul(&z.mul(&a).invert())
    } else {
        b.neg().mul(&a.invert()).mul(&Fe::one().add(&t))
    };
    let x2 = zu2.mul(&x1);
    // Both candidates, and the one whose right-hand side is a square
    // kept by a mask: which one it is depends on the password.
    let (y1, square) = p256::curve_rhs(&x1).sqrt_masked();
    let (y2, _) = p256::curve_rhs(&x2).sqrt_masked();
    let mut x = x2;
    x.select(&x1, square);
    let mut y = y2;
    y.select(&y1, square);
    let flip = ((u.is_odd() != y.is_odd()) as u32).wrapping_neg();
    let negated = y.neg();
    y.select(&negated, flip);
    Point::from_affine(&x, &y)
}

/// The network's secret point for hash-to-element: it depends on the
/// network name and the password only, so it is computed once and kept.
pub fn password_point(ssid: &[u8], password: &[u8], identifier: &[u8]) -> Option<Point> {
    // HKDF-Extract with the network name as salt.
    let seed = hmac(ssid, &[password, identifier]);
    let half = |label: &[u8]| {
        // 48 bytes, reduced modulo p, so the result is close to uniform.
        let mut wide = [0u8; 48];
        hkdf_expand(&seed, label, &mut wide);
        let mut hi = [0u8; 32];
        hi[16..].copy_from_slice(&wide[..16]);
        let mut lo = [0u8; 32];
        lo.copy_from_slice(&wide[16..]);
        map_to_curve(&Fe::from_wide(
            &p256::from_bytes(&hi),
            &p256::from_bytes(&lo),
        ))
    };
    Some(half(b"SAE Hash to Element u1 P1")?.add(&half(b"SAE Hash to Element u2 P2")?))
}

/// The password element for one pair of stations, from the network's
/// secret point.
pub fn password_element_from_point(point: &Point, a: &Mac, b: &Mac) -> Point {
    let value = hmac(&[0; 32], &[&ordered(a, b)]);
    // Into 1..=n-1.
    let mut order_less_one = p256::N;
    order_less_one[0] -= 1;
    let one = [1, 0, 0, 0, 0, 0, 0, 0];
    let scalar = p256::add_mod(
        &p256::reduce(&p256::from_bytes(&value), &order_less_one),
        &one,
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

/// Length of a commit in an authentication frame: group, scalar, element.
pub const COMMIT_LEN: usize = 98;

impl Commit {
    pub fn to_bytes(&self) -> [u8; COMMIT_LEN] {
        let mut out = [0u8; COMMIT_LEN];
        out[..2].copy_from_slice(&GROUP.to_le_bytes());
        out[2..34].copy_from_slice(&self.scalar);
        out[34..].copy_from_slice(&self.element);
        out
    }

    /// Parse a frame body; `None` if it is not a group 19 commit.
    pub fn from_bytes(bytes: &[u8]) -> Option<Commit> {
        if bytes.len() < COMMIT_LEN || bytes[..2] != GROUP.to_le_bytes() {
            return None;
        }
        let mut commit = Commit {
            scalar: [0; 32],
            element: [0; 64],
        };
        commit.scalar.copy_from_slice(&bytes[2..34]);
        commit.element.copy_from_slice(&bytes[34..COMMIT_LEN]);
        Some(commit)
    }
}

/// One run of the exchange, for one end.
#[derive(Clone)]
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

/// Bring 32 random bytes into 2..n.
fn private_number(bytes: &[u8; 32]) -> Limbs {
    let mut n = p256::reduce(&p256::from_bytes(bytes), &p256::N);
    if n[1..].iter().all(|l| *l == 0) && n[0] < 2 {
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
        // A multiple of a point of prime order is never infinity.
        let hidden = element.mul(&mask).neg().to_bytes().unwrap_or([0; 64]);
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
        let small = scalar[1..].iter().all(|l| *l == 0) && scalar[0] < 2;
        if small || !p256::less(&scalar, &p256::N) {
            return Err(SaeError::BadScalar);
        }
        let element = Point::from_bytes(&peer.element).ok_or(SaeError::BadElement)?;
        let shared = self.element.mul(&scalar).add(&element).mul(&self.rand);
        let (k, _) = shared.affine().ok_or(SaeError::NoSharedKey)?;

        let keyseed = hmac(&[0; 32], &[&k.to_bytes()]);
        let sum = p256::to_bytes(&p256::add_mod(
            &p256::from_bytes(&self.own.scalar),
            &scalar,
            &p256::N,
        ));
        let mut keys = [0u8; 64];
        kdf(&keyseed, b"SAE KCK and PMK", &sum, &mut keys);
        self.kck.copy_from_slice(&keys[..32]);
        self.pmk.copy_from_slice(&keys[32..]);
        self.pmkid.copy_from_slice(&sum[..16]);
        self.peer = Some(peer.clone());
        Ok(())
    }

    fn confirm_value(&self, counter: u16, first: &Commit, second: &Commit) -> [u8; 32] {
        hmac(
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

    /// Our confirm for the given send-confirm counter; `None` before
    /// the peer's commit was processed.
    pub fn confirm(&self, counter: u16) -> Option<[u8; 32]> {
        Some(self.confirm_value(counter, &self.own, self.peer.as_ref()?))
    }

    /// Whether the peer's confirm proves it holds the same key.
    pub fn check_confirm(&self, counter: u16, value: &[u8]) -> bool {
        self.peer
            .as_ref()
            .is_some_and(|peer| constant_eq(&self.confirm_value(counter, peer, &self.own), value))
    }
}

/// IEEE Std 802.11-2020, Annex J.10: the inputs of the standard's own
/// test run, public so the firmware can replay it on the real processor.
pub mod vector {
    pub const ADDR1: [u8; 6] = [0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87];
    pub const ADDR2: [u8; 6] = [0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c];
    pub const PASSWORD: &[u8] = b"mekmitasdigoat";
    pub const RAND: [u8; 32] = [
        0x99, 0x24, 0x65, 0xfd, 0x3d, 0xaa, 0x3c, 0x60, 0xaa, 0x65, 0x65, 0xb7, 0xf6, 0x2a, 0x2a,
        0x7f, 0x2e, 0x12, 0xdd, 0x12, 0xf1, 0x98, 0xfa, 0xf4, 0xfb, 0xed, 0x89, 0xd7, 0xff, 0x1a,
        0xce, 0x94,
    ];
    pub const MASK: [u8; 32] = [
        0x95, 0x07, 0xa9, 0x0f, 0x77, 0x7a, 0x04, 0x4d, 0x6a, 0x08, 0x30, 0xb9, 0x1e, 0xa3, 0xd5,
        0xdd, 0x70, 0xbe, 0xce, 0x44, 0xe1, 0xac, 0xff, 0xb8, 0x69, 0x83, 0xb5, 0xe1, 0xbf, 0x9f,
        0xb3, 0x22,
    ];
    pub const LOCAL_COMMIT: [u8; 98] = [
        0x13, 0x00, 0x2e, 0x2c, 0x0f, 0x0d, 0xb5, 0x24, 0x40, 0xad, 0x14, 0x6d, 0x96, 0x71, 0x14,
        0xce, 0x00, 0x5c, 0xe1, 0xea, 0xb0, 0xaa, 0x2c, 0x2e, 0x5c, 0x28, 0x71, 0xb7, 0x74, 0xf6,
        0xc2, 0x57, 0x5c, 0x65, 0xd5, 0xad, 0x9e, 0x00, 0x82, 0x97, 0x07, 0xaa, 0x36, 0xba, 0x8b,
        0x85, 0x97, 0x38, 0xfc, 0x96, 0x1d, 0x08, 0x24, 0x35, 0x05, 0xf4, 0x7c, 0x03, 0x53, 0x76,
        0xd7, 0xac, 0x4b, 0xc8, 0xd7, 0xb9, 0x50, 0x83, 0xbf, 0x43, 0x82, 0x7d, 0x0f, 0xc3, 0x1e,
        0xd7, 0x78, 0xdd, 0x36, 0x71, 0xfd, 0x21, 0xa4, 0x6d, 0x10, 0x91, 0xd6, 0x4b, 0x6f, 0x9a,
        0x1e, 0x12, 0x72, 0x62, 0x13, 0x25, 0xdb, 0xe1,
    ];
    pub const PEER_COMMIT: [u8; 98] = [
        0x13, 0x00, 0x59, 0x1b, 0x96, 0xf3, 0x39, 0x7f, 0xb9, 0x45, 0x10, 0x08, 0x48, 0xe7, 0xb5,
        0x50, 0x54, 0x3b, 0x67, 0x20, 0xd8, 0x83, 0x37, 0xee, 0x93, 0xfc, 0x49, 0xfd, 0x6d, 0xf7,
        0xe0, 0x8b, 0x52, 0x23, 0xe7, 0x1b, 0x9b, 0xb0, 0x48, 0xd3, 0x87, 0x3f, 0x20, 0x55, 0x69,
        0x53, 0xa9, 0x6c, 0x91, 0x53, 0x6f, 0xd8, 0xee, 0x6c, 0xa9, 0xb4, 0xa6, 0x8a, 0x14, 0x8b,
        0x05, 0x6a, 0x90, 0x9b, 0xe0, 0x3e, 0x83, 0xae, 0x20, 0x8f, 0x60, 0xf8, 0xef, 0x55, 0x37,
        0x85, 0x80, 0x74, 0xdb, 0x06, 0x68, 0x70, 0x32, 0x39, 0x98, 0x62, 0x99, 0x9b, 0x51, 0x1e,
        0x0a, 0x15, 0x52, 0xa5, 0xfe, 0xa3, 0x17, 0xc2,
    ];
    pub const PMK: [u8; 32] = [
        0x4e, 0x4d, 0xfa, 0xb1, 0xa2, 0xdd, 0x8a, 0xc1, 0xa9, 0x17, 0x90, 0xf9, 0x53, 0xfa, 0xaa,
        0x45, 0x2a, 0xe5, 0xc6, 0x87, 0x3a, 0xb7, 0x5b, 0x63, 0x60, 0x5b, 0xa6, 0x63, 0xf8, 0xa7,
        0xfe, 0x59,
    ];
    pub const PMKID: [u8; 16] = [
        0x87, 0x47, 0xa6, 0x00, 0xee, 0xa3, 0xf9, 0xf2, 0x24, 0x75, 0xdf, 0x58, 0xca, 0x1e, 0x54,
        0x98,
    ];
    /// Hash-to-element: network name, identifier, the two addresses and
    /// the password element they give.
    pub const SSID: &[u8] = b"byteme";
    pub const IDENTIFIER: &[u8] = b"psk4internet";
    pub const ADDR1B: [u8; 6] = [0x00, 0x09, 0x5b, 0x66, 0xec, 0x1e];
    pub const ADDR2B: [u8; 6] = [0x00, 0x0b, 0x6b, 0xd9, 0x02, 0x46];
    pub const ELEMENT: [u8; 64] = [
        0xc9, 0x30, 0x49, 0xb9, 0xe6, 0x40, 0x00, 0xf8, 0x48, 0x20, 0x16, 0x49, 0xe9, 0x99, 0xf2,
        0xb5, 0xc2, 0x2d, 0xea, 0x69, 0xb5, 0x63, 0x2c, 0x9d, 0xf4, 0xd6, 0x33, 0xb8, 0xaa, 0x1f,
        0x6c, 0x1e, 0x73, 0x63, 0x4e, 0x94, 0xb5, 0x3d, 0x82, 0xe7, 0x38, 0x3a, 0x8d, 0x25, 0x81,
        0x99, 0xd9, 0xdc, 0x1a, 0x5e, 0xe8, 0x26, 0x9d, 0x06, 0x03, 0x82, 0xcc, 0xbf, 0x33, 0xe6,
        0x14, 0xff, 0x59, 0xa0,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunting_and_pecking_matches_the_ieee_vector() {
        let element =
            password_element_looping(&vector::ADDR1, &vector::ADDR2, vector::PASSWORD).unwrap();
        let mut session = Session::new(element, &vector::RAND, &vector::MASK);
        assert_eq!(session.commit().to_bytes(), vector::LOCAL_COMMIT);
        session
            .process_commit(&Commit::from_bytes(&vector::PEER_COMMIT).unwrap())
            .unwrap();
        assert_eq!(session.pmk, vector::PMK);
        assert_eq!(session.pmkid, vector::PMKID);
    }

    #[test]
    fn hash_to_element_matches_the_ieee_vector() {
        let point = password_point(vector::SSID, vector::PASSWORD, vector::IDENTIFIER).unwrap();
        let element = password_element_from_point(&point, &vector::ADDR1B, &vector::ADDR2B);
        assert_eq!(element.to_bytes(), Some(vector::ELEMENT));
    }

    #[test]
    fn two_ends_agree_and_a_wrong_password_does_not() {
        let (a, b) = ([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]);
        let run = |pass_a: &[u8], pass_b: &[u8]| {
            let mut x = Session::new(
                password_element_looping(&a, &b, pass_a).unwrap(),
                &[7; 32],
                &[9; 32],
            );
            let mut y = Session::new(
                password_element_looping(&b, &a, pass_b).unwrap(),
                &[11; 32],
                &[13; 32],
            );
            x.process_commit(&y.commit().clone()).unwrap();
            y.process_commit(&x.commit().clone()).unwrap();
            (x, y)
        };
        let (x, y) = run(b"carotte", b"carotte");
        assert_eq!(x.pmk, y.pmk);
        assert!(y.check_confirm(1, &x.confirm(1).unwrap()));
        assert!(!x.check_confirm(2, &y.confirm(1).unwrap()));
        let (x, y) = run(b"carotte", b"navet");
        assert_ne!(x.pmk, y.pmk);
        assert!(!y.check_confirm(1, &x.confirm(1).unwrap()));
    }

    #[test]
    fn bad_commits_are_refused() {
        let element =
            password_element_looping(&vector::ADDR1, &vector::ADDR2, vector::PASSWORD).unwrap();
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
