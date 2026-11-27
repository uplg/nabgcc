//! The access point's SAE commit and confirm, as the station takes
//! them: parsed, checked, and the keys derived. Most fuzzed elements
//! are off the curve; half the inputs put theirs on it, from an x
//! coordinate.

#![no_main]

use std::sync::OnceLock;

use lapin_core::p256::{self, Fe, Point};
use lapin_core::sae::{self, Commit, Session};
use lapin_fuzz::input::Input;

const STA: [u8; 6] = [0x00, 0x19, 0xDB, 0x9C, 0x28, 0x15];
const AP: [u8; 6] = [0x02, 0, 0, 0, 0, 0xA1];

fn session() -> &'static Session {
    static S: OnceLock<Session> = OnceLock::new();
    S.get_or_init(|| {
        let e = sae::password_element_looping(&STA, &AP, b"carotte-violette").unwrap();
        Session::new(e, &[0x11; 32], &[0x22; 32])
    })
}

fn scalar(input: &mut Input) -> [u8; 32] {
    let mut n1 = p256::N;
    n1[0] -= 1;
    let mut n2 = p256::N;
    n2[0] += 1;
    match input.u8() % 8 {
        0 => [0; 32],
        1 => p256::to_bytes(&[1, 0, 0, 0, 0, 0, 0, 0]),
        2 => p256::to_bytes(&[2, 0, 0, 0, 0, 0, 0, 0]),
        3 => p256::to_bytes(&n1),
        4 => p256::to_bytes(&p256::N),
        5 => p256::to_bytes(&n2),
        _ => input.array(),
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let how = input.u8();
    let mut body = Vec::new();
    if how & 1 == 0 {
        body.extend_from_slice(input.bytes(200));
    } else {
        body.extend_from_slice(&19u16.to_le_bytes());
        body.extend_from_slice(&scalar(&mut input));
        let x: [u8; 32] = input.array();
        let odd = input.bool();
        let point = match how >> 1 & 3 {
            // Our own element, or its opposite.
            0 => session().commit().element,
            1 => {
                let mut e = session().commit().element;
                let y = Fe::from_bytes(&e[32..].try_into().unwrap()).neg();
                e[32..].copy_from_slice(&y.to_bytes());
                e
            }
            _ => {
                let xf = Fe::from_bytes(&x);
                match p256::curve_rhs(&xf).sqrt() {
                    Some(y) => {
                        let y = if y.is_odd() != odd { y.neg() } else { y };
                        let p = Point::from_affine(&xf, &y).unwrap();
                        p.to_bytes().unwrap()
                    }
                    None => {
                        let mut e = [0u8; 64];
                        e[..32].copy_from_slice(&x);
                        e
                    }
                }
            }
        };
        body.extend_from_slice(&point);
        body.extend_from_slice(input.bytes(8));
    }
    let Some(theirs) = Commit::from_bytes(&body) else {
        return;
    };
    let mut s = session().clone();
    let ok = s.process_commit(&theirs).is_ok();
    let confirm = s.confirm(1);
    assert_eq!(ok, confirm.is_some());
    let counter = input.u16();
    let value = input.bytes(40);
    let _ = s.check_confirm(counter, value);
    if ok {
        // A peer that knows the key passes.
        let c = s.confirm(counter).unwrap();
        let _ = c;
    }
    // The hash-to-element point of a network name heard on the air.
    if how & 0xF0 == 0xF0 {
        let ssid = input.bytes(32);
        let _ = sae::password_point(ssid, b"carotte-violette", &[]);
    }
});
