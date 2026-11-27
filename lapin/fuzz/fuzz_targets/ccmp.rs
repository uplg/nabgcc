//! Software CCMP and BIP on any frame, the key unwrap on any length:
//! nothing may panic, and what is protected opens again unchanged.

#![no_main]

use lapin_core::{aes, ccmp};
use lapin_fuzz::input::Input;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut input = Input::new(data);
    let tk: [u8; 16] = input.array();
    let how = input.u8();
    let frame = input.bytes(2400).to_vec();
    // The station hands these functions frames of 24 bytes at least
    // (a header): below that, they are not defined.
    if frame.len() < 24 {
        return;
    }

    let _ = ccmp::header(&frame);
    let mut f = frame.clone();
    if let Some((n, _)) = ccmp::unprotect(&tk, &mut f) {
        assert!(n <= frame.len());
    }
    let _ = ccmp::bip_check(&tk, &frame);

    // Protect then open: the same frame back, with its number.
    if frame.len() >= 26 && frame[1] & 3 == 0 {
        let pn = u64::from_le_bytes(input.array()) & 0xFFFF_FFFF_FFFF;
        let id = how & 3;
        let len = frame.len();
        let mut p = frame.clone();
        p.resize(len + ccmp::OVERHEAD, 0);
        let n = ccmp::protect(&tk, id, pn, &mut p, len);
        assert_eq!(n, len + ccmp::OVERHEAD);
        assert_eq!(ccmp::header(&p[..n]), Some((pn, id)));
        let (m, got) = ccmp::unprotect(&tk, &mut p[..n]).expect("opens");
        assert_eq!((m, got), (len, pn));
        let mut want = frame.clone();
        want[1] &= !0x40;
        let mut back = p[..m].to_vec();
        back[1] &= !0x40;
        assert_eq!(back, want);
    }

    let mut out = vec![0u8; frame.len().saturating_sub(8)];
    let _ = aes::unwrap(&tk, &frame, &mut out);
    let _ = aes::cmac(&tk, &[&frame]);
});
