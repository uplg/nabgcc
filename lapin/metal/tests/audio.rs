//! The machine feeding the codec from the play callback (`audio.rs`),
//! against a codec that plays as time goes and takes data only while
//! its DREQ is up, as the VS1003 does (`kit::Board`).

mod kit;

use kit::asm::{Fun, bytecode, bytecode_with};
use kit::{Board, FIFO, memory};
use lapin_metal::Vm;
use lapin_metal::op::*;

const CHUNK: i32 = 300;

/// The player's integer globals, after the stream and four spare
/// strings: how much of the stream went, and how many calls came.
const POSITION: u8 = 5;
const CALLS: u8 = 6;

/// `stream` played from the callback: `CHUNK` bytes every other call
/// (the calls between give nothing), and every other time it gives,
/// the codec fills up (DREQ falls) before it returns; with `eof` the
/// end is said once it is all in.
fn player(stream: &[u8], eof: bool) -> Vec<u8> {
    let mut main = Fun::new(0, 4);
    main.int(1).int(1).op(PLAYSTART).op(DROP).op(NIL_).op(RET);
    let mut cb = Fun::new(1, 4);
    let (skip, full) = (cb.label(), cb.label());
    cb.int(CALLS as i32)
        .b(GETGLOBALB, CALLS)
        .int(1)
        .op(ADD)
        .op(SETGLOBAL);
    cb.int(1).op(AND).jump(ELSE, skip);
    cb.int(POSITION as i32)
        .b(GETGLOBALB, 0)
        .b(GETGLOBALB, POSITION)
        .int(CHUNK)
        .op(PLAYFEED)
        .b(GETGLOBALB, POSITION)
        .op(ADD)
        .op(SETGLOBAL)
        .op(DROP);
    // Calls 3, 7, 11...: the codec fills up meanwhile.
    cb.b(GETGLOBALB, CALLS).int(2).op(AND).jump(ELSE, full);
    cb.int(0x0F).int(1).op(SNDWRITE).op(DROP).here(full);
    if eof {
        let (last, end) = (cb.label(), cb.label());
        cb.b(GETGLOBALB, POSITION)
            .int(stream.len() as i32)
            .op(SUB)
            .jump(ELSE, last)
            .jump(GOTO, end);
        cb.here(last)
            .op(NIL_)
            .op(NIL_)
            .op(NIL_)
            .op(PLAYFEED)
            .op(DROP)
            .here(end);
    }
    cb.here(skip).op(NIL_).op(RET);
    let spare = [0u8; 4];
    bytecode_with(
        &[stream, &spare, &spare, &spare, &spare],
        &[0, 0],
        &[&main, &cb],
    )
}

fn play(stream: &[u8], eof: bool, turns: usize) -> Board {
    let mut mem = memory();
    let mut vm = Vm::new(
        Board {
            room: FIFO,
            ..Board::default()
        },
        &mut mem,
    );
    vm.boot(&player(stream, eof));
    for _ in 0..turns {
        vm.main_loop_once();
    }
    vm.into_host()
}

fn stream(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 + 1).collect()
}

/// The C writes the byte it took from the ring after the refill even if
/// the refill's collection filled the codec meanwhile (DREQ fell): the
/// VS1003 has room for it. Dropped, as lapin did, one byte lost swaps
/// every 16-bit sample after it (A14). It is held and goes next.
#[test]
fn no_byte_is_lost_when_the_refill_fills_the_codec() {
    let s = stream(30 * CHUNK as usize);
    let codec = play(&s, false, 400);
    assert!(
        codec.played.len() > s.len() / 2,
        "{} played",
        codec.played.len()
    );
    let n = codec.played.len().min(s.len());
    let wrong = (0..n).find(|&i| codec.played[i] != s[i]);
    assert_eq!(wrong, None, "{} bytes played", codec.played.len());
}

/// At the end of a stream (playFeed nil), 2048 zeros follow it so the
/// VS1003 plays its last frames (data sheet 9.3), then the amplifier
/// goes off; the C sent nothing and left it on (B40).
#[test]
fn the_end_of_a_stream_is_flushed_then_the_amplifier_goes_off() {
    let s = stream(4 * CHUNK as usize);
    let codec = play(&s, true, 400);
    assert_eq!(codec.played[..s.len()], s[..]);
    let tail = &codec.played[s.len()..];
    assert_eq!(tail.len(), 2048);
    assert!(tail.iter().all(|b| *b == 0));
    assert!(!codec.amplifier);
}

/// recVol from a negative start: the C reads the 256 bytes before the
/// string (B38); 0 here, as from a start too close to its end.
#[test]
fn rec_vol_from_a_negative_start_is_0() {
    let block = [0x77u8; 512];
    let mut main = Fun::new(0, 4);
    for start in [-256, -1, 0, 300] {
        main.b(GETGLOBALB, 0).int(start).op(RECVOL).show();
    }
    main.op(NIL_).op(RET);
    let mut mem = memory();
    let mut vm = Vm::new(Board::default(), &mut mem);
    vm.boot(&bytecode(&[&block], &[&main]));
    let console = String::from_utf8(vm.into_host().console).unwrap();
    let values: Vec<&str> = console.lines().collect();
    assert_eq!(values[0], "0");
    assert_eq!(values[1], "0");
    assert_ne!(values[2], "0", "a real block is loud");
    assert_eq!(values[3], "0");
}
