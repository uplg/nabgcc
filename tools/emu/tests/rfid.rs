//! The released firmware reading tags held in front of the rabbit.

mod common;

use common::{UID, find, until_every, wait};
use nabemu::rfid::Tag;
use nabemu::testing::is_lapin;
use nabemu::{Machine, metal};

/// Boot a one-function program and return what it printed.
fn run(function: &[u8], strings: &[&[u8]], tags: Vec<Tag>) -> (Machine, Vec<u8>) {
    let mut m = common::under_test();
    m.soc.board.rfid.tags = tags;
    let mut code = metal::FUNCTION_HEADER.to_vec();
    code.extend_from_slice(function);
    code.push(metal::OP_RET);
    m.serve(&metal::bytecode(strings, &code));
    until_every(&mut m, 50, 40_000, "the boot bytecode done", |m| {
        m.console().contains("BOOT DONE")
    });
    wait(&mut m, 3000);
    let mark = find(&m.soc.uart_tx, b"BOOT DONE").unwrap();
    let printed = m.soc.uart_tx[mark..].to_vec();
    (m, printed)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

#[test]
fn reads_the_identifier_of_a_tag() {
    let (m, printed) = run(
        &[metal::OP_RFID_GET, metal::OP_SECHOLN],
        &[],
        vec![Tag::new(UID)],
    );
    assert!(contains(&printed, &UID), "{printed:02x?}");
    assert!(m.soc.board.rfid.exchanges > 0);
    assert_eq!(m.events, []);
}

#[test]
fn sees_nothing_when_no_tag_is_there() {
    let (m, printed) = run(&[metal::OP_RFID_GET, metal::OP_SECHOLN], &[], Vec::new());
    assert!(!contains(&printed, &UID[..4]), "{printed:02x?}");
    assert!(m.soc.board.rfid.exchanges > 0, "it did ask");
}

#[test]
fn reads_and_writes_a_tag_s_memory() {
    let mut tag = Tag::new(UID);
    // The firmware's block 1 is the tag's block 8.
    tag.blocks[8] = *b"miam";
    let mut f = vec![metal::OP_RFID_GET, metal::OP_DROP];
    // rfidRead uid 1, printed; then rfidWrite uid 2 "noix".
    f.extend([metal::OP_GETGLOBALB, 0]);
    f.extend(metal::int(1));
    f.extend([metal::OP_RFID_READ, metal::OP_SECHOLN, metal::OP_DROP]);
    f.extend([metal::OP_GETGLOBALB, 0]);
    f.extend(metal::int(2));
    f.extend([metal::OP_GETGLOBALB, 1, metal::OP_RFID_WRITE]);
    let (m, printed) = run(&f, &[&UID, b"noix"], vec![tag]);
    assert!(contains(&printed, b"miam"), "{printed:02x?}");
    assert_eq!(m.soc.board.rfid.tags[0].blocks[9], *b"noix");
}

/// A tag programs a written block into its EEPROM, up to 5 ms with
/// nothing to say when it is done: the field must stay on, and the tag
/// be left alone, that long. r3 turns the field off at once. lapin
/// returns to the bytecode at once too, and the field goes off once the
/// 5 ms are over: at the next operation on the reader, which waits out
/// what remains (here an immediate second write, then a read of both
/// blocks), or at the next turn of the main loop.
#[test]
fn a_written_block_is_left_to_program_and_reads_back() {
    let mut f = Vec::new();
    // rfidWrite uid 2 "noix", then at once uid 3 "pomm", then reads.
    for (block, data) in [(2, 1), (3, 2)] {
        f.extend([metal::OP_GETGLOBALB, 0]);
        f.extend(metal::int(block));
        f.extend([
            metal::OP_GETGLOBALB,
            data,
            metal::OP_RFID_WRITE,
            metal::OP_DROP,
        ]);
    }
    for block in [2, 3] {
        f.extend([metal::OP_GETGLOBALB, 0]);
        f.extend(metal::int(block));
        f.extend([metal::OP_RFID_READ, metal::OP_SECHOLN, metal::OP_DROP]);
    }
    let (m, printed) = run(&f, &[&UID, b"noix", b"pomm"], vec![Tag::new(UID)]);
    assert!(contains(&printed, b"noix"), "{printed:02x?}");
    assert!(contains(&printed, b"pomm"), "{printed:02x?}");
    let tag = &m.soc.board.rfid.tags[0];
    assert_eq!((tag.blocks[9], tag.blocks[10]), (*b"noix", *b"pomm"));
    let cut = m.soc.board.rfid.cut_short;
    if is_lapin() {
        assert_eq!(cut, 0, "a block's programming cut short");
    } else {
        assert!(cut > 0, "Known defect: r3 turns the field off at once");
    }
}

/// A write with nothing after it: the field still goes off, once the
/// tag has had its 5 ms, from the main loop.
#[test]
fn the_field_goes_off_after_a_write() {
    let mut f = Vec::new();
    f.extend([metal::OP_GETGLOBALB, 0]);
    f.extend(metal::int(2));
    f.extend([
        metal::OP_GETGLOBALB,
        1,
        metal::OP_RFID_WRITE,
        metal::OP_DROP,
    ]);
    let (m, _) = run(&f, &[&UID, b"noix"], vec![Tag::new(UID)]);
    assert!(!m.soc.board.rfid.field_on(), "the field left on");
    assert_eq!(m.soc.board.rfid.tags[0].blocks[9], *b"noix");
    assert_eq!(
        m.soc.board.rfid.cut_short == 0,
        is_lapin(),
        "Known defect on r3"
    );
}
