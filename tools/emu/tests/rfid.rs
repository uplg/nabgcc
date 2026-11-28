//! The released firmware reading tags held in front of the rabbit.

mod common;

use common::{UID, find, until_every, wait};
use nabemu::rfid::Tag;
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
