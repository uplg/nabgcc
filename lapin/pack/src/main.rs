//! `lapin-pack lapin-full.bin lapin-first.bin`: the first image, for a
//! rabbit that still runs the C firmware. Its rescue core as in
//! `lapin-full.bin` (its 20 KB, trailer included), then the application
//! packed (`lapin_core::pack`) behind a header of five words: the
//! rescue core unpacks it at its first start (`lapin/fw/src/boot.rs`).

use lapin_core::pack::{self, HEADER_LEN, MAGIC};

const RESCUE_SIZE: usize = 20 * 1024;
/// The application's place: up to the settings sector.
const AREA: usize = 124 * 1024 - RESCUE_SIZE;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, full, first] = &args[..] else {
        eprintln!("usage: lapin-pack lapin-full.bin lapin-first.bin");
        std::process::exit(2);
    };
    let full = std::fs::read(full).expect("the whole image");
    assert!(
        full.len() > RESCUE_SIZE,
        "no application after the rescue core"
    );
    let (core, app) = full.split_at(RESCUE_SIZE);
    let mut filtered = app.to_vec();
    pack::thumb_calls(&mut filtered, false);
    let stream = pack::pack(core, &filtered);

    // What the rescue core will do with it, checked here.
    let mut buf = full.clone();
    buf[RESCUE_SIZE..].fill(0);
    assert!(pack::unpack(
        &stream,
        &mut buf,
        RESCUE_SIZE,
        &mut [0; pack::CONTEXTS],
        || {}
    ));
    pack::thumb_calls(&mut buf[RESCUE_SIZE..], true);
    assert!(
        buf == full,
        "the packed application does not unpack the same"
    );

    let mut image = core.to_vec();
    for word in [
        MAGIC,
        stream.len() as u32,
        app.len() as u32,
        lapin_core::pack::crc32(app, || {}),
        lapin_core::pack::crc32(&stream, || {}),
    ] {
        image.extend_from_slice(&word.to_le_bytes());
    }
    assert_eq!(image.len(), RESCUE_SIZE + HEADER_LEN);
    image.extend_from_slice(&stream);
    // The packed application must end before the application's place
    // ends.
    assert!(
        image.len() - RESCUE_SIZE <= AREA,
        "the packed application does not fit"
    );
    std::fs::write(first, &image).expect("the first image");
    // What r3's write costs is about 97 ms a sector at the manual's
    // slowest flash (an erase, then its words): say how close the next
    // one is (tools/emu/tests/first_flash.rs measures it).
    let sectors = image.len().div_ceil(4096);
    println!(
        "lapin-first.bin: {} bytes, the application's {} packed to {} ({:.1} %); \
         r3 writes {sectors} sectors, {} bytes short of one more",
        image.len(),
        app.len(),
        stream.len(),
        100.0 * stream.len() as f64 / app.len() as f64,
        sectors * 4096 - image.len()
    );
}
