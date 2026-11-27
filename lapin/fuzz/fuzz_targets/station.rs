#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    lapin_fuzz::station::run(data);
});
