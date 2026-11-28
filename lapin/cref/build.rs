//! Build the C firmware's virtual machine for the machine running the
//! tests: `src/vm/*.c` as they are but for one line of `vinterp.c`
//! (`OPbytecode`'s pull, [`vinterp_as_lapin`]), the play and record half
//! of `src/hal/audio.c` with its hardware functions cut out, and a shim
//! that sends every hardware call to the Rust side.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The functions of `audio.c` that touch the board: the shim has its
/// own.
const HARDWARE: &[&str] = &[
    "get_adc_value",
    "vlsi_read_sci",
    "vlsi_write_sci",
    "vlsi_feed_sdi",
    "vlsi_fifo_ready",
    "vlsi_ampli",
    "init_vlsi",
];

/// `audio.c` without the definitions of `HARDWARE`, its chip selects
/// and its byte to the codec sent to the shim.
fn audio_without_hardware(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut last_include = 0;
    while i < lines.len() {
        let line = lines[i];
        let defines = HARDWARE.iter().any(|name| {
            !line.starts_with(' ')
                && !line.starts_with('\t')
                && !line.trim_end().ends_with(';')
                && line.contains(&format!(" {name}("))
        });
        if defines {
            while i < lines.len() && lines[i] != "}" {
                i += 1;
            }
            i += 1;
            continue;
        }
        if line.starts_with("#include") {
            last_include = out.len();
        }
        out.push(line.to_string());
        i += 1;
    }
    out.insert(
        last_include + 1,
        "#undef CS_AUDIO_SDI_CLEAR\n#define CS_AUDIO_SDI_CLEAR\n\
         #undef CS_AUDIO_SDI_SET\n#define CS_AUDIO_SDI_SET\n\
         #undef disable_ohci_irq\n#define disable_ohci_irq()\n\
         #undef enable_ohci_irq\n#define enable_ohci_irq()\n\
         void shim_sdi_byte(uint8_t);\n#define WriteSPI(v) shim_sdi_byte(v)"
            .to_string(),
    );
    out.join("\n") + "\n"
}

/// `vinterp.c` without the pull that ends `OPbytecode`: the one
/// difference from r3's machine lapin's makes on purpose (HANDOFF.md,
/// "Deliberate differences from r3"). r3 pulls the new main's result
/// there, its caller pulls again, off the new stack, and the new
/// bytecode's last global falls above the top. Everything else is
/// compared against the C as it is.
fn vinterp_as_lapin(source: &str) -> String {
    let lines: Vec<&str> = source.split_inclusive('\n').collect();
    let pull: Vec<usize> = (1..lines.len() - 1)
        .filter(|&i| {
            lines[i - 1].trim() == "interpGo();"
                && lines[i].trim() == "(void)VPULL();"
                && lines[i + 1].contains("OPbytecode done")
        })
        .collect();
    assert_eq!(pull.len(), 1, "OPbytecode's pull moved");
    let mut out = lines;
    out.remove(pull[0]);
    out.concat()
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo = manifest.join("../..").canonicalize().unwrap();
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());

    let audio = std::fs::read_to_string(repo.join("src/hal/audio.c")).unwrap();
    let audio_vm = out.join("audio_vm.c");
    std::fs::write(&audio_vm, audio_without_hardware(&audio)).unwrap();

    let vinterp = std::fs::read_to_string(repo.join("src/vm/vinterp.c")).unwrap();
    let vinterp_vm = out.join("vinterp.c");
    std::fs::write(&vinterp_vm, vinterp_as_lapin(&vinterp)).unwrap();

    let mut sources: Vec<PathBuf> = ["vmem", "vloader", "vlog", "vaudio", "vnet"]
        .iter()
        .map(|f| repo.join(format!("src/vm/{f}.c")))
        .collect();
    sources.push(vinterp_vm);
    sources.push(audio_vm);
    sources.push(manifest.join("c/shim.c"));

    let mut objects = Vec::new();
    for src in &sources {
        let obj = out.join(src.file_stem().unwrap()).with_extension("o");
        let status = Command::new(&cc)
            .args(["-c", "-O1", "-w", "-fno-strict-aliasing", "-fwrapv"])
            // As the release firmware: none of the debug output.
            .arg("-D_NAB_SIM")
            // Mach-O wants a segment in section names; the sections do
            // not matter here.
            .arg("-Dsection(x)=aligned(4)")
            .arg(format!("-I{}", repo.join("inc").display()))
            .arg(format!("-I{}", repo.join("sys/inc").display()))
            .arg(src)
            .arg("-o")
            .arg(&obj)
            .status()
            .expect("a C compiler (cc)");
        assert!(status.success(), "compiling {}", src.display());
        objects.push(obj);
        println!("cargo:rerun-if-changed={}", src.display());
    }
    let lib = out.join("libcvm.a");
    let _ = std::fs::remove_file(&lib);
    let status = Command::new("ar")
        .arg("crs")
        .arg(&lib)
        .args(&objects)
        .status()
        .expect("ar");
    assert!(status.success());
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=cvm");
    println!("cargo:rerun-if-changed={}", Path::new("c/shim.c").display());
    for patched in ["src/hal/audio.c", "src/vm/vinterp.c"] {
        println!("cargo:rerun-if-changed={}", repo.join(patched).display());
    }
    println!("cargo:rerun-if-changed={}", repo.join("inc").display());
}
