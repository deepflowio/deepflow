use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const BPF_PATH: &str = "src/bpf";
const SRC: &str = "uprobe";

fn generate_bpf() {
    let mut base_path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    base_path.extend(BPF_PATH.split("/"));

    let mut include_path = base_path.clone();
    include_path.push("include");

    let mut path = base_path.clone();
    path.push(SRC);

    let mut src_path = path.clone();
    src_path.set_extension("bpf.c");
    path.set_extension("skel.rs");
    SkeletonBuilder::new()
        .source(&src_path)
        .clang_args([OsStr::new("-I"), OsStr::new(&include_path)])
        .build_and_generate(&path)
        .unwrap();
    println!("cargo:rerun-if-changed={}", src_path.display());
}

fn generate_c_bindings() {
    let bindings = bindgen::Builder::default()
        .header("src/ctypes.h")
        .allowlist_function("get_process_starttime")
        .allowlist_function("get_sys_boot_time_ns")
        .allowlist_type("symbol_t")
        .allowlist_type("stack_trace_key_t")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("ctypes.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    #[cfg(feature = "with-libbpf")]
    generate_bpf();
    generate_c_bindings();
}
