use std::error::Error;
extern crate dunce;
use std::{env, path::PathBuf};

fn set_build_libebpf() -> Result<(), Box<dyn Error>> {
    let library_name = "ebpf";
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let library_dir = dunce::canonicalize(root.join("../../")).unwrap();
    println!("cargo:rustc-link-lib=static={}", library_name);
    println!(
        "cargo:rustc-link-search=native={}",
        env::join_paths(&[library_dir]).unwrap().to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=static=bddisasm");
    println!("cargo:rustc-link-lib=static=dwarf");
    println!("cargo:rustc-link-search=native=/usr/lib");
    println!("cargo:rustc-link-search=native=/usr/lib64");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=elf");
    println!("cargo:rustc-link-lib=dylib=z");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    set_build_libebpf()?;
    Ok(())
}
