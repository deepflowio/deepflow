/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::error::Error;
extern crate dunce;
use std::{env, path::PathBuf};

fn set_build_libtrace() -> Result<(), Box<dyn Error>> {
    let library_name = "trace";
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let library_dir = dunce::canonicalize(root.join("../../")).unwrap();
    println!("cargo:rustc-link-lib=static={}", library_name);
    println!(
        "cargo:rustc-link-search=native={}",
        env::join_paths(&[library_dir]).unwrap().to_str().unwrap()
    );

    println!("cargo:rustc-link-search=native=/usr/aarch64-linux-musl/lib64");
    println!("cargo:rustc-link-lib=static=GoReSym");
    println!("cargo:rustc-link-lib=static=dwarf");
    println!("cargo:rustc-link-lib=static=bcc_bpf");
    println!("cargo:rustc-link-lib=static=c");
    println!("cargo:rustc-link-lib=static=elf");
    println!("cargo:rustc-link-lib=static=pcap");
    println!("cargo:rustc-link-lib=static=m");
    println!("cargo:rustc-link-lib=static=z");
    println!("cargo:rustc-link-lib=static=pthread");
    println!("cargo:rustc-link-lib=static=rt");
    println!("cargo:rustc-link-lib=static=dl");

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    set_build_libtrace()?;
    Ok(())
}
