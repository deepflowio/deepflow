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

fn set_linkage() -> Result<(), Box<dyn Error>> {
    let library_name = "trace";
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let library_dir = dunce::canonicalize(root.join("../../../")).unwrap();
    println!("cargo:rustc-link-lib=static={}", library_name);
    println!(
        "cargo:rustc-link-search=native={}",
        env::join_paths(&[library_dir]).unwrap().to_str().unwrap()
    );

    let target_env = env::var("CARGO_CFG_TARGET_ENV")?;
    if target_env.as_str() == "musl" {
        #[cfg(target_arch = "x86_64")]
        println!("cargo:rustc-link-search=native=/usr/x86_64-linux-musl/lib64");

        #[cfg(target_arch = "aarch64")]
        println!("cargo:rustc-link-search=native=/usr/aarch64-linux-musl/lib64");
    }
    println!("cargo:rustc-link-search=native=/usr/lib");
    println!("cargo:rustc-link-search=native=/usr/lib64");

    println!("cargo:rustc-link-lib=static=GoReSym");

    #[cfg(target_arch = "x86_64")]
    println!("cargo:rustc-link-lib=static=bddisasm");

    println!("cargo:rustc-link-lib=static=dwarf");
    println!("cargo:rustc-link-lib=static=bcc_bpf");
    println!("cargo:rustc-link-lib=static=pcap");
    println!("cargo:rustc-link-lib=static=elf");

    match target_env.as_str() {
        "gnu" => {
            println!("cargo:rustc-link-lib=static=bcc");
            println!("cargo:rustc-link-lib=dylib=pthread");
            println!("cargo:rustc-link-lib=dylib=z");
            println!("cargo:rustc-link-lib=dylib=stdc++");
        }
        "musl" => {
            #[cfg(target_arch = "x86_64")]
            println!("cargo:rustc-link-lib=static=bcc");

            #[cfg(target_arch = "x86_64")]
            println!("cargo:rustc-link-lib=static=stdc++");

            println!("cargo:rustc-link-lib=static=c");
            println!("cargo:rustc-link-lib=static=elf");
            println!("cargo:rustc-link-lib=static=m");
            println!("cargo:rustc-link-lib=static=z");
            println!("cargo:rustc-link-lib=static=pthread");
            println!("cargo:rustc-link-lib=static=rt");
            println!("cargo:rustc-link-lib=static=dl");
        }
        _ => panic!("Unsupported target"),
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    set_linkage()?;
    Ok(())
}
