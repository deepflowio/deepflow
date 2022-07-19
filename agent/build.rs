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
use std::process::Command;
extern crate dunce;
use std::{env, path::PathBuf};

fn generate_protobuf() -> Result<(), Box<dyn Error>> {
    tonic_build::configure()
        .build_server(false)
        .out_dir("src/proto")
        .compile(
            &[
                "src/proto/message/common.proto",
                "src/proto/message/trident.proto",
                "src/proto/message/metric.proto",
                "src/proto/message/flow_log.proto",
            ],
            &["src/proto/message"],
        )?;
    Ok(())
}

struct EnvCommand(&'static str, Vec<&'static str>);

fn set_build_info() -> Result<(), Box<dyn Error>> {
    println!("cargo:rustc-env=AGENT_NAME=deepflow-agent-ce");
    let entries = vec![
        EnvCommand("REV_COUNT", vec!["git", "rev-list", "--count", "HEAD"]),
        EnvCommand(
            "COMMIT_DATE",
            vec!["git", "show", "-s", "--format=%cd", "--date=short", "HEAD"],
        ),
        EnvCommand("REVISION", vec!["git", "rev-parse", "HEAD"]),
        EnvCommand("RUSTC_VERSION", vec!["rustc", "--version"]),
    ];
    for e in entries {
        let output = Command::new(e.1[0]).args(&e.1[1..]).output()?.stdout;
        println!("cargo:rustc-env={}={}", e.0, String::from_utf8(output)?);
    }
    Ok(())
}

fn set_build_libebpf() -> Result<(), Box<dyn Error>> {
    Command::new("sh")
        .arg("-c")
        .arg("cd src/ebpf && make clean && make --no-print-directory && make tools --no-print-directory")
        .output()
        .expect("compile libebpf.a error!");
    let library_name = "ebpf";
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let library_dir = dunce::canonicalize(root.join("src/ebpf/")).unwrap();
    println!("cargo:rustc-link-lib=static={}", library_name);
    println!(
        "cargo:rustc-link-search=native={}",
        env::join_paths(&[library_dir]).unwrap().to_str().unwrap()
    );
    Ok(())
}

fn set_linkage() -> Result<(), Box<dyn Error>> {
    println!("cargo:rustc-link-search=native=/usr/lib");
    println!("cargo:rustc-link-search=native=/usr/lib64");
    println!("cargo:rustc-link-lib=static=bddisasm");
    println!("cargo:rustc-link-lib=static=dwarf");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=elf");
    println!("cargo:rustc-link-lib=dylib=z");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    generate_protobuf()?;
    set_build_info()?;
    set_build_libebpf()?;
    set_linkage()?;
    Ok(())
}
