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

use std::{env, error::Error, path::PathBuf, process::Command, str};

use chrono::prelude::*;

fn get_branch() -> Result<String, Box<dyn Error>> {
    if let Ok(branch) = env::var("GITHUB_REF_NAME") {
        return Ok(branch);
    }

    let output = Command::new("git")
        .args(["branch", "--show-current"])
        .output()?;
    if output.status.success() {
        return Ok(String::from_utf8(output.stdout)?);
    }

    let output = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()?;
    if output.status.success() && &output.stdout != "HEAD".as_bytes() {
        return Ok(String::from_utf8(output.stdout)?);
    }

    let output = Command::new("git")
        .args(["log", "-n", "1", "--pretty=%D", "HEAD"])
        .output()?;
    if output.status.success() {
        // output: HEAD -> master, origin/main
        return match output.stdout.iter().position(|x| *x == ',' as u8) {
            Some(mut position) => {
                while (output.stdout[position] as char).is_ascii_whitespace()
                    && position < output.stdout.len()
                {
                    position += 1;
                }
                Ok(str::from_utf8(&output.stdout[position..])?.to_owned())
            }
            _ => Ok(String::from_utf8(output.stdout)?),
        };
    }

    panic!("no branch name found")
}

struct EnvCommand(&'static str, Vec<&'static str>);

fn set_build_info() -> Result<(), Box<dyn Error>> {
    println!("cargo:rustc-env=AGENT_NAME=deepflow-agent-ce");
    println!("cargo:rustc-env=BRANCH={}", get_branch()?);
    println!(
        "cargo:rustc-env=COMPILE_TIME={}",
        Local::now().format("%F %T")
    );
    let entries = vec![
        EnvCommand("COMMIT_ID", vec!["git", "rev-parse", "HEAD"]),
        EnvCommand("REV_COUNT", vec!["git", "rev-list", "--count", "HEAD"]),
        EnvCommand("RUSTC_VERSION", vec!["rustc", "--version"]),
    ];
    for e in entries {
        let output = Command::new(e.1[0]).args(&e.1[1..]).output()?.stdout;
        println!("cargo:rustc-env={}={}", e.0, String::from_utf8(output)?);
    }
    Ok(())
}

fn set_build_libtrace() -> Result<(), Box<dyn Error>> {
    let output = match env::var("CARGO_CFG_TARGET_ENV")?.as_str() {
        "gnu" => Command::new("sh").arg("-c")
            .arg("cd src/ebpf && make clean && make --no-print-directory && make tools --no-print-directory")
            .output()?,
        "musl" => Command::new("sh").arg("-c")
            .arg("cd src/ebpf && make clean && CC=musl-gcc CLANG=musl-clang make --no-print-directory && CC=musl-gcc CLANG=musl-clang make tools --no-print-directory")
            .output()?,
        _ => panic!("Unsupported target"),
    };
    if !output.status.success() {
        eprintln!("{}", str::from_utf8(&output.stderr)?);
        panic!("compile libtrace.a error!");
    }
    let library_name = "trace";
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let library_dir = dunce::canonicalize(root.join("src/ebpf/"))?;
    println!("cargo:rustc-link-lib=static={}", library_name);
    println!(
        "cargo:rustc-link-search=native={}",
        env::join_paths(&[library_dir])?.to_str().unwrap()
    );
    Ok(())
}

fn set_linkage() -> Result<(), Box<dyn Error>> {
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

    println!("cargo:rustc-link-lib=static=elf");

    match target_env.as_str() {
        "gnu" => {
            println!("cargo:rustc-link-lib=static=bcc");
            println!("cargo:rustc-link-lib=dylib=pthread");
            println!("cargo:rustc-link-lib=dylib=z");
            println!("cargo:rustc-link-lib=dylib=stdc++");
            #[cfg(target_arch = "x86_64")]
            println!("cargo:rustc-link-lib=static=pcap");
            #[cfg(target_arch = "aarch64")]
            println!("cargo:rustc-link-lib=dylib=pcap");
        }
        "musl" => {
            #[cfg(target_arch = "x86_64")]
            println!("cargo:rustc-link-lib=static=bcc");

            #[cfg(target_arch = "x86_64")]
            println!("cargo:rustc-link-lib=static=stdc++");

            println!("cargo:rustc-link-lib=static=pcap");
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

fn compile_wasm_plugin_proto() -> Result<(), Box<dyn Error>> {
    tonic_build::configure()
        .build_server(false)
        .out_dir("src/plugin/wasm")
        .compile(&["./src/plugin/WasmPluginApi.proto"], &["./src/plugin"])?;
    Ok(())
}

fn make_pulsar_proto() -> Result<(), Box<dyn Error>> {
    tonic_build::configure()
        .field_attribute(".", "#[serde(skip_serializing_if = \"Option::is_none\")]")
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .build_server(false)
        .out_dir("src/flow_generator/protocol_logs/mq")
        .compile(
            &["src/flow_generator/protocol_logs/mq/PulsarApi.proto"],
            &["src/flow_generator/protocol_logs/mq"],
        )?;

    // remove `#[serde(skip_serializing_if = "Option::is_none")]` for non-optional fields
    let filename = "src/flow_generator/protocol_logs/mq/pulsar.proto.rs";
    let content = std::fs::read_to_string(filename)?;
    let lines = content.lines().collect::<Vec<_>>();
    let mut new_lines = Vec::new();
    new_lines.push(*lines.get(0).unwrap());
    for a in lines.windows(2) {
        if a[1].contains("skip_serializing_if") && !a[0].contains("optional") {
            continue;
        }
        new_lines.push(a[1]);
    }
    std::fs::write(filename, new_lines.join("\n"))?;
    Command::new("cargo")
        .args([
            "fmt",
            "--",
            "src/flow_generator/protocol_logs/mq/pulsar.proto.rs",
        ])
        .spawn()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    set_build_info()?;
    compile_wasm_plugin_proto()?;
    make_pulsar_proto()?;
    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    if target_os.as_str() == "linux" {
        set_build_libtrace()?;
        set_linkage()?;
    }
    Ok(())
}
