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

use std::{
    env,
    fs,
    path::{Path, PathBuf},
    process::Command,
    str,
};

use anyhow::Result;
use chrono::prelude::*;
use walkdir::WalkDir;

fn get_branch() -> Result<String> {
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

fn set_build_info() -> Result<()> {
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

// libtrace scatters generated files in different folders, making it difficult to watch a single folder for changes
//
// rerun build script when one of the following file changes
// - C source files, except for
//   - generated bpf bytecode files (`*_bpf_*.c`, e.g. socket_trace_bpf_*.c / perf_profiler_bpf_*.c)
//   - java agent so files and jattach bin
// - Header files
// - `src/ebpf/mod.rs` (to exclude rust sources in `samples` folder)
// - Makefiles
fn set_libtrace_rerun_files() -> Result<()> {
    fn watched(path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            match ext {
                "c" => {
                    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                        if name.contains("_bpf_") {
                            return false;
                        }
                        if name.starts_with("socket_trace_") || name.starts_with("perf_profiler_") {
                            return false;
                        }
                        if name.starts_with("java_agent_so_") {
                            return false;
                        }
                        if name == "deepflow_jattach_bin.c" {
                            return false;
                        }
                        return true;
                    }
                }
                "h" => return true,
                _ => (),
            }
        }
        if path == Path::new("src/ebpf/mods.rs") {
            return true;
        }
        if let Some(name) = path.file_name() {
            if name == "Makefile" {
                return true;
            }
        }
        false
    }
    let base_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    for entry in WalkDir::new(base_dir.join("src/ebpf")) {
        let entry = entry?;
        let relative_path = entry.path().strip_prefix(&base_dir)?;
        if !watched(relative_path) {
            continue;
        }
        println!("cargo:rerun-if-changed={}", relative_path.display());
    }
    Ok(())
}

fn set_build_libtrace() -> Result<()> {
    set_libtrace_rerun_files()?;
    println!("cargo:rerun-if-env-changed=DF_EBPF_CLEAN");
    println!("cargo:rerun-if-env-changed=DF_EBPF_OBJDUMP");
    println!("cargo:rerun-if-env-changed=PROFILE");

    let target_env = env::var("CARGO_CFG_TARGET_ENV")?;

    let target_id = format!(
        "{}-{}-{}",
        env::var("CARGO_CFG_TARGET_OS").unwrap_or_default(),
        env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default(),
        target_env
    );
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_owned());

    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let state_file = root.join("src/ebpf/.last_ebpf_build_target");
    let previous_target = fs::read_to_string(&state_file)
        .ok()
        .map(|s| s.trim().to_owned());

    let force_clean = match env::var("DF_EBPF_CLEAN") {
        Ok(s) => !s.is_empty() && s != "0" && s.to_lowercase() != "false",
        Err(_) => false,
    };
    let need_clean = force_clean
        || previous_target
            .as_deref()
            .map(|t| t != target_id)
            .unwrap_or(false);

    // NOTE:
    // Keep default behavior consistent with historical builds: always generate `*.objdump`.
    // Override with `DF_EBPF_OBJDUMP=0/false` to disable.
    let objdump_enabled = match env::var("DF_EBPF_OBJDUMP") {
        Ok(s) => {
            let v = s.trim().to_lowercase();
            !(v == "0" || v == "false" || v == "off" || v == "no")
        }
        Err(_) => true,
    };
    let objdump_value = if objdump_enabled { "1" } else { "0" };
    let kernel_output_dir = format!(".output/{}/{}/objdump{}", target_id, profile, objdump_value);

    let cargo_makeflags = env::var("CARGO_MAKEFLAGS").ok();
    let num_jobs = env::var("NUM_JOBS").ok();

    let mut run_make = |targets: &[&str]| -> Result<()> {
        let mut cmd = Command::new("make");
        cmd.current_dir(root.join("src/ebpf"));
        if let Some(makeflags) = &cargo_makeflags {
            cmd.env("MAKEFLAGS", makeflags);
        } else if let Some(jobs) = &num_jobs {
            cmd.arg(format!("-j{}", jobs));
        }
        cmd.arg("--no-print-directory");
        cmd.arg(format!("VMLINUX_OBJDUMP={}", objdump_value));
        cmd.arg(format!("KERNEL_OUTPUT_DIR={}", kernel_output_dir));
        match target_env.as_str() {
            "gnu" => {}
            "musl" => {
                cmd.env("CC", "musl-gcc");
                cmd.env("CLANG", "musl-clang");
            }
            _ => panic!("Unsupported target"),
        }
        cmd.args(targets);

        let output = cmd.output()?;
        if !output.status.success() {
            eprintln!("{}", str::from_utf8(&output.stderr)?);
            eprintln!("{}", str::from_utf8(&output.stdout)?);
            panic!("compile libtrace.a error!");
        }
        Ok(())
    };

    if need_clean {
        run_make(&["clean"])?;
    }
    run_make(&["build", "tools"])?;
    fs::write(&state_file, format!("{}\n", target_id))?;

    let library_name = "trace";
    let library_dir = dunce::canonicalize(root.join("src/ebpf/"))?;
    println!("cargo:rustc-link-lib=static={}", library_name);
    println!(
        "cargo:rustc-link-search=native={}",
        env::join_paths(&[library_dir])?.to_str().unwrap()
    );
    Ok(())
}

fn set_linkage() -> Result<()> {
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
            #[cfg(feature = "dylib_pcap")]
            println!("cargo:rustc-link-lib=dylib=pcap");
            #[cfg(not(feature = "dylib_pcap"))]
            println!("cargo:rustc-link-lib=static=pcap");
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

#[allow(dead_code)]
fn compile_wasm_plugin_proto() -> Result<()> {
    tonic_build::configure()
        .build_server(false)
        .emit_rerun_if_changed(false)
        .out_dir("src/plugin/wasm")
        .compile(&["src/plugin/WasmPluginApi.proto"], &["src/plugin"])?;
    println!("cargo:rerun-if-changed=src/plugin/WasmPluginApi.proto");
    Ok(())
}

fn make_pulsar_proto() -> Result<()> {
    tonic_build::configure()
        .field_attribute(".", "#[serde(skip_serializing_if = \"Option::is_none\")]")
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .build_server(false)
        .emit_rerun_if_changed(false)
        .out_dir("src/flow_generator/protocol_logs/mq")
        .compile(
            &["src/flow_generator/protocol_logs/mq/PulsarApi.proto"],
            &["src/flow_generator/protocol_logs/mq"],
        )?;
    println!("cargo:rerun-if-changed=src/flow_generator/protocol_logs/mq/PulsarApi.proto");

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
    Ok(())
}

fn make_brpc_proto() -> Result<()> {
    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .build_server(false)
        .emit_rerun_if_changed(false)
        .out_dir("src/flow_generator/protocol_logs/rpc/brpc")
        .compile(
            &["src/flow_generator/protocol_logs/rpc/brpc/baidu_rpc_meta.proto"],
            &["src/flow_generator/protocol_logs/rpc"],
        )?;
    println!(
        "cargo:rerun-if-changed=src/flow_generator/protocol_logs/rpc/brpc/baidu_rpc_meta.proto"
    );
    Ok(())
}

fn main() -> Result<()> {
    set_build_info()?;
    /*
     * The protoc binary is too old (3.12) in rust-build image, which cannot handle optional fields in protobuf v3 correctly.
     * And it's not easy to upgrade because of the EOL issue of Centos7.
     * We are pushing the generated protobuf code to repo as a workaround.
     *
     * TODO: Fix this issue in the rust-build image.
     *
    compile_wasm_plugin_proto()?;
     */
    make_pulsar_proto()?;
    make_brpc_proto()?;
    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    if target_os.as_str() == "linux" {
        set_build_libtrace()?;
        set_linkage()?;
    }
    Ok(())
}
