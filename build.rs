use std::error::Error;
use std::process::Command;

fn generate_protobuf() -> Result<(), Box<dyn Error>> {
    tonic_build::configure()
        .build_server(false)
        .out_dir("src/proto")
        .compile(
            &[
                "src/proto/message/common.proto",
                "src/proto/message/trident.proto",
                "src/proto/message/metric.proto",
            ],
            &["src/proto/message"],
        )?;
    Ok(())
}

struct EnvCommand(&'static str, Vec<&'static str>);

fn set_build_info() -> Result<(), Box<dyn Error>> {
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

fn main() -> Result<(), Box<dyn Error>> {
    generate_protobuf()?;
    set_build_info()?;
    Ok(())
}
