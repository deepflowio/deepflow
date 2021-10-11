fn generate_protobuf() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .out_dir("src/proto")
        .compile(
            &[
                "src/proto/message/common.proto",
                "src/proto/message/trident.proto",
            ],
            &["src/proto/message"],
        )?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    generate_protobuf()?;
    Ok(())
}
