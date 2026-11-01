// SPDX-License-Identifier: GPL-3.0-only

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let schema = "proto/ppanel/server.proto";
    println!("cargo:rerun-if-changed={schema}");
    prost_build::Config::new()
        .protoc_executable(protoc_bin_vendored::protoc_bin_path()?)
        .btree_map(["."])
        .skip_debug(["."])
        .compile_protos(
            &[schema],
            &[
                std::path::PathBuf::from("proto"),
                protoc_bin_vendored::include_path()?,
            ],
        )?;
    Ok(())
}
