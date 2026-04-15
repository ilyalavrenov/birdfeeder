use std::{env, error::Error, path::PathBuf};

use prost::Message as _;

const PROTO: &str = "../../api/roost/v1/roost.proto";

// protox compiles the schema in-process, so you don't need protoc installed.
fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed={PROTO}");
    let fds = protox::compile([PROTO], ["../../api"])?;
    let out = PathBuf::from(env::var("OUT_DIR")?);
    let descriptors = out.join("descriptors.bin");
    std::fs::write(&descriptors, fds.encode_to_vec())?;
    // sorted maps, so JSON output and table rows come out in the same order every time.
    tonic_prost_build::configure()
        .btree_map(".")
        .build_transport(false)
        .file_descriptor_set_path(&descriptors)
        .skip_protoc_run()
        .compile_fds(fds)?;
    // emit zeros and empty lists too, so scripts can index them without checking first.
    pbjson_build::Builder::new()
        .register_descriptors(&std::fs::read(&descriptors)?)?
        .btree_map(["."])
        .emit_fields()
        .build(&[".birdfeeder.roost.v1"])?;
    Ok(())
}
