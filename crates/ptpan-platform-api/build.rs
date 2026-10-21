// Compiles proto/ptpan/platform/v1/platform.proto with protox (no protoc
// install needed) and generates the tonic client and server.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../../proto";
    let file = "ptpan/platform/v1/platform.proto";
    println!("cargo:rerun-if-changed={proto_root}/{file}");
    let descriptors = protox::compile([file], [proto_root])?;
    tonic_build::configure().compile_fds(descriptors)?;
    Ok(())
}
