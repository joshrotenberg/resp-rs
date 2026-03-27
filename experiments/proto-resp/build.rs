fn main() {
    prost_build::compile_protos(&["proto/resp.proto"], &["proto/"]).unwrap();
}
