fn main() {
    prost_build::compile_protos(&["src/proto/resp.proto"], &["src/proto/"]).unwrap();
}
