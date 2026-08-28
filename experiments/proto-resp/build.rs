fn main() {
    // prost-build shells out to protoc. Point it at a vendored binary rather
    // than requiring a system protobuf-compiler: without this, any
    // `cargo check --workspace` fails on a machine that does not have one,
    // which is every CI runner (issue #90).
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    // SAFETY: build scripts are single-threaded, so there is no concurrent
    // reader of the environment here.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }
    prost_build::compile_protos(&["proto/resp.proto"], &["proto/"]).unwrap();
}
