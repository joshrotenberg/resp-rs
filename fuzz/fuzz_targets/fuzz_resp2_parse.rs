#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = Bytes::copy_from_slice(data);
    let _ = resp_rs::resp2::parse_frame(input);
});
