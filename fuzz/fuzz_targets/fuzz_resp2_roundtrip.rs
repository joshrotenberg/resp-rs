#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use resp_rs::resp2::{frame_to_bytes, parse_frame};

fuzz_target!(|data: &[u8]| {
    let input = Bytes::copy_from_slice(data);
    if let Ok((frame, _)) = parse_frame(input) {
        let serialized = frame_to_bytes(&frame);
        let (reparsed, remaining) = parse_frame(serialized).expect("roundtrip parse must succeed");
        assert_eq!(frame, reparsed, "roundtrip must produce identical frame");
        assert!(remaining.is_empty(), "roundtrip must consume all bytes");
    }
});
