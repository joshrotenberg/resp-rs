#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use resp_rs::resp2::{frame_to_bytes, parse_frame};

fuzz_target!(|data: &[u8]| {
    let input = Bytes::copy_from_slice(data);
    if let Ok((frame, rest)) = parse_frame(input.clone()) {
        // Roundtrip: serialize and reparse.
        let serialized = frame_to_bytes(&frame);
        let (reparsed, remaining) = parse_frame(serialized).expect("roundtrip parse must succeed");
        assert_eq!(frame, reparsed, "roundtrip must produce identical frame");
        assert!(remaining.is_empty(), "roundtrip must consume all bytes");

        // Deterministic prefix: parsing the exact consumed prefix must produce
        // the same frame with no remainder.
        let consumed = input.len() - rest.len();
        let prefix = input.slice(..consumed);
        let (reparsed_prefix, rest2) = parse_frame(prefix).expect("prefix reparse must succeed");
        assert_eq!(
            frame, reparsed_prefix,
            "prefix must produce identical frame"
        );
        assert!(rest2.is_empty(), "prefix must be fully consumed");
    }
});
