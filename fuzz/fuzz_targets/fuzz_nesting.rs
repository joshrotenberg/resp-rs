#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use resp_rs::{ParseError, resp2, resp3};

// Nesting is generated directly rather than left to chance: the generic parse
// fuzzers will not stumble onto tens of thousands of repetitions of a 4-byte
// sequence on their own, which is how the unbounded recursion in issue #47
// went unnoticed.
//
// Depth comes from the first two bytes. The rest select aggregate tags so
// mixed nesting is covered, not just repeated arrays. Every generated input is
// well-formed, so parsing must either succeed or report DepthExceeded, and
// which one it is follows entirely from the depth.
fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let depth = u16::from_le_bytes([data[0], data[1]]) as usize;
    let tags = &data[2..];

    // RESP2: arrays are the only recursing type.
    let mut wire = String::with_capacity(depth * 4 + 5);
    for _ in 0..depth {
        wire.push_str("*1\r\n");
    }
    wire.push_str(":1\r\n");

    match resp2::parse_frame(Bytes::from(wire)) {
        Ok(_) => assert!(depth <= resp2::MAX_DEPTH as usize, "resp2 accepted {depth}"),
        Err(ParseError::DepthExceeded) => {
            assert!(depth > resp2::MAX_DEPTH as usize, "resp2 rejected {depth}")
        }
        Err(e) => panic!("resp2 depth {depth}: unexpected error {e:?}"),
    }

    // RESP3 tags that nest through a repeatable unit. Maps need a key before
    // the nested value, so their unit carries one.
    //
    // `|` is not here. An attribute carries metadata for the frame that follows
    // and is skipped where a frame is expected (issue #59), so a chain of
    // attributes never reaches a real frame and is not well-formed input. The
    // attribute depth path is parse_pairs, which `%` already exercises.
    let mut wire = String::new();
    for i in 0..depth {
        let tag = if tags.is_empty() {
            0
        } else {
            tags[i % tags.len()] % 4
        };
        wire.push_str(match tag {
            0 => "*1\r\n",
            1 => "~1\r\n",
            2 => ">1\r\n",
            _ => "%1\r\n+k\r\n",
        });
    }
    wire.push_str(":1\r\n");

    match resp3::parse_frame(Bytes::from(wire)) {
        Ok(_) => assert!(depth <= resp3::MAX_DEPTH as usize, "resp3 accepted {depth}"),
        Err(ParseError::DepthExceeded) => {
            assert!(depth > resp3::MAX_DEPTH as usize, "resp3 rejected {depth}")
        }
        Err(e) => panic!("resp3 depth {depth}: unexpected error {e:?}"),
    }
});
