#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use resp_rs::{resp2, resp3};

// Safe versus unchecked is the one oracle axis in this crate empirically proven
// to find a real bug: issue #65, where `find_cr` stopped at a bare CR while
// `find_crlf` required the pair, so the unchecked path desynchronized on input
// the safe path had already validated.
//
// It was found by proptest, not here, because `fuzz/Cargo.toml` declared
// `resp-rs` with no `features` key, so `parse_frame_unchecked` was not compiled
// into any fuzz binary at all. The axis existed and was unreachable.
//
// The unchecked parsers are only defined on input the safe parser accepts, so
// every case is gated on a successful safe parse first. Feeding them anything
// else is undefined behavior, not a finding.

fuzz_target!(|input: &[u8]| {
    // First byte selects the protocol, the rest is the frame. Same shape as
    // fuzz_nesting, and it avoids pulling in arbitrary's derive feature.
    let Some((selector, data)) = input.split_first() else {
        return;
    };
    let bytes = Bytes::copy_from_slice(data);

    match selector % 2 {
        0 => {
            // The safe parse is the precondition, and its `rest` matters as
            // much as its frame: #65 was a disagreement about where the frame
            // ended, not about what it contained.
            let Ok((safe_frame, safe_rest)) = resp2::parse_frame(bytes.clone()) else {
                return;
            };
            // SAFETY: parse_frame just accepted this buffer, which is exactly
            // the contract parse_frame_unchecked documents.
            let (unchecked_frame, unchecked_rest) =
                unsafe { resp2::parse_frame_unchecked(bytes) };
            assert_eq!(safe_frame, unchecked_frame, "frames differ: {data:?}");
            assert_eq!(safe_rest, unchecked_rest, "consumed lengths differ: {data:?}");
        }
        _ => {
            let Ok((safe_frame, safe_rest)) = resp3::parse_frame(bytes.clone()) else {
                return;
            };
            // SAFETY: as above.
            let (unchecked_frame, unchecked_rest) =
                unsafe { resp3::parse_frame_unchecked(bytes) };
            assert_eq!(safe_frame, unchecked_frame, "frames differ: {data:?}");
            assert_eq!(safe_rest, unchecked_rest, "consumed lengths differ: {data:?}");
        }
    }
});
