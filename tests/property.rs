use bytes::Bytes;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Arbitrary frame generators
// ---------------------------------------------------------------------------

/// Generate a byte string that is safe for RESP simple strings / errors.
///
/// Only `\n` is excluded. A payload with no `\n` cannot contain `\r\n`, so it
/// cannot terminate its own line, which is the parser's constraint. A bare `\r`
/// is payload to the parser and is deliberately included: excluding it also
/// excluded the only byte on which the safe and unchecked parsers disagreed
/// (issue #65), so the equivalence properties were asserting equivalence over
/// an alphabet chosen to omit the counterexample. The checked serializer
/// refuses a bare `\r` (#99); the iff properties account for that with
/// `resp3_scrub` and `resp2_scrub`.
fn safe_line_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop::num::u8::ANY.prop_filter("no LF", |b| *b != b'\n'),
        0..128,
    )
}

/// Generate an arbitrary RESP2 frame (recursive for arrays).
fn arb_resp2_frame() -> impl Strategy<Value = resp_rs::resp2::Frame> {
    use resp_rs::resp2::Frame;

    let leaf = prop_oneof![
        safe_line_bytes().prop_map(|b| Frame::SimpleString(Bytes::from(b))),
        safe_line_bytes().prop_map(|b| Frame::Error(Bytes::from(b))),
        any::<i64>().prop_map(Frame::Integer),
        prop::option::of(prop::collection::vec(any::<u8>(), 0..256))
            .prop_map(|opt| Frame::BulkString(opt.map(Bytes::from))),
    ];

    leaf.prop_recursive(
        3,  // max depth
        64, // max nodes
        8,  // items per collection
        |inner| prop::option::of(prop::collection::vec(inner, 0..8)).prop_map(Frame::Array),
    )
}

/// Generate an arbitrary RESP3 frame (recursive for arrays/maps/sets/etc).
fn arb_resp3_frame() -> impl Strategy<Value = resp_rs::resp3::Frame> {
    use resp_rs::resp3::Frame;

    let leaf = prop_oneof![
        safe_line_bytes().prop_map(|b| Frame::SimpleString(Bytes::from(b))),
        safe_line_bytes().prop_map(|b| Frame::Error(Bytes::from(b))),
        any::<i64>().prop_map(Frame::Integer),
        prop::option::of(prop::collection::vec(any::<u8>(), 0..256))
            .prop_map(|opt| Frame::BulkString(opt.map(Bytes::from))),
        Just(Frame::Null),
        any::<bool>().prop_map(Frame::Boolean),
        // Use finite f64 only (NaN breaks PartialEq, special floats have separate repr)
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(Frame::Double),
        // A big number is an optional sign followed by one or more decimal
        // digits (issue #58). Generating arbitrary line bytes here would assert
        // a round trip the parser does not claim, since it now rejects payloads
        // that are not big numbers.
        (
            // `-` only: a `+` sign is rejected since #104.
            prop::option::of(Just('-')),
            prop::collection::vec(prop::num::u8::ANY.prop_map(|b| b'0' + b % 10), 1..40),
        )
            .prop_map(|(sign, digits)| {
                let mut s = String::new();
                if let Some(c) = sign {
                    s.push(c);
                }
                s.push_str(core::str::from_utf8(&digits).unwrap());
                Frame::BigNumber(Bytes::from(s))
            }),
        prop::collection::vec(any::<u8>(), 0..256).prop_map(|b| Frame::BlobError(Bytes::from(b))),
        // VerbatimString: 3-byte format tag + arbitrary content
        (
            prop::collection::vec(
                prop::num::u8::ANY.prop_filter("no colon/cr/lf", |b| {
                    *b != b':' && *b != b'\r' && *b != b'\n'
                }),
                3..=3,
            ),
            prop::collection::vec(any::<u8>(), 0..128),
        )
            .prop_map(|(fmt, content)| {
                // Payload is stored whole, so the generator assembles
                // `fmt:content` rather than the two halves.
                let mut payload = fmt;
                payload.push(b':');
                payload.extend_from_slice(&content);
                Frame::VerbatimString {
                    payload: Bytes::from(payload),
                }
            }),
    ];

    // Attribute is deliberately absent from the recursive branch. An attribute
    // carries metadata for the frame that follows and does not occupy an
    // element slot, so the parser skips it inside an aggregate (issue #59).
    // A Frame::Attribute sitting in an aggregate's Vec is therefore not a
    // structure the parser can produce, and serializing one emits wire bytes
    // that mean something different on the way back. Generating it here would
    // assert a roundtrip that is not claimed.
    let nested = leaf.prop_recursive(
        3,  // max depth
        64, // max nodes
        6,  // items per collection
        |inner| {
            prop_oneof![
                // Array
                prop::option::of(prop::collection::vec(inner.clone(), 0..6)).prop_map(Frame::Array),
                // Set
                prop::collection::vec(inner.clone(), 0..6).prop_map(Frame::Set),
                // Map
                prop::collection::vec((inner.clone(), inner.clone()), 0..4).prop_map(Frame::Map),
                // Push
                prop::collection::vec(inner, 0..6).prop_map(Frame::Push),
            ]
        },
    );

    // Attributes are still covered, in the one position where they round-trip:
    // standing alone, which is where a real peer sends them.
    prop_oneof![
        9 => nested.clone(),
        1 => prop::collection::vec((nested.clone(), nested), 0..4).prop_map(Frame::Attribute),
    ]
}

/// The six frames only `parse_streaming_sequence` produces, at the top level or
/// inside another streamed aggregate. Mirrors `resp3::is_assembled_streaming`.
fn is_assembled_streaming(frame: &resp_rs::resp3::Frame) -> bool {
    use resp_rs::resp3::Frame;
    matches!(
        frame,
        Frame::StreamedString(_)
            | Frame::StreamedArray(_)
            | Frame::StreamedSet(_)
            | Frame::StreamedMap(_)
            | Frame::StreamedAttribute(_)
            | Frame::StreamedPush(_)
    )
}

/// Replace each `\r` and `\n` in a line payload with a space, as Redis does,
/// and report whether any were found.
fn scrub_line(b: &Bytes, found: &mut bool) -> Bytes {
    if b.iter().any(|&c| c == b'\r' || c == b'\n') {
        *found = true;
        b.iter()
            .map(|&c| if c == b'\r' || c == b'\n' { b' ' } else { c })
            .collect::<Vec<u8>>()
            .into()
    } else {
        b.clone()
    }
}

/// Scrub every simple string and error in the frame with [`scrub_line`].
///
/// A bare CR or LF in those payloads round-trips through this crate's parser
/// but `try_frame_to_bytes` refuses it, because the specs forbid it and hiredis
/// rejects it (#99). The iff properties assert that refusal, then check the
/// scrubbed frame, so the exception does not hide any other rule in the same
/// frame. The match is exhaustive so a new variant has to be placed here.
fn resp3_scrub(frame: &resp_rs::resp3::Frame, found: &mut bool) -> resp_rs::resp3::Frame {
    use resp_rs::resp3::Frame;
    let items = |v: &Vec<Frame>, found: &mut bool| -> Vec<Frame> {
        v.iter().map(|f| resp3_scrub(f, found)).collect()
    };
    let pairs = |v: &Vec<(Frame, Frame)>, found: &mut bool| -> Vec<(Frame, Frame)> {
        v.iter()
            .map(|(k, val)| (resp3_scrub(k, found), resp3_scrub(val, found)))
            .collect()
    };
    match frame {
        Frame::SimpleString(b) => Frame::SimpleString(scrub_line(b, found)),
        Frame::Error(b) => Frame::Error(scrub_line(b, found)),
        Frame::Array(Some(v)) => Frame::Array(Some(items(v, found))),
        Frame::Set(v) => Frame::Set(items(v, found)),
        Frame::Push(v) => Frame::Push(items(v, found)),
        Frame::StreamedArray(v) => Frame::StreamedArray(items(v, found)),
        Frame::StreamedSet(v) => Frame::StreamedSet(items(v, found)),
        Frame::StreamedPush(v) => Frame::StreamedPush(items(v, found)),
        Frame::Map(v) => Frame::Map(pairs(v, found)),
        Frame::Attribute(v) => Frame::Attribute(pairs(v, found)),
        Frame::StreamedMap(v) => Frame::StreamedMap(pairs(v, found)),
        Frame::StreamedAttribute(v) => Frame::StreamedAttribute(pairs(v, found)),
        // No line payload: typed values, length-prefixed bodies and fixed tokens.
        Frame::Array(None)
        | Frame::Integer(_)
        | Frame::BulkString(_)
        | Frame::BlobError(_)
        | Frame::StreamedStringHeader
        | Frame::StreamedBlobErrorHeader
        | Frame::StreamedVerbatimStringHeader
        | Frame::StreamedArrayHeader
        | Frame::StreamedSetHeader
        | Frame::StreamedMapHeader
        | Frame::StreamedAttributeHeader
        | Frame::StreamedPushHeader
        | Frame::StreamedStringChunk(_)
        | Frame::StreamedString(_)
        | Frame::StreamTerminator
        | Frame::Null
        | Frame::Double(_)
        | Frame::SpecialFloat(_)
        | Frame::Boolean(_)
        | Frame::BigNumber(_)
        | Frame::VerbatimString { .. } => frame.clone(),
    }
}

/// RESP2 counterpart of [`resp3_scrub`].
fn resp2_scrub(frame: &resp_rs::resp2::Frame, found: &mut bool) -> resp_rs::resp2::Frame {
    use resp_rs::resp2::Frame;
    match frame {
        Frame::SimpleString(b) => Frame::SimpleString(scrub_line(b, found)),
        Frame::Error(b) => Frame::Error(scrub_line(b, found)),
        Frame::Array(Some(v)) => {
            Frame::Array(Some(v.iter().map(|f| resp2_scrub(f, found)).collect()))
        }
        Frame::Array(None) | Frame::Integer(_) | Frame::BulkString(_) => frame.clone(),
    }
}

/// Whether the frame round-trips through the reader it actually has.
///
/// Assembled streaming frames are read back by parse_streaming_sequence, never
/// by parse_frame, which sees only their bare header and leaves the body
/// behind. Using parse_frame for them would assert that they can never be
/// serialized, which is not what the crate claims: the top level is exactly
/// where they are legitimate.
fn resp3_round_trips(frame: &resp_rs::resp3::Frame) -> bool {
    let bytes = resp_rs::resp3::frame_to_bytes(frame);
    let parsed = if is_assembled_streaming(frame) {
        resp_rs::resp3::parse_streaming_sequence(bytes)
    } else {
        resp_rs::resp3::parse_frame(bytes)
    };
    matches!(parsed, Ok((p, rest)) if &p == frame && rest.is_empty())
}

fn resp2_round_trips(frame: &resp_rs::resp2::Frame) -> bool {
    matches!(
        resp_rs::resp2::parse_frame(resp_rs::resp2::frame_to_bytes(frame)),
        Ok((p, rest)) if &p == frame && rest.is_empty()
    )
}

/// Frames including shapes that deliberately may NOT round-trip.
///
/// `arb_resp3_frame` is the round-trippable set, and several tests depend on
/// that, so the questionable shapes live here instead. Only the iff property
/// consumes this, because it is the one assertion that accepts either outcome
/// and decides which is correct by construction.
///
/// These are the positions the old generator could not reach, which is why the
/// iff property held while issues #82 through #85 were live. The property was
/// right; the generator could not produce a counterexample.
fn arb_resp3_frame_any() -> impl Strategy<Value = resp_rs::resp3::Frame> {
    use resp_rs::resp3::Frame;

    let element = prop_oneof![
        8 => arb_resp3_frame(),
        // Terminates a streamed container in place, but is an ordinary element
        // inside a counted one (#84). The opposite rule to Attribute, which is
        // why one shared check produced an immediate counterexample.
        1 => Just(Frame::StreamTerminator),
        // Only parse_streaming_sequence produces these. Inside a counted
        // aggregate they read back as a bare header with the body left over
        // (#83); inside a streamed one they are assembled and round-trip (#97).
        1 => Just(Frame::StreamedString(vec![Bytes::from_static(b"abc")])),
        1 => Just(Frame::StreamedArray(vec![Frame::Integer(1)])),
        // A bare streamed header: an ordinary element of a counted aggregate,
        // but inside a streamed one the parser reads its body (#97).
        1 => Just(Frame::StreamedArrayHeader),
        // Skipped by the parser inside a streamed aggregate, like a counted
        // attribute (#98).
        1 => Just(Frame::StreamedAttribute(vec![])),
        1 => Just(Frame::StreamedAttribute(vec![(Frame::Integer(1), Frame::Null)])),
        // Pass through unchanged inside a streamed aggregate: a chunk is an
        // ordinary element there, and RESP3 defines no body for `=?` or `!?`.
        1 => Just(Frame::StreamedStringChunk(Bytes::from_static(b"abc"))),
        1 => Just(Frame::StreamedVerbatimStringHeader),
        1 => Just(Frame::StreamedBlobErrorHeader),
        // Nesting more than one level, and the remaining streamed kinds.
        1 => Just(Frame::StreamedSet(vec![Frame::StreamedPush(vec![Frame::Integer(1)])])),
        // The over-length case for #82 is deliberately NOT here. It found the
        // bug, but a 64 KB payload allocated on every generated case is a real
        // cost, and it shrinks to a 65 KB literal in the regressions file. The
        // boundary is a fixed constant, so it is pinned by a deterministic test
        // instead: tests/resp3.rs::line_payload_over_the_ceiling_is_refused.
        // CRLF inside a line payload, which the checked path catches at top
        // level but skipped inside streamed aggregates (#85).
        1 => Just(Frame::SimpleString(Bytes::from_static(b"sp\r\nlit"))),
        // A bare LF, which safe_line_bytes never produces (#99).
        1 => Just(Frame::Error(Bytes::from_static(b"ERR a\nb"))),
    ];

    prop_oneof![
        8 => arb_resp3_frame(),
        // Counted aggregates carrying the questionable elements.
        2 => prop::collection::vec(element.clone(), 0..4).prop_map(|v| Frame::Array(Some(v))),
        2 => prop::collection::vec(element.clone(), 0..4).prop_map(Frame::Push),
        // Streamed aggregates, whose contents bypassed every per-frame check
        // through the catch-all arm (#85).
        2 => prop::collection::vec(element.clone(), 0..4).prop_map(Frame::StreamedArray),
        2 => prop::collection::vec(element.clone(), 0..4).prop_map(Frame::StreamedSet),
        2 => prop::collection::vec(element.clone(), 0..4).prop_map(Frame::StreamedPush),
        2 => prop::collection::vec((element.clone(), element.clone()), 0..3)
                .prop_map(Frame::StreamedMap),
        2 => prop::collection::vec((element.clone(), element), 0..3)
                .prop_map(Frame::StreamedAttribute),
    ]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Split a byte slice into variable-size chunks using split_points as guides.
fn split_into_chunks(data: &[u8], split_points: &[usize]) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return vec![vec![]];
    }
    let mut chunks = Vec::new();
    let mut pos = 0;
    for &sp in split_points {
        if pos >= data.len() {
            break;
        }
        let step = (sp % 16) + 1; // 1..=16 byte chunks
        let end = (pos + step).min(data.len());
        chunks.push(data[pos..end].to_vec());
        pos = end;
    }
    if pos < data.len() {
        chunks.push(data[pos..].to_vec());
    }
    chunks
}

// ---------------------------------------------------------------------------
// RESP2 property tests
// ---------------------------------------------------------------------------

proptest! {
    /// Roundtrip: for any valid RESP2 frame, serialize then parse should yield
    /// the identical frame with no remaining bytes.
    #[test]
    fn resp2_roundtrip(frame in arb_resp2_frame()) {
        let wire = resp_rs::resp2::frame_to_bytes(&frame);
        let (parsed, rest) = resp_rs::resp2::parse_frame(wire).unwrap();
        prop_assert_eq!(&parsed, &frame);
        prop_assert!(rest.is_empty(), "leftover bytes: {:?}", rest);
    }

    /// Arbitrary bytes should never cause a panic -- only Ok or Err.
    #[test]
    fn resp2_no_panic(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = resp_rs::resp2::parse_frame(Bytes::from(data));
    }

    /// If parse succeeds consuming some prefix, re-parsing that exact prefix
    /// should produce the same result.
    #[test]
    fn resp2_deterministic(data in prop::collection::vec(any::<u8>(), 1..512)) {
        let input = Bytes::from(data);
        if let Ok((frame1, rest1)) = resp_rs::resp2::parse_frame(input.clone()) {
            let consumed = input.len() - rest1.len();
            let prefix = input.slice(..consumed);
            let (frame2, rest2) = resp_rs::resp2::parse_frame(prefix).unwrap();
            prop_assert_eq!(frame1, frame2);
            prop_assert!(rest2.is_empty());
        }
    }

    /// Concatenating serialized frames produces parseable pipelined data.
    #[test]
    fn resp2_pipeline(
        frames in prop::collection::vec(arb_resp2_frame(), 1..8)
    ) {
        let mut wire = Vec::new();
        for f in &frames {
            wire.extend_from_slice(&resp_rs::resp2::frame_to_bytes(f));
        }
        let mut input = Bytes::from(wire);
        for expected in &frames {
            let (parsed, rest) = resp_rs::resp2::parse_frame(input).unwrap();
            prop_assert_eq!(&parsed, expected);
            input = rest;
        }
        prop_assert!(input.is_empty());
    }

    /// The streaming parser should produce the same frames as direct parsing.
    #[test]
    fn resp2_streaming_matches_direct(frame in arb_resp2_frame()) {
        let wire = resp_rs::resp2::frame_to_bytes(&frame);

        let mut parser = resp_rs::resp2::Parser::new();
        parser.feed(wire);
        let parsed = parser.next_frame().unwrap().unwrap();
        prop_assert_eq!(&parsed, &frame);
        prop_assert!(parser.next_frame().unwrap().is_none());
    }

    /// Chunked pipeline: serialize N frames, split into arbitrary chunks,
    /// feed chunk-by-chunk to Parser, and assert output equals original frames.
    #[test]
    fn resp2_chunked_pipeline(
        frames in prop::collection::vec(arb_resp2_frame(), 1..8),
        split_points in prop::collection::vec(0usize..256, 1..32),
    ) {
        let mut wire = Vec::new();
        for f in &frames {
            wire.extend_from_slice(&resp_rs::resp2::frame_to_bytes(f));
        }

        let chunks = split_into_chunks(&wire, &split_points);

        let mut parser = resp_rs::resp2::Parser::new();
        let mut out = Vec::new();

        for chunk in chunks {
            parser.feed(Bytes::from(chunk));
            while let Some(frame) = parser.next_frame().unwrap() {
                out.push(frame);
            }
        }

        prop_assert_eq!(&out, &frames);
    }

    /// Parser clears buffer on hard error and can recover.
    #[test]
    fn resp2_parser_error_clears_buffer(
        garbage in prop::collection::vec(
            prop::num::u8::ANY.prop_filter("not a valid tag", |b| {
                !matches!(b, b'+' | b'-' | b':' | b'$' | b'*')
            }),
            1..64,
        ),
    ) {
        let mut input = garbage;
        // Ensure it ends with \r\n so the parser can find a line
        input.extend_from_slice(b"\r\n");

        let mut parser = resp_rs::resp2::Parser::new();
        parser.feed(Bytes::from(input));

        match parser.next_frame() {
            Err(_) => {
                prop_assert_eq!(parser.buffered_bytes(), 0);
            }
            Ok(None) => {} // incomplete is fine
            Ok(Some(_)) => {} // happened to parse something
        }
    }
}

// ---------------------------------------------------------------------------
// RESP3 property tests
// ---------------------------------------------------------------------------

proptest! {
    /// Roundtrip: for any valid RESP3 frame, serialize then parse should yield
    /// the identical frame with no remaining bytes.
    #[test]
    fn resp3_roundtrip(frame in arb_resp3_frame()) {
        let wire = resp_rs::resp3::frame_to_bytes(&frame);
        let (parsed, rest) = resp_rs::resp3::parse_frame(wire).unwrap();
        prop_assert_eq!(&parsed, &frame);
        prop_assert!(rest.is_empty(), "leftover bytes: {:?}", rest);
    }

    /// Arbitrary bytes should never cause a panic -- only Ok or Err.
    #[test]
    fn resp3_no_panic(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = resp_rs::resp3::parse_frame(Bytes::from(data));
    }

    /// If parse succeeds consuming some prefix, re-parsing that exact prefix
    /// should produce the same result.
    #[test]
    fn resp3_deterministic(data in prop::collection::vec(any::<u8>(), 1..512)) {
        let input = Bytes::from(data);
        if let Ok((frame1, rest1)) = resp_rs::resp3::parse_frame(input.clone()) {
            let consumed = input.len() - rest1.len();
            let prefix = input.slice(..consumed);
            let (frame2, rest2) = resp_rs::resp3::parse_frame(prefix).unwrap();
            prop_assert_eq!(frame1, frame2);
            prop_assert!(rest2.is_empty());
        }
    }

    /// Concatenating serialized frames produces parseable pipelined data.
    #[test]
    fn resp3_pipeline(
        frames in prop::collection::vec(arb_resp3_frame(), 1..8)
    ) {
        let mut wire = Vec::new();
        for f in &frames {
            wire.extend_from_slice(&resp_rs::resp3::frame_to_bytes(f));
        }
        let mut input = Bytes::from(wire);
        for expected in &frames {
            let (parsed, rest) = resp_rs::resp3::parse_frame(input).unwrap();
            prop_assert_eq!(&parsed, expected);
            input = rest;
        }
        prop_assert!(input.is_empty());
    }

    /// The streaming parser should produce the same frames as direct parsing.
    #[test]
    fn resp3_streaming_matches_direct(frame in arb_resp3_frame()) {
        let wire = resp_rs::resp3::frame_to_bytes(&frame);

        let mut parser = resp_rs::resp3::Parser::new();
        parser.feed(wire);
        let parsed = parser.next_frame().unwrap().unwrap();
        prop_assert_eq!(&parsed, &frame);
        prop_assert!(parser.next_frame().unwrap().is_none());
    }

    /// Chunked pipeline: serialize N frames, split into arbitrary chunks,
    /// feed chunk-by-chunk to Parser, and assert output equals original frames.
    #[test]
    fn resp3_chunked_pipeline(
        frames in prop::collection::vec(arb_resp3_frame(), 1..8),
        split_points in prop::collection::vec(0usize..256, 1..32),
    ) {
        let mut wire = Vec::new();
        for f in &frames {
            wire.extend_from_slice(&resp_rs::resp3::frame_to_bytes(f));
        }

        let chunks = split_into_chunks(&wire, &split_points);

        let mut parser = resp_rs::resp3::Parser::new();
        let mut out = Vec::new();

        for chunk in chunks {
            parser.feed(Bytes::from(chunk));
            while let Some(frame) = parser.next_frame().unwrap() {
                out.push(frame);
            }
        }

        prop_assert_eq!(&out, &frames);
    }

    /// Parser clears buffer on hard error.
    #[test]
    fn resp3_parser_error_clears_buffer(
        garbage in prop::collection::vec(
            prop::num::u8::ANY.prop_filter("not a valid tag", |b| {
                !matches!(b, b'+' | b'-' | b':' | b'$' | b'*' | b'_' | b',' |
                             b'#' | b'(' | b'=' | b'!' | b'~' | b'%' | b'|' |
                             b'>' | b';' | b'.')
            }),
            1..64,
        ),
    ) {
        let mut input = garbage;
        input.extend_from_slice(b"\r\n");

        let mut parser = resp_rs::resp3::Parser::new();
        parser.feed(Bytes::from(input));

        match parser.next_frame() {
            Err(_) => {
                prop_assert_eq!(parser.buffered_bytes(), 0);
            }
            Ok(None) => {}
            Ok(Some(_)) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Arbitrary streaming frame generator
// ---------------------------------------------------------------------------

/// Generate an arbitrary accumulated RESP3 streaming frame.
fn arb_resp3_streaming_frame() -> impl Strategy<Value = resp_rs::resp3::Frame> {
    use resp_rs::resp3::Frame;

    // Non-streaming leaf for use inside streaming containers
    let inner_leaf = prop_oneof![
        safe_line_bytes().prop_map(|b| Frame::SimpleString(Bytes::from(b))),
        safe_line_bytes().prop_map(|b| Frame::Error(Bytes::from(b))),
        any::<i64>().prop_map(Frame::Integer),
        prop::option::of(prop::collection::vec(any::<u8>(), 0..64))
            .prop_map(|opt| Frame::BulkString(opt.map(Bytes::from))),
        Just(Frame::Null),
        any::<bool>().prop_map(Frame::Boolean),
    ];

    // Streamed values nested directly in a streamed aggregate are assembled by
    // parse_streaming_sequence (#97), so they belong in the round-trip set.
    let nested_streamed = prop_oneof![
        prop::collection::vec(
            prop::collection::vec(any::<u8>(), 1..16).prop_map(Bytes::from),
            0..3,
        )
        .prop_map(Frame::StreamedString),
        prop::collection::vec(inner_leaf.clone(), 0..3).prop_map(Frame::StreamedArray),
        prop::collection::vec((inner_leaf.clone(), inner_leaf.clone()), 0..2)
            .prop_map(Frame::StreamedMap),
    ];
    let element = prop_oneof![4 => inner_leaf.clone(), 1 => nested_streamed];

    prop_oneof![
        // StreamedString
        prop::collection::vec(
            prop::collection::vec(any::<u8>(), 1..64).prop_map(Bytes::from),
            0..6,
        )
        .prop_map(Frame::StreamedString),
        // Streamed aggregates holding streamed values
        prop::collection::vec(element.clone(), 0..6).prop_map(Frame::StreamedArray),
        prop::collection::vec((element.clone(), element), 0..4).prop_map(Frame::StreamedMap),
        // StreamedArray
        prop::collection::vec(inner_leaf.clone(), 0..6).prop_map(Frame::StreamedArray),
        // StreamedSet
        prop::collection::vec(inner_leaf.clone(), 0..6).prop_map(Frame::StreamedSet),
        // StreamedMap
        prop::collection::vec((inner_leaf.clone(), inner_leaf.clone()), 0..4)
            .prop_map(Frame::StreamedMap),
        // StreamedAttribute
        prop::collection::vec((inner_leaf.clone(), inner_leaf.clone()), 0..4)
            .prop_map(Frame::StreamedAttribute),
        // StreamedPush
        prop::collection::vec(inner_leaf, 0..6).prop_map(Frame::StreamedPush),
    ]
}

// ---------------------------------------------------------------------------
// RESP3 streaming property tests
// ---------------------------------------------------------------------------

proptest! {
    /// Roundtrip for accumulated streaming frames via parse_streaming_sequence.
    #[test]
    fn resp3_streaming_roundtrip(frame in arb_resp3_streaming_frame()) {
        let wire = resp_rs::resp3::frame_to_bytes(&frame);
        let (parsed, rest) = resp_rs::resp3::parse_streaming_sequence(wire).unwrap();
        prop_assert_eq!(&parsed, &frame);
        prop_assert!(rest.is_empty(), "leftover bytes: {:?}", rest);
    }

    /// Chunked pipeline for streaming frames.
    #[test]
    fn resp3_streaming_chunked_roundtrip(
        frame in arb_resp3_streaming_frame(),
        split_points in prop::collection::vec(0usize..256, 1..32),
    ) {
        let wire = resp_rs::resp3::frame_to_bytes(&frame);
        let wire_bytes = wire.to_vec();
        let chunks = split_into_chunks(&wire_bytes, &split_points);

        // Feed all chunks then parse the accumulated buffer
        let mut buf = Vec::new();
        for chunk in chunks {
            buf.extend_from_slice(&chunk);
        }
        let (parsed, rest) = resp_rs::resp3::parse_streaming_sequence(Bytes::from(buf)).unwrap();
        prop_assert_eq!(&parsed, &frame);
        prop_assert!(rest.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Malformed-wire property tests
// ---------------------------------------------------------------------------

proptest! {
    /// Mutating a single byte in a valid RESP2 frame should either still parse
    /// or return an error, never panic.
    #[test]
    fn resp2_mutated_frame_no_panic(
        frame in arb_resp2_frame(),
        flip_pos in any::<prop::sample::Index>(),
        flip_byte in any::<u8>(),
    ) {
        let mut wire = resp_rs::resp2::frame_to_bytes(&frame).to_vec();
        if !wire.is_empty() {
            let idx = flip_pos.index(wire.len());
            wire[idx] = flip_byte;
        }
        let _ = resp_rs::resp2::parse_frame(Bytes::from(wire));
    }

    /// Mutating a single byte in a valid RESP3 frame should either still parse
    /// or return an error, never panic.
    #[test]
    fn resp3_mutated_frame_no_panic(
        frame in arb_resp3_frame(),
        flip_pos in any::<prop::sample::Index>(),
        flip_byte in any::<u8>(),
    ) {
        let mut wire = resp_rs::resp3::frame_to_bytes(&frame).to_vec();
        if !wire.is_empty() {
            let idx = flip_pos.index(wire.len());
            wire[idx] = flip_byte;
        }
        let _ = resp_rs::resp3::parse_frame(Bytes::from(wire));
    }

    /// Truncating a valid RESP2 frame should return Incomplete or error, never panic.
    #[test]
    fn resp2_truncated_frame_no_panic(
        frame in arb_resp2_frame(),
        truncate_at in any::<prop::sample::Index>(),
    ) {
        let wire = resp_rs::resp2::frame_to_bytes(&frame);
        if wire.len() > 1 {
            let idx = truncate_at.index(wire.len() - 1) + 1; // at least 1 byte
            let truncated = wire.slice(..idx);
            let _ = resp_rs::resp2::parse_frame(truncated);
        }
    }

    /// Truncating a valid RESP3 frame should return Incomplete or error, never panic.
    #[test]
    fn resp3_truncated_frame_no_panic(
        frame in arb_resp3_frame(),
        truncate_at in any::<prop::sample::Index>(),
    ) {
        let wire = resp_rs::resp3::frame_to_bytes(&frame);
        if wire.len() > 1 {
            let idx = truncate_at.index(wire.len() - 1) + 1;
            let truncated = wire.slice(..idx);
            let _ = resp_rs::resp3::parse_frame(truncated);
        }
    }
}

// ---------------------------------------------------------------------------
// Unchecked parser property tests (feature = "unsafe-internals")
// ---------------------------------------------------------------------------

#[cfg(feature = "unsafe-internals")]
proptest! {
    /// Unchecked RESP2 parser must produce identical output to safe parser.
    #[test]
    fn resp2_unchecked_matches_safe(frame in arb_resp2_frame()) {
        let wire = resp_rs::resp2::frame_to_bytes(&frame);
        let (safe_frame, safe_rest) = resp_rs::resp2::parse_frame(wire.clone()).unwrap();
        let (unsafe_frame, unsafe_rest) = unsafe {
            resp_rs::resp2::parse_frame_unchecked(wire)
        };
        prop_assert_eq!(safe_frame, unsafe_frame);
        prop_assert_eq!(safe_rest, unsafe_rest);
    }

    /// Unchecked RESP3 parser must produce identical output to safe parser.
    #[test]
    fn resp3_unchecked_matches_safe(frame in arb_resp3_frame()) {
        let wire = resp_rs::resp3::frame_to_bytes(&frame);
        let (safe_frame, safe_rest) = resp_rs::resp3::parse_frame(wire.clone()).unwrap();
        let (unsafe_frame, unsafe_rest) = unsafe {
            resp_rs::resp3::parse_frame_unchecked(wire)
        };
        prop_assert_eq!(safe_frame, unsafe_frame);
        prop_assert_eq!(safe_rest, unsafe_rest);
    }

    /// Unchecked RESP2 pipeline must match safe pipeline.
    #[test]
    fn resp2_unchecked_pipeline(
        frames in prop::collection::vec(arb_resp2_frame(), 1..8)
    ) {
        let mut wire = Vec::new();
        for f in &frames {
            wire.extend_from_slice(&resp_rs::resp2::frame_to_bytes(f));
        }
        let mut input = Bytes::from(wire);
        for expected in &frames {
            let (frame, rest) = unsafe {
                resp_rs::resp2::parse_frame_unchecked(input)
            };
            prop_assert_eq!(&frame, expected);
            input = rest;
        }
        prop_assert!(input.is_empty());
    }

    /// Unchecked RESP3 pipeline must match safe pipeline.
    #[test]
    fn resp3_unchecked_pipeline(
        frames in prop::collection::vec(arb_resp3_frame(), 1..8)
    ) {
        let mut wire = Vec::new();
        for f in &frames {
            wire.extend_from_slice(&resp_rs::resp3::frame_to_bytes(f));
        }
        let mut input = Bytes::from(wire);
        for expected in &frames {
            let (frame, rest) = unsafe {
                resp_rs::resp3::parse_frame_unchecked(input)
            };
            prop_assert_eq!(&frame, expected);
            input = rest;
        }
        prop_assert!(input.is_empty());
    }

    /// Unchecked RESP3 streaming frames must match safe parser.
    #[test]
    fn resp3_unchecked_streaming_matches_safe(frame in arb_resp3_streaming_frame()) {
        let wire = resp_rs::resp3::frame_to_bytes(&frame);

        // parse_streaming_sequence uses parse_frame internally, but the
        // individual frame parsing should match. Test the header + first frame.
        let (safe_frame, safe_rest) = resp_rs::resp3::parse_frame(wire.clone()).unwrap();
        let (unsafe_frame, unsafe_rest) = unsafe {
            resp_rs::resp3::parse_frame_unchecked(wire)
        };
        prop_assert_eq!(safe_frame, unsafe_frame);
        prop_assert_eq!(safe_rest, unsafe_rest);
    }
}

// ---------------------------------------------------------------------------
// Checked serialization (issue #60)
// ---------------------------------------------------------------------------

/// Generate frames that are deliberately NOT representable on the wire, one per
/// rule, so the property is exercised from both sides.
fn arb_invalid_resp3_frame() -> impl Strategy<Value = resp_rs::resp3::Frame> {
    use resp_rs::resp3::Frame;
    prop_oneof![
        // CRLF inside a line payload splits the frame.
        Just(Frame::SimpleString(Bytes::from(&b"a\r\nb"[..]))),
        Just(Frame::Error(Bytes::from(&b"ERR x\r\n+OK"[..]))),
        // Big numbers are digit-strict since #67.
        Just(Frame::BigNumber(Bytes::from(&b"abc"[..]))),
        Just(Frame::BigNumber(Bytes::new())),
        Just(Frame::BigNumber(Bytes::from(&b"1.5"[..]))),
        // A `+` sign, rejected since #104.
        Just(Frame::BigNumber(Bytes::from(&b"+123"[..]))),
        // SpecialFloat is exactly these three spellings; anything else
        // normalizes to a Double on the way back.
        Just(Frame::SpecialFloat(Bytes::from(&b"1.5"[..]))),
        Just(Frame::SpecialFloat(Bytes::from(&b"INF"[..]))),
        // Non-finite doubles come back as SpecialFloat, changing type.
        Just(Frame::Double(f64::NAN)),
        Just(Frame::Double(f64::INFINITY)),
        Just(Frame::Double(f64::NEG_INFINITY)),
        // The parser requires the verbatim separator at index 3 exactly. The
        // single-payload representation relabels these rather than removing
        // them: each is still constructible and still does not round-trip.
        Just(Frame::VerbatimString {
            payload: Bytes::from(&b"text:x"[..]),
        }),
        Just(Frame::VerbatimString {
            payload: Bytes::from(&b"ab:x"[..]),
        }),
        Just(Frame::VerbatimString {
            payload: Bytes::from(&b":x"[..]),
        }),
        Just(Frame::VerbatimString {
            payload: Bytes::from(&b"a:b:x"[..]),
        }),
        // No separator at all, which the split form could not express.
        Just(Frame::VerbatimString {
            payload: Bytes::from(&b"txt"[..]),
        }),
        // An empty chunk is the end-of-stream marker.
        Just(Frame::StreamedString(vec![
            Bytes::from(&b"a"[..]),
            Bytes::new(),
            Bytes::from(&b"b"[..]),
        ])),
        // An attribute does not occupy an element slot (#59).
        Just(Frame::Array(Some(vec![Frame::Attribute(vec![])]))),
        Just(Frame::Set(vec![Frame::Attribute(vec![])])),
        Just(Frame::Map(vec![(
            Frame::Attribute(vec![]),
            Frame::Integer(1)
        )])),
    ]
}

proptest! {
    /// The specification: checked serialization succeeds exactly when the bytes
    /// parse back to an identical frame with nothing left over.
    ///
    /// Stated as an iff so it cannot go stale the way a rule list does. A parse
    /// arm tightening without a matching serializer rule breaks this
    /// immediately, which is how #67 opened the BigNumber gap unnoticed.
    #[test]
    fn resp3_checked_serialization_iff_roundtrip(frame in arb_resp3_frame_any()) {
        // The one deliberate exception (#99): a bare CR or LF in a line payload
        // is refused even where it round-trips. Assert that, then hold the
        // scrubbed frame to the iff so every other rule is still checked.
        let mut found = false;
        let scrubbed = resp3_scrub(&frame, &mut found);
        if found {
            prop_assert!(
                resp_rs::resp3::try_frame_to_bytes(&frame).is_err(),
                "CR or LF in a line payload was accepted: {:?}",
                frame
            );
        }
        prop_assert_eq!(
            resp_rs::resp3::try_frame_to_bytes(&scrubbed).is_ok(),
            resp3_round_trips(&scrubbed),
            "checked serialization disagreed with round trip for {:?}",
            scrubbed
        );
    }

    #[test]
    fn resp2_checked_serialization_iff_roundtrip(
        frame in prop_oneof![
            9 => arb_resp2_frame(),
            // safe_line_bytes never produces a bare LF.
            1 => Just(resp_rs::resp2::Frame::Error(Bytes::from_static(b"ERR a\nb"))),
        ]
    ) {
        let mut found = false;
        let scrubbed = resp2_scrub(&frame, &mut found);
        if found {
            prop_assert!(
                resp_rs::resp2::try_frame_to_bytes(&frame).is_err(),
                "CR or LF in a line payload was accepted: {:?}",
                frame
            );
        }
        prop_assert_eq!(
            resp_rs::resp2::try_frame_to_bytes(&scrubbed).is_ok(),
            resp2_round_trips(&scrubbed),
            "checked serialization disagreed with round trip for {:?}",
            scrubbed
        );
    }

    /// Same property from the other side: every frame that is deliberately
    /// unrepresentable must be refused, and must genuinely fail to round trip.
    #[test]
    fn resp3_invalid_frames_are_refused(frame in arb_invalid_resp3_frame()) {
        let round_trips = match resp_rs::resp3::parse_frame(
            resp_rs::resp3::frame_to_bytes(&frame),
        ) {
            Ok((parsed, rest)) => parsed == frame && rest.is_empty(),
            Err(_) => false,
        };
        prop_assert!(!round_trips, "expected {:?} not to round trip", frame);
        prop_assert!(
            resp_rs::resp3::try_frame_to_bytes(&frame).is_err(),
            "expected {:?} to be refused",
            frame
        );
    }

    /// A checked serialization that succeeds must produce exactly the same
    /// bytes as the unchecked one, so the two paths cannot drift.
    #[test]
    fn resp3_checked_and_unchecked_agree_when_valid(frame in arb_resp3_frame()) {
        if let Ok(checked) = resp_rs::resp3::try_frame_to_bytes(&frame) {
            prop_assert_eq!(checked, resp_rs::resp3::frame_to_bytes(&frame));
        }
    }
}
