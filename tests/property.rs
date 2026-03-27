use bytes::Bytes;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Arbitrary frame generators
// ---------------------------------------------------------------------------

/// Generate a byte string that is safe for RESP simple strings / errors
/// (no \r or \n characters).
fn safe_line_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop::num::u8::ANY.prop_filter("no CR/LF", |b| *b != b'\r' && *b != b'\n'),
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
        safe_line_bytes().prop_map(|b| Frame::BigNumber(Bytes::from(b))),
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
                Frame::VerbatimString(Bytes::from(fmt), Bytes::from(content))
            }),
    ];

    leaf.prop_recursive(
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
                // Attribute
                prop::collection::vec((inner.clone(), inner.clone()), 0..4)
                    .prop_map(Frame::Attribute),
                // Push
                prop::collection::vec(inner, 0..6).prop_map(Frame::Push),
            ]
        },
    )
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

    prop_oneof![
        // StreamedString
        prop::collection::vec(
            prop::collection::vec(any::<u8>(), 1..64).prop_map(Bytes::from),
            0..6,
        )
        .prop_map(Frame::StreamedString),
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
