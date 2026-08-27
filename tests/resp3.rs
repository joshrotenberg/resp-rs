#![allow(clippy::approx_constant)]

use bytes::Bytes;
use resp_rs::ParseError;
use resp_rs::resp3::{self, Frame};

// --- RESP3-specific types ---

#[test]
fn null_type() {
    let (frame, rest) = resp3::parse_frame(Bytes::from("_\r\n")).unwrap();
    assert_eq!(frame, Frame::Null);
    assert!(rest.is_empty());
}

#[test]
fn boolean_true() {
    let (frame, _) = resp3::parse_frame(Bytes::from("#t\r\n")).unwrap();
    assert_eq!(frame, Frame::Boolean(true));
}

#[test]
fn boolean_false() {
    let (frame, _) = resp3::parse_frame(Bytes::from("#f\r\n")).unwrap();
    assert_eq!(frame, Frame::Boolean(false));
}

#[test]
fn boolean_invalid() {
    assert_eq!(
        resp3::parse_frame(Bytes::from("#x\r\n")),
        Err(ParseError::InvalidBoolean)
    );
}

#[test]
fn double_positive() {
    let (frame, _) = resp3::parse_frame(Bytes::from(",3.14\r\n")).unwrap();
    assert_eq!(frame, Frame::Double(3.14));
}

#[test]
fn double_negative() {
    let (frame, _) = resp3::parse_frame(Bytes::from(",-2.5\r\n")).unwrap();
    assert_eq!(frame, Frame::Double(-2.5));
}

#[test]
fn double_zero() {
    let (frame, _) = resp3::parse_frame(Bytes::from(",0\r\n")).unwrap();
    assert_eq!(frame, Frame::Double(0.0));
}

#[test]
fn special_float_inf() {
    let (frame, _) = resp3::parse_frame(Bytes::from(",inf\r\n")).unwrap();
    assert_eq!(frame, Frame::SpecialFloat(Bytes::from("inf")));
}

#[test]
fn special_float_neg_inf() {
    let (frame, _) = resp3::parse_frame(Bytes::from(",-inf\r\n")).unwrap();
    assert_eq!(frame, Frame::SpecialFloat(Bytes::from("-inf")));
}

#[test]
fn special_float_nan() {
    let (frame, _) = resp3::parse_frame(Bytes::from(",nan\r\n")).unwrap();
    assert_eq!(frame, Frame::SpecialFloat(Bytes::from("nan")));
}

#[test]
fn big_number() {
    let (frame, _) = resp3::parse_frame(Bytes::from(
        "(3492890328409238509324850943850943825024385\r\n",
    ))
    .unwrap();
    assert_eq!(
        frame,
        Frame::BigNumber(Bytes::from("3492890328409238509324850943850943825024385"))
    );
}

#[test]
fn blob_error() {
    let (frame, _) = resp3::parse_frame(Bytes::from("!12\r\nSYNTAX error\r\n")).unwrap();
    assert_eq!(frame, Frame::BlobError(Bytes::from("SYNTAX error")));
}

#[test]
fn verbatim_string_txt() {
    let (frame, _) = resp3::parse_frame(Bytes::from("=15\r\ntxt:hello world\r\n")).unwrap();
    assert_eq!(
        frame,
        Frame::VerbatimString {
            payload: Bytes::from("txt:hello world")
        }
    );
}

#[test]
fn verbatim_string_mkd() {
    let (frame, _) = resp3::parse_frame(Bytes::from("=12\r\nmkd:# Header\r\n")).unwrap();
    assert_eq!(
        frame,
        Frame::VerbatimString {
            payload: Bytes::from("mkd:# Header")
        }
    );
}

// --- Maps ---

#[test]
fn map_simple() {
    let wire = Bytes::from("%2\r\n+first\r\n:1\r\n+second\r\n:2\r\n");
    let (frame, rest) = resp3::parse_frame(wire).unwrap();
    assert!(rest.is_empty());
    assert_eq!(
        frame,
        Frame::Map(vec![
            (Frame::SimpleString(Bytes::from("first")), Frame::Integer(1)),
            (
                Frame::SimpleString(Bytes::from("second")),
                Frame::Integer(2)
            ),
        ])
    );
}

#[test]
fn map_empty() {
    let (frame, _) = resp3::parse_frame(Bytes::from("%0\r\n")).unwrap();
    assert_eq!(frame, Frame::Map(vec![]));
}

// --- Sets ---

#[test]
fn set_simple() {
    let wire = Bytes::from("~3\r\n+a\r\n+b\r\n+c\r\n");
    let (frame, rest) = resp3::parse_frame(wire).unwrap();
    assert!(rest.is_empty());
    assert_eq!(
        frame,
        Frame::Set(vec![
            Frame::SimpleString(Bytes::from("a")),
            Frame::SimpleString(Bytes::from("b")),
            Frame::SimpleString(Bytes::from("c")),
        ])
    );
}

// --- Push ---

#[test]
fn push_pubsub_message() {
    let wire = Bytes::from(">3\r\n+message\r\n+channel\r\n$7\r\npayload\r\n");
    let (frame, rest) = resp3::parse_frame(wire).unwrap();
    assert!(rest.is_empty());
    assert_eq!(
        frame,
        Frame::Push(vec![
            Frame::SimpleString(Bytes::from("message")),
            Frame::SimpleString(Bytes::from("channel")),
            Frame::BulkString(Some(Bytes::from("payload"))),
        ])
    );
}

// --- Attributes ---

#[test]
fn attribute_with_data() {
    let wire = Bytes::from("|1\r\n+ttl\r\n:3600\r\n");
    let (frame, _) = resp3::parse_frame(wire).unwrap();
    assert_eq!(
        frame,
        Frame::Attribute(vec![(
            Frame::SimpleString(Bytes::from("ttl")),
            Frame::Integer(3600),
        )])
    );
}

// --- Streaming sequences ---

#[test]
fn streaming_string() {
    let wire = Bytes::from("$?\r\n;5\r\nHello\r\n;6\r\n World\r\n;0\r\n");
    let (frame, rest) = resp3::parse_streaming_sequence(wire).unwrap();
    assert!(rest.is_empty());
    match frame {
        Frame::StreamedString(chunks) => {
            assert_eq!(chunks.len(), 2);
            assert_eq!(chunks[0], Bytes::from("Hello"));
            assert_eq!(chunks[1], Bytes::from(" World"));
        }
        _ => panic!("expected StreamedString"),
    }
}

#[test]
fn streaming_array() {
    let wire = Bytes::from("*?\r\n+hello\r\n:42\r\n#t\r\n.\r\n");
    let (frame, rest) = resp3::parse_streaming_sequence(wire).unwrap();
    assert!(rest.is_empty());
    match frame {
        Frame::StreamedArray(items) => {
            assert_eq!(items.len(), 3);
            assert_eq!(items[0], Frame::SimpleString(Bytes::from("hello")));
            assert_eq!(items[1], Frame::Integer(42));
            assert_eq!(items[2], Frame::Boolean(true));
        }
        _ => panic!("expected StreamedArray"),
    }
}

#[test]
fn streaming_map() {
    let wire = Bytes::from("%?\r\n+key1\r\n+val1\r\n+key2\r\n:123\r\n.\r\n");
    let (frame, rest) = resp3::parse_streaming_sequence(wire).unwrap();
    assert!(rest.is_empty());
    match frame {
        Frame::StreamedMap(pairs) => {
            assert_eq!(pairs.len(), 2);
        }
        _ => panic!("expected StreamedMap"),
    }
}

// --- Real Redis RESP3 response patterns ---

#[test]
fn hello_response() {
    // Simplified HELLO response as a map
    let wire = Bytes::from(
        "%3\r\n\
         +server\r\n+redis\r\n\
         +version\r\n+7.0.0\r\n\
         +proto\r\n:3\r\n",
    );
    let (frame, rest) = resp3::parse_frame(wire).unwrap();
    assert!(rest.is_empty());
    match frame {
        Frame::Map(pairs) => {
            assert_eq!(pairs.len(), 3);
            assert_eq!(
                pairs[2],
                (Frame::SimpleString(Bytes::from("proto")), Frame::Integer(3),)
            );
        }
        _ => panic!("expected map"),
    }
}

#[test]
fn mixed_type_array() {
    let wire = Bytes::from("*5\r\n+OK\r\n:42\r\n#t\r\n,3.14\r\n_\r\n");
    let (frame, rest) = resp3::parse_frame(wire).unwrap();
    assert!(rest.is_empty());
    assert_eq!(
        frame,
        Frame::Array(Some(vec![
            Frame::SimpleString(Bytes::from("OK")),
            Frame::Integer(42),
            Frame::Boolean(true),
            Frame::Double(3.14),
            Frame::Null,
        ]))
    );
}

// --- Pipelining ---

#[test]
fn pipelined_resp3_responses() {
    let wire = Bytes::from("+OK\r\n_\r\n#t\r\n,2.718\r\n");

    let (f1, rest) = resp3::parse_frame(wire).unwrap();
    assert_eq!(f1, Frame::SimpleString(Bytes::from("OK")));

    let (f2, rest) = resp3::parse_frame(rest).unwrap();
    assert_eq!(f2, Frame::Null);

    let (f3, rest) = resp3::parse_frame(rest).unwrap();
    assert_eq!(f3, Frame::Boolean(true));

    let (f4, rest) = resp3::parse_frame(rest).unwrap();
    assert_eq!(f4, Frame::Double(2.718));

    assert!(rest.is_empty());
}

// --- Roundtrips ---

#[test]
fn roundtrip_all_fixed_types() {
    let frames = vec![
        Frame::SimpleString(Bytes::from("OK")),
        Frame::Error(Bytes::from("ERR bad")),
        Frame::Integer(42),
        Frame::Integer(-1),
        Frame::Integer(0),
        Frame::BulkString(Some(Bytes::from("hello"))),
        Frame::BulkString(None),
        Frame::Null,
        Frame::Boolean(true),
        Frame::Boolean(false),
        Frame::Double(3.14),
        Frame::BigNumber(Bytes::from("12345678901234567890")),
        Frame::BlobError(Bytes::from("SYNTAX error")),
        Frame::Array(Some(vec![Frame::Integer(1), Frame::Integer(2)])),
        Frame::Array(None),
        Frame::Set(vec![
            Frame::SimpleString(Bytes::from("a")),
            Frame::SimpleString(Bytes::from("b")),
        ]),
        Frame::Map(vec![(
            Frame::SimpleString(Bytes::from("key")),
            Frame::Integer(1),
        )]),
        Frame::Push(vec![
            Frame::SimpleString(Bytes::from("message")),
            Frame::SimpleString(Bytes::from("data")),
        ]),
    ];

    for frame in &frames {
        let bytes = resp3::frame_to_bytes(frame);
        let (parsed, rest) = resp3::parse_frame(bytes).unwrap();
        assert!(rest.is_empty(), "rest not empty for {frame:?}");
        assert_eq!(&parsed, frame, "roundtrip failed for {frame:?}");
    }
}

// --- Streaming parser ---

#[test]
fn streaming_parser_interleaved_types() {
    let mut parser = resp3::Parser::new();
    parser.feed(Bytes::from("+OK\r\n_\r\n#t\r\n:99\r\n"));

    assert_eq!(
        parser.next_frame().unwrap().unwrap(),
        Frame::SimpleString(Bytes::from("OK"))
    );
    assert_eq!(parser.next_frame().unwrap().unwrap(), Frame::Null);
    assert_eq!(parser.next_frame().unwrap().unwrap(), Frame::Boolean(true));
    assert_eq!(parser.next_frame().unwrap().unwrap(), Frame::Integer(99));
    assert!(parser.next_frame().unwrap().is_none());
}

#[test]
fn streaming_parser_byte_at_a_time_map() {
    let wire = b"%1\r\n+k\r\n:1\r\n";
    let mut parser = resp3::Parser::new();

    for (i, &byte) in wire.iter().enumerate() {
        parser.feed(Bytes::from(vec![byte]));
        let result = parser.next_frame().unwrap();
        if i < wire.len() - 1 {
            assert!(result.is_none(), "unexpected frame at byte {i}");
        } else {
            let frame = result.unwrap();
            assert_eq!(
                frame,
                Frame::Map(vec![(
                    Frame::SimpleString(Bytes::from("k")),
                    Frame::Integer(1)
                )])
            );
        }
    }
}

// --- Integer edge cases ---

#[test]
fn integer_boundaries() {
    let max = format!(":{}\r\n", i64::MAX);
    let (frame, _) = resp3::parse_frame(Bytes::from(max)).unwrap();
    assert_eq!(frame, Frame::Integer(i64::MAX));

    let min = format!(":{}\r\n", i64::MIN);
    let (frame, _) = resp3::parse_frame(Bytes::from(min)).unwrap();
    assert_eq!(frame, Frame::Integer(i64::MIN));
}

#[test]
fn integer_overflow() {
    let overflow = format!(":{}0\r\n", i64::MAX);
    assert_eq!(
        resp3::parse_frame(Bytes::from(overflow)),
        Err(ParseError::Overflow)
    );
}

#[test]
fn integer_zero() {
    let (frame, _) = resp3::parse_frame(Bytes::from(":0\r\n")).unwrap();
    assert_eq!(frame, Frame::Integer(0));
}

// --- Error cases ---

#[test]
fn incomplete_empty() {
    assert_eq!(
        resp3::parse_frame(Bytes::new()),
        Err(ParseError::Incomplete)
    );
}

#[test]
fn invalid_tag() {
    assert_eq!(
        resp3::parse_frame(Bytes::from("Z\r\n")),
        Err(ParseError::InvalidTag(b'Z'))
    );
}

// --- Nesting depth limit (issue #47) ---

/// Build `depth` nested single-element aggregates wrapping an integer.
///
/// `header` is the repeat unit for one level. Maps and attributes need a key
/// before the nested value, so their unit carries one.
fn nested(header: &str, depth: usize) -> Bytes {
    let mut s = String::with_capacity(depth * header.len() + 5);
    for _ in 0..depth {
        s.push_str(header);
    }
    s.push_str(":42\r\n");
    Bytes::from(s)
}

/// Every RESP3 tag that recurses through a repeatable unit, with that unit.
///
/// `|` is absent deliberately. An attribute carries metadata for the frame that
/// follows and is skipped where a frame is expected (issue #59), so a chain of
/// attributes never reaches a real frame and is not well-formed input. The
/// attribute depth path is `parse_pairs`, which is the same function `%`
/// exercises above; `attribute_wrapping_deep_content_respects_max_depth` covers
/// the `|` tag specifically.
const NESTING_TAGS: &[&str] = &[
    "*1\r\n",       // array
    "~1\r\n",       // set
    ">1\r\n",       // push
    "%1\r\n+k\r\n", // map: key then nested value
];

#[test]
fn nesting_at_max_depth_parses() {
    for header in NESTING_TAGS {
        let wire = nested(header, resp3::MAX_DEPTH as usize);
        let (_, rest) =
            resp3::parse_frame(wire).unwrap_or_else(|e| panic!("{}: {e:?}", header.escape_debug()));
        assert!(rest.is_empty(), "{}", header.escape_debug());
    }
}

#[test]
fn nesting_past_max_depth_errors() {
    for header in NESTING_TAGS {
        assert_eq!(
            resp3::parse_frame(nested(header, resp3::MAX_DEPTH as usize + 1)),
            Err(ParseError::DepthExceeded),
            "{}",
            header.escape_debug()
        );
    }
}

#[test]
fn nesting_far_past_max_depth_errors_instead_of_overflowing_stack() {
    // Without a depth limit this aborts the process around 30,000 levels on an
    // 8 MB stack, and around 7,500 on a 2 MB tokio worker.
    for header in NESTING_TAGS {
        assert_eq!(
            resp3::parse_frame(nested(header, 100_000)),
            Err(ParseError::DepthExceeded),
            "{}",
            header.escape_debug()
        );
    }
}

#[test]
fn deep_nesting_errors_before_incomplete() {
    // Truncated deep input: the depth limit must fire rather than reporting
    // Incomplete, so a streaming caller fails fast instead of buffering more.
    for header in NESTING_TAGS {
        let wire = Bytes::from(header.repeat(100_000));
        assert_eq!(
            resp3::parse_frame(wire),
            Err(ParseError::DepthExceeded),
            "{}",
            header.escape_debug()
        );
    }
}

#[test]
fn empty_aggregate_does_not_spend_depth_budget() {
    // MAX_DEPTH aggregates, the innermost empty: no recursion happens at the
    // innermost level, so this is within budget.
    for (header, empty) in [
        ("*1\r\n", "*0\r\n"),
        ("~1\r\n", "~0\r\n"),
        ("%1\r\n+k\r\n", "%0\r\n"),
    ] {
        let mut s = header.repeat(resp3::MAX_DEPTH as usize - 1);
        s.push_str(empty);
        assert!(
            resp3::parse_frame(Bytes::from(s)).is_ok(),
            "{}",
            header.escape_debug()
        );
    }
}

#[test]
fn streaming_sequence_rejects_deep_nesting() {
    // A streamed array whose first item is deeply nested: the inner parse_frame
    // call carries the same bound.
    let mut s = String::from("*?\r\n");
    s.push_str(&"*1\r\n".repeat(100_000));
    assert_eq!(
        resp3::parse_streaming_sequence(Bytes::from(s)),
        Err(ParseError::DepthExceeded)
    );
}

#[test]
fn parser_rejects_deep_nesting() {
    let mut parser = resp3::Parser::new();
    parser.feed(nested("*1\r\n", 100_000));
    assert_eq!(parser.next_frame(), Err(ParseError::DepthExceeded));
}

// --- Integer sign and classification (issues #49, #55) ---
//
// Transcribed from the RESP grammar `:[<+|->]<value>\r\n`, not from
// frame_to_bytes, which emits i64 via Display and so never produces a leading
// `+`. Any test whose input comes from the serializer is blind to this form.

#[test]
fn integer_accepts_explicit_plus() {
    for (wire, want) in [
        (&b":+42\r\n"[..], 42i64),
        (&b":+0\r\n"[..], 0),
        (&b":+9223372036854775807\r\n"[..], i64::MAX),
    ] {
        let (frame, rest) = resp3::parse_frame(Bytes::copy_from_slice(wire))
            .unwrap_or_else(|e| panic!("{:?}: {e:?}", String::from_utf8_lossy(wire)));
        assert!(rest.is_empty());
        assert_eq!(
            frame,
            Frame::Integer(want),
            "{}",
            String::from_utf8_lossy(wire)
        );
    }
}

#[test]
fn integer_rejects_malformed_signs() {
    for wire in [
        &b":+\r\n"[..],
        &b":-\r\n"[..],
        &b":++1\r\n"[..],
        &b":+-1\r\n"[..],
        &b":1+\r\n"[..],
    ] {
        assert_eq!(
            resp3::parse_frame(Bytes::copy_from_slice(wire)),
            Err(ParseError::InvalidFormat),
            "{}",
            String::from_utf8_lossy(wire)
        );
    }
}

#[test]
fn integer_signed_overflow_matches_unsigned() {
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b":+9223372036854775808\r\n")),
        Err(ParseError::Overflow)
    );
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b":9223372036854775808\r\n")),
        Err(ParseError::Overflow)
    );
}

#[test]
fn trailing_junk_is_malformed_not_overflow() {
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b":-9223372036854775808X\r\n")),
        Err(ParseError::InvalidFormat)
    );
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b":-9223372036854775808\r\n"))
            .unwrap()
            .0,
        Frame::Integer(i64::MIN)
    );
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b":-9223372036854775809\r\n")),
        Err(ParseError::Overflow)
    );
}

#[test]
fn signed_integer_inside_every_aggregate() {
    // The failure previously took the enclosing frame with it, for all five
    // recursing tags.
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b"*1\r\n:+42\r\n"))
            .unwrap()
            .0,
        Frame::Array(Some(vec![Frame::Integer(42)]))
    );
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b"~1\r\n:+42\r\n"))
            .unwrap()
            .0,
        Frame::Set(vec![Frame::Integer(42)])
    );
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b">1\r\n:+42\r\n"))
            .unwrap()
            .0,
        Frame::Push(vec![Frame::Integer(42)])
    );
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b"%1\r\n:+1\r\n:+2\r\n"))
            .unwrap()
            .0,
        Frame::Map(vec![(Frame::Integer(1), Frame::Integer(2))])
    );
}

// --- Attributes must not consume an element slot (issue #59) ---
//
// An attribute is not a reply. It carries metadata for the frame that follows,
// so a `*3` header followed by an attribute is followed by four frames. When an
// attribute eats a slot the aggregate ends early and the real element is left
// in the buffer, which shifts every subsequent reply on the connection.

#[test]
fn spec_attribute_example_parses_as_three_elements() {
    // Straight from the spec's Attributes section.
    let wire = Bytes::from_static(b"*3\r\n:1\r\n:2\r\n|1\r\n+ttl\r\n:3600\r\n:3\r\n");
    let (frame, rest) = resp3::parse_frame(wire).unwrap();
    assert!(rest.is_empty(), "left {rest:?} unconsumed");
    assert_eq!(
        frame,
        Frame::Array(Some(vec![
            Frame::Integer(1),
            Frame::Integer(2),
            Frame::Integer(3)
        ]))
    );
}

#[test]
fn attribute_in_any_element_position() {
    let attr = "|1\r\n+ttl\r\n:3600\r\n";
    for wire in [
        format!("*3\r\n{attr}:1\r\n:2\r\n:3\r\n"), // first
        format!("*3\r\n:1\r\n{attr}:2\r\n:3\r\n"), // middle
        format!("*3\r\n:1\r\n:2\r\n{attr}:3\r\n"), // last
    ] {
        let (frame, rest) = resp3::parse_frame(Bytes::from(wire.clone()))
            .unwrap_or_else(|e| panic!("{wire:?}: {e:?}"));
        assert!(rest.is_empty(), "{wire:?} left {rest:?}");
        assert_eq!(
            frame,
            Frame::Array(Some(vec![
                Frame::Integer(1),
                Frame::Integer(2),
                Frame::Integer(3)
            ])),
            "{wire:?}"
        );
    }
}

#[test]
fn consecutive_attributes_before_one_element() {
    let wire = Bytes::from_static(b"*1\r\n|1\r\n+a\r\n:1\r\n|1\r\n+b\r\n:2\r\n:42\r\n");
    let (frame, rest) = resp3::parse_frame(wire).unwrap();
    assert!(rest.is_empty());
    assert_eq!(frame, Frame::Array(Some(vec![Frame::Integer(42)])));
}

#[test]
fn attribute_before_a_map_key_or_value() {
    let attr = "|1\r\n+ttl\r\n:3600\r\n";
    for wire in [
        format!("%1\r\n{attr}+k\r\n+v\r\n"), // before the key
        format!("%1\r\n+k\r\n{attr}+v\r\n"), // before the value
    ] {
        let (frame, rest) = resp3::parse_frame(Bytes::from(wire.clone()))
            .unwrap_or_else(|e| panic!("{wire:?}: {e:?}"));
        assert!(rest.is_empty(), "{wire:?} left {rest:?}");
        assert_eq!(
            frame,
            Frame::Map(vec![(
                Frame::SimpleString(Bytes::from_static(b"k")),
                Frame::SimpleString(Bytes::from_static(b"v"))
            )]),
            "{wire:?}"
        );
    }
}

#[test]
fn attribute_skipped_in_every_aggregate_type() {
    let attr = "|1\r\n+ttl\r\n:3600\r\n";
    for (tag, build) in [
        ("*", Frame::Array(Some(vec![Frame::Integer(1)]))),
        ("~", Frame::Set(vec![Frame::Integer(1)])),
        (">", Frame::Push(vec![Frame::Integer(1)])),
    ] {
        let wire = format!("{tag}1\r\n{attr}:1\r\n");
        let (frame, rest) = resp3::parse_frame(Bytes::from(wire.clone()))
            .unwrap_or_else(|e| panic!("{wire:?}: {e:?}"));
        assert!(rest.is_empty(), "{wire:?}");
        assert_eq!(frame, build, "{wire:?}");
    }
}

#[test]
fn bare_attribute_still_parses_as_an_attribute() {
    // Only the in-aggregate position changes. A standalone attribute is
    // unaffected.
    let (frame, rest) = resp3::parse_frame(Bytes::from_static(b"|1\r\n+ttl\r\n:3600\r\n")).unwrap();
    assert!(rest.is_empty());
    assert_eq!(
        frame,
        Frame::Attribute(vec![(
            Frame::SimpleString(Bytes::from_static(b"ttl")),
            Frame::Integer(3600)
        )])
    );
}

#[test]
fn attribute_inside_a_nested_aggregate_does_not_disturb_the_outer_count() {
    let wire = Bytes::from_static(b"*2\r\n*1\r\n|1\r\n+a\r\n:1\r\n:9\r\n+tail\r\n");
    let (frame, rest) = resp3::parse_frame(wire).unwrap();
    assert!(rest.is_empty());
    assert_eq!(
        frame,
        Frame::Array(Some(vec![
            Frame::Array(Some(vec![Frame::Integer(9)])),
            Frame::SimpleString(Bytes::from_static(b"tail")),
        ]))
    );
}

#[test]
fn attribute_does_not_shift_pipelined_reply_boundaries() {
    // The regression that matters: a stolen slot leaves the real element in the
    // buffer, where it is returned as the reply to the next command.
    let mut parser = resp3::Parser::new();
    parser.feed(Bytes::from_static(
        b"*3\r\n:1\r\n:2\r\n|1\r\n+ttl\r\n:3600\r\n:3\r\n",
    ));
    parser.feed(Bytes::from_static(b"+SECOND\r\n"));

    assert_eq!(
        parser.next_frame().unwrap().unwrap(),
        Frame::Array(Some(vec![
            Frame::Integer(1),
            Frame::Integer(2),
            Frame::Integer(3)
        ]))
    );
    assert_eq!(
        parser.next_frame().unwrap().unwrap(),
        Frame::SimpleString(Bytes::from_static(b"SECOND"))
    );
    assert_eq!(parser.next_frame().unwrap(), None);
}

#[test]
fn truncated_attribute_inside_an_aggregate_reports_incomplete() {
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b"*1\r\n|1\r\n+ttl\r\n")),
        Err(ParseError::Incomplete)
    );
}

#[test]
fn attribute_wrapping_deep_content_respects_max_depth() {
    // `|` cannot be chained (see NESTING_TAGS), so its depth accounting is
    // checked by wrapping a deep array: the attribute spends one level and the
    // array spends the rest.
    let deep = |levels: usize| {
        let mut s = String::from("|1\r\n+k\r\n");
        s.push_str(&"*1\r\n".repeat(levels));
        s.push_str(":42\r\n");
        Bytes::from(s)
    };

    // One attribute plus MAX_DEPTH - 1 arrays is exactly at the limit.
    let (frame, rest) = resp3::parse_frame(deep(resp3::MAX_DEPTH as usize - 1)).unwrap();
    assert!(rest.is_empty());
    // Skipping applies where an element is expected. Here the attribute is the
    // whole frame, so it is returned as itself with the array as its value.
    assert!(matches!(frame, Frame::Attribute(_)));

    // One deeper exceeds it.
    assert_eq!(
        resp3::parse_frame(deep(resp3::MAX_DEPTH as usize)),
        Err(ParseError::DepthExceeded)
    );
}

// --- Scalar conformance (issues #57, #58, #62) ---

#[test]
fn null_and_terminator_distinguish_truncated_from_invalid() {
    // Complete but invalid must not be reported as truncated, or Parser waits
    // forever for data that cannot help.
    for wire in [
        &b"_x\r\n"[..],
        &b"_\r\r\n"[..],
        &b".x\r\n"[..],
        &b".\r\r\n"[..],
    ] {
        assert_eq!(
            resp3::parse_frame(Bytes::copy_from_slice(wire)),
            Err(ParseError::InvalidFormat),
            "{}",
            String::from_utf8_lossy(wire)
        );
    }

    // Genuinely truncated still reports Incomplete.
    for wire in [&b"_"[..], &b"_\r"[..], &b"."[..], &b".\r"[..]] {
        assert_eq!(
            resp3::parse_frame(Bytes::copy_from_slice(wire)),
            Err(ParseError::Incomplete),
            "{}",
            String::from_utf8_lossy(wire)
        );
    }

    // Valid forms unchanged.
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b"_\r\n")).unwrap().0,
        Frame::Null
    );
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b".\r\n")).unwrap().0,
        Frame::StreamTerminator
    );
}

#[test]
fn parser_terminates_on_a_malformed_null() {
    // The regression that matters: Incomplete means "need more data", so a
    // malformed null previously left the connection with no reason to close.
    let mut parser = resp3::Parser::new();
    parser.feed(Bytes::from_static(b"_x\r\n"));
    assert_eq!(parser.next_frame(), Err(ParseError::InvalidFormat));
}

#[test]
fn sibling_scalar_arms_are_unchanged() {
    // Controls, so the null and terminator fix does not overshoot.
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b"#x\r\n")),
        Err(ParseError::InvalidBoolean)
    );
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b":x\r\n")),
        Err(ParseError::InvalidFormat)
    );
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b"$x\r\n")),
        Err(ParseError::BadLength)
    );
}

#[test]
fn big_number_requires_optional_sign_then_digits() {
    for wire in [
        &b"(\r\n"[..],
        &b"(not-a-number\r\n"[..],
        &b"(1.5\r\n"[..],
        &b"(--1\r\n"[..],
        &b"( 12\r\n"[..],
        &b"(+\r\n"[..],
        &b"(12x\r\n"[..],
    ] {
        assert_eq!(
            resp3::parse_frame(Bytes::copy_from_slice(wire)),
            Err(ParseError::InvalidFormat),
            "{}",
            String::from_utf8_lossy(wire)
        );
    }

    // The spec's example, unsigned and signed.
    for wire in [
        &b"(3492890328409238509324850943850943825024385\r\n"[..],
        &b"(+3492890328409238509324850943850943825024385\r\n"[..],
        &b"(-3492890328409238509324850943850943825024385\r\n"[..],
        &b"(0\r\n"[..],
    ] {
        let (frame, rest) = resp3::parse_frame(Bytes::copy_from_slice(wire))
            .unwrap_or_else(|e| panic!("{}: {e:?}", String::from_utf8_lossy(wire)));
        assert!(rest.is_empty());
        assert!(matches!(frame, Frame::BigNumber(_)));
    }
}

#[test]
fn streamed_string_terminator_is_four_bytes() {
    // `;0\r\n`, not `;0\r\n\r\n`.
    let wire = Bytes::from_static(b"$?\r\n;5\r\nHello\r\n;6\r\n World\r\n;0\r\n");
    let (frame, rest) = resp3::parse_streaming_sequence(wire).unwrap();
    assert!(rest.is_empty());
    match frame {
        Frame::StreamedString(chunks) => {
            assert_eq!(chunks.len(), 2);
            assert_eq!(chunks[0], Bytes::from_static(b"Hello"));
            assert_eq!(chunks[1], Bytes::from_static(b" World"));
        }
        other => panic!("expected StreamedString, got {other:?}"),
    }
}

#[test]
fn streamed_string_terminator_round_trips() {
    let frame = Frame::StreamedString(vec![Bytes::from_static(b"ab"), Bytes::from_static(b"cd")]);
    let wire = resp3::frame_to_bytes(&frame);
    assert_eq!(
        wire,
        Bytes::from_static(b"$?\r\n;2\r\nab\r\n;2\r\ncd\r\n;0\r\n")
    );

    let (reparsed, rest) = resp3::parse_streaming_sequence(wire).unwrap();
    assert!(rest.is_empty());
    assert_eq!(reparsed, frame);
}

#[test]
fn empty_streamed_chunk_serializes_to_four_bytes() {
    let wire = resp3::frame_to_bytes(&Frame::StreamedStringChunk(Bytes::new()));
    assert_eq!(wire, Bytes::from_static(b";0\r\n"));

    // A non-empty chunk still carries its trailing CRLF.
    let wire = resp3::frame_to_bytes(&Frame::StreamedStringChunk(Bytes::from_static(b"hi")));
    assert_eq!(wire, Bytes::from_static(b";2\r\nhi\r\n"));
}

// --- Line length ceiling (issue #63) ---

#[test]
fn unterminated_line_is_rejected_for_every_line_type() {
    for tag in [
        "+", "-", ":", "(", ",", "#", "!", "=", "$", "*", "%", "~", ">",
    ] {
        let mut wire = tag.to_string();
        wire.push_str(&"x".repeat(resp3::MAX_LINE_LENGTH + 1));
        assert_eq!(
            resp3::parse_frame(Bytes::from(wire)),
            Err(ParseError::LineTooLong),
            "tag {tag}"
        );
    }
}

#[test]
fn a_line_at_the_limit_still_parses() {
    let mut wire = String::from("+");
    wire.push_str(&"y".repeat(resp3::MAX_LINE_LENGTH));
    wire.push_str("\r\n");
    let (frame, rest) = resp3::parse_frame(Bytes::from(wire)).unwrap();
    assert!(rest.is_empty());
    assert!(matches!(frame, Frame::SimpleString(ref b) if b.len() == resp3::MAX_LINE_LENGTH));
}

#[test]
fn bulk_string_body_is_not_subject_to_the_line_ceiling() {
    // The ceiling applies to CRLF-scanned lines. A bulk string body is
    // length-prefixed and read directly, so large payloads still work.
    let body = vec![b'z'; resp3::MAX_LINE_LENGTH * 4];
    let mut wire = format!("${}\r\n", body.len()).into_bytes();
    wire.extend_from_slice(&body);
    wire.extend_from_slice(b"\r\n");
    let (frame, rest) = resp3::parse_frame(Bytes::from(wire)).unwrap();
    assert!(rest.is_empty());
    assert!(matches!(frame, Frame::BulkString(Some(ref b)) if b.len() == body.len()));
}

#[test]
fn an_over_long_line_is_rejected_even_when_terminated() {
    // See the RESP2 counterpart: the ceiling applies to terminated lines too.
    let mut wire = String::from("+");
    wire.push_str(&"x".repeat(resp3::MAX_LINE_LENGTH + 1));
    wire.push_str("\r\n");
    assert_eq!(
        resp3::parse_frame(Bytes::from(wire)),
        Err(ParseError::LineTooLong)
    );

    // A bulk string body is length-prefixed, not scanned, so it stays exempt.
    let body = vec![b'z'; resp3::MAX_LINE_LENGTH * 4];
    let mut wire = format!("${}\r\n", body.len()).into_bytes();
    wire.extend_from_slice(&body);
    wire.extend_from_slice(b"\r\n");
    assert!(resp3::parse_frame(Bytes::from(wire)).is_ok());
}

// --- Checked serializer round-trip property (issues #82, #83, #84, #85) ---
//
// try_frame_to_bytes documents an iff: it succeeds exactly when the bytes parse
// back to an identical frame with nothing left over. These are the four ways it
// was violated, kept as literal reproductions from the issues.

#[test]
fn line_payload_over_the_ceiling_is_refused() {
    // #82. #63 and #71 tightened the parser; the serializer was not brought
    // along, so an over-long payload passed the checked path and the parser
    // then rejected the bytes.
    let payload = vec![b'a'; resp3::MAX_LINE_LENGTH + 1];
    let frame = Frame::SimpleString(Bytes::from(payload));
    assert_eq!(
        resp3::try_frame_to_bytes(&frame),
        Err(resp_rs::SerializeError::LineTooLong)
    );
    // At the ceiling it is still accepted, and still round-trips.
    let ok = Frame::SimpleString(Bytes::from(vec![b'b'; resp3::MAX_LINE_LENGTH]));
    let bytes = resp3::try_frame_to_bytes(&ok).unwrap();
    assert_eq!(resp3::parse_frame(bytes).unwrap().0, ok);
}

#[test]
fn assembled_streaming_frame_cannot_be_nested() {
    // #83. The wire is `*1\r\n$?\r\n;3\r\nabc\r\n;0\r\n`, which parses without
    // error as Array([StreamedStringHeader]) with 13 bytes left over, so the
    // leftover surfaces as the next reply.
    let frame = Frame::Array(Some(vec![Frame::StreamedString(vec![Bytes::from_static(
        b"abc",
    )])]));
    assert_eq!(
        resp3::try_frame_to_bytes(&frame),
        Err(resp_rs::SerializeError::NestedStreamingFrame)
    );
    // Top level is the position parse_streaming_sequence can reproduce, so it
    // stays accepted there.
    let top = Frame::StreamedString(vec![Bytes::from_static(b"abc")]);
    let bytes = resp3::try_frame_to_bytes(&top).unwrap();
    assert_eq!(resp3::parse_streaming_sequence(bytes).unwrap().0, top);
}

#[test]
fn terminator_in_a_streamed_aggregate_is_refused() {
    // #84. A streamed aggregate is terminated rather than counted, so a
    // terminator inside one ends its own container early.
    let frame = Frame::StreamedArray(vec![Frame::StreamTerminator]);
    assert_eq!(
        resp3::try_frame_to_bytes(&frame),
        Err(resp_rs::SerializeError::TerminatorInStreamedAggregate)
    );

    // The position is what matters, and the rule is the opposite of the
    // attribute rule. Inside a COUNTED aggregate the count says how many frames
    // to read and `.\r\n` parses as one, so it round-trips.
    let counted = Frame::Array(Some(vec![Frame::StreamTerminator]));
    let bytes = resp3::try_frame_to_bytes(&counted).unwrap();
    assert_eq!(resp3::parse_frame(bytes).unwrap().0, counted);
}

#[test]
fn streamed_aggregate_contents_are_validated() {
    // #85. The catch-all arm handed these to the unchecked writer, so no
    // per-frame check ran inside them. This is #60's CRLF injection resurfacing
    // through the one path #60 did not cover.
    let frame = Frame::StreamedArray(vec![Frame::SimpleString(Bytes::from_static(b"sp\r\nlit"))]);
    assert_eq!(
        resp3::try_frame_to_bytes(&frame),
        Err(resp_rs::SerializeError::LineContainsCrlf)
    );

    // The worse shape from the issue: a payload that splits into two frames
    // which both parse, so the array comes back with a phantom element and no
    // error at all.
    let injected =
        Frame::StreamedArray(vec![Frame::SimpleString(Bytes::from_static(b"sp\r\n+ok"))]);
    assert_eq!(
        resp3::try_frame_to_bytes(&injected),
        Err(resp_rs::SerializeError::LineContainsCrlf)
    );

    // Every other per-frame check applies inside a streamed aggregate too.
    let bad_double = Frame::StreamedSet(vec![Frame::Double(f64::NAN)]);
    assert!(resp3::try_frame_to_bytes(&bad_double).is_err());
    let bad_verbatim = Frame::StreamedPush(vec![Frame::VerbatimString {
        payload: Bytes::from_static(b"ab:cd"),
    }]);
    assert!(resp3::try_frame_to_bytes(&bad_verbatim).is_err());
}
