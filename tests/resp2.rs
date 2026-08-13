use bytes::Bytes;
use resp_rs::ParseError;
use resp_rs::resp2::{self, Frame};

// --- Real Redis command patterns ---

#[test]
fn redis_set_command() {
    let wire = Bytes::from("*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n");
    let (frame, rest) = resp2::parse_frame(wire).unwrap();
    assert!(rest.is_empty());
    assert_eq!(
        frame,
        Frame::Array(Some(vec![
            Frame::BulkString(Some(Bytes::from("SET"))),
            Frame::BulkString(Some(Bytes::from("mykey"))),
            Frame::BulkString(Some(Bytes::from("myvalue"))),
        ]))
    );
}

#[test]
fn redis_get_response_hit() {
    let wire = Bytes::from("$5\r\nhello\r\n");
    let (frame, _) = resp2::parse_frame(wire).unwrap();
    assert_eq!(frame, Frame::BulkString(Some(Bytes::from("hello"))));
}

#[test]
fn redis_get_response_miss() {
    let wire = Bytes::from("$-1\r\n");
    let (frame, _) = resp2::parse_frame(wire).unwrap();
    assert_eq!(frame, Frame::BulkString(None));
}

#[test]
fn redis_info_multiline_bulk_string() {
    let payload = "# Server\r\nredis_version:7.0.0\r\nredis_mode:standalone\r\n";
    let wire_str = format!("${}\r\n{}\r\n", payload.len(), payload);
    let wire = Bytes::from(wire_str);
    let (frame, rest) = resp2::parse_frame(wire).unwrap();
    assert!(rest.is_empty());
    match frame {
        Frame::BulkString(Some(data)) => {
            assert!(data.starts_with(b"# Server"));
            assert_eq!(data.len(), payload.len());
        }
        _ => panic!("expected bulk string"),
    }
}

#[test]
fn redis_mget_with_nulls() {
    // MGET key1 key2 key3 where key2 doesn't exist
    let wire = Bytes::from("*3\r\n$5\r\nvalue\r\n$-1\r\n$7\r\nanother\r\n");
    let (frame, _) = resp2::parse_frame(wire).unwrap();
    assert_eq!(
        frame,
        Frame::Array(Some(vec![
            Frame::BulkString(Some(Bytes::from("value"))),
            Frame::BulkString(None),
            Frame::BulkString(Some(Bytes::from("another"))),
        ]))
    );
}

#[test]
fn redis_error_responses() {
    let cases = [
        (
            "-ERR unknown command 'foobar'\r\n",
            "ERR unknown command 'foobar'",
        ),
        (
            "-WRONGTYPE Operation against a key\r\n",
            "WRONGTYPE Operation against a key",
        ),
        (
            "-MOVED 3999 127.0.0.1:6381\r\n",
            "MOVED 3999 127.0.0.1:6381",
        ),
    ];
    for (wire, expected) in cases {
        let (frame, _) = resp2::parse_frame(Bytes::from(wire)).unwrap();
        assert_eq!(frame, Frame::Error(Bytes::from(expected)));
    }
}

// --- Pipelining (multiple frames in one buffer) ---

#[test]
fn pipelined_commands() {
    let wire = Bytes::from(
        "*3\r\n$3\r\nSET\r\n$1\r\na\r\n$1\r\n1\r\n\
         *2\r\n$3\r\nGET\r\n$1\r\na\r\n",
    );

    let (frame1, rest) = resp2::parse_frame(wire).unwrap();
    assert!(matches!(frame1, Frame::Array(Some(ref v)) if v.len() == 3));

    let (frame2, rest) = resp2::parse_frame(rest).unwrap();
    assert!(matches!(frame2, Frame::Array(Some(ref v)) if v.len() == 2));

    assert!(rest.is_empty());
}

#[test]
fn pipelined_responses() {
    let wire = Bytes::from("+OK\r\n$5\r\nhello\r\n:42\r\n");

    let (f1, rest) = resp2::parse_frame(wire).unwrap();
    assert_eq!(f1, Frame::SimpleString(Bytes::from("OK")));

    let (f2, rest) = resp2::parse_frame(rest).unwrap();
    assert_eq!(f2, Frame::BulkString(Some(Bytes::from("hello"))));

    let (f3, rest) = resp2::parse_frame(rest).unwrap();
    assert_eq!(f3, Frame::Integer(42));

    assert!(rest.is_empty());
}

// --- Roundtrip (parse -> serialize -> parse) ---

#[test]
fn roundtrip_nested_arrays() {
    let original = Frame::Array(Some(vec![
        Frame::Array(Some(vec![Frame::Integer(1), Frame::Integer(2)])),
        Frame::Array(Some(vec![
            Frame::BulkString(Some(Bytes::from("three"))),
            Frame::BulkString(None),
        ])),
        Frame::SimpleString(Bytes::from("OK")),
    ]));

    let bytes = resp2::frame_to_bytes(&original);
    let (parsed, rest) = resp2::parse_frame(bytes).unwrap();
    assert!(rest.is_empty());
    assert_eq!(parsed, original);
}

// --- Streaming parser ---

#[test]
fn streaming_parser_byte_at_a_time() {
    let wire = b"+OK\r\n";
    let mut parser = resp2::Parser::new();

    for (i, &byte) in wire.iter().enumerate() {
        parser.feed(Bytes::from(vec![byte]));
        let result = parser.next_frame().unwrap();
        if i < wire.len() - 1 {
            assert!(result.is_none(), "should not have frame at byte {i}");
        } else {
            assert_eq!(result.unwrap(), Frame::SimpleString(Bytes::from("OK")));
        }
    }
}

#[test]
fn streaming_parser_pipeline() {
    let mut parser = resp2::Parser::new();
    parser.feed(Bytes::from("+OK\r\n:100\r\n$3\r\nfoo\r\n"));

    let f1 = parser.next_frame().unwrap().unwrap();
    assert_eq!(f1, Frame::SimpleString(Bytes::from("OK")));

    let f2 = parser.next_frame().unwrap().unwrap();
    assert_eq!(f2, Frame::Integer(100));

    let f3 = parser.next_frame().unwrap().unwrap();
    assert_eq!(f3, Frame::BulkString(Some(Bytes::from("foo"))));

    assert!(parser.next_frame().unwrap().is_none());
}

#[test]
fn streaming_parser_buffered_bytes() {
    let mut parser = resp2::Parser::new();
    assert_eq!(parser.buffered_bytes(), 0);

    parser.feed(Bytes::from("+OK\r"));
    assert_eq!(parser.buffered_bytes(), 4);

    assert!(parser.next_frame().unwrap().is_none());
    assert_eq!(parser.buffered_bytes(), 4);

    parser.feed(Bytes::from("\n"));
    parser.next_frame().unwrap().unwrap();
    assert_eq!(parser.buffered_bytes(), 0);
}

#[test]
fn streaming_parser_clear() {
    let mut parser = resp2::Parser::new();
    parser.feed(Bytes::from("+OK\r"));
    parser.clear();
    assert_eq!(parser.buffered_bytes(), 0);
    assert!(parser.next_frame().unwrap().is_none());
}

// --- Error cases ---

#[test]
fn incomplete_bulk_string_length_only() {
    assert_eq!(
        resp2::parse_frame(Bytes::from("$10\r\n")),
        Err(ParseError::Incomplete)
    );
}

#[test]
fn incomplete_array_partial_element() {
    assert_eq!(
        resp2::parse_frame(Bytes::from("*2\r\n+OK\r\n")),
        Err(ParseError::Incomplete)
    );
}

#[test]
fn bad_integer() {
    assert!(resp2::parse_frame(Bytes::from(":abc\r\n")).is_err());
}

#[test]
fn bad_bulk_string_length() {
    assert!(resp2::parse_frame(Bytes::from("$abc\r\n")).is_err());
}

// --- Edge cases ---

#[test]
fn large_integer_boundaries() {
    let max = format!(":{}\r\n", i64::MAX);
    let (frame, _) = resp2::parse_frame(Bytes::from(max)).unwrap();
    assert_eq!(frame, Frame::Integer(i64::MAX));

    let min = format!(":{}\r\n", i64::MIN);
    let (frame, _) = resp2::parse_frame(Bytes::from(min)).unwrap();
    assert_eq!(frame, Frame::Integer(i64::MIN));
}

#[test]
fn bulk_string_with_crlf_in_payload() {
    // Bulk string containing \r\n in the data -- length-prefixed so it works
    let wire = Bytes::from("$8\r\nfoo\r\nbar\r\n");
    let (frame, rest) = resp2::parse_frame(wire).unwrap();
    assert_eq!(
        frame,
        Frame::BulkString(Some(Bytes::from(&b"foo\r\nbar"[..])))
    );
    assert!(rest.is_empty());
}

#[test]
fn deeply_nested_array() {
    // 5 levels deep
    let wire = Bytes::from("*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n:42\r\n");
    let (frame, rest) = resp2::parse_frame(wire).unwrap();
    assert!(rest.is_empty());

    // Walk down to the integer
    let mut current = &frame;
    for _ in 0..5 {
        match current {
            Frame::Array(Some(items)) => {
                assert_eq!(items.len(), 1);
                current = &items[0];
            }
            _ => panic!("expected array"),
        }
    }
    assert_eq!(current, &Frame::Integer(42));
}

// --- Nesting depth limit (issue #47) ---

/// Build `depth` nested single-element arrays wrapping an integer.
fn nested_arrays(depth: usize) -> Bytes {
    let mut s = String::with_capacity(depth * 4 + 5);
    for _ in 0..depth {
        s.push_str("*1\r\n");
    }
    s.push_str(":42\r\n");
    Bytes::from(s)
}

#[test]
fn nesting_at_max_depth_parses() {
    let (frame, rest) = resp2::parse_frame(nested_arrays(resp2::MAX_DEPTH as usize)).unwrap();
    assert!(rest.is_empty());

    let mut current = &frame;
    for _ in 0..resp2::MAX_DEPTH {
        match current {
            Frame::Array(Some(items)) => current = &items[0],
            _ => panic!("expected array"),
        }
    }
    assert_eq!(current, &Frame::Integer(42));
}

#[test]
fn nesting_past_max_depth_errors() {
    assert_eq!(
        resp2::parse_frame(nested_arrays(resp2::MAX_DEPTH as usize + 1)),
        Err(ParseError::DepthExceeded)
    );
}

#[test]
fn nesting_far_past_max_depth_errors_instead_of_overflowing_stack() {
    // Without a depth limit this aborts the process around 30,000 levels on an
    // 8 MB stack, and around 7,500 on a 2 MB tokio worker.
    assert_eq!(
        resp2::parse_frame(nested_arrays(100_000)),
        Err(ParseError::DepthExceeded)
    );
}

#[test]
fn deep_nesting_errors_before_incomplete() {
    // Truncated deep input: the depth limit must fire rather than reporting
    // Incomplete, so a streaming caller fails fast instead of buffering more.
    let wire = Bytes::from("*1\r\n".repeat(100_000));
    assert_eq!(resp2::parse_frame(wire), Err(ParseError::DepthExceeded));
}

#[test]
fn empty_array_does_not_spend_depth_budget() {
    // MAX_DEPTH arrays, the innermost empty: no recursion happens at the
    // innermost level, so this is within budget.
    let mut s = "*1\r\n".repeat(resp2::MAX_DEPTH as usize - 1);
    s.push_str("*0\r\n");
    assert!(resp2::parse_frame(Bytes::from(s)).is_ok());
}

#[test]
fn parser_rejects_deep_nesting() {
    let mut parser = resp2::Parser::new();
    parser.feed(nested_arrays(100_000));
    assert_eq!(parser.next_frame(), Err(ParseError::DepthExceeded));
}

// --- Integer sign and classification (issues #49, #55) ---
//
// These cases are transcribed from the RESP grammar `:[<+|->]<value>\r\n`,
// not from frame_to_bytes. The serializer emits i64 via Display, which never
// produces a leading `+`, so no test whose input comes from the serializer can
// reach the signed form. That closed loop is why #49 went unnoticed.

#[test]
fn integer_accepts_explicit_plus() {
    for (wire, want) in [
        (&b":+42\r\n"[..], 42i64),
        (&b":+0\r\n"[..], 0),
        (&b":+1\r\n"[..], 1),
        (&b":+9223372036854775807\r\n"[..], i64::MAX),
    ] {
        let (frame, rest) = resp2::parse_frame(Bytes::copy_from_slice(wire))
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
fn integer_sign_forms_agree() {
    // The three spellings of the same value must parse identically.
    let plus = resp2::parse_frame(Bytes::from_static(b":+42\r\n"))
        .unwrap()
        .0;
    let bare = resp2::parse_frame(Bytes::from_static(b":42\r\n"))
        .unwrap()
        .0;
    assert_eq!(plus, bare);
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b":-42\r\n"))
            .unwrap()
            .0,
        Frame::Integer(-42)
    );
}

#[test]
fn integer_rejects_malformed_signs() {
    for wire in [
        &b":+\r\n"[..],
        &b":-\r\n"[..],
        &b":++1\r\n"[..],
        &b":+-1\r\n"[..],
        &b":-+1\r\n"[..],
        &b":1+\r\n"[..],
        &b":+ 1\r\n"[..],
    ] {
        assert_eq!(
            resp2::parse_frame(Bytes::copy_from_slice(wire)),
            Err(ParseError::InvalidFormat),
            "{}",
            String::from_utf8_lossy(wire)
        );
    }
}

#[test]
fn integer_signed_overflow_matches_unsigned() {
    // Accepting the sign moves this from InvalidFormat to Overflow, which is
    // the point: it should classify the same as the unsigned spelling.
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b":+9223372036854775808\r\n")),
        Err(ParseError::Overflow)
    );
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b":9223372036854775808\r\n")),
        Err(ParseError::Overflow)
    );
}

#[test]
fn trailing_junk_is_malformed_not_overflow() {
    // The i64::MIN digits followed by junk are malformed, not out of range.
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b":-9223372036854775808X\r\n")),
        Err(ParseError::InvalidFormat)
    );
    // Same shape one digit lower, which never tripped the guard.
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b":9223372036854775807X\r\n")),
        Err(ParseError::InvalidFormat)
    );
    // i64::MIN itself must still parse, and one past it is still Overflow.
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b":-9223372036854775808\r\n"))
            .unwrap()
            .0,
        Frame::Integer(i64::MIN)
    );
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b":-9223372036854775809\r\n")),
        Err(ParseError::Overflow)
    );
}

#[test]
fn signed_integer_inside_an_aggregate() {
    // The failure previously took the enclosing frame with it.
    let (frame, _) = resp2::parse_frame(Bytes::from_static(b"*1\r\n:+42\r\n")).unwrap();
    assert_eq!(frame, Frame::Array(Some(vec![Frame::Integer(42)])));
}

#[test]
fn lengths_and_counts_still_reject_a_plus() {
    // The sign is part of the integer grammar only. Lengths and counts have no
    // sign, so a leading `+` must stay rejected there.
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b"$+5\r\nhello\r\n")),
        Err(ParseError::BadLength)
    );
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b"*+1\r\n:1\r\n")),
        Err(ParseError::BadLength)
    );
}

// --- Line length ceiling (issue #63) ---

#[test]
fn unterminated_line_is_rejected_not_buffered_forever() {
    // Every line-based prefix. Without a ceiling these all returned Incomplete,
    // which Parser reads as "need more data", so the peer could grow the buffer
    // without bound.
    for tag in ["+", "-", ":", "$", "*"] {
        let mut wire = tag.to_string();
        wire.push_str(&"x".repeat(resp2::MAX_LINE_LENGTH + 1));
        assert_eq!(
            resp2::parse_frame(Bytes::from(wire)),
            Err(ParseError::LineTooLong),
            "tag {tag}"
        );
    }
}

#[test]
fn a_line_at_the_limit_still_parses() {
    // The ceiling must not reject anything a peer could legitimately send just
    // under it.
    let mut wire = String::from("+");
    wire.push_str(&"y".repeat(resp2::MAX_LINE_LENGTH));
    wire.push_str("\r\n");
    let (frame, rest) = resp2::parse_frame(Bytes::from(wire)).unwrap();
    assert!(rest.is_empty());
    assert_eq!(frame.as_bytes().unwrap().len(), resp2::MAX_LINE_LENGTH);
}

#[test]
fn a_short_unterminated_line_is_still_incomplete() {
    // Under the ceiling, "not yet" must still be reported as Incomplete so
    // streaming works.
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b"+partial")),
        Err(ParseError::Incomplete)
    );
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b"+partial\r")),
        Err(ParseError::Incomplete)
    );
}

#[test]
fn parser_stops_buffering_an_unterminated_line() {
    let mut parser = resp2::Parser::new();
    parser.feed(Bytes::from_static(b"+"));

    let mut fed = 1usize;
    for _ in 0..64 {
        parser.feed(Bytes::from(vec![b'x'; 8192]));
        fed += 8192;
        match parser.next_frame() {
            Ok(None) => continue,
            Err(ParseError::LineTooLong) => {
                // Hard error, so the buffer is dropped rather than retained.
                assert_eq!(parser.buffered_bytes(), 0);
                assert!(
                    fed < resp2::MAX_LINE_LENGTH * 2,
                    "kept buffering to {fed} bytes"
                );
                return;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    panic!("parser never stopped buffering");
}
