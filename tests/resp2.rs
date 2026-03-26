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
