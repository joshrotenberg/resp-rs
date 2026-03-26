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
        Frame::VerbatimString(Bytes::from("txt"), Bytes::from("hello world"))
    );
}

#[test]
fn verbatim_string_mkd() {
    let (frame, _) = resp3::parse_frame(Bytes::from("=12\r\nmkd:# Header\r\n")).unwrap();
    assert_eq!(
        frame,
        Frame::VerbatimString(Bytes::from("mkd"), Bytes::from("# Header"))
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
    let wire = Bytes::from("$?\r\n;5\r\nHello\r\n;6\r\n World\r\n;0\r\n\r\n");
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
