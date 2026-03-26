//! Zero-copy RESP2 and RESP3 protocol parser and serializer.
//!
//! `resp-rs` provides high-performance parsing and serialization for the
//! [Redis Serialization Protocol](https://redis.io/docs/latest/develop/reference/protocol-spec/)
//! (RESP), supporting both RESP2 and RESP3.
//!
//! # Features
//!
//! - **Zero-copy parsing** using [`bytes::Bytes`] -- parsing a bulk string is an O(1)
//!   slice operation, not a copy
//! - **RESP2 and RESP3** support with separate [`resp2::Frame`] and [`resp3::Frame`] types
//! - **Streaming parser** ([`resp2::Parser`] / [`resp3::Parser`]) for incremental data --
//!   handles partial reads and pipelining
//! - **Serialization** via [`resp2::frame_to_bytes`] and [`resp3::frame_to_bytes`]
//! - **Minimal dependencies** -- only [`bytes`] and [`thiserror`]
//! - **No async runtime required** -- pure sync parsing that works in any context
//!
//! # Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`resp2`] | RESP2 types, [`resp2::parse_frame`], [`resp2::frame_to_bytes`], [`resp2::Parser`] |
//! | [`resp3`] | RESP3 types, [`resp3::parse_frame`], [`resp3::frame_to_bytes`], [`resp3::Parser`], [`resp3::parse_streaming_sequence`] |
//!
//! # Quick Start
//!
//! ## Parsing a RESP2 command
//!
//! ```
//! use bytes::Bytes;
//! use resp_rs::resp2::{self, Frame};
//!
//! // A Redis SET command on the wire
//! let data = Bytes::from("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
//! let (frame, remaining) = resp2::parse_frame(data).unwrap();
//!
//! assert_eq!(frame, Frame::Array(Some(vec![
//!     Frame::BulkString(Some(Bytes::from("SET"))),
//!     Frame::BulkString(Some(Bytes::from("key"))),
//!     Frame::BulkString(Some(Bytes::from("value"))),
//! ])));
//! assert!(remaining.is_empty());
//! ```
//!
//! ## Parsing RESP3 types
//!
//! RESP3 adds null, booleans, doubles, maps, sets, and more:
//!
//! ```
//! use bytes::Bytes;
//! use resp_rs::resp3::{self, Frame};
//!
//! // Simple string
//! let (frame, _) = resp3::parse_frame(Bytes::from("+OK\r\n")).unwrap();
//! assert_eq!(frame, Frame::SimpleString(Bytes::from("OK")));
//!
//! // Null
//! let (frame, _) = resp3::parse_frame(Bytes::from("_\r\n")).unwrap();
//! assert_eq!(frame, Frame::Null);
//!
//! // Boolean
//! let (frame, _) = resp3::parse_frame(Bytes::from("#t\r\n")).unwrap();
//! assert_eq!(frame, Frame::Boolean(true));
//!
//! // Double
//! let (frame, _) = resp3::parse_frame(Bytes::from(",3.14\r\n")).unwrap();
//! assert_eq!(frame, Frame::Double(3.14));
//!
//! // Integer
//! let (frame, _) = resp3::parse_frame(Bytes::from(":-42\r\n")).unwrap();
//! assert_eq!(frame, Frame::Integer(-42));
//!
//! // Bulk string
//! let (frame, _) = resp3::parse_frame(Bytes::from("$5\r\nhello\r\n")).unwrap();
//! assert_eq!(frame, Frame::BulkString(Some(Bytes::from("hello"))));
//!
//! // Null bulk string
//! let (frame, _) = resp3::parse_frame(Bytes::from("$-1\r\n")).unwrap();
//! assert_eq!(frame, Frame::BulkString(None));
//!
//! // Array
//! let (frame, _) = resp3::parse_frame(Bytes::from("*2\r\n:1\r\n:2\r\n")).unwrap();
//! assert_eq!(frame, Frame::Array(Some(vec![Frame::Integer(1), Frame::Integer(2)])));
//!
//! // Map
//! let data = Bytes::from("%2\r\n+name\r\n$5\r\nAlice\r\n+age\r\n:30\r\n");
//! let (frame, _) = resp3::parse_frame(data).unwrap();
//! assert_eq!(frame, Frame::Map(vec![
//!     (Frame::SimpleString(Bytes::from("name")), Frame::BulkString(Some(Bytes::from("Alice")))),
//!     (Frame::SimpleString(Bytes::from("age")), Frame::Integer(30)),
//! ]));
//!
//! // Set
//! let (frame, _) = resp3::parse_frame(Bytes::from("~3\r\n:1\r\n:2\r\n:3\r\n")).unwrap();
//! assert_eq!(frame, Frame::Set(vec![Frame::Integer(1), Frame::Integer(2), Frame::Integer(3)]));
//!
//! // Big number
//! let (frame, _) = resp3::parse_frame(Bytes::from("(12345678901234567890\r\n")).unwrap();
//! assert_eq!(frame, Frame::BigNumber(Bytes::from("12345678901234567890")));
//!
//! // Verbatim string
//! let (frame, _) = resp3::parse_frame(Bytes::from("=15\r\ntxt:hello world\r\n")).unwrap();
//! assert_eq!(frame, Frame::VerbatimString(Bytes::from("txt"), Bytes::from("hello world")));
//!
//! // Blob error
//! let (frame, _) = resp3::parse_frame(Bytes::from("!5\r\nOOPS!\r\n")).unwrap();
//! assert_eq!(frame, Frame::BlobError(Bytes::from("OOPS!")));
//!
//! // Error
//! let (frame, _) = resp3::parse_frame(Bytes::from("-ERR unknown\r\n")).unwrap();
//! assert_eq!(frame, Frame::Error(Bytes::from("ERR unknown")));
//! ```
//!
//! ## Serialization
//!
//! Convert any [`resp2::Frame`] or [`resp3::Frame`] back to wire format:
//!
//! ```
//! use bytes::Bytes;
//! use resp_rs::resp2::{Frame, frame_to_bytes};
//!
//! let frame = Frame::Array(Some(vec![
//!     Frame::BulkString(Some(Bytes::from("GET"))),
//!     Frame::BulkString(Some(Bytes::from("mykey"))),
//! ]));
//! let wire = frame_to_bytes(&frame);
//! assert_eq!(wire, Bytes::from("*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n"));
//! ```
//!
//! Roundtrip is guaranteed: `parse_frame(frame_to_bytes(&frame)) == Ok((frame, empty))`.
//!
//! ## Streaming parser
//!
//! The [`resp2::Parser`] and [`resp3::Parser`] types buffer incremental data
//! and yield frames as they become complete -- ideal for reading from TCP sockets.
//!
//! ```
//! use bytes::Bytes;
//! use resp_rs::resp3::{Parser, Frame};
//!
//! let mut parser = Parser::new();
//!
//! // Simulate receiving data in chunks (e.g., from TCP)
//! parser.feed(Bytes::from("+HEL"));
//! assert!(parser.next_frame().unwrap().is_none()); // not enough data yet
//!
//! parser.feed(Bytes::from("LO\r\n:42\r\n"));
//! // Now we have two complete frames buffered
//!
//! let frame1 = parser.next_frame().unwrap().unwrap();
//! assert_eq!(frame1, Frame::SimpleString(Bytes::from("HELLO")));
//!
//! let frame2 = parser.next_frame().unwrap().unwrap();
//! assert_eq!(frame2, Frame::Integer(42));
//!
//! assert!(parser.next_frame().unwrap().is_none()); // buffer exhausted
//! ```
//!
//! ## Pipelined commands
//!
//! Multiple frames in a single buffer parse naturally in sequence:
//!
//! ```
//! use bytes::Bytes;
//! use resp_rs::resp2::{self, Frame};
//!
//! let wire = Bytes::from("+OK\r\n$5\r\nhello\r\n:42\r\n");
//!
//! let (f1, rest) = resp2::parse_frame(wire).unwrap();
//! assert_eq!(f1, Frame::SimpleString(Bytes::from("OK")));
//!
//! let (f2, rest) = resp2::parse_frame(rest).unwrap();
//! assert_eq!(f2, Frame::BulkString(Some(Bytes::from("hello"))));
//!
//! let (f3, rest) = resp2::parse_frame(rest).unwrap();
//! assert_eq!(f3, Frame::Integer(42));
//!
//! assert!(rest.is_empty());
//! ```
//!
//! ## RESP3 streaming sequences
//!
//! RESP3 supports chunked/streaming data. Use [`resp3::parse_streaming_sequence`]
//! to accumulate chunks into a complete frame:
//!
//! ```
//! use bytes::Bytes;
//! use resp_rs::resp3::{self, Frame};
//!
//! // Streaming string: $?\r\n followed by chunks, terminated by ;0\r\n
//! let data = Bytes::from("$?\r\n;5\r\nHello\r\n;6\r\n World\r\n;0\r\n\r\n");
//! let (frame, _) = resp3::parse_streaming_sequence(data).unwrap();
//!
//! if let Frame::StreamedString(chunks) = frame {
//!     assert_eq!(chunks.len(), 2);
//!     assert_eq!(chunks[0], Bytes::from("Hello"));
//!     assert_eq!(chunks[1], Bytes::from(" World"));
//! }
//! ```
//!
//! # Error Handling
//!
//! All parsing functions return [`Result<_, ParseError>`]. The [`ParseError::Incomplete`]
//! variant signals that more data is needed (not a protocol error), while other
//! variants indicate malformed input.
//!
//! ```
//! use bytes::Bytes;
//! use resp_rs::{ParseError, resp2};
//!
//! // Not enough data
//! assert_eq!(resp2::parse_frame(Bytes::from("$5\r\nhel")), Err(ParseError::Incomplete));
//!
//! // Unknown type tag
//! assert_eq!(resp2::parse_frame(Bytes::from("X\r\n")), Err(ParseError::InvalidTag(b'X')));
//!
//! // Empty input
//! assert_eq!(resp2::parse_frame(Bytes::new()), Err(ParseError::Incomplete));
//! ```

pub mod resp2;
pub mod resp3;

/// Errors that can occur during RESP parsing.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ParseError {
    /// Not enough data to parse a complete frame.
    #[error("incomplete data")]
    Incomplete,

    /// Invalid type tag byte at the start of a frame.
    #[error("invalid tag byte: 0x{0:02x}")]
    InvalidTag(u8),

    /// Invalid length in a bulk string or collection.
    #[error("invalid length")]
    BadLength,

    /// Invalid UTF-8 in a string value.
    #[error("invalid UTF-8")]
    Utf8Error,

    /// Invalid frame format.
    #[error("invalid format")]
    InvalidFormat,

    /// Invalid boolean value (not 't' or 'f').
    #[error("invalid boolean value")]
    InvalidBoolean,

    /// Invalid special float (not 'inf', '-inf', or 'nan').
    #[error("invalid special float")]
    InvalidSpecialFloat,

    /// Integer value overflowed i64 range.
    #[error("integer overflow")]
    Overflow,
}
