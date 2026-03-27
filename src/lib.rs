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
//! # Tokio Codec (async)
//!
//! Enable the `codec` feature for `tokio_util::codec` integration:
//!
//! ```toml
//! [dependencies]
//! resp-rs = { version = "0.1", features = ["codec"] }
//! tokio = { version = "1", features = ["net"] }
//! tokio-util = { version = "0.7", features = ["codec"] }
//! futures = "0.3"  # for SinkExt / StreamExt
//! ```
//!
//! This provides `resp2::Codec` and `resp3::Codec`, which implement
//! `tokio_util::codec::Decoder` and `tokio_util::codec::Encoder`.
//! Wrap a TCP stream with `tokio_util::codec::Framed` for async
//! frame-level I/O:
//!
//! ```ignore
//! use resp_rs::resp2::{Codec, Frame};
//! use tokio::net::TcpStream;
//! use tokio_util::codec::Framed;
//! use futures::{SinkExt, StreamExt};
//! use bytes::Bytes;
//!
//! let stream = TcpStream::connect("127.0.0.1:6379").await?;
//! let mut framed = Framed::new(stream, Codec::new());
//!
//! // Send a PING
//! framed.send(Frame::Array(Some(vec![
//!     Frame::BulkString(Some(Bytes::from("PING"))),
//! ]))).await?;
//!
//! // Read the response
//! if let Some(Ok(frame)) = framed.next().await {
//!     println!("{frame:?}"); // SimpleString("PONG")
//! }
//! ```
//!
//! The decoder uses the same zero-copy [`parse_frame`](resp2::parse_frame) path
//! internally. Errors are returned as `codec::CodecError`, which wraps both
//! [`ParseError`] and `std::io::Error`.
//!
//! # Working with Frames
//!
//! Both [`resp2::Frame`] and [`resp3::Frame`] provide convenience methods for
//! extracting typed data without manual pattern matching:
//!
//! ```
//! use bytes::Bytes;
//! use resp_rs::resp2::{self, Frame};
//!
//! let data = Bytes::from("*3\r\n+SET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
//! let (frame, _) = resp2::parse_frame(data).unwrap();
//!
//! // Extract array items
//! let items = frame.into_array().unwrap();
//! assert_eq!(items[0].as_str(), Some("SET"));
//! assert_eq!(items[1].as_str(), Some("key"));
//! assert_eq!(items[2].as_str(), Some("value"));
//! ```
//!
//! Available methods include:
//!
//! | Method | Returns | Works on |
//! |--------|---------|----------|
//! | `as_bytes()` | `Option<&Bytes>` | Strings, bulk strings, errors |
//! | `as_str()` | `Option<&str>` | String-like frames with valid UTF-8 |
//! | `as_integer()` | `Option<i64>` | `Integer` |
//! | `as_double()` | `Option<f64>` | `Double` (RESP3 only) |
//! | `as_boolean()` | `Option<bool>` | `Boolean` (RESP3 only) |
//! | `as_array()` | `Option<&[Frame]>` | `Array` |
//! | `as_map()` | `Option<&[(Frame, Frame)]>` | `Map` (RESP3 only) |
//! | `into_array()` | `Result<Vec<Frame>, Frame>` | `Array` |
//! | `into_bulk_string()` | `Result<Bytes, Frame>` | `BulkString` |
//! | `into_map()` | `Result<Vec<(Frame, Frame)>, Frame>` | `Map` (RESP3 only) |
//! | `is_null()` | `bool` | Any frame |
//! | `is_error()` | `bool` | Any frame |
//!
//! # Redis Cluster (hash slots)
//!
//! Enable the `cluster` feature for hash slot calculation:
//!
//! ```toml
//! [dependencies]
//! resp-rs = { version = "0.1", features = ["cluster"] }
//! ```
//!
//! ```ignore
//! use resp_rs::cluster::hash_slot;
//!
//! // Keys with the same hash tag route to the same slot
//! assert_eq!(hash_slot(b"{user}.name"), hash_slot(b"{user}.email"));
//! ```
//!
//! Implements CRC16-CCITT with hash tag extraction per the
//! [Redis Cluster specification](https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/#hash-tags).
//!
//! # Performance
//!
//! The parser uses offset-based internal parsing to minimize allocations. Bulk string
//! parsing is an O(1) slice into the input buffer, not a copy.
//!
//! ## `parse_frame` vs `Parser`
//!
//! [`resp2::parse_frame`] and [`resp3::parse_frame`] parse directly from a [`bytes::Bytes`]
//! buffer with no overhead. The [`resp2::Parser`] and [`resp3::Parser`] wrappers add
//! incremental buffering for TCP streams, but have roughly 2x overhead per frame due to
//! internal `BytesMut` split/unsplit operations.
//!
//! **If you already have a complete buffer** (e.g., a full response read from a socket),
//! call `parse_frame` directly in a loop rather than going through `Parser`:
//!
//! ```
//! use bytes::Bytes;
//! use resp_rs::resp2;
//!
//! let wire = Bytes::from("+OK\r\n:42\r\n$5\r\nhello\r\n");
//! let mut input = wire;
//! while !input.is_empty() {
//!     match resp2::parse_frame(input) {
//!         Ok((frame, rest)) => {
//!             // process frame
//!             input = rest;
//!         }
//!         Err(resp_rs::ParseError::Incomplete) => break, // need more data
//!         Err(e) => panic!("parse error: {e}"),
//!     }
//! }
//! ```
//!
//! **Use `Parser` when** data arrives incrementally (e.g., reading from a TCP socket in
//! chunks) and you need to buffer partial frames across reads.
//!
//! ## RESP2 vs RESP3
//!
//! RESP2 parsing is roughly 3x faster than RESP3 for simple types due to RESP2's smaller
//! type tag match (5 variants vs 16+). The gap narrows for collection-heavy workloads
//! where per-element parsing dominates. If your application only needs RESP2, prefer the
//! [`resp2`] module for best performance.
//!
//! ## Representative timings
//!
//! Measured on Apple M4 (single core, criterion):
//!
//! | Operation | RESP2 | RESP3 |
//! |-----------|-------|-------|
//! | Simple string | 12 ns | 39 ns |
//! | Bulk string | 13 ns | 39 ns |
//! | Integer | 25 ns | 47 ns |
//! | 3-element array | 43 ns | 82 ns |
//! | 100-element array | 822 ns | 2.0 us |
//! | 5-frame pipeline (direct) | 107 ns | 129 ns |
//! | 5-frame pipeline (Parser) | 242 ns | 286 ns |
//! | Streaming string (2 chunks) | -- | 124 ns |
//! | Streaming array (5 elements) | -- | 226 ns |
//!
//! Run `cargo bench` to reproduce on your hardware.
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

#[cfg(feature = "codec")]
pub mod codec;

#[cfg(feature = "cluster")]
pub mod cluster;

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
