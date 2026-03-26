//! Zero-copy RESP2 and RESP3 protocol parser and serializer.
//!
//! `resp-rs` provides high-performance parsing and serialization for the
//! Redis Serialization Protocol (RESP), supporting both RESP2 and RESP3.
//!
//! # Features
//!
//! - **Zero-copy parsing** using `bytes::Bytes` for efficient memory management
//! - **RESP2 and RESP3** support with separate frame types
//! - **Streaming parser** for incremental data (handles partial reads and pipelining)
//! - **High performance**: 4.8-8.0 GB/s throughput in benchmarks
//!
//! # Quick Start
//!
//! ## RESP3 (recommended for new projects)
//!
//! ```
//! use bytes::Bytes;
//! use resp_rs::resp3;
//!
//! let data = Bytes::from("+OK\r\n");
//! let (frame, remaining) = resp3::parse_frame(data).unwrap();
//! assert_eq!(frame, resp3::Frame::SimpleString(Bytes::from("OK")));
//! ```
//!
//! ## RESP2
//!
//! ```
//! use bytes::Bytes;
//! use resp_rs::resp2;
//!
//! let data = Bytes::from("+OK\r\n");
//! let (frame, remaining) = resp2::parse_frame(data).unwrap();
//! assert_eq!(frame, resp2::Frame::SimpleString(Bytes::from("OK")));
//! ```
//!
//! ## Streaming parser (handles partial reads)
//!
//! ```
//! use bytes::Bytes;
//! use resp_rs::resp3::Parser;
//!
//! let mut parser = Parser::new();
//!
//! // Feed partial data
//! parser.feed(Bytes::from("+HEL"));
//! assert!(parser.next_frame().unwrap().is_none()); // Incomplete
//!
//! // Feed the rest
//! parser.feed(Bytes::from("LO\r\n"));
//! let frame = parser.next_frame().unwrap().unwrap(); // Complete!
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
