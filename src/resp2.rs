//! RESP2 protocol parser and serializer.
//!
//! RESP2 supports five data types:
//! - Simple String: `+OK\r\n`
//! - Error: `-ERR message\r\n`
//! - Integer: `:42\r\n`
//! - Bulk String: `$6\r\nfoobar\r\n` (or `$-1\r\n` for null)
//! - Array: `*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n` (or `*-1\r\n` for null)
//!
//! # Performance
//!
//! For complete buffers, call [`parse_frame`] directly in a loop rather than
//! using [`Parser`]. The `Parser` wrapper adds ~2x overhead per frame for its
//! incremental buffering. See the [crate-level performance docs](crate#performance)
//! for details and representative timings.
//!
//! # Protocol permissiveness
//!
//! Simple strings and errors are treated as raw bytes, not validated UTF-8.
//! The parser accepts any byte sequence that does not contain `\r` or `\n`.
//! This is intentional for zero-copy operation and compatibility with
//! servers that may send non-UTF-8 data in these fields.

use alloc::string::ToString;
use alloc::vec::Vec;

use bytes::{BufMut, Bytes, BytesMut};

use crate::ParseError;

/// Maximum reasonable size for collections to prevent DoS attacks.
const MAX_COLLECTION_SIZE: usize = 10_000_000;

/// Maximum reasonable size for bulk string payloads (512 MB).
const MAX_BULK_STRING_SIZE: usize = 512 * 1024 * 1024;

/// A parsed RESP2 frame.
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    /// Simple string: `+OK\r\n`
    SimpleString(Bytes),
    /// Error: `-ERR message\r\n`
    Error(Bytes),
    /// Integer: `:42\r\n`
    Integer(i64),
    /// Bulk string: `$6\r\nfoobar\r\n`
    BulkString(Option<Bytes>),
    /// Array: `*N\r\n...`
    Array(Option<Vec<Frame>>),
}

impl Frame {
    /// Returns the bytes if this is a `SimpleString`, `Error`, or `BulkString`.
    ///
    /// For `BulkString(None)` (null), returns `None`.
    pub fn as_bytes(&self) -> Option<&Bytes> {
        match self {
            Frame::SimpleString(b) | Frame::Error(b) => Some(b),
            Frame::BulkString(opt) => opt.as_ref(),
            _ => None,
        }
    }

    /// Returns the string data as a UTF-8 `&str`, if this is a string-like frame
    /// and contains valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| core::str::from_utf8(b).ok())
    }

    /// Returns the integer value if this is an `Integer` frame.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Frame::Integer(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns a reference to the array items if this is an `Array`.
    ///
    /// For `Array(None)` (null), returns `None`.
    pub fn as_array(&self) -> Option<&[Frame]> {
        match self {
            Frame::Array(Some(items)) => Some(items),
            _ => None,
        }
    }

    /// Consumes the frame and returns the array items.
    ///
    /// Returns `Err(self)` if this is not a non-null `Array`.
    pub fn into_array(self) -> Result<Vec<Frame>, Frame> {
        match self {
            Frame::Array(Some(items)) => Ok(items),
            other => Err(other),
        }
    }

    /// Consumes the frame and returns the bulk string bytes.
    ///
    /// Returns `Err(self)` if this is not a non-null `BulkString`.
    pub fn into_bulk_string(self) -> Result<Bytes, Frame> {
        match self {
            Frame::BulkString(Some(b)) => Ok(b),
            other => Err(other),
        }
    }

    /// Returns `true` if this is a null bulk string or null array.
    pub fn is_null(&self) -> bool {
        matches!(self, Frame::BulkString(None) | Frame::Array(None))
    }

    /// Returns `true` if this is an `Error` frame.
    pub fn is_error(&self) -> bool {
        matches!(self, Frame::Error(_))
    }
}

/// Parse a single RESP2 frame from the provided bytes.
///
/// Returns the parsed frame and any remaining unconsumed bytes.
///
/// # Errors
///
/// Returns `ParseError::Incomplete` if there isn't enough data for a complete frame.
/// Returns other `ParseError` variants for malformed input.
///
/// # Examples
///
/// ```
/// use bytes::Bytes;
/// use resp_rs::resp2::parse_frame;
///
/// let data = Bytes::from("+OK\r\nrest");
/// let (frame, rest) = parse_frame(data).unwrap();
/// assert_eq!(rest, Bytes::from("rest"));
/// ```
pub fn parse_frame(input: Bytes) -> Result<(Frame, Bytes), ParseError> {
    let (frame, consumed) = parse_frame_inner(&input, 0)?;
    Ok((frame, input.slice(consumed..)))
}

/// Offset-based internal parser. Works with byte positions to avoid creating
/// intermediate `Bytes::slice()` objects. Only slices for actual frame data.
pub(crate) fn parse_frame_inner(input: &Bytes, pos: usize) -> Result<(Frame, usize), ParseError> {
    let buf = input.as_ref();
    if pos >= buf.len() {
        return Err(ParseError::Incomplete);
    }

    let tag = buf[pos];

    match tag {
        b'+' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            Ok((
                Frame::SimpleString(input.slice(pos + 1..line_end)),
                after_crlf,
            ))
        }
        b'-' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            Ok((Frame::Error(input.slice(pos + 1..line_end)), after_crlf))
        }
        b':' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let v = parse_i64(&buf[pos + 1..line_end])?;
            Ok((Frame::Integer(v), after_crlf))
        }
        b'$' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let len_bytes = &buf[pos + 1..line_end];
            // null bulk string: $-1\r\n
            if len_bytes == b"-1" {
                return Ok((Frame::BulkString(None), after_crlf));
            }
            let len = parse_usize(len_bytes)?;
            if len > MAX_BULK_STRING_SIZE {
                return Err(ParseError::BadLength);
            }
            if len == 0 {
                if after_crlf + 1 >= buf.len() {
                    return Err(ParseError::Incomplete);
                }
                if buf[after_crlf] == b'\r' && buf[after_crlf + 1] == b'\n' {
                    return Ok((Frame::BulkString(Some(Bytes::new())), after_crlf + 2));
                } else {
                    return Err(ParseError::InvalidFormat);
                }
            }
            let data_start = after_crlf;
            let data_end = data_start.checked_add(len).ok_or(ParseError::BadLength)?;
            if data_end + 1 >= buf.len() {
                return Err(ParseError::Incomplete);
            }
            if buf[data_end] != b'\r' || buf[data_end + 1] != b'\n' {
                return Err(ParseError::InvalidFormat);
            }
            Ok((
                Frame::BulkString(Some(input.slice(data_start..data_end))),
                data_end + 2,
            ))
        }
        b'*' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let len_bytes = &buf[pos + 1..line_end];
            // null array: *-1\r\n
            if len_bytes == b"-1" {
                return Ok((Frame::Array(None), after_crlf));
            }
            let count = parse_count(len_bytes)?;
            if count == 0 {
                return Ok((Frame::Array(Some(Vec::new())), after_crlf));
            }
            let mut cursor = after_crlf;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                let (item, next) = parse_frame_inner(input, cursor)?;
                items.push(item);
                cursor = next;
            }
            Ok((Frame::Array(Some(items)), cursor))
        }
        _ => Err(ParseError::InvalidTag(tag)),
    }
}

#[cfg(feature = "unsafe-internals")]
#[path = "resp2_unchecked.rs"]
mod unchecked;
#[cfg(feature = "unsafe-internals")]
pub use unchecked::parse_frame_unchecked;

#[cfg(feature = "codec")]
#[path = "resp2_codec.rs"]
mod codec_impl;
#[cfg(feature = "codec")]
pub use codec_impl::Codec;

/// Serialize a RESP2 frame to bytes.
///
/// # Examples
///
/// ```
/// use bytes::Bytes;
/// use resp_rs::resp2::{Frame, frame_to_bytes};
///
/// let frame = Frame::SimpleString(Bytes::from("OK"));
/// assert_eq!(frame_to_bytes(&frame), Bytes::from("+OK\r\n"));
/// ```
pub fn frame_to_bytes(frame: &Frame) -> Bytes {
    let mut buf = BytesMut::new();
    serialize_frame(frame, &mut buf);
    buf.freeze()
}

fn serialize_frame(frame: &Frame, buf: &mut BytesMut) {
    match frame {
        Frame::SimpleString(s) => {
            buf.put_u8(b'+');
            buf.extend_from_slice(s);
            buf.extend_from_slice(b"\r\n");
        }
        Frame::Error(s) => {
            buf.put_u8(b'-');
            buf.extend_from_slice(s);
            buf.extend_from_slice(b"\r\n");
        }
        Frame::Integer(i) => {
            buf.put_u8(b':');
            buf.extend_from_slice(i.to_string().as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        Frame::BulkString(opt) => {
            buf.put_u8(b'$');
            match opt {
                Some(data) => {
                    buf.extend_from_slice(data.len().to_string().as_bytes());
                    buf.extend_from_slice(b"\r\n");
                    buf.extend_from_slice(data);
                    buf.extend_from_slice(b"\r\n");
                }
                None => buf.extend_from_slice(b"-1\r\n"),
            }
        }
        Frame::Array(opt) => {
            buf.put_u8(b'*');
            match opt {
                Some(items) => {
                    buf.extend_from_slice(items.len().to_string().as_bytes());
                    buf.extend_from_slice(b"\r\n");
                    for item in items {
                        serialize_frame(item, buf);
                    }
                }
                None => buf.extend_from_slice(b"-1\r\n"),
            }
        }
    }
}

/// Streaming RESP2 parser.
///
/// Feed data incrementally and extract frames as they become available.
///
/// # Examples
///
/// ```
/// use bytes::Bytes;
/// use resp_rs::resp2::{Parser, Frame};
///
/// let mut parser = Parser::new();
/// parser.feed(Bytes::from("+HEL"));
/// assert!(parser.next_frame().unwrap().is_none());
///
/// parser.feed(Bytes::from("LO\r\n"));
/// let frame = parser.next_frame().unwrap().unwrap();
/// assert_eq!(frame, Frame::SimpleString(Bytes::from("HELLO")));
/// ```
#[derive(Default, Debug)]
pub struct Parser {
    buffer: BytesMut,
}

impl Parser {
    /// Create a new empty parser.
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }

    /// Feed data into the parser buffer.
    pub fn feed(&mut self, data: Bytes) {
        self.buffer.extend_from_slice(&data);
    }

    /// Try to extract the next complete frame.
    ///
    /// Returns `Ok(None)` if there isn't enough data yet.
    /// Returns `Err` on protocol errors (buffer is cleared).
    pub fn next_frame(&mut self) -> Result<Option<Frame>, ParseError> {
        if self.buffer.is_empty() {
            return Ok(None);
        }

        let bytes = self.buffer.split().freeze();

        match parse_frame_inner(&bytes, 0) {
            Ok((frame, consumed)) => {
                if consumed < bytes.len() {
                    self.buffer.unsplit(BytesMut::from(&bytes[consumed..]));
                }
                Ok(Some(frame))
            }
            Err(ParseError::Incomplete) => {
                self.buffer.unsplit(bytes.into());
                Ok(None)
            }
            Err(e) => {
                // Buffer was emptied by split() above; intentionally not restored
                // on hard errors so the parser doesn't re-parse corrupt data.
                Err(e)
            }
        }
    }

    /// Number of bytes currently buffered.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Clear the internal buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Find `\r\n` in `buf` starting at `from`. Returns `(line_end, after_crlf)` where
/// `line_end` is the position of `\r` and `after_crlf` is the position after `\n`.
#[inline]
fn find_crlf(buf: &[u8], from: usize) -> Result<(usize, usize), ParseError> {
    let mut i = from;
    let len = buf.len();
    while i + 1 < len {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Ok((i, i + 2));
        }
        i += 1;
    }
    Err(ParseError::Incomplete)
}

/// Parse a `usize` directly from ASCII digit bytes, no UTF-8 validation needed.
#[inline]
fn parse_usize(buf: &[u8]) -> Result<usize, ParseError> {
    if buf.is_empty() {
        return Err(ParseError::BadLength);
    }
    let mut v: usize = 0;
    for &b in buf {
        if !b.is_ascii_digit() {
            return Err(ParseError::BadLength);
        }
        v = v.checked_mul(10).ok_or(ParseError::BadLength)?;
        v = v
            .checked_add((b - b'0') as usize)
            .ok_or(ParseError::BadLength)?;
    }
    Ok(v)
}

/// Parse a collection count (usize) with MAX_COLLECTION_SIZE check.
#[inline]
fn parse_count(buf: &[u8]) -> Result<usize, ParseError> {
    let count = parse_usize(buf)?;
    if count > MAX_COLLECTION_SIZE {
        return Err(ParseError::BadLength);
    }
    Ok(count)
}

/// Parse an `i64` directly from ASCII bytes (optional leading `-`), no UTF-8 validation.
#[inline]
fn parse_i64(buf: &[u8]) -> Result<i64, ParseError> {
    if buf.is_empty() {
        return Err(ParseError::InvalidFormat);
    }
    let (neg, digits) = if buf[0] == b'-' {
        (true, &buf[1..])
    } else {
        (false, buf)
    };
    if digits.is_empty() {
        return Err(ParseError::InvalidFormat);
    }
    let mut v: i64 = 0;
    for (i, &d) in digits.iter().enumerate() {
        if !d.is_ascii_digit() {
            return Err(ParseError::InvalidFormat);
        }
        let digit = (d - b'0') as i64;
        if neg && v == i64::MAX / 10 && digit == 8 && i == digits.len() - 1 {
            return Ok(i64::MIN);
        }
        if v > i64::MAX / 10 || (v == i64::MAX / 10 && digit > i64::MAX % 10) {
            return Err(ParseError::Overflow);
        }
        v = v * 10 + digit;
    }
    if neg { Ok(-v) } else { Ok(v) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_string() {
        let (frame, rest) = parse_frame(Bytes::from("+OK\r\nrest")).unwrap();
        assert_eq!(frame, Frame::SimpleString(Bytes::from("OK")));
        assert_eq!(rest, Bytes::from("rest"));
    }

    #[test]
    fn error() {
        let (frame, _) = parse_frame(Bytes::from("-ERR fail\r\n")).unwrap();
        assert_eq!(frame, Frame::Error(Bytes::from("ERR fail")));
    }

    #[test]
    fn integer() {
        let (frame, _) = parse_frame(Bytes::from(":42\r\n")).unwrap();
        assert_eq!(frame, Frame::Integer(42));

        let (frame, _) = parse_frame(Bytes::from(":-123\r\n")).unwrap();
        assert_eq!(frame, Frame::Integer(-123));
    }

    #[test]
    fn bulk_string() {
        let (frame, rest) = parse_frame(Bytes::from("$5\r\nhello\r\nX")).unwrap();
        assert_eq!(frame, Frame::BulkString(Some(Bytes::from("hello"))));
        assert_eq!(rest, Bytes::from("X"));
    }

    #[test]
    fn null_bulk_string() {
        let (frame, _) = parse_frame(Bytes::from("$-1\r\n")).unwrap();
        assert_eq!(frame, Frame::BulkString(None));
    }

    #[test]
    fn empty_bulk_string() {
        let (frame, rest) = parse_frame(Bytes::from("$0\r\n\r\nX")).unwrap();
        assert_eq!(frame, Frame::BulkString(Some(Bytes::new())));
        assert_eq!(rest, Bytes::from("X"));
    }

    #[test]
    fn array() {
        let input = Bytes::from("*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n");
        let (frame, _) = parse_frame(input).unwrap();
        assert_eq!(
            frame,
            Frame::Array(Some(vec![
                Frame::BulkString(Some(Bytes::from("foo"))),
                Frame::BulkString(Some(Bytes::from("bar"))),
            ]))
        );
    }

    #[test]
    fn null_array() {
        let (frame, _) = parse_frame(Bytes::from("*-1\r\n")).unwrap();
        assert_eq!(frame, Frame::Array(None));
    }

    #[test]
    fn empty_array() {
        let (frame, _) = parse_frame(Bytes::from("*0\r\n")).unwrap();
        assert_eq!(frame, Frame::Array(Some(vec![])));
    }

    #[test]
    fn nested_array() {
        let input = Bytes::from("*2\r\n*1\r\n:1\r\n+OK\r\n");
        let (frame, _) = parse_frame(input).unwrap();
        assert_eq!(
            frame,
            Frame::Array(Some(vec![
                Frame::Array(Some(vec![Frame::Integer(1)])),
                Frame::SimpleString(Bytes::from("OK")),
            ]))
        );
    }

    #[test]
    fn incomplete() {
        assert_eq!(parse_frame(Bytes::new()), Err(ParseError::Incomplete));
        assert_eq!(
            parse_frame(Bytes::from("+OK\r")),
            Err(ParseError::Incomplete)
        );
        assert_eq!(
            parse_frame(Bytes::from("$5\r\nhel")),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn invalid_tag() {
        assert_eq!(
            parse_frame(Bytes::from("X\r\n")),
            Err(ParseError::InvalidTag(b'X'))
        );
    }

    #[test]
    fn roundtrip() {
        let frames = vec![
            Frame::SimpleString(Bytes::from("OK")),
            Frame::Error(Bytes::from("ERR bad")),
            Frame::Integer(42),
            Frame::BulkString(Some(Bytes::from("hello"))),
            Frame::BulkString(None),
            Frame::Array(Some(vec![
                Frame::Integer(1),
                Frame::BulkString(Some(Bytes::from("two"))),
            ])),
            Frame::Array(None),
        ];
        for frame in &frames {
            let bytes = frame_to_bytes(frame);
            let (parsed, rest) = parse_frame(bytes).unwrap();
            assert_eq!(&parsed, frame);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn streaming_parser() {
        let mut parser = Parser::new();
        parser.feed(Bytes::from("+HEL"));
        assert!(parser.next_frame().unwrap().is_none());

        parser.feed(Bytes::from("LO\r\n:42\r\n"));
        let f1 = parser.next_frame().unwrap().unwrap();
        assert_eq!(f1, Frame::SimpleString(Bytes::from("HELLO")));

        let f2 = parser.next_frame().unwrap().unwrap();
        assert_eq!(f2, Frame::Integer(42));

        assert!(parser.next_frame().unwrap().is_none());
    }

    #[test]
    fn chained_frames() {
        let input = Bytes::from("+OK\r\n:1\r\n$3\r\nfoo\r\n");
        let (f1, rest) = parse_frame(input).unwrap();
        assert_eq!(f1, Frame::SimpleString(Bytes::from("OK")));
        let (f2, rest) = parse_frame(rest).unwrap();
        assert_eq!(f2, Frame::Integer(1));
        let (f3, rest) = parse_frame(rest).unwrap();
        assert_eq!(f3, Frame::BulkString(Some(Bytes::from("foo"))));
        assert!(rest.is_empty());
    }

    #[test]
    fn binary_bulk_string() {
        let mut data = Vec::new();
        data.extend_from_slice(b"$5\r\n");
        data.extend_from_slice(&[0x00, 0x01, 0xFF, 0xFE, 0x42]);
        data.extend_from_slice(b"\r\n");
        let (frame, _) = parse_frame(Bytes::from(data)).unwrap();
        match frame {
            Frame::BulkString(Some(b)) => {
                assert_eq!(b.as_ref(), &[0x00, 0x01, 0xFF, 0xFE, 0x42]);
            }
            _ => panic!("expected bulk string"),
        }
    }

    #[test]
    fn rejects_resp3_types() {
        // RESP3-only types should fail with InvalidTag in RESP2 mode
        assert!(parse_frame(Bytes::from("_\r\n")).is_err()); // Null
        assert!(parse_frame(Bytes::from(",3.14\r\n")).is_err()); // Double
        assert!(parse_frame(Bytes::from("#t\r\n")).is_err()); // Boolean
        assert!(parse_frame(Bytes::from("(123\r\n")).is_err()); // Big number
    }

    #[test]
    fn integer_overflow() {
        // One past i64::MAX
        assert_eq!(
            parse_frame(Bytes::from(":9223372036854775808\r\n")),
            Err(ParseError::Overflow)
        );

        // i64::MAX should succeed
        let (frame, _) = parse_frame(Bytes::from(":9223372036854775807\r\n")).unwrap();
        assert_eq!(frame, Frame::Integer(i64::MAX));

        // i64::MIN should succeed
        let (frame, _) = parse_frame(Bytes::from(":-9223372036854775808\r\n")).unwrap();
        assert_eq!(frame, Frame::Integer(i64::MIN));

        // One past i64::MIN
        assert!(parse_frame(Bytes::from(":-9223372036854775809\r\n")).is_err());
    }

    #[test]
    fn zero_length_bulk_edge_cases() {
        // No trailing data at all
        assert_eq!(
            parse_frame(Bytes::from("$0\r\n")),
            Err(ParseError::Incomplete)
        );

        // Only one byte of trailing CRLF
        assert_eq!(
            parse_frame(Bytes::from("$0\r\n\r")),
            Err(ParseError::Incomplete)
        );

        // Wrong bytes where CRLF should be
        assert_eq!(
            parse_frame(Bytes::from("$0\r\nXY")),
            Err(ParseError::InvalidFormat)
        );
    }

    #[test]
    fn nonempty_bulk_malformed_terminator() {
        // Not enough data after payload
        assert_eq!(
            parse_frame(Bytes::from("$3\r\nfoo")),
            Err(ParseError::Incomplete)
        );

        // Only one byte after payload
        assert_eq!(
            parse_frame(Bytes::from("$3\r\nfooX")),
            Err(ParseError::Incomplete)
        );

        // Two bytes present but wrong
        assert_eq!(
            parse_frame(Bytes::from("$3\r\nfooXY")),
            Err(ParseError::InvalidFormat)
        );
    }

    #[test]
    fn array_size_limit() {
        // One over MAX_COLLECTION_SIZE
        assert_eq!(
            parse_frame(Bytes::from("*10000001\r\n")),
            Err(ParseError::BadLength)
        );

        // At the limit should be accepted (returns Incomplete since elements are missing)
        assert_eq!(
            parse_frame(Bytes::from("*10000000\r\n")),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn bulk_string_size_limit() {
        // Over MAX_BULK_STRING_SIZE (512 MB)
        assert_eq!(
            parse_frame(Bytes::from("$536870913\r\n")),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn streaming_parser_clears_buffer_on_error() {
        let mut parser = Parser::new();
        parser.feed(Bytes::from("X\r\n"));
        assert_eq!(parser.next_frame(), Err(ParseError::InvalidTag(b'X')));
        assert_eq!(parser.buffered_bytes(), 0);
    }

    #[test]
    fn streaming_parser_recovers_after_error() {
        let mut parser = Parser::new();
        // Feed invalid data
        parser.feed(Bytes::from("X\r\n"));
        assert!(parser.next_frame().is_err());
        assert_eq!(parser.buffered_bytes(), 0);

        // Feed valid data - parser should work normally
        parser.feed(Bytes::from("+OK\r\n"));
        let frame = parser.next_frame().unwrap().unwrap();
        assert_eq!(frame, Frame::SimpleString(Bytes::from("OK")));
    }

    #[test]
    fn frame_as_bytes() {
        assert_eq!(
            Frame::SimpleString(Bytes::from("OK")).as_bytes(),
            Some(&Bytes::from("OK"))
        );
        assert_eq!(
            Frame::Error(Bytes::from("ERR")).as_bytes(),
            Some(&Bytes::from("ERR"))
        );
        assert_eq!(
            Frame::BulkString(Some(Bytes::from("data"))).as_bytes(),
            Some(&Bytes::from("data"))
        );
        assert_eq!(Frame::BulkString(None).as_bytes(), None);
        assert_eq!(Frame::Integer(42).as_bytes(), None);
    }

    #[test]
    fn frame_as_str() {
        assert_eq!(Frame::SimpleString(Bytes::from("OK")).as_str(), Some("OK"));
        // Invalid UTF-8
        assert_eq!(
            Frame::BulkString(Some(Bytes::from_static(&[0xFF]))).as_str(),
            None
        );
    }

    #[test]
    fn frame_as_integer() {
        assert_eq!(Frame::Integer(42).as_integer(), Some(42));
        assert_eq!(Frame::SimpleString(Bytes::from("42")).as_integer(), None);
    }

    #[test]
    fn frame_as_array() {
        let arr = Frame::Array(Some(vec![Frame::Integer(1)]));
        assert_eq!(arr.as_array(), Some([Frame::Integer(1)].as_slice()));
        assert_eq!(Frame::Array(None).as_array(), None);
        assert_eq!(Frame::Integer(1).as_array(), None);
    }

    #[test]
    fn frame_into_array() {
        let arr = Frame::Array(Some(vec![Frame::Integer(1)]));
        assert_eq!(arr.into_array(), Ok(vec![Frame::Integer(1)]));
        assert!(Frame::Array(None).into_array().is_err());
        assert!(Frame::Integer(1).into_array().is_err());
    }

    #[test]
    fn frame_into_bulk_string() {
        let bs = Frame::BulkString(Some(Bytes::from("data")));
        assert_eq!(bs.into_bulk_string(), Ok(Bytes::from("data")));
        assert!(Frame::BulkString(None).into_bulk_string().is_err());
    }

    #[test]
    fn frame_is_null() {
        assert!(Frame::BulkString(None).is_null());
        assert!(Frame::Array(None).is_null());
        assert!(!Frame::BulkString(Some(Bytes::new())).is_null());
        assert!(!Frame::Integer(0).is_null());
    }

    #[test]
    fn frame_is_error() {
        assert!(Frame::Error(Bytes::from("ERR")).is_error());
        assert!(!Frame::SimpleString(Bytes::from("OK")).is_error());
    }
}
