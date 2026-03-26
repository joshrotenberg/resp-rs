//! RESP2 protocol parser and serializer.
//!
//! RESP2 supports five data types:
//! - Simple String: `+OK\r\n`
//! - Error: `-ERR message\r\n`
//! - Integer: `:42\r\n`
//! - Bulk String: `$6\r\nfoobar\r\n` (or `$-1\r\n` for null)
//! - Array: `*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n` (or `*-1\r\n` for null)

use bytes::{BufMut, Bytes, BytesMut};

use crate::ParseError;

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
    if input.is_empty() {
        return Err(ParseError::Incomplete);
    }

    let tag = input[0];
    let after_tag = input.slice(1..);

    match tag {
        b'+' => {
            let (line, rest) = split_line(&after_tag)?;
            Ok((Frame::SimpleString(line), rest))
        }
        b'-' => {
            let (line, rest) = split_line(&after_tag)?;
            Ok((Frame::Error(line), rest))
        }
        b':' => {
            let (line, rest) = split_line(&after_tag)?;
            let s = std::str::from_utf8(&line).map_err(|_| ParseError::Utf8Error)?;
            let v: i64 = s.parse().map_err(|_| ParseError::InvalidFormat)?;
            Ok((Frame::Integer(v), rest))
        }
        b'$' => {
            let (len_line, rest) = split_line(&after_tag)?;
            let len_str = std::str::from_utf8(&len_line).map_err(|_| ParseError::Utf8Error)?;
            if len_str == "-1" {
                return Ok((Frame::BulkString(None), rest));
            }
            let len: usize = len_str.parse().map_err(|_| ParseError::BadLength)?;
            if len == 0 {
                if rest.len() < 2 {
                    return Err(ParseError::Incomplete);
                }
                if rest.starts_with(b"\r\n") {
                    return Ok((Frame::BulkString(Some(Bytes::new())), rest.slice(2..)));
                } else {
                    return Err(ParseError::InvalidFormat);
                }
            }
            if rest.len() < len + 2 || &rest[len..len + 2] != b"\r\n" {
                return Err(ParseError::Incomplete);
            }
            let chunk = rest.slice(..len);
            let remaining = rest.slice(len + 2..);
            Ok((Frame::BulkString(Some(chunk)), remaining))
        }
        b'*' => {
            // Fast path for empty array
            if after_tag.starts_with(b"0\r\n") {
                return Ok((Frame::Array(Some(Vec::new())), after_tag.slice(3..)));
            }
            let (len_line, rest) = split_line(&after_tag)?;
            let len_str = std::str::from_utf8(&len_line).map_err(|_| ParseError::Utf8Error)?;
            if len_str == "-1" {
                return Ok((Frame::Array(None), rest));
            }
            let count: usize = len_str.parse().map_err(|_| ParseError::BadLength)?;
            let mut cursor = rest;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                let (item, next) = parse_frame(cursor)?;
                items.push(item);
                cursor = next;
            }
            Ok((Frame::Array(Some(items)), cursor))
        }
        _ => Err(ParseError::InvalidTag(tag)),
    }
}

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

        match parse_frame(bytes.clone()) {
            Ok((frame, rest)) => {
                self.buffer.unsplit(rest.into());
                Ok(Some(frame))
            }
            Err(ParseError::Incomplete) => {
                self.buffer.unsplit(bytes.into());
                Ok(None)
            }
            Err(e) => Err(e),
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

/// Find `\r\n` in the input, return the line (before) and rest (after).
fn split_line(input: &Bytes) -> Result<(Bytes, Bytes), ParseError> {
    let buf = input.as_ref();
    let mut start = 0;
    while let Some(idx) = buf[start..].iter().position(|&b| b == b'\r') {
        let pos = start + idx;
        if pos + 1 < buf.len() && buf[pos + 1] == b'\n' {
            let line = input.slice(..pos);
            let rest = input.slice(pos + 2..);
            return Ok((line, rest));
        }
        start = pos + 1;
    }
    Err(ParseError::Incomplete)
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
}
