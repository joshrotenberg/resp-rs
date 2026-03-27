//! BRESP: Binary Redis Serialization Protocol (experimental).
//!
//! A hypothetical binary encoding for RESP that eliminates text parsing overhead.
//! Same semantics as RESP3, but with fixed-width binary framing instead of
//! ASCII lengths and CRLF terminators.
//!
//! # Wire format
//!
//! Every frame starts with a 1-byte tag, followed by type-specific payload:
//!
//! | Tag | Type | Payload |
//! |-----|------|---------|
//! | `0x01` | Integer | 8 bytes big-endian i64 |
//! | `0x02` | Double | 8 bytes IEEE 754 f64 |
//! | `0x03` | Boolean | 1 byte (0x00 or 0x01) |
//! | `0x04` | Null | (none) |
//! | `0x10` | String | 4-byte u32 length + data |
//! | `0x11` | Error | 4-byte u32 length + data |
//! | `0x12` | BlobError | 4-byte u32 length + data |
//! | `0x13` | Verbatim | 3-byte format + 4-byte u32 length + data |
//! | `0x14` | BigNumber | 4-byte u32 length + data |
//! | `0x20` | Array | 4-byte u32 count + items |
//! | `0x21` | Map | 4-byte u32 count + key-value pairs |
//! | `0x22` | Set | 4-byte u32 count + items |
//! | `0x23` | Attribute | 4-byte u32 count + key-value pairs |
//! | `0x24` | Push | 4-byte u32 count + items |
//! | `0x30` | NullString | (none) |
//! | `0x31` | NullArray | (none) |

use bytes::{BufMut, Bytes, BytesMut};

// Tags
const TAG_INTEGER: u8 = 0x01;
const TAG_DOUBLE: u8 = 0x02;
const TAG_BOOLEAN: u8 = 0x03;
const TAG_NULL: u8 = 0x04;
const TAG_STRING: u8 = 0x10;
const TAG_ERROR: u8 = 0x11;
const TAG_BLOB_ERROR: u8 = 0x12;
const TAG_VERBATIM: u8 = 0x13;
const TAG_BIG_NUMBER: u8 = 0x14;
const TAG_ARRAY: u8 = 0x20;
const TAG_MAP: u8 = 0x21;
const TAG_SET: u8 = 0x22;
const TAG_ATTRIBUTE: u8 = 0x23;
const TAG_PUSH: u8 = 0x24;
const TAG_NULL_STRING: u8 = 0x30;
const TAG_NULL_ARRAY: u8 = 0x31;

/// A parsed BRESP frame. Same variants as RESP3, binary encoding.
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    SimpleString(Bytes),
    Error(Bytes),
    Integer(i64),
    BulkString(Option<Bytes>),
    Null,
    Double(f64),
    Boolean(bool),
    BigNumber(Bytes),
    BlobError(Bytes),
    VerbatimString(Bytes, Bytes),
    Array(Option<Vec<Frame>>),
    Set(Vec<Frame>),
    Map(Vec<(Frame, Frame)>),
    Attribute(Vec<(Frame, Frame)>),
    Push(Vec<Frame>),
}

/// Parse error for BRESP.
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    Incomplete,
    InvalidTag(u8),
}

/// Parse a single BRESP frame from the input.
pub fn parse_frame(input: Bytes) -> Result<(Frame, Bytes), ParseError> {
    let (frame, consumed) = parse_inner(&input, 0)?;
    Ok((frame, input.slice(consumed..)))
}

fn parse_inner(input: &Bytes, pos: usize) -> Result<(Frame, usize), ParseError> {
    let buf = input.as_ref();
    if pos >= buf.len() {
        return Err(ParseError::Incomplete);
    }

    let tag = buf[pos];
    let after_tag = pos + 1;

    match tag {
        TAG_INTEGER => {
            if after_tag + 8 > buf.len() {
                return Err(ParseError::Incomplete);
            }
            let v = i64::from_be_bytes(buf[after_tag..after_tag + 8].try_into().unwrap());
            Ok((Frame::Integer(v), after_tag + 8))
        }
        TAG_DOUBLE => {
            if after_tag + 8 > buf.len() {
                return Err(ParseError::Incomplete);
            }
            let v = f64::from_be_bytes(buf[after_tag..after_tag + 8].try_into().unwrap());
            Ok((Frame::Double(v), after_tag + 8))
        }
        TAG_BOOLEAN => {
            if after_tag >= buf.len() {
                return Err(ParseError::Incomplete);
            }
            Ok((Frame::Boolean(buf[after_tag] != 0), after_tag + 1))
        }
        TAG_NULL => Ok((Frame::Null, after_tag)),
        TAG_NULL_STRING => Ok((Frame::BulkString(None), after_tag)),
        TAG_NULL_ARRAY => Ok((Frame::Array(None), after_tag)),

        TAG_STRING => parse_blob(input, buf, after_tag, |b| Frame::BulkString(Some(b))),
        TAG_ERROR => parse_blob(input, buf, after_tag, Frame::Error),
        TAG_BLOB_ERROR => parse_blob(input, buf, after_tag, Frame::BlobError),
        TAG_BIG_NUMBER => parse_blob(input, buf, after_tag, Frame::BigNumber),

        TAG_VERBATIM => {
            if after_tag + 3 > buf.len() {
                return Err(ParseError::Incomplete);
            }
            let format = input.slice(after_tag..after_tag + 3);
            let len_pos = after_tag + 3;
            if len_pos + 4 > buf.len() {
                return Err(ParseError::Incomplete);
            }
            let len = u32::from_be_bytes(buf[len_pos..len_pos + 4].try_into().unwrap()) as usize;
            let data_start = len_pos + 4;
            if data_start + len > buf.len() {
                return Err(ParseError::Incomplete);
            }
            let content = input.slice(data_start..data_start + len);
            Ok((Frame::VerbatimString(format, content), data_start + len))
        }

        TAG_ARRAY => parse_list(input, buf, after_tag, |items| Frame::Array(Some(items))),
        TAG_SET => parse_list(input, buf, after_tag, Frame::Set),
        TAG_PUSH => parse_list(input, buf, after_tag, Frame::Push),

        TAG_MAP => parse_pairs(input, buf, after_tag, Frame::Map),
        TAG_ATTRIBUTE => parse_pairs(input, buf, after_tag, Frame::Attribute),

        _ => Err(ParseError::InvalidTag(tag)),
    }
}

#[inline]
fn read_u32_len(buf: &[u8], pos: usize) -> Result<(usize, usize), ParseError> {
    if pos + 4 > buf.len() {
        return Err(ParseError::Incomplete);
    }
    let len = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
    Ok((len, pos + 4))
}

fn parse_blob(
    input: &Bytes,
    buf: &[u8],
    pos: usize,
    make: impl FnOnce(Bytes) -> Frame,
) -> Result<(Frame, usize), ParseError> {
    let (len, data_start) = read_u32_len(buf, pos)?;
    if data_start + len > buf.len() {
        return Err(ParseError::Incomplete);
    }
    let data = if len == 0 {
        Bytes::new()
    } else {
        input.slice(data_start..data_start + len)
    };
    Ok((make(data), data_start + len))
}

fn parse_list(
    input: &Bytes,
    buf: &[u8],
    pos: usize,
    make: impl FnOnce(Vec<Frame>) -> Frame,
) -> Result<(Frame, usize), ParseError> {
    let (count, mut cursor) = read_u32_len(buf, pos)?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let (frame, next) = parse_inner(input, cursor)?;
        items.push(frame);
        cursor = next;
    }
    Ok((make(items), cursor))
}

fn parse_pairs(
    input: &Bytes,
    buf: &[u8],
    pos: usize,
    make: impl FnOnce(Vec<(Frame, Frame)>) -> Frame,
) -> Result<(Frame, usize), ParseError> {
    let (count, mut cursor) = read_u32_len(buf, pos)?;
    let mut pairs = Vec::with_capacity(count);
    for _ in 0..count {
        let (key, next1) = parse_inner(input, cursor)?;
        let (val, next2) = parse_inner(input, next1)?;
        pairs.push((key, val));
        cursor = next2;
    }
    Ok((make(pairs), cursor))
}

/// Serialize a BRESP frame to bytes.
pub fn frame_to_bytes(frame: &Frame) -> Bytes {
    let mut buf = BytesMut::new();
    serialize(frame, &mut buf);
    buf.freeze()
}

fn serialize(frame: &Frame, buf: &mut BytesMut) {
    match frame {
        Frame::Integer(v) => {
            buf.put_u8(TAG_INTEGER);
            buf.put_i64(*v);
        }
        Frame::Double(v) => {
            buf.put_u8(TAG_DOUBLE);
            buf.put_f64(*v);
        }
        Frame::Boolean(v) => {
            buf.put_u8(TAG_BOOLEAN);
            buf.put_u8(if *v { 1 } else { 0 });
        }
        Frame::Null => buf.put_u8(TAG_NULL),
        Frame::SimpleString(s) => serialize_blob(TAG_STRING, s, buf),
        Frame::Error(e) => serialize_blob(TAG_ERROR, e, buf),
        Frame::BlobError(e) => serialize_blob(TAG_BLOB_ERROR, e, buf),
        Frame::BigNumber(n) => serialize_blob(TAG_BIG_NUMBER, n, buf),
        Frame::BulkString(Some(s)) => serialize_blob(TAG_STRING, s, buf),
        Frame::BulkString(None) => buf.put_u8(TAG_NULL_STRING),
        Frame::VerbatimString(format, content) => {
            buf.put_u8(TAG_VERBATIM);
            buf.put_slice(format);
            buf.put_u32(content.len() as u32);
            buf.put_slice(content);
        }
        Frame::Array(Some(items)) => serialize_list(TAG_ARRAY, items, buf),
        Frame::Array(None) => buf.put_u8(TAG_NULL_ARRAY),
        Frame::Set(items) => serialize_list(TAG_SET, items, buf),
        Frame::Push(items) => serialize_list(TAG_PUSH, items, buf),
        Frame::Map(pairs) => serialize_pairs(TAG_MAP, pairs, buf),
        Frame::Attribute(pairs) => serialize_pairs(TAG_ATTRIBUTE, pairs, buf),
    }
}

fn serialize_blob(tag: u8, data: &Bytes, buf: &mut BytesMut) {
    buf.put_u8(tag);
    buf.put_u32(data.len() as u32);
    buf.put_slice(data);
}

fn serialize_list(tag: u8, items: &[Frame], buf: &mut BytesMut) {
    buf.put_u8(tag);
    buf.put_u32(items.len() as u32);
    for item in items {
        serialize(item, buf);
    }
}

fn serialize_pairs(tag: u8, pairs: &[(Frame, Frame)], buf: &mut BytesMut) {
    buf.put_u8(tag);
    buf.put_u32(pairs.len() as u32);
    for (key, val) in pairs {
        serialize(key, buf);
        serialize(val, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_integer() {
        let frame = Frame::Integer(i64::MAX);
        let wire = frame_to_bytes(&frame);
        assert_eq!(wire.len(), 9); // tag + 8 bytes
        let (parsed, rest) = parse_frame(wire).unwrap();
        assert_eq!(parsed, frame);
        assert!(rest.is_empty());
    }

    #[test]
    fn roundtrip_double() {
        let frame = Frame::Double(1.23456789);
        let wire = frame_to_bytes(&frame);
        assert_eq!(wire.len(), 9);
        let (parsed, rest) = parse_frame(wire).unwrap();
        assert_eq!(parsed, frame);
        assert!(rest.is_empty());
    }

    #[test]
    fn roundtrip_boolean() {
        for v in [true, false] {
            let frame = Frame::Boolean(v);
            let wire = frame_to_bytes(&frame);
            assert_eq!(wire.len(), 2);
            let (parsed, _) = parse_frame(wire).unwrap();
            assert_eq!(parsed, frame);
        }
    }

    #[test]
    fn roundtrip_null() {
        let wire = frame_to_bytes(&Frame::Null);
        assert_eq!(wire.len(), 1);
        let (parsed, _) = parse_frame(wire).unwrap();
        assert_eq!(parsed, Frame::Null);
    }

    #[test]
    fn roundtrip_string() {
        // SimpleString and BulkString(Some) both serialize as TAG_STRING
        // and parse back as BulkString(Some) -- no distinction in binary format
        let frame = Frame::SimpleString(Bytes::from("OK"));
        let wire = frame_to_bytes(&frame);
        assert_eq!(wire.len(), 1 + 4 + 2); // tag + len + "OK"
        let (parsed, _) = parse_frame(wire).unwrap();
        assert_eq!(parsed, Frame::BulkString(Some(Bytes::from("OK"))));
    }

    #[test]
    fn roundtrip_bulk_null() {
        let frame = Frame::BulkString(None);
        let wire = frame_to_bytes(&frame);
        assert_eq!(wire.len(), 1);
        let (parsed, _) = parse_frame(wire).unwrap();
        assert_eq!(parsed, frame);
    }

    #[test]
    fn roundtrip_array() {
        let frame = Frame::Array(Some(vec![
            Frame::BulkString(Some(Bytes::from("SET"))),
            Frame::BulkString(Some(Bytes::from("key"))),
            Frame::BulkString(Some(Bytes::from("value"))),
        ]));
        let wire = frame_to_bytes(&frame);
        let (parsed, rest) = parse_frame(wire).unwrap();
        assert_eq!(parsed, frame);
        assert!(rest.is_empty());
    }

    #[test]
    fn roundtrip_map() {
        let frame = Frame::Map(vec![
            (
                Frame::BulkString(Some(Bytes::from("key1"))),
                Frame::Integer(1),
            ),
            (
                Frame::BulkString(Some(Bytes::from("key2"))),
                Frame::Integer(2),
            ),
        ]);
        let wire = frame_to_bytes(&frame);
        let (parsed, rest) = parse_frame(wire).unwrap();
        assert_eq!(parsed, frame);
        assert!(rest.is_empty());
    }

    #[test]
    fn roundtrip_verbatim() {
        let frame = Frame::VerbatimString(Bytes::from("txt"), Bytes::from("hello world"));
        let wire = frame_to_bytes(&frame);
        let (parsed, rest) = parse_frame(wire).unwrap();
        assert_eq!(parsed, frame);
        assert!(rest.is_empty());
    }

    #[test]
    fn wire_size_comparison() {
        // SET key value command
        let frame = Frame::Array(Some(vec![
            Frame::BulkString(Some(Bytes::from("SET"))),
            Frame::BulkString(Some(Bytes::from("key"))),
            Frame::BulkString(Some(Bytes::from("value"))),
        ]));

        let bresp_wire = frame_to_bytes(&frame);

        // Equivalent RESP3 wire format
        let resp3_wire = "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n";

        println!("SET key value:");
        println!("  RESP3: {} bytes", resp3_wire.len());
        println!("  BRESP: {} bytes", bresp_wire.len());
        println!(
            "  Savings: {} bytes ({:.0}%)",
            resp3_wire.len() as i64 - bresp_wire.len() as i64,
            (1.0 - bresp_wire.len() as f64 / resp3_wire.len() as f64) * 100.0
        );
    }
}
