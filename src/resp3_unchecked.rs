//! Unsafe RESP3 parser that skips bounds checks for maximum performance.
//!
//! All functions in this module require that the input contains valid,
//! complete RESP3 data. Passing truncated or malformed input is undefined
//! behavior.

// This entire module is unsafe-by-design. Every function operates on
// pre-validated data with unchecked access for performance.
#![allow(unsafe_op_in_unsafe_fn)]

use bytes::Bytes;

use crate::resp3::Frame;

#[inline(always)]
unsafe fn find_cr(buf: &[u8], from: usize) -> usize {
    let ptr = buf.as_ptr();
    let mut i = from;
    while *ptr.add(i) != b'\r' {
        i += 1;
    }
    i
}

#[inline(always)]
unsafe fn parse_usize_unchecked(buf: &[u8]) -> usize {
    let mut v: usize = 0;
    for i in 0..buf.len() {
        v = v * 10 + (*buf.get_unchecked(i) - b'0') as usize;
    }
    v
}

#[inline(always)]
unsafe fn parse_i64_unchecked(buf: &[u8]) -> i64 {
    let mut i = 0;
    let neg = *buf.get_unchecked(0) == b'-';
    if neg {
        i = 1;
    }
    let mut v: i64 = 0;
    while i < buf.len() {
        v = v * 10 + (*buf.get_unchecked(i) - b'0') as i64;
        i += 1;
    }
    if neg { -v } else { v }
}

unsafe fn parse_inner(input: &Bytes, pos: usize) -> (Frame, usize) {
    let buf = input.as_ref();
    let tag = *buf.get_unchecked(pos);

    match tag {
        b'+' => {
            let cr = find_cr(buf, pos + 1);
            (Frame::SimpleString(input.slice(pos + 1..cr)), cr + 2)
        }
        b'-' => {
            let cr = find_cr(buf, pos + 1);
            (Frame::Error(input.slice(pos + 1..cr)), cr + 2)
        }
        b':' => {
            let cr = find_cr(buf, pos + 1);
            let v = parse_i64_unchecked(buf.get_unchecked(pos + 1..cr));
            (Frame::Integer(v), cr + 2)
        }
        b'$' => {
            let cr = find_cr(buf, pos + 1);
            let len_slice = buf.get_unchecked(pos + 1..cr);
            if len_slice == b"?" {
                return (Frame::StreamedStringHeader, cr + 2);
            }
            if *len_slice.get_unchecked(0) == b'-' {
                return (Frame::BulkString(None), cr + 2);
            }
            let len = parse_usize_unchecked(len_slice);
            if len == 0 {
                return (Frame::BulkString(Some(Bytes::new())), cr + 4);
            }
            let ds = cr + 2;
            let de = ds + len;
            (Frame::BulkString(Some(input.slice(ds..de))), de + 2)
        }
        b'_' => (Frame::Null, pos + 3),
        b',' => {
            let cr = find_cr(buf, pos + 1);
            let line = buf.get_unchecked(pos + 1..cr);
            if line == b"inf" || line == b"-inf" || line == b"nan" {
                return (Frame::SpecialFloat(input.slice(pos + 1..cr)), cr + 2);
            }
            let s = std::str::from_utf8_unchecked(line);
            let v: f64 = s.parse().unwrap_unchecked();
            (Frame::Double(v), cr + 2)
        }
        b'#' => {
            let val = *buf.get_unchecked(pos + 1) == b't';
            (Frame::Boolean(val), pos + 4)
        }
        b'(' => {
            let cr = find_cr(buf, pos + 1);
            (Frame::BigNumber(input.slice(pos + 1..cr)), cr + 2)
        }
        b'=' => {
            let cr = find_cr(buf, pos + 1);
            let len_slice = buf.get_unchecked(pos + 1..cr);
            if len_slice == b"?" {
                return (Frame::StreamedVerbatimStringHeader, cr + 2);
            }
            let len = parse_usize_unchecked(len_slice);
            let ds = cr + 2;
            let de = ds + len;
            let format = input.slice(ds..ds + 3);
            let content = input.slice(ds + 4..de);
            (Frame::VerbatimString(format, content), de + 2)
        }
        b'!' => {
            let cr = find_cr(buf, pos + 1);
            let len_slice = buf.get_unchecked(pos + 1..cr);
            if len_slice == b"?" {
                return (Frame::StreamedBlobErrorHeader, cr + 2);
            }
            let len = parse_usize_unchecked(len_slice);
            if len == 0 {
                return (Frame::BlobError(Bytes::new()), cr + 4);
            }
            let ds = cr + 2;
            let de = ds + len;
            (Frame::BlobError(input.slice(ds..de)), de + 2)
        }
        b'*' => {
            let cr = find_cr(buf, pos + 1);
            let len_slice = buf.get_unchecked(pos + 1..cr);
            if len_slice == b"?" {
                return (Frame::StreamedArrayHeader, cr + 2);
            }
            if *len_slice.get_unchecked(0) == b'-' {
                return (Frame::Array(None), cr + 2);
            }
            let count = parse_usize_unchecked(len_slice);
            if count == 0 {
                return (Frame::Array(Some(Vec::new())), cr + 2);
            }
            let mut cursor = cr + 2;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                let (frame, next) = parse_inner(input, cursor);
                items.push(frame);
                cursor = next;
            }
            (Frame::Array(Some(items)), cursor)
        }
        b'~' => {
            let cr = find_cr(buf, pos + 1);
            let len_slice = buf.get_unchecked(pos + 1..cr);
            if len_slice == b"?" {
                return (Frame::StreamedSetHeader, cr + 2);
            }
            let count = parse_usize_unchecked(len_slice);
            let mut cursor = cr + 2;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                let (frame, next) = parse_inner(input, cursor);
                items.push(frame);
                cursor = next;
            }
            (Frame::Set(items), cursor)
        }
        b'%' | b'|' => {
            let cr = find_cr(buf, pos + 1);
            let len_slice = buf.get_unchecked(pos + 1..cr);
            if len_slice == b"?" {
                return if tag == b'%' {
                    (Frame::StreamedMapHeader, cr + 2)
                } else {
                    (Frame::StreamedAttributeHeader, cr + 2)
                };
            }
            let count = parse_usize_unchecked(len_slice);
            let mut cursor = cr + 2;
            let mut pairs = Vec::with_capacity(count);
            for _ in 0..count {
                let (key, next1) = parse_inner(input, cursor);
                let (val, next2) = parse_inner(input, next1);
                pairs.push((key, val));
                cursor = next2;
            }
            if tag == b'%' {
                (Frame::Map(pairs), cursor)
            } else {
                (Frame::Attribute(pairs), cursor)
            }
        }
        b'>' => {
            let cr = find_cr(buf, pos + 1);
            let len_slice = buf.get_unchecked(pos + 1..cr);
            if len_slice == b"?" {
                return (Frame::StreamedPushHeader, cr + 2);
            }
            let count = parse_usize_unchecked(len_slice);
            let mut cursor = cr + 2;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                let (frame, next) = parse_inner(input, cursor);
                items.push(frame);
                cursor = next;
            }
            (Frame::Push(items), cursor)
        }
        b';' => {
            let cr = find_cr(buf, pos + 1);
            let len = parse_usize_unchecked(buf.get_unchecked(pos + 1..cr));
            if len == 0 {
                return (Frame::StreamedStringChunk(Bytes::new()), cr + 4);
            }
            let ds = cr + 2;
            let de = ds + len;
            (Frame::StreamedStringChunk(input.slice(ds..de)), de + 2)
        }
        b'.' => (Frame::StreamTerminator, pos + 3),
        _ => std::hint::unreachable_unchecked(),
    }
}

/// Parse a single RESP3 frame without bounds checks.
///
/// This is the unchecked counterpart of [`super::parse_frame`]. It produces
/// identical `Frame` values but skips all validation for speed.
///
/// # Safety
///
/// The caller **must** guarantee that `input` contains at least one valid,
/// complete RESP3 frame. Passing truncated, malformed, or empty input is
/// **undefined behavior**.
pub unsafe fn parse_frame_unchecked(input: Bytes) -> (Frame, Bytes) {
    let (frame, consumed) = parse_inner(&input, 0);
    (frame, input.slice(consumed..))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp3;

    #[test]
    fn unchecked_matches_safe() {
        let cases = vec![
            "+OK\r\n",
            "-ERR fail\r\n",
            ":42\r\n",
            ":-123\r\n",
            ":0\r\n",
            "$5\r\nhello\r\n",
            "$0\r\n\r\n",
            "$-1\r\n",
            "_\r\n",
            "#t\r\n",
            "#f\r\n",
            ",3.14\r\n",
            ",inf\r\n",
            ",-inf\r\n",
            ",nan\r\n",
            "(12345\r\n",
            "=8\r\ntxt:data\r\n",
            "!5\r\nERROR\r\n",
            "!0\r\n\r\n",
            "*0\r\n",
            "*-1\r\n",
            "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n",
            "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n",
            "~2\r\n+a\r\n+b\r\n",
            "%1\r\n+key\r\n:1\r\n",
            "|1\r\n+meta\r\n+val\r\n",
            ">2\r\n+msg\r\n+data\r\n",
            ".\r\n",
            "$?\r\n",
            "*?\r\n",
            ";5\r\nhello\r\n",
            ";0\r\n\r\n",
        ];

        for wire in cases {
            let input = Bytes::from(wire);
            let (safe_frame, safe_rest) = resp3::parse_frame(input.clone()).unwrap();
            let (unsafe_frame, unsafe_rest) = unsafe { parse_frame_unchecked(input) };
            assert_eq!(safe_frame, unsafe_frame, "mismatch for: {wire}");
            assert_eq!(safe_rest, unsafe_rest, "rest mismatch for: {wire}");
        }
    }
}
