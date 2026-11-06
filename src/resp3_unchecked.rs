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

/// Find the CRLF terminating a line, starting at `from`. Returns the position
/// of the `\r`.
///
/// Scans for the `\r\n` pair, not a bare `\r`, so that it agrees with the safe
/// [`crate::resp3::find_crlf`]. See the RESP2 counterpart for the reasoning.
///
/// # Safety
///
/// Caller must ensure `buf[from..]` contains a `\r\n` pair before the end of
/// the allocation.
#[inline(always)]
unsafe fn find_cr(buf: &[u8], from: usize) -> usize {
    let ptr = buf.as_ptr();
    let mut i = from;
    // SAFETY: caller guarantees a CRLF exists in bounds, at some index j with
    // j + 1 in bounds. The loop only reads i + 1 while i < j, so i + 1 <= j.
    while !(*ptr.add(i) == b'\r' && *ptr.add(i + 1) == b'\n') {
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
    // Only `-` is valid input since #102, but a `+` is still skipped: left in
    // the digit run, `b'+' - b'0'` wraps, so `:+0\r\n` decoded as 2510 and
    // panicked under debug assertions (issue #77). A contract violation should
    // give a wrong value, not that.
    let first = *buf.get_unchecked(0);
    let neg = first == b'-';
    if neg || first == b'+' {
        i = 1;
    }
    // Accumulate negatively. i64::MIN has no positive counterpart, so building
    // the magnitude first and negating overflows on exactly that value: the
    // safe parser carries a special case for it, this had none. In release the
    // two overflows cancel and the answer comes out right by accident, but
    // under -Cdebug-assertions, which is how cargo-fuzz builds, it panics
    // inside an unsafe fn that promises not to.
    let mut v: i64 = 0;
    while i < buf.len() {
        v = v * 10 - (*buf.get_unchecked(i) - b'0') as i64;
        i += 1;
    }
    // Negative accumulation reaches i64::MIN exactly, and i64::MAX negates
    // without overflow, so no valid input overflows either branch.
    if neg { v } else { -v }
}

/// Read one aggregate element, skipping any attributes that precede it.
///
/// Mirrors `resp3::parse_element`. An attribute is metadata for the frame that
/// follows and does not occupy an element slot, so the two parsers must agree
/// on this or the equivalence property between them breaks.
///
/// # Safety
///
/// Same contract as [`parse_inner`]: `input` holds valid, complete RESP3 from
/// `pos`, which guarantees a non-attribute frame eventually follows.
#[inline(always)]
unsafe fn parse_element(input: &Bytes, pos: usize) -> (Frame, usize) {
    // Only a `|` tag starts an attribute; check it before parsing, as the safe
    // parser does, so the common path is a direct call.
    if *input.as_ref().get_unchecked(pos) == b'|' {
        return parse_element_after_attributes(input, pos);
    }
    parse_inner(input, pos)
}

/// The rare path of [`parse_element`]: skip one or more leading attributes.
///
/// # Safety
///
/// Same contract as [`parse_element`].
#[cold]
#[inline(never)]
unsafe fn parse_element_after_attributes(input: &Bytes, pos: usize) -> (Frame, usize) {
    let mut cursor = pos;
    loop {
        let (frame, next) = parse_inner(input, cursor);
        cursor = next;
        if !matches!(frame, Frame::Attribute(_)) {
            return (frame, cursor);
        }
    }
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
            // Same special-value rule as the safe parser, case variants and
            // `-nan` included. Matching only the exact spellings here once made
            // `,Inf\r\n` come back as Double(inf) instead of SpecialFloat.
            if let Some(canonical) = crate::resp3::special_float(line) {
                let frame = if line == canonical {
                    Frame::SpecialFloat(input.slice(pos + 1..cr))
                } else {
                    Frame::SpecialFloat(Bytes::from_static(canonical))
                };
                return (frame, cr + 2);
            }
            let s = core::str::from_utf8_unchecked(line);
            // Valid input is finite here: the safe parser rejects any other
            // non-finite literal (#103).
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
            // One length-delimited slice, structurally identical to the `!`
            // BlobError arm. The hardcoded 3 and 4 that used to live here were
            // an unchecked restatement of the safe parser's `sep != 3` rule,
            // and that duplication is where #65, #77 and the float
            // canonicalization bug all came from.
            (
                Frame::VerbatimString {
                    payload: input.slice(ds..de),
                },
                de + 2,
            )
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
                let (frame, next) = parse_element(input, cursor);
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
                let (frame, next) = parse_element(input, cursor);
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
                let (key, next1) = parse_element(input, cursor);
                let (val, next2) = parse_element(input, next1);
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
                let (frame, next) = parse_element(input, cursor);
                items.push(frame);
                cursor = next;
            }
            (Frame::Push(items), cursor)
        }
        b';' => {
            let cr = find_cr(buf, pos + 1);
            let len = parse_usize_unchecked(buf.get_unchecked(pos + 1..cr));
            if len == 0 {
                // End-of-stream marker `;0\r\n`: four bytes, no payload and no
                // trailing CRLF. Must match resp3::parse_streamed_chunk.
                return (Frame::StreamedStringChunk(Bytes::new()), cr + 2);
            }
            let ds = cr + 2;
            let de = ds + len;
            (Frame::StreamedStringChunk(input.slice(ds..de)), de + 2)
        }
        b'.' => (Frame::StreamTerminator, pos + 3),
        _ => core::hint::unreachable_unchecked(),
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
///
/// The caller **must also** bound aggregate nesting depth. This function
/// recurses once per level and has no depth limit of its own, so deeply nested
/// input overflows the stack and aborts the process. Validating with
/// [`super::parse_frame`] first is sufficient: it rejects anything deeper than
/// [`super::MAX_DEPTH`].
pub unsafe fn parse_frame_unchecked(input: Bytes) -> (Frame, Bytes) {
    let (frame, consumed) = parse_inner(&input, 0);
    (frame, input.slice(consumed..))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp3;

    #[test]
    fn plus_sign_is_skipped_not_wrapped() {
        // Outside the contract since #102, but the `+` skip from #77 stays so
        // that a contract violation gives a value rather than a wrapped byte
        // (2510 for `:+0`, or a panic under debug assertions).
        let (frame, _) = unsafe { parse_frame_unchecked(Bytes::from_static(b":+0\r\n")) };
        assert_eq!(frame, Frame::Integer(0));
    }

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
            // `:+0` and `:+42` were here for #77, while the safe parser
            // accepted a `+` sign. It rejects one since #102, so they are no
            // longer valid input for either parser.
            ":0\r\n",
            ":-1\r\n",
            // i64::MIN. Building the magnitude positively overflows on exactly
            // this value; in release the overflows cancel, under
            // debug-assertions it panicked (found by fuzz_unchecked on main).
            ":-9223372036854775808\r\n",
            ":9223372036854775807\r\n",
            "*2\r\n:1\r\n:-1\r\n",
            // Non-canonical spellings of the special floats. The safe parser
            // canonicalizes any non-finite value to a SpecialFloat, so these
            // must not come back as Double here.
            ",Inf\r\n",
            ",NaN\r\n",
            ",-Inf\r\n",
            ",-nan\r\n",
            ",NAN\r\n",
            "%1\r\n+key\r\n:1\r\n",
            "|1\r\n+meta\r\n+val\r\n",
            ">2\r\n+msg\r\n+data\r\n",
            ".\r\n",
            "$?\r\n",
            "*?\r\n",
            ";5\r\nhello\r\n",
            ";0\r\n",
            // The bare-CR payloads from #65 were here; invalid input since #99.
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
