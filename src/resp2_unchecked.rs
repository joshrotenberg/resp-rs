//! Unsafe RESP2 parser that skips bounds checks for maximum performance.
//!
//! All functions in this module require that the input contains valid,
//! complete RESP2 data. Passing truncated or malformed input is undefined
//! behavior.

// This entire module is unsafe-by-design. Every function operates on
// pre-validated data with unchecked access for performance.
#![allow(unsafe_op_in_unsafe_fn)]

use bytes::Bytes;

use crate::resp2::Frame;

/// Find the CRLF terminating a line, starting at `from`, using unchecked
/// pointer access. Returns the position of the `\r`.
///
/// This scans for the `\r\n` pair, not for a bare `\r`. It must agree with the
/// safe [`crate::resp2::find_crlf`], which treats a lone `\r` inside a payload
/// as ordinary data. Stopping at the first `\r` would end the line early on
/// input the safe parser accepts, desynchronizing the cursor and resuming on a
/// byte that is not a frame tag.
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

/// Parse an integer from ASCII digits without bounds checks.
///
/// # Safety
///
/// Caller must ensure `buf` contains only ASCII digits, optionally preceded
/// by `+` or `-`, and is non-empty.
#[inline(always)]
unsafe fn parse_i64_unchecked(buf: &[u8]) -> i64 {
    let mut i = 0;
    // Both signs, mirroring the safe parser. Missing `+` here does not merely
    // reject: the byte stays in the digit run and `b'+' - b'0'` wraps, so
    // `:+0\r\n` decoded as 2510 (issue #77).
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

/// Parse a usize from ASCII digits without bounds checks.
///
/// # Safety
///
/// Caller must ensure `buf` contains only ASCII digits and is non-empty.
#[inline(always)]
unsafe fn parse_usize_unchecked(buf: &[u8]) -> usize {
    let mut v: usize = 0;
    for i in 0..buf.len() {
        v = v * 10 + (*buf.get_unchecked(i) - b'0') as usize;
    }
    v
}

/// Internal recursive parser.
///
/// # Safety
///
/// `input` must contain valid, complete RESP2 data starting at `pos`.
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
            // SAFETY: valid RESP2 integer between pos+1 and cr
            let v = parse_i64_unchecked(buf.get_unchecked(pos + 1..cr));
            (Frame::Integer(v), cr + 2)
        }
        b'$' => {
            let cr = find_cr(buf, pos + 1);
            // SAFETY: valid RESP2 length between pos+1 and cr
            let len_slice = buf.get_unchecked(pos + 1..cr);
            // Null: $-1\r\n
            if *len_slice.get_unchecked(0) == b'-' {
                return (Frame::BulkString(None), cr + 2);
            }
            let len = parse_usize_unchecked(len_slice);
            if len == 0 {
                return (Frame::BulkString(Some(Bytes::new())), cr + 4);
            }
            let data_start = cr + 2;
            let data_end = data_start + len;
            (
                Frame::BulkString(Some(input.slice(data_start..data_end))),
                data_end + 2,
            )
        }
        b'*' => {
            let cr = find_cr(buf, pos + 1);
            // SAFETY: valid RESP2 count between pos+1 and cr
            let len_slice = buf.get_unchecked(pos + 1..cr);
            // Null: *-1\r\n
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
        // SAFETY: caller guarantees valid RESP2, so tag must be one of the above
        _ => core::hint::unreachable_unchecked(),
    }
}

/// Parse a single RESP2 frame without bounds checks.
///
/// This is the unchecked counterpart of [`super::parse_frame`]. It produces
/// identical `Frame` values but skips all validation for speed.
///
/// # Safety
///
/// The caller **must** guarantee that `input` contains at least one valid,
/// complete RESP2 frame. Passing truncated, malformed, or empty input is
/// **undefined behavior**.
///
/// The caller **must also** bound array nesting depth. This function recurses
/// once per level and has no depth limit of its own, so deeply nested input
/// overflows the stack and aborts the process. Validating with
/// [`super::parse_frame`] first is sufficient: it rejects anything deeper than
/// [`super::MAX_DEPTH`].
///
/// # Examples
///
/// ```
/// use bytes::Bytes;
/// use resp_rs::resp2::{self, Frame};
///
/// let data = Bytes::from("+OK\r\n");
/// // SAFETY: we know this is a valid, complete RESP2 frame.
/// let (frame, rest) = unsafe { resp2::parse_frame_unchecked(data) };
/// assert_eq!(frame, Frame::SimpleString(Bytes::from("OK")));
/// assert!(rest.is_empty());
/// ```
pub unsafe fn parse_frame_unchecked(input: Bytes) -> (Frame, Bytes) {
    let (frame, consumed) = parse_inner(&input, 0);
    (frame, input.slice(consumed..))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp2;

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
            "*0\r\n",
            "*-1\r\n",
            "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n",
            "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n",
            "*2\r\n*1\r\n:1\r\n+OK\r\n",
            // Bare CR inside a payload is data, not a line terminator. These
            // desynchronized the unchecked cursor before issue #65: the first
            // gave a silently wrong result, the second reached
            // unreachable_unchecked and aborted.
            "+a\rb\r\n",
            "-a\rb\r\n",
            "*2\r\n+a\rZ+b\r\n+x\r\n",
            "*2\r\n+a\rb\r\n+x\r\n",
            // An explicit plus sign. The safe parser accepted these from #56
            // while this one still stripped only `-`, leaving `+` in the digit
            // run where `b'+' - b'0'` wrapped: `:+0\r\n` decoded as 2510
            // (issue #77).
            ":+0\r\n",
            ":+42\r\n",
            // i64::MIN. Building the magnitude positively overflows on exactly
            // this value; in release the overflows cancel, under
            // debug-assertions it panicked (found by fuzz_unchecked on main).
            ":-9223372036854775808\r\n",
            ":9223372036854775807\r\n",
            "*2\r\n:+1\r\n:-1\r\n",
        ];

        for wire in cases {
            let input = Bytes::from(wire);
            let (safe_frame, safe_rest) = resp2::parse_frame(input.clone()).unwrap();
            let (unsafe_frame, unsafe_rest) = unsafe { parse_frame_unchecked(input) };
            assert_eq!(safe_frame, unsafe_frame, "mismatch for: {wire}");
            assert_eq!(safe_rest, unsafe_rest, "rest mismatch for: {wire}");
        }
    }
}
