#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use redis_protocol::resp2::types::OwnedFrame as TheirFrame;
use resp_rs::{ParseError, resp2};

// Every other oracle in this crate compares the crate against itself: roundtrip
// against its own serializer, direct parse against its own Parser, safe against
// its own unchecked path. All of those are closed under a consistent mistake. A
// parser and serializer that are wrong in the same direction are a fixed point
// of the roundtrip property, and no amount of runtime finds it.
//
// This target compares against redis-protocol, which was written by someone
// else from the same spec. It cannot be talked into the same mistake.
//
// Measured motivation: seven already-fixed bugs were reverted one at a time and
// the existing targets executed roughly 50 million inputs against them without
// a single finding.

/// A shape both crates can be mapped onto without losing anything that matters.
///
/// The two model frames differently, so comparing `Debug` output or either
/// native type directly would report differences that are not defects.
#[derive(Debug, PartialEq)]
enum Norm {
    Simple(Vec<u8>),
    Error(Vec<u8>),
    Int(i64),
    Bulk(Vec<u8>),
    /// Both null forms collapse here. resp-rs distinguishes `BulkString(None)`
    /// from `Array(None)`; redis-protocol has a single `Null`. The distinction
    /// is real but unobservable through this oracle, so it is not compared.
    Null,
    Array(Vec<Norm>),
}

fn norm_ours(f: &resp2::Frame) -> Norm {
    match f {
        resp2::Frame::SimpleString(b) => Norm::Simple(b.to_vec()),
        resp2::Frame::Error(b) => Norm::Error(b.to_vec()),
        resp2::Frame::Integer(i) => Norm::Int(*i),
        resp2::Frame::BulkString(Some(b)) => Norm::Bulk(b.to_vec()),
        resp2::Frame::BulkString(None) => Norm::Null,
        resp2::Frame::Array(Some(v)) => Norm::Array(v.iter().map(norm_ours).collect()),
        resp2::Frame::Array(None) => Norm::Null,
    }
}

fn norm_theirs(f: &TheirFrame) -> Norm {
    match f {
        TheirFrame::SimpleString(v) => Norm::Simple(v.clone()),
        TheirFrame::Error(s) => Norm::Error(s.as_bytes().to_vec()),
        TheirFrame::Integer(i) => Norm::Int(*i),
        TheirFrame::BulkString(v) => Norm::Bulk(v.clone()),
        TheirFrame::Null => Norm::Null,
        TheirFrame::Array(v) => Norm::Array(v.iter().map(norm_theirs).collect()),
    }
}

/// Errors that mean "this crate imposes a limit the reference does not", rather
/// than "these two disagree about the grammar".
///
/// Keeping this list short is the point. Anything not on it that diverges is a
/// bug in one crate or the other.
fn is_resource_limit(e: &ParseError) -> bool {
    matches!(
        e,
        // MAX_DEPTH, MAX_LINE_LENGTH, MAX_COLLECTION_SIZE, MAX_BULK_STRING_SIZE.
        ParseError::DepthExceeded | ParseError::LineTooLong | ParseError::BadLength
    )
}

/// True when the reference's laxness about bulk strings could explain a
/// divergence, so the divergence should not be blamed on this crate.
///
/// The target found this on its first run. redis-protocol does not verify the
/// CRLF that terminates a bulk string body:
///
/// ```text
/// $1\r\nX!!      ours=InvalidFormat  theirs=BulkString("X")   consumed=7
/// $3\r\nabcZZ    ours=InvalidFormat  theirs=BulkString("abc") consumed=9
/// $0\r\nZZ       ours=InvalidFormat  theirs=BulkString("")    consumed=6
/// ```
///
/// The grammar is `$<length>\r\n<data>\r\n` with the trailing CRLF required, so
/// this crate is right to reject and the reference is lax. Worth reporting
/// upstream; it is not a defect here.
///
/// Detecting it exactly would mean re-serialising the reference's frame and
/// comparing against the consumed prefix, which needs a reverse mapping whose
/// null handling is ambiguous (`Null` is both `$-1` and `*-1`). Rather than
/// hand-roll that and get it subtly wrong, this excludes any input carrying a
/// bulk tag at all.
///
/// The cost is real and worth stating: divergences on inputs containing `$` are
/// not checked in the we-reject-they-accept direction. Frames built only from
/// `+` `-` `:` `*` are still checked. That is the direction that caught #49,
/// where the reference reads `:+42\r\n` as 42 and this crate refused the sign;
/// since #102 refusing it is deliberate, and `has_noncanonical_number` excuses
/// exactly that case.
fn bulk_laxness_may_apply(data: &[u8], consumed: usize) -> bool {
    data[..consumed.min(data.len())].contains(&b'$')
}

/// redis-protocol types a simple error as `String`, so it rejects payloads this
/// crate accepts as raw bytes. That permissiveness is deliberate and documented
/// (issue #17), so a divergence is only excused when the bytes really are not
/// UTF-8.
fn ours_holds_non_utf8_error(f: &resp2::Frame) -> bool {
    match f {
        resp2::Frame::Error(b) => core::str::from_utf8(b).is_err(),
        resp2::Frame::Array(Some(v)) => v.iter().any(ours_holds_non_utf8_error),
        _ => false,
    }
}

/// True if the frame the reference accepted spells a `:` integer
/// non-canonically: a `+` sign, a leading zero, or `-0`.
///
/// Redis and hiredis reject these (`string2ll`), and so does this crate since
/// #101 and #102, with `InvalidFormat`; redis-protocol accepts them. The frame
/// is walked header by header over the bytes the reference consumed, so a `+`
/// or `0` inside a simple string or bulk payload excuses nothing. `$` and `*`
/// headers are walked only to find the integers: a rejected length or count is
/// `BadLength`, which `is_resource_limit` already excuses.
///
/// Known limit: a wrongly rejected canonical integer in the same frame as a
/// non-canonical one is excused too.
fn has_noncanonical_number(data: &[u8], consumed: usize) -> bool {
    fn line(data: &[u8], pos: usize) -> Option<(&[u8], usize)> {
        let rel = data.get(pos..)?.windows(2).position(|w| w == b"\r\n")?;
        Some((&data[pos..pos + rel], pos + rel + 2))
    }
    fn noncanonical(text: &[u8]) -> bool {
        let digits = text.strip_prefix(b"-").unwrap_or(text);
        text.first() == Some(&b'+')
            || (digits.first() == Some(&b'0') && (digits.len() > 1 || digits.len() != text.len()))
    }
    // Returns whether a non-canonical integer was found, and where the frame
    // ends. `None` (no excuse) past MAX_DEPTH, which this crate rejects anyway.
    fn walk(data: &[u8], pos: usize, depth: u32) -> Option<(bool, usize)> {
        if depth > resp2::MAX_DEPTH {
            return None;
        }
        let tag = *data.get(pos)?;
        let (text, next) = line(data, pos + 1)?;
        match tag {
            b'+' | b'-' => Some((false, next)),
            b':' => Some((noncanonical(text), next)),
            b'$' => {
                let n: i64 = core::str::from_utf8(text).ok()?.parse().ok()?;
                Some((false, if n < 0 { next } else { next + n as usize + 2 }))
            }
            b'*' => {
                let n: i64 = core::str::from_utf8(text).ok()?.parse().ok()?;
                let mut cursor = next;
                for _ in 0..n.max(0) {
                    let (found, end) = walk(data, cursor, depth + 1)?;
                    if found {
                        return Some((true, end));
                    }
                    cursor = end;
                }
                Some((false, cursor))
            }
            _ => None,
        }
    }
    matches!(
        walk(&data[..consumed.min(data.len())], 0, 0),
        Some((true, _))
    )
}

fuzz_target!(|data: &[u8]| {
    let ours = resp2::parse_frame(Bytes::copy_from_slice(data));
    let theirs = redis_protocol::resp2::decode::decode(data);

    match (&ours, &theirs) {
        (Ok((our_frame, rest)), Ok(Some((their_frame, their_consumed)))) => {
            // Framing first. Disagreeing about how many bytes a frame occupies
            // desynchronizes a connection, which is worse than disagreeing
            // about the value: every later reply is attributed to the wrong
            // command. This is the assertion that catches that class.
            if !bulk_laxness_may_apply(data, *their_consumed) {
                assert_eq!(
                    data.len() - rest.len(),
                    *their_consumed,
                    "consumed lengths differ\n  input:  {data:?}\n  ours:   {our_frame:?}\n  theirs: {their_frame:?}"
                );
            }
            assert_eq!(
                norm_ours(our_frame),
                norm_theirs(their_frame),
                "decoded values differ\n  input: {data:?}"
            );
        }

        // Both want more input.
        (Err(ParseError::Incomplete), Ok(None)) => {}

        // Both reject. Includes the case where we want more input and they
        // reject outright, which is reachable because the two decide some
        // malformed prefixes at different points in the buffer.
        (Err(_), Err(_)) => {}

        // They want more input, we rejected.
        //
        // Not asserted. `Ok(None)` is the reference declining to decide yet,
        // not the reference disagreeing, so it cannot contradict our verdict.
        // The same bulk-terminator laxness described above surfaces here as
        // well: for `*11\r\n$0\r\n\r\r` this crate says InvalidFormat, which is
        // correct because a `\r\r` terminator can never become valid, while the
        // reference asks for more bytes. There is no `consumed` to check the
        // way there is in the `Ok(Some)` arm.
        //
        // What this gives up is catching a hard error returned on a genuinely
        // valid prefix, which would break streaming. The `fuzz_resp2_streaming`
        // target already covers that from the other direction, by requiring a
        // chunked feed to agree with a whole-buffer parse.
        (Err(_), Ok(None)) => {}

        // We accept, they reject. Only acceptable for the documented raw-bytes
        // permissiveness in errors.
        (Ok((our_frame, _)), Err(_)) => {
            assert!(
                ours_holds_non_utf8_error(our_frame),
                "we accept what the reference rejects\n  input: {data:?}\n  ours:  {our_frame:?}"
            );
        }

        // We reject, they accept. This is the over-strictness direction, and it
        // is exactly how issue #49 would have been caught: the reference reads
        // `:+42\r\n` as 42 while this crate used to refuse the sign. Since
        // #102 refusing it is deliberate again, matching Redis and hiredis, so
        // non-canonical number text is excused by walking the frame for it.
        (Err(e), Ok(Some((their_frame, their_consumed)))) => {
            assert!(
                is_resource_limit(e)
                    || bulk_laxness_may_apply(data, *their_consumed)
                    || (*e == ParseError::InvalidFormat
                        && has_noncanonical_number(data, *their_consumed)),
                "we reject what the reference accepts\n  input:  {data:?}\n  ours:   {e:?}\n  theirs: {their_frame:?}"
            );
        }

        // We accept, they want more. Would mean we framed a shorter prefix than
        // the reference thinks is complete.
        (Ok((our_frame, _)), Ok(None)) => {
            panic!(
                "we accept a frame the reference considers incomplete\n  input: {data:?}\n  ours:  {our_frame:?}"
            );
        }
    }
});
