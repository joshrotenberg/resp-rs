#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use redis_protocol::resp3::types::{OwnedFrame as TheirFrame, VerbatimStringFormat};
use resp_rs::{ParseError, resp3};

// The RESP3 counterpart to fuzz_resp2_differential. See that file for why a
// second implementation is the only oracle here that is not closed under a
// consistent mistake.
//
// RESP3 has a much larger surface, so the allowance list is thirteen entries
// rather than two. The risk that creates is an oracle that explains away
// everything and asserts nothing, so two allowances below are deliberately
// narrow, and each carries a note saying which real bug a broader form would
// have swallowed.

/// A shape both crates map onto. Ordered so sets and maps can be canonicalized.
///
/// Doubles land here as a string rather than an f64: it sidesteps NaN's lack of
/// Ord, and both crates parse the same text with the same Rust FromStr, so the
/// formatting agrees whenever the values do.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Norm {
    Simple(Vec<u8>),
    Err(Vec<u8>),
    Int(i64),
    Blob(Vec<u8>),
    BlobErr(Vec<u8>),
    Null,
    Dbl(String),
    Bool(bool),
    Big(Vec<u8>),
    Verb(Vec<u8>, Vec<u8>),
    Arr(Vec<Norm>),
    Push(Vec<Norm>),
    /// Sorted and deduped. redis-protocol decodes into a HashSet, so ordering
    /// and multiplicity are not preserved on their side (allowance A9).
    Set(Vec<Norm>),
    /// Sorted, first key wins. Theirs is a HashMap (allowance A10).
    Map(Vec<(Norm, Norm)>),
    Chunk(Vec<u8>),
    StreamHdr(u8),
}

fn canon_double(v: f64) -> String {
    if v.is_nan() {
        "nan".to_string()
    } else if v.is_infinite() {
        if v.is_sign_negative() { "-inf" } else { "inf" }.to_string()
    } else {
        format!("{v:?}")
    }
}

fn canon_special(b: &[u8]) -> String {
    match b {
        b"inf" => "inf".to_string(),
        b"-inf" => "-inf".to_string(),
        _ => "nan".to_string(),
    }
}

fn sorted_set(mut v: Vec<Norm>) -> Vec<Norm> {
    v.sort();
    v.dedup();
    v
}

fn sorted_map(mut v: Vec<(Norm, Norm)>) -> Vec<(Norm, Norm)> {
    v.sort();
    v.dedup_by(|a, b| a.0 == b.0);
    v
}

fn norm_ours(f: &resp3::Frame) -> Norm {
    use resp3::Frame as F;
    match f {
        F::SimpleString(b) => Norm::Simple(b.to_vec()),
        F::Error(b) => Norm::Err(b.to_vec()),
        F::Integer(i) => Norm::Int(*i),
        F::BulkString(Some(b)) => Norm::Blob(b.to_vec()),
        F::BulkString(None) => Norm::Null,
        F::BlobError(b) => Norm::BlobErr(b.to_vec()),
        F::Null => Norm::Null,
        F::Double(v) => Norm::Dbl(canon_double(*v)),
        F::SpecialFloat(b) => Norm::Dbl(canon_special(b)),
        F::Boolean(v) => Norm::Bool(*v),
        F::BigNumber(b) => Norm::Big(b.to_vec()),
        F::VerbatimString(fmt, c) => Norm::Verb(fmt.to_vec(), c.to_vec()),
        F::Array(Some(v)) => Norm::Arr(v.iter().map(norm_ours).collect()),
        F::Array(None) => Norm::Null,
        F::Push(v) => Norm::Push(v.iter().map(norm_ours).collect()),
        F::Set(v) => Norm::Set(sorted_set(v.iter().map(norm_ours).collect())),
        F::Map(v) | F::Attribute(v) => Norm::Map(sorted_map(
            v.iter().map(|(k, x)| (norm_ours(k), norm_ours(x))).collect(),
        )),
        F::StreamedStringChunk(b) => Norm::Chunk(b.to_vec()),
        F::StreamTerminator => Norm::Chunk(Vec::new()),
        F::StreamedStringHeader => Norm::StreamHdr(b'$'),
        F::StreamedArrayHeader => Norm::StreamHdr(b'*'),
        F::StreamedSetHeader => Norm::StreamHdr(b'~'),
        F::StreamedMapHeader => Norm::StreamHdr(b'%'),
        F::StreamedPushHeader => Norm::StreamHdr(b'>'),
        F::StreamedAttributeHeader => Norm::StreamHdr(b'|'),
        F::StreamedVerbatimStringHeader => Norm::StreamHdr(b'='),
        F::StreamedBlobErrorHeader => Norm::StreamHdr(b'!'),
        // Accumulated streaming frames come only from parse_streaming_sequence,
        // never from parse_frame, so they are unreachable here.
        other => Norm::Simple(format!("{other:?}").into_bytes()),
    }
}

fn norm_theirs(f: &TheirFrame) -> Norm {
    use TheirFrame as T;
    match f {
        T::BlobString { data, .. } => Norm::Blob(data.clone()),
        T::BlobError { data, .. } => Norm::BlobErr(data.clone()),
        T::SimpleString { data, .. } => Norm::Simple(data.clone()),
        T::SimpleError { data, .. } => Norm::Err(data.as_bytes().to_vec()),
        T::Boolean { data, .. } => Norm::Bool(*data),
        T::Null => Norm::Null,
        T::Number { data, .. } => Norm::Int(*data),
        T::Double { data, .. } => Norm::Dbl(canon_double(*data)),
        T::BigNumber { data, .. } => Norm::Big(data.clone()),
        T::VerbatimString { data, format, .. } => {
            // to_str is pub(crate), so the mapping is restated here.
            let fmt: &[u8] = match format {
                VerbatimStringFormat::Text => b"txt",
                VerbatimStringFormat::Markdown => b"mkd",
            };
            Norm::Verb(fmt.to_vec(), data.clone())
        }
        T::Array { data, .. } => Norm::Arr(data.iter().map(norm_theirs).collect()),
        T::Push { data, .. } => Norm::Push(data.iter().map(norm_theirs).collect()),
        T::Set { data, .. } => Norm::Set(sorted_set(data.iter().map(norm_theirs).collect())),
        T::Map { data, .. } => Norm::Map(sorted_map(
            data.iter().map(|(k, v)| (norm_theirs(k), norm_theirs(v))).collect(),
        )),
        T::ChunkedString(v) => Norm::Chunk(v.clone()),
        // Gated before normalization reaches here (A11).
        T::Hello { .. } => Norm::Simple(b"<hello>".to_vec()),
    }
}

/// A2. The reference never checks the two bytes terminating a length-delimited
/// body: `d_parse_blobstring`, `d_parse_bloberror`, `d_parse_verbatimstring`
/// and `d_parse_chunked_string` all use `terminated(take(len), take(2))`. So it
/// accepts `$1\r\nXZZ`, `!1\r\nXZZ`, `=8\r\ntxt:helloZZ`, `;1\r\nXZZ`.
///
/// Expressed over the reference's decoded frame, NOT as a byte scan for
/// `$ ! = ;`. That distinction is load-bearing, and the exact boundary was
/// established by measurement rather than reasoning:
///
/// ```text
/// $0\r\nZZ   ours=InvalidFormat  theirs=BlobString([])  consumed=6
/// ;0\r\n     ours=StreamedStringChunk(b"")  theirs=ChunkedString([])  both consumed=4
/// ```
///
/// An empty blob still carries a trailing CRLF, so the reference's unchecked
/// `take(2)` applies and the allowance must cover it. A zero-length chunk is
/// the stream terminator itself: it has no body and no trailing CRLF, both
/// crates agree at 4 bytes, so it stays inside the checked set. That is exactly
/// the shape bug #62 lived in, and a byte scan for `;` would have swallowed it.
fn has_delimited_body(f: &TheirFrame) -> bool {
    their_any(f, &|x| {
        use TheirFrame as T;
        match x {
            T::BlobString { .. } | T::BlobError { .. } | T::VerbatimString { .. } => true,
            T::ChunkedString(v) => !v.is_empty(),
            _ => false,
        }
    })
}

/// Walk the reference's decoded frame, including through aggregates.
///
/// Every predicate over their tree has to recurse. A top-level-only check looks
/// right and silently stops firing the moment the shape appears one level down,
/// which is how the first two iterations of this target failed: `(abc` nested
/// in a map, and an empty blob inside an array.
fn their_any(f: &TheirFrame, pred: &dyn Fn(&TheirFrame) -> bool) -> bool {
    if pred(f) {
        return true;
    }
    use TheirFrame as T;
    match f {
        T::Array { data, .. } | T::Push { data, .. } => data.iter().any(|x| their_any(x, pred)),
        T::Set { data, .. } => data.iter().any(|x| their_any(x, pred)),
        T::Map { data, .. } => data
            .iter()
            .any(|(k, v)| their_any(k, pred) || their_any(v, pred)),
        _ => false,
    }
}

/// A10. Duplicate map keys are nondeterministic on their side: the intermediate
/// map is keyed by byte ranges, which are distinct, and collapses only in
/// `build_owned_frame` in HashMap iteration order. Observed returning different
/// values for the same input within one process. Values are not comparable when
/// this holds.
fn ours_map_has_duplicate_keys(f: &resp3::Frame) -> bool {
    use resp3::Frame as F;
    match f {
        F::Map(v) | F::Attribute(v) => {
            let mut keys: Vec<Norm> = v.iter().map(|(k, _)| norm_ours(k)).collect();
            let before = keys.len();
            keys.sort();
            keys.dedup();
            keys.len() != before
                || v.iter()
                    .any(|(k, x)| ours_map_has_duplicate_keys(k) || ours_map_has_duplicate_keys(x))
        }
        F::Array(Some(v)) | F::Push(v) | F::Set(v) => v.iter().any(ours_map_has_duplicate_keys),
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // A1. A top-level attribute is a frame here and metadata there: they attach
    // it to the frame that follows and report a longer consumed length.
    //
    // Gated on the FIRST byte, not on the input containing `|` anywhere. That
    // is load-bearing: a blanket scan would swallow #59, where an attribute
    // nested inside an aggregate wrongly consumed an element slot. Nested
    // attributes reconcile cleanly, verified, so only the top-level case needs
    // excusing.
    if data[0] == b'|' {
        return;
    }
    // A11. HELLO is a command they decode and we reject as an invalid tag.
    if data[0] == b'H' {
        return;
    }
    // A12. They discard the payload of `_` and `.`, accepting `_junk\r\n`; we
    // reject it, which is the #57 fix.
    if data[0] == b'_' || data[0] == b'.' {
        return;
    }

    let ours = resp3::parse_frame(Bytes::copy_from_slice(data));
    let theirs = redis_protocol::resp3::decode::complete::decode(data);

    match (&ours, &theirs) {
        (Ok((our_frame, rest)), Ok(Some((their_frame, their_consumed)))) => {
            if has_delimited_body(their_frame) {
                return; // A2
            }
            if ours_map_has_duplicate_keys(our_frame) {
                return; // A10
            }
            // Framing first: disagreeing about a frame's length desynchronizes
            // a connection, which is worse than disagreeing about its value.
            assert_eq!(
                data.len() - rest.len(),
                *their_consumed,
                "consumed lengths differ\n  input:  {data:?}\n  ours:   {our_frame:?}\n  theirs: {their_frame:?}"
            );
            assert_eq!(
                norm_ours(our_frame),
                norm_theirs(their_frame),
                "decoded values differ\n  input: {data:?}"
            );
        }

        // Both want more, or both reject.
        (Err(ParseError::Incomplete), Ok(None)) => {}
        (Err(_), Err(_)) => {}

        // They decline to decide. Not a contradiction, so not asserted. See the
        // RESP2 target for the reasoning and what it gives up.
        (Err(_), Ok(None)) => {}

        // The two acceptance-direction arms are deliberately NOT asserted for
        // RESP3, which is the one place this target is weaker than its RESP2
        // sibling. The reasoning, and the evidence for it:
        //
        // RESP3 acceptance policy diverges in thirteen catalogued classes (A1
        // to A13 above). Five successive attempts to express them as predicates
        // over the decoded frames each ran clean for a while and then found a
        // new nesting or interaction the previous predicate missed: a bignumber
        // inside a map, a `_junk` inside a map, a nested `.`, and so on. Each
        // fix was correct and none of them converged, because the reference's
        // acceptance boundary is not a function of its own decoded output. It
        // depends on bytes it discarded.
        //
        // Asserting through a predicate set that is still growing means one of
        // two failure modes: a target that is red for reasons that are not
        // bugs, or an allowance list broad enough that it stops being able to
        // fail. Neither is worth having.
        //
        // What is kept is the arm that has been clean throughout: when both
        // crates accept, framing and value must agree. That is where #59
        // (attribute consuming an element slot) and #62 (terminator length)
        // live, and it is the class self-consistent oracles structurally
        // cannot see. Across every run above, that assertion never fired.
        //
        // Making the acceptance directions assertable needs a classifier that
        // reasons about the input bytes rather than the decoded frames. Tracked
        // in #76, not attempted here.
        (Ok(_), Err(_)) => {}
        (Err(_), Ok(Some(_))) => {}

        (Ok((our_frame, _)), Ok(None)) => {
            panic!("we accept a frame the reference considers incomplete\n  input: {data:?}\n  ours:  {our_frame:?}");
        }
    }
});
