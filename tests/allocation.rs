//! Allocation regression tests for issue #50.
//!
//! A behavioural test cannot catch this one. A collection header claiming more
//! elements than the input could hold returns `Incomplete` both before and
//! after the fix; only the allocation differs. So these tests measure the
//! allocation directly, through a tracking global allocator.
//!
//! The gap under test is roughly zero against hundreds of megabytes, so the
//! thresholds are far outside the range of any measurement noise.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use bytes::Bytes;
use resp_rs::{ParseError, resp2, resp3};

// Counters are per thread, not per process. The test harness runs each test on
// its own thread, so this attributes every allocation to the test that made it.
//
// A process-wide counter cannot work here even under a mutex: a mutex only
// serialises the tests that take it, while sibling tests allocate on other
// threads throughout, and those allocations land in whatever measurement
// happens to be open. That produced a roughly 1-in-12 flake.
//
// `const` initialisation matters: it keeps this allocation-free, so observing
// an allocation cannot itself allocate and recurse. `Cell<usize>` has no
// destructor, so there is no TLS teardown ordering to worry about, and
// `try_with` degrades to not counting rather than panicking if it is ever
// reached during teardown.
thread_local! {
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
    /// Cumulative bytes requested, never decremented.
    ///
    /// Distinct from PEAK on purpose. Churn that is freed as fast as it is
    /// allocated leaves PEAK flat, so a quadratic copy loop is invisible to a
    /// peak measurement and only shows up in the running total.
    static TOTAL: Cell<usize> = const { Cell::new(0) };
}

struct Tracking;

// SAFETY: every method forwards to the system allocator unchanged; the counters
// only observe sizes and never affect the pointers handed back.
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = TOTAL.try_with(|total| total.set(total.get() + layout.size()));
        let _ = LIVE.try_with(|live| {
            let now = live.get() + layout.size();
            live.set(now);
            let _ = PEAK.try_with(|peak| {
                if now > peak.get() {
                    peak.set(now);
                }
            });
        });
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Saturating: a buffer allocated on another thread and dropped on this
        // one would otherwise underflow.
        let _ = LIVE.try_with(|live| live.set(live.get().saturating_sub(layout.size())));
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Tracking = Tracking;

/// Peak bytes allocated on this thread while `f` runs.
fn peak_alloc<T>(f: impl FnOnce() -> T) -> usize {
    let before = LIVE.with(|live| live.get());
    PEAK.with(|peak| peak.set(before));
    let value = f();
    let peak = PEAK.with(|peak| peak.get());
    drop(value);
    peak.saturating_sub(before)
}

/// Cumulative bytes allocated on this thread while `f` runs.
fn total_alloc<T>(f: impl FnOnce() -> T) -> usize {
    let before = TOTAL.with(|t| t.get());
    let value = f();
    let after = TOTAL.with(|t| t.get());
    drop(value);
    after - before
}

/// Well clear of the ~0 a bounded parse needs, and far below the 381 MB to
/// 1373 MB the unbounded version reserved.
const BUDGET: usize = 1024 * 1024;

// --- A header alone must not reserve anything ---

#[test]
fn resp2_array_header_reserves_nothing() {
    let peak = peak_alloc(|| {
        let r = resp2::parse_frame(Bytes::from_static(b"*10000000\r\n"));
        assert_eq!(r, Err(ParseError::Incomplete));
    });
    assert!(peak < BUDGET, "reserved {peak} bytes for an 11-byte input");
}

#[test]
fn resp3_collection_headers_reserve_nothing() {
    for wire in [
        &b"*10000000\r\n"[..],
        &b"~10000000\r\n"[..],
        &b">10000000\r\n"[..],
    ] {
        let peak = peak_alloc(|| {
            let r = resp3::parse_frame(Bytes::copy_from_slice(wire));
            assert_eq!(r, Err(ParseError::Incomplete));
        });
        assert!(
            peak < BUDGET,
            "reserved {peak} bytes for {:?}",
            String::from_utf8_lossy(wire)
        );
    }
}

#[test]
fn resp3_pair_headers_reserve_nothing() {
    // Maps and attributes cost double, since each element is a key and a value.
    for wire in [&b"%10000000\r\n"[..], &b"|10000000\r\n"[..]] {
        let peak = peak_alloc(|| {
            let r = resp3::parse_frame(Bytes::copy_from_slice(wire));
            assert_eq!(r, Err(ParseError::Incomplete));
        });
        assert!(
            peak < BUDGET,
            "reserved {peak} bytes for {:?}",
            String::from_utf8_lossy(wire)
        );
    }
}

/// `depth` nested collection headers, each claiming `count` elements, followed
/// by `pad` bytes so every level sees a large remaining-byte budget.
fn nested_headers(depth: usize, count: usize, pad: usize) -> Bytes {
    let header = format!("*{count}\r\n");
    let mut wire = String::with_capacity(depth * header.len() + pad);
    for _ in 0..depth {
        wire.push_str(&header);
    }
    wire.extend(core::iter::repeat_n('x', pad));
    Bytes::from(wire)
}

#[test]
fn nested_headers_do_not_multiply_the_reservation() {
    // Clamping to the remaining bytes is per level, and each enclosing
    // collection holds its reservation while its children parse. Without a cap
    // on the initial reservation, MAX_DEPTH of those clamps are live at once:
    // this input reached 351 MB, about 3000x its own size.
    let wire = nested_headers(128, 40_000, 120_000);
    let len = wire.len();
    let peak = peak_alloc(|| {
        let r = resp3::parse_frame(wire);
        assert_eq!(r, Err(ParseError::InvalidTag(b'x')));
    });
    assert!(
        peak < 2 * BUDGET,
        "reserved {peak} bytes for a {len}-byte input ({}x)",
        peak / len
    );
}

#[test]
fn nested_header_reservation_is_independent_of_input_size() {
    // The bound is MAX_DEPTH * PREALLOC_CAP * size_of::<Frame>(), a constant.
    // Growing the input must not grow the reservation. Build the inputs outside
    // the measurement so only the parse is counted.
    //
    // The count has to be large enough that the remaining-bytes clamp is what
    // binds, not the count itself, or padding cannot move the reservation and
    // the test would pass whether or not the cap exists.
    let small_wire = nested_headers(128, 10_000_000, 30_000);
    let large_wire = nested_headers(128, 10_000_000, 120_000);

    let small = peak_alloc(|| resp3::parse_frame(small_wire.clone()));
    let large = peak_alloc(|| resp3::parse_frame(large_wire.clone()));

    // Bytes::clone is a refcount bump, so neither closure allocates the input.
    assert!(
        large <= small + BUDGET / 16,
        "8x the input grew the reservation from {small} to {large} bytes"
    );
}

#[test]
fn allocation_tracks_input_not_claimed_count() {
    // Same claimed count, one byte of payload apart: allocation must not jump.
    let small = peak_alloc(|| resp2::parse_frame(Bytes::from_static(b"*1000000\r\n")));
    let padded = peak_alloc(|| resp2::parse_frame(Bytes::from_static(b"*1000000\r\n:1\r\n")));
    assert!(
        small < BUDGET && padded < BUDGET,
        "reserved {small} and {padded} bytes"
    );
}

// --- Legitimate input must still parse ---

#[test]
fn complete_collections_still_parse() {
    let cases: &[&[u8]] = &[
        b"*3\r\n:1\r\n:2\r\n:3\r\n",
        b"~3\r\n:1\r\n:2\r\n:3\r\n",
        b">3\r\n:1\r\n:2\r\n:3\r\n",
        b"%2\r\n+a\r\n:1\r\n+b\r\n:2\r\n",
        b"|1\r\n+k\r\n+v\r\n",
    ];
    for wire in cases {
        let (_, rest) = resp3::parse_frame(Bytes::copy_from_slice(wire))
            .unwrap_or_else(|e| panic!("{:?}: {e:?}", String::from_utf8_lossy(wire)));
        assert!(rest.is_empty(), "{:?}", String::from_utf8_lossy(wire));
    }
}

#[test]
fn smallest_possible_elements_are_not_rejected() {
    // MIN_FRAME_SIZE is 3 bytes. These inputs sit exactly on that bound, so
    // they prove the check does not reject the tightest legal encoding.
    let (frame, rest) = resp2::parse_frame(Bytes::from_static(b"*1\r\n+\r\n")).unwrap();
    assert!(rest.is_empty());
    assert_eq!(
        frame,
        resp2::Frame::Array(Some(vec![resp2::Frame::SimpleString(Bytes::new())]))
    );

    // A map element is a pair, so this is 6 bytes of payload for one element.
    let (frame, rest) = resp3::parse_frame(Bytes::from_static(b"%1\r\n+\r\n+\r\n")).unwrap();
    assert!(rest.is_empty());
    assert_eq!(
        frame,
        resp3::Frame::Map(vec![(
            resp3::Frame::SimpleString(Bytes::new()),
            resp3::Frame::SimpleString(Bytes::new())
        )])
    );
}

#[test]
fn genuinely_truncated_collection_still_reports_incomplete() {
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b"*2\r\n+\r\n")),
        Err(ParseError::Incomplete)
    );
}

// --- An oversized count must not mask a definite protocol error ---
//
// Bounding the reservation must not decide the outcome. If the bytes already
// present contain something that can never be valid, no amount of further data
// changes that, so the parse has to fail rather than report Incomplete. Getting
// this wrong turns fail-fast into never-fail: `Parser` treats Incomplete as
// "need more data" and would buffer from a peer forever without ever having
// grounds to drop the connection.

#[test]
fn oversized_count_still_reports_an_invalid_tag() {
    // `<` is not a type tag in either protocol, and the count is far larger
    // than the remaining bytes could hold.
    assert_eq!(
        resp2::parse_frame(Bytes::from_static(b"*9999999\r\n<garbage\r\n")),
        Err(ParseError::InvalidTag(b'<'))
    );
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b"~9999999\r\n<garbage\r\n")),
        Err(ParseError::InvalidTag(b'<'))
    );
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b"%9999999\r\n<garbage\r\n")),
        Err(ParseError::InvalidTag(b'<'))
    );
}

#[test]
fn oversized_count_matches_small_count_on_malformed_input() {
    // The count must not change the diagnosis. These pairs differ only in the
    // declared count, so they must produce the same error.
    let cases: &[(&[u8], &[u8])] = &[
        (b"~1\r\n<garbage\r\n", b"~9999999\r\n<garbage\r\n"),
        (b"*1\r\n<garbage\r\n", b"*9999999\r\n<garbage\r\n"),
        (b"%1\r\n<garbage\r\n", b"%9999999\r\n<garbage\r\n"),
    ];
    for (small, large) in cases {
        let small_result = resp3::parse_frame(Bytes::copy_from_slice(small));
        let large_result = resp3::parse_frame(Bytes::copy_from_slice(large));
        assert_eq!(
            small_result,
            large_result,
            "{:?} and {:?} diverged",
            String::from_utf8_lossy(small),
            String::from_utf8_lossy(large)
        );
    }
}

#[test]
fn parser_terminates_on_oversized_count_with_invalid_tag() {
    // Regression guard: a peer sends a header claiming millions of elements
    // followed by one invalid byte, then keeps sending. The parser must error
    // rather than buffer without bound.
    let mut parser = resp3::Parser::new();
    parser.feed(Bytes::from_static(b"~9999999\r\n"));
    parser.feed(Bytes::from_static(b"<garbage\r\n"));
    assert_eq!(parser.next_frame(), Err(ParseError::InvalidTag(b'<')));
}

#[test]
fn differential_fuzzer_divergences() {
    // Inputs from the resp-zig differential fuzzer that reported Incomplete
    // when the Zig port reported a definite error.
    let cases: &[(&[u8], ParseError)] = &[
        (b"~3\r\nab\xe9\r\n", ParseError::InvalidTag(b'a')),
        (b"%4\r\nabc:\r\n", ParseError::InvalidTag(b'a')),
    ];
    for (wire, expected) in cases {
        assert_eq!(
            resp3::parse_frame(Bytes::copy_from_slice(wire)),
            Err(expected.clone()),
            "{:?}",
            String::from_utf8_lossy(wire)
        );
    }

    // Nested case: the inner map's count outruns the buffer, and `<` inside it
    // is not a valid tag.
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(
            b"*2\r\n%8\r\n+k\r\n<1\r\n#t\r\n\x945\r\n"
        )),
        Err(ParseError::InvalidTag(b'<'))
    );
}

#[test]
fn oversized_count_with_valid_prefix_still_reports_incomplete() {
    // The other side of the same coin: when the bytes present are valid as far
    // as they go, Incomplete is still the right answer and streaming works.
    assert_eq!(
        resp3::parse_frame(Bytes::from_static(b"~9999999\r\n:1\r\n:2\r\n")),
        Err(ParseError::Incomplete)
    );
}

// --- Streaming must still assemble across feeds ---

#[test]
fn collection_split_across_feeds_still_parses() {
    // The header arrives before its elements, so the first read is short and
    // must report Incomplete rather than erroring or over-reserving.
    let mut parser = resp2::Parser::new();
    parser.feed(Bytes::from_static(b"*3\r\n"));
    assert_eq!(parser.next_frame(), Ok(None));

    parser.feed(Bytes::from_static(b":1\r\n:2\r\n"));
    assert_eq!(parser.next_frame(), Ok(None));

    parser.feed(Bytes::from_static(b":3\r\n"));
    let frame = parser.next_frame().unwrap().unwrap();
    assert_eq!(
        frame,
        resp2::Frame::Array(Some(vec![
            resp2::Frame::Integer(1),
            resp2::Frame::Integer(2),
            resp2::Frame::Integer(3),
        ]))
    );
}

#[test]
fn large_collection_parses_once_its_bytes_arrive() {
    // 50,000 elements is well past any per-call reservation the header alone
    // could justify, and must still parse when the data is actually present.
    let count = 50_000;
    let mut wire = format!("*{count}\r\n");
    for _ in 0..count {
        wire.push_str(":1\r\n");
    }
    let (frame, rest) = resp2::parse_frame(Bytes::from(wire)).unwrap();
    assert!(rest.is_empty());
    match frame {
        resp2::Frame::Array(Some(items)) => assert_eq!(items.len(), count),
        other => panic!("expected array, got {other:?}"),
    }
}

// --- Draining a pipelined buffer must not copy the tail (issue #61) ---

/// Feed `n` frames in one go, then drain to exhaustion.
fn drain_pipelined(n: usize) -> (usize, usize) {
    let wire = Bytes::from("+OK\r\n".repeat(n));
    let input = wire.len();
    let mut parser = resp2::Parser::new();
    let peak = total_alloc(|| {
        parser.feed(wire);
        let mut got = 0;
        while let Ok(Some(_)) = parser.next_frame() {
            got += 1;
        }
        assert_eq!(got, n);
    });
    (input, peak)
}

#[test]
fn draining_a_pipelined_buffer_is_linear_not_quadratic() {
    // Every frame used to rebuild the unconsumed remainder with a fresh
    // allocation and a full copy, so draining K frames copied the tail K times.
    // 200,000 frames over 1 MB of input allocated 100 GB.
    let (input, peak) = drain_pipelined(50_000);
    assert!(
        peak < input * 4,
        "drained 50,000 frames from {input} bytes using {peak} bytes ({}x)",
        peak / input.max(1)
    );
}

#[test]
fn drain_cost_grows_with_input_not_with_input_squared() {
    // Doubling the frame count must roughly double the allocation, not
    // quadruple it. Quadratic behaviour showed a 4x step here.
    let (_, small) = drain_pipelined(25_000);
    let (_, large) = drain_pipelined(50_000);
    assert!(
        large < small * 3,
        "doubling the input took allocation from {small} to {large} bytes"
    );
}

#[test]
fn a_hard_error_still_discards_everything() {
    // The buffer used to be emptied as a side effect of split(). It is not any
    // more, so the discard is explicit and worth pinning.
    let mut parser = resp2::Parser::new();
    parser.feed(Bytes::from_static(b"+ok\r\nX bad\r\n+more\r\n"));
    assert!(parser.next_frame().unwrap().is_some());
    assert!(parser.next_frame().is_err());
    assert_eq!(parser.buffered_bytes(), 0);
    assert_eq!(parser.next_frame().unwrap(), None);
}

#[test]
fn buffered_bytes_counts_data_fed_mid_drain() {
    // Feeds now land in a staging buffer until the next read merges them, so
    // the accessor has to account for both.
    let mut parser = resp2::Parser::new();
    parser.feed(Bytes::from_static(b"+a\r\n+b\r\n"));
    assert_eq!(parser.buffered_bytes(), 8);

    assert!(parser.next_frame().unwrap().is_some());
    assert_eq!(parser.buffered_bytes(), 4);

    parser.feed(Bytes::from_static(b"+c\r\n"));
    assert_eq!(parser.buffered_bytes(), 8);

    assert!(parser.next_frame().unwrap().is_some());
    assert!(parser.next_frame().unwrap().is_some());
    assert_eq!(parser.buffered_bytes(), 0);
    assert_eq!(parser.next_frame().unwrap(), None);
}

#[test]
fn feeding_mid_frame_still_assembles() {
    // A feed arriving while an incomplete frame is buffered must merge, not
    // replace.
    let mut parser = resp3::Parser::new();
    parser.feed(Bytes::from_static(b"$5\r\nhel"));
    assert_eq!(parser.next_frame().unwrap(), None);
    parser.feed(Bytes::from_static(b"lo\r\n:7\r\n"));
    assert_eq!(
        parser.next_frame().unwrap().unwrap(),
        resp3::Frame::BulkString(Some(Bytes::from_static(b"hello")))
    );
    assert_eq!(
        parser.next_frame().unwrap().unwrap(),
        resp3::Frame::Integer(7)
    );
    assert_eq!(parser.next_frame().unwrap(), None);
}
