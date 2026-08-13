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
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use resp_rs::{ParseError, resp2, resp3};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Tracking;

// SAFETY: every method forwards to the system allocator unchanged; the atomics
// only observe sizes and never affect the pointers handed back.
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
        PEAK.fetch_max(live, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Tracking = Tracking;

/// Serialises measurement so tests running in parallel cannot pollute the
/// counters for one another.
static MEASURING: Mutex<()> = Mutex::new(());

/// Peak bytes allocated while `f` runs.
fn peak_alloc<T>(f: impl FnOnce() -> T) -> usize {
    let _guard = MEASURING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let before = LIVE.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let value = f();
    let peak = PEAK.load(Ordering::SeqCst);
    drop(value);
    peak.saturating_sub(before)
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
