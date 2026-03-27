#![allow(unsafe_op_in_unsafe_fn)]
//! Experimental benchmark: how close to Redis C can we get with unsafe Rust?
//!
//! This is NOT production code. It strips all safety to find the theoretical
//! floor for RESP parsing in Rust, answering: "is the gap inherent to Rust,
//! or is it in our safety abstractions?"
//!
//! Three variants tested:
//! 1. Current safe parser (baseline)
//! 2. Unsafe offset-only parser (no Bytes, no bounds checks, no Frame construction)
//! 3. Unsafe with Frame construction but unchecked buffer access

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};

// ---------------------------------------------------------------------------
// Variant 2: Raw unsafe offset parser (no allocation, no Bytes, no Frame)
// This is the Rust equivalent of Redis C's callback approach.
// ---------------------------------------------------------------------------

/// Bare minimum: find \r, return offset. No bounds checks.
#[inline(always)]
unsafe fn find_cr_unchecked(buf: *const u8, from: usize) -> usize {
    let mut i = from;
    while *buf.add(i) != b'\r' {
        i += 1;
    }
    i
}

/// Parse a single RESP2 frame from raw pointer, returning bytes consumed.
/// Only counts frames (like Redis C's noop callbacks).
/// SAFETY: buf must point to valid, complete RESP2 data.
#[inline(never)]
unsafe fn parse_resp2_raw(buf: *const u8, pos: usize) -> usize {
    let tag = *buf.add(pos);
    match tag {
        b'+' | b'-' => {
            let cr = find_cr_unchecked(buf, pos + 1);
            cr + 2 // skip \r\n
        }
        b':' => {
            let cr = find_cr_unchecked(buf, pos + 1);
            cr + 2
        }
        b'$' => {
            let cr = find_cr_unchecked(buf, pos + 1);
            // Parse length manually
            let mut len: usize = 0;
            let mut i = pos + 1;
            let neg = *buf.add(i) == b'-';
            if neg {
                // $-1\r\n (null)
                return cr + 2;
            }
            while i < cr {
                len = len * 10 + (*buf.add(i) - b'0') as usize;
                i += 1;
            }
            let data_start = cr + 2;
            data_start + len + 2 // data + \r\n
        }
        b'*' => {
            let cr = find_cr_unchecked(buf, pos + 1);
            let mut i = pos + 1;
            let neg = *buf.add(i) == b'-';
            if neg {
                return cr + 2;
            }
            let mut count: usize = 0;
            while i < cr {
                count = count * 10 + (*buf.add(i) - b'0') as usize;
                i += 1;
            }
            let mut cursor = cr + 2;
            for _ in 0..count {
                cursor = parse_resp2_raw(buf, cursor);
            }
            cursor
        }
        _ => pos + 1, // shouldn't happen with valid data
    }
}

// ---------------------------------------------------------------------------
// Variant 3: Unsafe with Frame construction but unchecked buffer access
// ---------------------------------------------------------------------------

/// Parse RESP2 into Frame but skip all bounds checks.
/// SAFETY: buf must be valid, complete RESP2 data.
unsafe fn parse_resp2_unchecked_frame(input: &Bytes, pos: usize) -> (resp_rs::resp2::Frame, usize) {
    use resp_rs::resp2::Frame;

    let buf = input.as_ref();
    let tag = *buf.get_unchecked(pos);
    match tag {
        b'+' => {
            let cr = find_cr_unchecked(buf.as_ptr(), pos + 1);
            (Frame::SimpleString(input.slice(pos + 1..cr)), cr + 2)
        }
        b'-' => {
            let cr = find_cr_unchecked(buf.as_ptr(), pos + 1);
            (Frame::Error(input.slice(pos + 1..cr)), cr + 2)
        }
        b':' => {
            let cr = find_cr_unchecked(buf.as_ptr(), pos + 1);
            // Simple atoi
            let mut i = pos + 1;
            let neg = *buf.get_unchecked(i) == b'-';
            if neg {
                i += 1;
            }
            let mut v: i64 = 0;
            while i < cr {
                v = v * 10 + (*buf.get_unchecked(i) - b'0') as i64;
                i += 1;
            }
            if neg {
                v = -v;
            }
            (Frame::Integer(v), cr + 2)
        }
        b'$' => {
            let cr = find_cr_unchecked(buf.as_ptr(), pos + 1);
            let mut i = pos + 1;
            if *buf.get_unchecked(i) == b'-' {
                return (Frame::BulkString(None), cr + 2);
            }
            let mut len: usize = 0;
            while i < cr {
                len = len * 10 + (*buf.get_unchecked(i) - b'0') as usize;
                i += 1;
            }
            let data_start = cr + 2;
            let data_end = data_start + len;
            (
                Frame::BulkString(Some(input.slice(data_start..data_end))),
                data_end + 2,
            )
        }
        b'*' => {
            let cr = find_cr_unchecked(buf.as_ptr(), pos + 1);
            let mut i = pos + 1;
            if *buf.get_unchecked(i) == b'-' {
                return (Frame::Array(None), cr + 2);
            }
            let mut count: usize = 0;
            while i < cr {
                count = count * 10 + (*buf.get_unchecked(i) - b'0') as usize;
                i += 1;
            }
            let mut cursor = cr + 2;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                let (frame, next) = parse_resp2_unchecked_frame(input, cursor);
                items.push(frame);
                cursor = next;
            }
            (Frame::Array(Some(items)), cursor)
        }
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_simple_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("unsafe_exp/simple_string");
    let wire = "+OK\r\n";
    let data = Bytes::from(wire);

    group.bench_function("safe", |b| {
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("unsafe_raw", |b| {
        let ptr = wire.as_ptr();
        b.iter(|| unsafe { parse_resp2_raw(ptr, 0) });
    });
    group.bench_function("unsafe_frame", |b| {
        b.iter(|| unsafe { parse_resp2_unchecked_frame(&data, 0) });
    });
    group.finish();
}

fn bench_bulk_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("unsafe_exp/bulk_string");
    let wire = "$11\r\nhello world\r\n";
    let data = Bytes::from(wire);

    group.bench_function("safe", |b| {
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("unsafe_raw", |b| {
        let ptr = wire.as_ptr();
        b.iter(|| unsafe { parse_resp2_raw(ptr, 0) });
    });
    group.bench_function("unsafe_frame", |b| {
        b.iter(|| unsafe { parse_resp2_unchecked_frame(&data, 0) });
    });
    group.finish();
}

fn bench_integer(c: &mut Criterion) {
    let mut group = c.benchmark_group("unsafe_exp/integer");
    let wire = ":9223372036854775807\r\n";
    let data = Bytes::from(wire);

    group.bench_function("safe", |b| {
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("unsafe_raw", |b| {
        let ptr = wire.as_ptr();
        b.iter(|| unsafe { parse_resp2_raw(ptr, 0) });
    });
    group.bench_function("unsafe_frame", |b| {
        b.iter(|| unsafe { parse_resp2_unchecked_frame(&data, 0) });
    });
    group.finish();
}

fn bench_array_3(c: &mut Criterion) {
    let mut group = c.benchmark_group("unsafe_exp/array_3");
    let wire = "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n";
    let data = Bytes::from(wire);

    group.bench_function("safe", |b| {
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("unsafe_raw", |b| {
        let ptr = wire.as_ptr();
        b.iter(|| unsafe { parse_resp2_raw(ptr, 0) });
    });
    group.bench_function("unsafe_frame", |b| {
        b.iter(|| unsafe { parse_resp2_unchecked_frame(&data, 0) });
    });
    group.finish();
}

fn bench_array_100(c: &mut Criterion) {
    let mut group = c.benchmark_group("unsafe_exp/array_100");

    let mut wire = "*100\r\n".to_string();
    for i in 0..100 {
        let s = format!("value-{i:03}");
        wire.push_str(&format!("${}\r\n{}\r\n", s.len(), s));
    }
    let data = Bytes::from(wire.clone());

    group.bench_function("safe", |b| {
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("unsafe_raw", |b| {
        let ptr = wire.as_ptr();
        b.iter(|| unsafe { parse_resp2_raw(ptr, 0) });
    });
    group.bench_function("unsafe_frame", |b| {
        b.iter(|| unsafe { parse_resp2_unchecked_frame(&data, 0) });
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Feature-gated parse_frame_unchecked benchmarks
// ---------------------------------------------------------------------------

#[cfg(feature = "unsafe-internals")]
fn bench_feature_gated(c: &mut Criterion) {
    let mut group = c.benchmark_group("feature_gated");

    group.bench_function("resp2_simple_string", |b| {
        let data = Bytes::from("+OK\r\n");
        b.iter(|| unsafe { resp_rs::resp2::parse_frame_unchecked(data.clone()) });
    });

    group.bench_function("resp2_array_3", |b| {
        let data = Bytes::from("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
        b.iter(|| unsafe { resp_rs::resp2::parse_frame_unchecked(data.clone()) });
    });

    group.bench_function("resp3_simple_string", |b| {
        let data = Bytes::from("+OK\r\n");
        b.iter(|| unsafe { resp_rs::resp3::parse_frame_unchecked(data.clone()) });
    });

    group.bench_function("resp3_array_3", |b| {
        let data = Bytes::from("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
        b.iter(|| unsafe { resp_rs::resp3::parse_frame_unchecked(data.clone()) });
    });

    let mut wire = "*100\r\n".to_string();
    for i in 0..100 {
        let s = format!("value-{i:03}");
        wire.push_str(&format!("${}\r\n{}\r\n", s.len(), s));
    }
    group.bench_function("resp3_array_100", |b| {
        let data = Bytes::from(wire.clone());
        b.iter(|| unsafe { resp_rs::resp3::parse_frame_unchecked(data.clone()) });
    });

    group.finish();
}

#[cfg(feature = "unsafe-internals")]
criterion_group!(
    benches,
    bench_simple_string,
    bench_bulk_string,
    bench_integer,
    bench_array_3,
    bench_array_100,
    bench_feature_gated,
);

#[cfg(not(feature = "unsafe-internals"))]
criterion_group!(
    benches,
    bench_simple_string,
    bench_bulk_string,
    bench_integer,
    bench_array_3,
    bench_array_100,
);

criterion_main!(benches);
