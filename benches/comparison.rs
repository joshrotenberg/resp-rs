//! Comparative benchmarks: resp-rs vs redis-protocol

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_resp2_simple_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp2/simple_string");
    let data = Bytes::from("+OK\r\n");
    let raw = b"+OK\r\n";

    group.bench_function("resp-rs", |b| {
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("redis-protocol", |b| {
        b.iter(|| redis_protocol::resp2::decode::decode(raw).unwrap());
    });
    group.finish();
}

fn bench_resp2_bulk_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp2/bulk_string");
    let data = Bytes::from("$11\r\nhello world\r\n");
    let raw = b"$11\r\nhello world\r\n";

    group.bench_function("resp-rs", |b| {
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("redis-protocol", |b| {
        b.iter(|| redis_protocol::resp2::decode::decode(raw).unwrap());
    });
    group.finish();
}

fn bench_resp2_array(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp2/array_3");
    let data = Bytes::from("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
    let raw = b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n";

    group.bench_function("resp-rs", |b| {
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("redis-protocol", |b| {
        b.iter(|| redis_protocol::resp2::decode::decode(raw).unwrap());
    });
    group.finish();
}

fn bench_resp3_simple_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp3/simple_string");
    let data = Bytes::from("+OK\r\n");
    let raw = b"+OK\r\n";

    group.bench_function("resp-rs", |b| {
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("redis-protocol", |b| {
        b.iter(|| redis_protocol::resp3::decode::complete::decode(raw).unwrap());
    });
    group.finish();
}

fn bench_resp3_bulk_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp3/bulk_string");
    let data = Bytes::from("$11\r\nhello world\r\n");
    let raw = b"$11\r\nhello world\r\n";

    group.bench_function("resp-rs", |b| {
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("redis-protocol", |b| {
        b.iter(|| redis_protocol::resp3::decode::complete::decode(raw).unwrap());
    });
    group.finish();
}

fn bench_resp3_array(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp3/array_3");
    let data = Bytes::from("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
    let raw = b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n";

    group.bench_function("resp-rs", |b| {
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("redis-protocol", |b| {
        b.iter(|| redis_protocol::resp3::decode::complete::decode(raw).unwrap());
    });
    group.finish();
}

fn bench_resp3_integer(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp3/integer");
    let data = Bytes::from(":9223372036854775807\r\n");
    let raw = b":9223372036854775807\r\n";

    group.bench_function("resp-rs", |b| {
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("redis-protocol", |b| {
        b.iter(|| redis_protocol::resp3::decode::complete::decode(raw).unwrap());
    });
    group.finish();
}

fn bench_resp2_large_array(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp2/array_100");

    // Build a 100-element array of bulk strings
    let mut wire = "*100\r\n".to_string();
    for i in 0..100 {
        let s = format!("value-{i:03}");
        wire.push_str(&format!("${}\r\n{}\r\n", s.len(), s));
    }
    let data = Bytes::from(wire.clone());
    let raw = wire.into_bytes();

    group.bench_function("resp-rs", |b| {
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("redis-protocol", |b| {
        b.iter(|| redis_protocol::resp2::decode::decode(&raw).unwrap());
    });
    group.finish();
}

fn bench_resp3_large_array(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp3/array_100");

    let mut wire = "*100\r\n".to_string();
    for i in 0..100 {
        let s = format!("value-{i:03}");
        wire.push_str(&format!("${}\r\n{}\r\n", s.len(), s));
    }
    let data = Bytes::from(wire.clone());
    let raw = wire.into_bytes();

    group.bench_function("resp-rs", |b| {
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });
    group.bench_function("redis-protocol", |b| {
        b.iter(|| redis_protocol::resp3::decode::complete::decode(&raw).unwrap());
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_resp2_simple_string,
    bench_resp2_bulk_string,
    bench_resp2_array,
    bench_resp2_large_array,
    bench_resp3_simple_string,
    bench_resp3_bulk_string,
    bench_resp3_array,
    bench_resp3_integer,
    bench_resp3_large_array,
);
criterion_main!(benches);
