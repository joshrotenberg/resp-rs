//! Parsing benchmarks for RESP2 and RESP3.

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_resp2_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp2");

    group.bench_function("simple_string", |b| {
        let data = Bytes::from("+OK\r\n");
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("bulk_string", |b| {
        let data = Bytes::from("$11\r\nhello world\r\n");
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("array_3", |b| {
        let data = Bytes::from("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });

    group.finish();
}

fn bench_resp3_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp3");

    group.bench_function("simple_string", |b| {
        let data = Bytes::from("+OK\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("bulk_string", |b| {
        let data = Bytes::from("$11\r\nhello world\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("array_3", |b| {
        let data = Bytes::from("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("integer", |b| {
        let data = Bytes::from(":9223372036854775807\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.finish();
}

criterion_group!(benches, bench_resp2_parse, bench_resp3_parse);
criterion_main!(benches);
