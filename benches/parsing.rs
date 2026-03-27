//! Parsing benchmarks for RESP2 and RESP3.

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};

fn bench_resp2_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp2");

    group.bench_function("simple_string", |b| {
        let data = Bytes::from("+OK\r\n");
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("error", |b| {
        let data = Bytes::from("-ERR unknown command 'FOOBAR'\r\n");
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("integer", |b| {
        let data = Bytes::from(":9223372036854775807\r\n");
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

    // 100-element array of bulk strings
    let mut wire = "*100\r\n".to_string();
    for i in 0..100 {
        let s = format!("value-{i:03}");
        wire.push_str(&format!("${}\r\n{}\r\n", s.len(), s));
    }
    group.bench_function("array_100", |b| {
        let data = Bytes::from(wire.clone());
        b.iter(|| resp_rs::resp2::parse_frame(data.clone()).unwrap());
    });

    group.finish();
}

fn bench_resp2_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp2_roundtrip");

    group.bench_function("set_command", |b| {
        let data = Bytes::from("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
        b.iter(|| {
            let (frame, _) = resp_rs::resp2::parse_frame(data.clone()).unwrap();
            resp_rs::resp2::frame_to_bytes(&frame)
        });
    });

    group.finish();
}

fn bench_resp2_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp2_pipeline");

    // 5 pipelined commands
    let pipeline = Bytes::from(
        "+OK\r\n\
         $5\r\nhello\r\n\
         :42\r\n\
         -ERR not found\r\n\
         *2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n",
    );

    group.bench_function("parse_5_frames", |b| {
        b.iter(|| {
            let mut input = pipeline.clone();
            for _ in 0..5 {
                let (_, rest) = resp_rs::resp2::parse_frame(input).unwrap();
                input = rest;
            }
        });
    });

    group.bench_function("parser_5_frames", |b| {
        b.iter(|| {
            let mut parser = resp_rs::resp2::Parser::new();
            parser.feed(pipeline.clone());
            let mut count = 0;
            while parser.next_frame().unwrap().is_some() {
                count += 1;
            }
            assert_eq!(count, 5);
        });
    });

    group.finish();
}

fn bench_resp3_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp3");

    group.bench_function("simple_string", |b| {
        let data = Bytes::from("+OK\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("error", |b| {
        let data = Bytes::from("-ERR unknown command 'FOOBAR'\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("integer", |b| {
        let data = Bytes::from(":9223372036854775807\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("bulk_string", |b| {
        let data = Bytes::from("$11\r\nhello world\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("null", |b| {
        let data = Bytes::from("_\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("boolean", |b| {
        let data = Bytes::from("#t\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("double", |b| {
        let data = Bytes::from(",3.14159265358979\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("verbatim_string", |b| {
        let data = Bytes::from("=15\r\ntxt:hello world\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("map_2", |b| {
        let data = Bytes::from("%2\r\n+key1\r\n$5\r\nval-1\r\n+key2\r\n:42\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.bench_function("array_3", |b| {
        let data = Bytes::from("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    // 100-element array of bulk strings
    let mut wire = "*100\r\n".to_string();
    for i in 0..100 {
        let s = format!("value-{i:03}");
        wire.push_str(&format!("${}\r\n{}\r\n", s.len(), s));
    }
    group.bench_function("array_100", |b| {
        let data = Bytes::from(wire.clone());
        b.iter(|| resp_rs::resp3::parse_frame(data.clone()).unwrap());
    });

    group.finish();
}

fn bench_resp3_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp3_roundtrip");

    group.bench_function("set_command", |b| {
        let data = Bytes::from("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
        b.iter(|| {
            let (frame, _) = resp_rs::resp3::parse_frame(data.clone()).unwrap();
            resp_rs::resp3::frame_to_bytes(&frame)
        });
    });

    group.bench_function("map_2", |b| {
        let data = Bytes::from("%2\r\n+key1\r\n$5\r\nval-1\r\n+key2\r\n:42\r\n");
        b.iter(|| {
            let (frame, _) = resp_rs::resp3::parse_frame(data.clone()).unwrap();
            resp_rs::resp3::frame_to_bytes(&frame)
        });
    });

    group.finish();
}

fn bench_resp3_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp3_pipeline");

    // 5 pipelined frames with mixed RESP3 types
    let pipeline = Bytes::from(
        "+OK\r\n\
         $5\r\nhello\r\n\
         :42\r\n\
         #t\r\n\
         %1\r\n+key\r\n$3\r\nval\r\n",
    );

    group.bench_function("parse_5_frames", |b| {
        b.iter(|| {
            let mut input = pipeline.clone();
            for _ in 0..5 {
                let (_, rest) = resp_rs::resp3::parse_frame(input).unwrap();
                input = rest;
            }
        });
    });

    group.bench_function("parser_5_frames", |b| {
        b.iter(|| {
            let mut parser = resp_rs::resp3::Parser::new();
            parser.feed(pipeline.clone());
            let mut count = 0;
            while parser.next_frame().unwrap().is_some() {
                count += 1;
            }
            assert_eq!(count, 5);
        });
    });

    group.finish();
}

fn bench_resp3_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp3_streaming");

    group.bench_function("streamed_string", |b| {
        let data = Bytes::from("$?\r\n;5\r\nhello\r\n;6\r\n world\r\n;0\r\n\r\n");
        b.iter(|| resp_rs::resp3::parse_streaming_sequence(data.clone()).unwrap());
    });

    group.bench_function("streamed_array_5", |b| {
        let data = Bytes::from("*?\r\n+one\r\n+two\r\n+three\r\n:4\r\n:5\r\n.\r\n");
        b.iter(|| resp_rs::resp3::parse_streaming_sequence(data.clone()).unwrap());
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_resp2_parse,
    bench_resp2_roundtrip,
    bench_resp2_pipeline,
    bench_resp3_parse,
    bench_resp3_roundtrip,
    bench_resp3_pipeline,
    bench_resp3_streaming,
);
criterion_main!(benches);
