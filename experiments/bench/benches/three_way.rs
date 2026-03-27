//! Head-to-head: RESP3 (text) vs BRESP (binary) vs Protobuf on identical commands.

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use prost::Message;

fn bench_simple_string(c: &mut Criterion) {
    let resp3_frame = resp_rs::resp3::Frame::SimpleString(Bytes::from("OK"));
    let resp3_wire = resp_rs::resp3::frame_to_bytes(&resp3_frame);

    let bresp_frame = bresp::Frame::SimpleString(Bytes::from("OK"));
    let bresp_wire = bresp::frame_to_bytes(&bresp_frame);

    let proto_frame = proto_resp::resp3_to_proto(&resp3_frame);
    let mut proto_wire = Vec::new();
    proto_frame.encode(&mut proto_wire).unwrap();
    let proto_bytes = Bytes::from(proto_wire);

    let mut group = c.benchmark_group("3way/simple_string");
    group.bench_function(format!("resp3 ({} B)", resp3_wire.len()), |b| {
        b.iter(|| resp_rs::resp3::parse_frame(resp3_wire.clone()).unwrap());
    });
    group.bench_function(format!("bresp ({} B)", bresp_wire.len()), |b| {
        b.iter(|| bresp::parse_frame(bresp_wire.clone()).unwrap());
    });
    group.bench_function(format!("proto ({} B)", proto_bytes.len()), |b| {
        b.iter(|| proto_resp::pb::Frame::decode(proto_bytes.as_ref()).unwrap());
    });
    group.finish();
}

fn bench_integer(c: &mut Criterion) {
    let resp3_frame = resp_rs::resp3::Frame::Integer(i64::MAX);
    let resp3_wire = resp_rs::resp3::frame_to_bytes(&resp3_frame);

    let bresp_frame = bresp::Frame::Integer(i64::MAX);
    let bresp_wire = bresp::frame_to_bytes(&bresp_frame);

    let proto_frame = proto_resp::resp3_to_proto(&resp3_frame);
    let mut proto_wire = Vec::new();
    proto_frame.encode(&mut proto_wire).unwrap();
    let proto_bytes = Bytes::from(proto_wire);

    let mut group = c.benchmark_group("3way/integer_max");
    group.bench_function(format!("resp3 ({} B)", resp3_wire.len()), |b| {
        b.iter(|| resp_rs::resp3::parse_frame(resp3_wire.clone()).unwrap());
    });
    group.bench_function(format!("bresp ({} B)", bresp_wire.len()), |b| {
        b.iter(|| bresp::parse_frame(bresp_wire.clone()).unwrap());
    });
    group.bench_function(format!("proto ({} B)", proto_bytes.len()), |b| {
        b.iter(|| proto_resp::pb::Frame::decode(proto_bytes.as_ref()).unwrap());
    });
    group.finish();
}

fn bench_double(c: &mut Criterion) {
    let resp3_frame = resp_rs::resp3::Frame::Double(1.23456789012345);
    let resp3_wire = resp_rs::resp3::frame_to_bytes(&resp3_frame);

    let bresp_frame = bresp::Frame::Double(1.23456789012345);
    let bresp_wire = bresp::frame_to_bytes(&bresp_frame);

    let proto_frame = proto_resp::resp3_to_proto(&resp3_frame);
    let mut proto_wire = Vec::new();
    proto_frame.encode(&mut proto_wire).unwrap();
    let proto_bytes = Bytes::from(proto_wire);

    let mut group = c.benchmark_group("3way/double");
    group.bench_function(format!("resp3 ({} B)", resp3_wire.len()), |b| {
        b.iter(|| resp_rs::resp3::parse_frame(resp3_wire.clone()).unwrap());
    });
    group.bench_function(format!("bresp ({} B)", bresp_wire.len()), |b| {
        b.iter(|| bresp::parse_frame(bresp_wire.clone()).unwrap());
    });
    group.bench_function(format!("proto ({} B)", proto_bytes.len()), |b| {
        b.iter(|| proto_resp::pb::Frame::decode(proto_bytes.as_ref()).unwrap());
    });
    group.finish();
}

fn bench_set_command(c: &mut Criterion) {
    let resp3_frame = resp_rs::resp3::Frame::Array(Some(vec![
        resp_rs::resp3::Frame::BulkString(Some(Bytes::from("SET"))),
        resp_rs::resp3::Frame::BulkString(Some(Bytes::from("key"))),
        resp_rs::resp3::Frame::BulkString(Some(Bytes::from("value"))),
    ]));
    let resp3_wire = resp_rs::resp3::frame_to_bytes(&resp3_frame);

    let bresp_frame = bresp::Frame::Array(Some(vec![
        bresp::Frame::BulkString(Some(Bytes::from("SET"))),
        bresp::Frame::BulkString(Some(Bytes::from("key"))),
        bresp::Frame::BulkString(Some(Bytes::from("value"))),
    ]));
    let bresp_wire = bresp::frame_to_bytes(&bresp_frame);

    let proto_frame = proto_resp::resp3_to_proto(&resp3_frame);
    let mut proto_wire = Vec::new();
    proto_frame.encode(&mut proto_wire).unwrap();
    let proto_bytes = Bytes::from(proto_wire);

    let mut group = c.benchmark_group("3way/SET_cmd");
    group.bench_function(format!("resp3 ({} B)", resp3_wire.len()), |b| {
        b.iter(|| resp_rs::resp3::parse_frame(resp3_wire.clone()).unwrap());
    });
    group.bench_function(format!("bresp ({} B)", bresp_wire.len()), |b| {
        b.iter(|| bresp::parse_frame(bresp_wire.clone()).unwrap());
    });
    group.bench_function(format!("proto ({} B)", proto_bytes.len()), |b| {
        b.iter(|| proto_resp::pb::Frame::decode(proto_bytes.as_ref()).unwrap());
    });
    group.finish();
}

fn bench_array_100(c: &mut Criterion) {
    let items: Vec<resp_rs::resp3::Frame> = (0..100)
        .map(|i| resp_rs::resp3::Frame::BulkString(Some(Bytes::from(format!("value-{i:03}")))))
        .collect();
    let resp3_frame = resp_rs::resp3::Frame::Array(Some(items));
    let resp3_wire = resp_rs::resp3::frame_to_bytes(&resp3_frame);

    let bresp_items: Vec<bresp::Frame> = (0..100)
        .map(|i| bresp::Frame::BulkString(Some(Bytes::from(format!("value-{i:03}")))))
        .collect();
    let bresp_frame = bresp::Frame::Array(Some(bresp_items));
    let bresp_wire = bresp::frame_to_bytes(&bresp_frame);

    let proto_frame = proto_resp::resp3_to_proto(&resp3_frame);
    let mut proto_wire = Vec::new();
    proto_frame.encode(&mut proto_wire).unwrap();
    let proto_bytes = Bytes::from(proto_wire);

    let mut group = c.benchmark_group("3way/array_100");
    group.bench_function(format!("resp3 ({} B)", resp3_wire.len()), |b| {
        b.iter(|| resp_rs::resp3::parse_frame(resp3_wire.clone()).unwrap());
    });
    group.bench_function(format!("bresp ({} B)", bresp_wire.len()), |b| {
        b.iter(|| bresp::parse_frame(bresp_wire.clone()).unwrap());
    });
    group.bench_function(format!("proto ({} B)", proto_bytes.len()), |b| {
        b.iter(|| proto_resp::pb::Frame::decode(proto_bytes.as_ref()).unwrap());
    });
    group.finish();
}

fn bench_map(c: &mut Criterion) {
    let resp3_frame = resp_rs::resp3::Frame::Map(vec![
        (
            resp_rs::resp3::Frame::SimpleString(Bytes::from("server")),
            resp_rs::resp3::Frame::BulkString(Some(Bytes::from("redis"))),
        ),
        (
            resp_rs::resp3::Frame::SimpleString(Bytes::from("version")),
            resp_rs::resp3::Frame::BulkString(Some(Bytes::from("7.0.0"))),
        ),
    ]);
    let resp3_wire = resp_rs::resp3::frame_to_bytes(&resp3_frame);

    let bresp_frame = bresp::Frame::Map(vec![
        (
            bresp::Frame::SimpleString(Bytes::from("server")),
            bresp::Frame::BulkString(Some(Bytes::from("redis"))),
        ),
        (
            bresp::Frame::SimpleString(Bytes::from("version")),
            bresp::Frame::BulkString(Some(Bytes::from("7.0.0"))),
        ),
    ]);
    let bresp_wire = bresp::frame_to_bytes(&bresp_frame);

    let proto_frame = proto_resp::resp3_to_proto(&resp3_frame);
    let mut proto_wire = Vec::new();
    proto_frame.encode(&mut proto_wire).unwrap();
    let proto_bytes = Bytes::from(proto_wire);

    let mut group = c.benchmark_group("3way/map_2");
    group.bench_function(format!("resp3 ({} B)", resp3_wire.len()), |b| {
        b.iter(|| resp_rs::resp3::parse_frame(resp3_wire.clone()).unwrap());
    });
    group.bench_function(format!("bresp ({} B)", bresp_wire.len()), |b| {
        b.iter(|| bresp::parse_frame(bresp_wire.clone()).unwrap());
    });
    group.bench_function(format!("proto ({} B)", proto_bytes.len()), |b| {
        b.iter(|| proto_resp::pb::Frame::decode(proto_bytes.as_ref()).unwrap());
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_simple_string,
    bench_integer,
    bench_double,
    bench_set_command,
    bench_array_100,
    bench_map,
);
criterion_main!(benches);
