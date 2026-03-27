//! Protobuf-encoded RESP frames (experimental).
//!
//! Models RESP3 frame types as Protocol Buffers messages for comparison
//! benchmarking. Same semantics as RESP3, protobuf wire encoding.

/// Generated protobuf types.
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/resp.rs"));
}

use bytes::Bytes;

/// Convert a resp3::Frame to a protobuf Frame.
pub fn resp3_to_proto(frame: &crate::resp3::Frame) -> pb::Frame {
    use crate::resp3::Frame as R;
    use pb::frame::Kind;

    let kind = match frame {
        R::SimpleString(b) => Kind::SimpleString(b.to_vec()),
        R::Error(b) => Kind::Error(b.to_vec()),
        R::Integer(v) => Kind::Integer(*v),
        R::Double(v) => Kind::DoubleVal(*v),
        R::Boolean(v) => Kind::Boolean(*v),
        R::Null => Kind::Null(pb::Null {}),
        R::BulkString(Some(b)) => Kind::BulkString(pb::NullableBytes {
            data: Some(b.to_vec()),
        }),
        R::BulkString(None) => Kind::BulkString(pb::NullableBytes { data: None }),
        R::BlobError(b) => Kind::BlobError(b.to_vec()),
        R::BigNumber(b) => Kind::BigNumber(b.to_vec()),
        R::VerbatimString(fmt, content) => Kind::VerbatimString(pb::VerbatimString {
            format: fmt.to_vec(),
            content: content.to_vec(),
        }),
        R::Array(Some(items)) => Kind::Array(pb::NullableArray {
            items: Some(pb::FrameList {
                items: items.iter().map(resp3_to_proto).collect(),
            }),
        }),
        R::Array(None) => Kind::Array(pb::NullableArray { items: None }),
        R::Set(items) => Kind::Set(pb::FrameList {
            items: items.iter().map(resp3_to_proto).collect(),
        }),
        R::Map(pairs) => Kind::Map(pb::PairList {
            entries: pairs
                .iter()
                .map(|(k, v)| pb::Pair {
                    key: Some(resp3_to_proto(k)),
                    value: Some(resp3_to_proto(v)),
                })
                .collect(),
        }),
        R::Attribute(pairs) => Kind::Attribute(pb::PairList {
            entries: pairs
                .iter()
                .map(|(k, v)| pb::Pair {
                    key: Some(resp3_to_proto(k)),
                    value: Some(resp3_to_proto(v)),
                })
                .collect(),
        }),
        R::Push(items) => Kind::Push(pb::FrameList {
            items: items.iter().map(resp3_to_proto).collect(),
        }),
        // Streaming types don't have a protobuf equivalent
        _ => Kind::Null(pb::Null {}),
    };

    pb::Frame { kind: Some(kind) }
}

/// Convert a protobuf Frame back to a resp3::Frame.
pub fn proto_to_resp3(frame: &pb::Frame) -> crate::resp3::Frame {
    use crate::resp3::Frame as R;
    use pb::frame::Kind;

    match frame.kind.as_ref().unwrap() {
        Kind::SimpleString(b) => R::SimpleString(Bytes::from(b.clone())),
        Kind::Error(b) => R::Error(Bytes::from(b.clone())),
        Kind::Integer(v) => R::Integer(*v),
        Kind::DoubleVal(v) => R::Double(*v),
        Kind::Boolean(v) => R::Boolean(*v),
        Kind::Null(_) => R::Null,
        Kind::BulkString(nb) => R::BulkString(nb.data.as_ref().map(|b| Bytes::from(b.clone()))),
        Kind::BlobError(b) => R::BlobError(Bytes::from(b.clone())),
        Kind::BigNumber(b) => R::BigNumber(Bytes::from(b.clone())),
        Kind::VerbatimString(vs) => R::VerbatimString(
            Bytes::from(vs.format.clone()),
            Bytes::from(vs.content.clone()),
        ),
        Kind::Array(na) => match &na.items {
            Some(list) => R::Array(Some(list.items.iter().map(proto_to_resp3).collect())),
            None => R::Array(None),
        },
        Kind::Set(list) => R::Set(list.items.iter().map(proto_to_resp3).collect()),
        Kind::Map(pairs) => R::Map(
            pairs
                .entries
                .iter()
                .map(|p| {
                    (
                        proto_to_resp3(p.key.as_ref().unwrap()),
                        proto_to_resp3(p.value.as_ref().unwrap()),
                    )
                })
                .collect(),
        ),
        Kind::Attribute(pairs) => R::Attribute(
            pairs
                .entries
                .iter()
                .map(|p| {
                    (
                        proto_to_resp3(p.key.as_ref().unwrap()),
                        proto_to_resp3(p.value.as_ref().unwrap()),
                    )
                })
                .collect(),
        ),
        Kind::Push(list) => R::Push(list.items.iter().map(proto_to_resp3).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn roundtrip_simple_string() {
        let original = crate::resp3::Frame::SimpleString(Bytes::from("OK"));
        let proto = resp3_to_proto(&original);
        let mut buf = Vec::new();
        proto.encode(&mut buf).unwrap();
        let decoded_proto = pb::Frame::decode(buf.as_slice()).unwrap();
        let back = proto_to_resp3(&decoded_proto);
        assert_eq!(original, back);
    }

    #[test]
    fn roundtrip_set_command() {
        let original = crate::resp3::Frame::Array(Some(vec![
            crate::resp3::Frame::BulkString(Some(Bytes::from("SET"))),
            crate::resp3::Frame::BulkString(Some(Bytes::from("key"))),
            crate::resp3::Frame::BulkString(Some(Bytes::from("value"))),
        ]));
        let proto = resp3_to_proto(&original);
        let mut buf = Vec::new();
        proto.encode(&mut buf).unwrap();
        let decoded_proto = pb::Frame::decode(buf.as_slice()).unwrap();
        let back = proto_to_resp3(&decoded_proto);
        assert_eq!(original, back);
    }

    #[test]
    fn roundtrip_map() {
        let original = crate::resp3::Frame::Map(vec![
            (
                crate::resp3::Frame::SimpleString(Bytes::from("key1")),
                crate::resp3::Frame::Integer(42),
            ),
            (
                crate::resp3::Frame::SimpleString(Bytes::from("key2")),
                crate::resp3::Frame::Boolean(true),
            ),
        ]);
        let proto = resp3_to_proto(&original);
        let mut buf = Vec::new();
        proto.encode(&mut buf).unwrap();
        let decoded_proto = pb::Frame::decode(buf.as_slice()).unwrap();
        let back = proto_to_resp3(&decoded_proto);
        assert_eq!(original, back);
    }

    #[test]
    fn wire_size_comparison() {
        use prost::Message;

        // SET key value
        let frame = crate::resp3::Frame::Array(Some(vec![
            crate::resp3::Frame::BulkString(Some(Bytes::from("SET"))),
            crate::resp3::Frame::BulkString(Some(Bytes::from("key"))),
            crate::resp3::Frame::BulkString(Some(Bytes::from("value"))),
        ]));

        let resp3_wire = crate::resp3::frame_to_bytes(&frame);
        let bresp_frame = crate::bresp::Frame::Array(Some(vec![
            crate::bresp::Frame::BulkString(Some(Bytes::from("SET"))),
            crate::bresp::Frame::BulkString(Some(Bytes::from("key"))),
            crate::bresp::Frame::BulkString(Some(Bytes::from("value"))),
        ]));
        let bresp_wire = crate::bresp::frame_to_bytes(&bresp_frame);

        let proto = resp3_to_proto(&frame);
        let proto_size = proto.encoded_len();

        println!("SET key value wire sizes:");
        println!("  RESP3:    {} bytes", resp3_wire.len());
        println!("  BRESP:    {} bytes", bresp_wire.len());
        println!("  Protobuf: {} bytes", proto_size);
    }
}
