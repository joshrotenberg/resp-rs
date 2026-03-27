# proto-resp -- Protobuf RESP

RESP3 frame types modeled as Protocol Buffers messages.

## Schema

```protobuf
message Frame {
  oneof kind {
    bytes simple_string = 1;
    bytes error = 2;
    int64 integer = 3;
    NullableBytes bulk_string = 4;
    Null null = 5;
    double double_val = 6;
    bool boolean = 7;
    bytes big_number = 8;
    bytes blob_error = 9;
    VerbatimString verbatim_string = 10;
    NullableArray array = 11;
    FrameList set = 12;
    PairList map = 13;
    PairList attribute = 14;
    FrameList push = 15;
  }
}
```

See [proto/resp.proto](proto/resp.proto) for the full schema.

## Performance characteristics

**Scalars: 5x faster than RESP3.** Protobuf decodes integers and doubles into
native types without `Bytes` reference counting. An i64 decodes in 9ns vs 48ns
for RESP3 text parsing.

**Collections: 2-5x slower than RESP3.** Each nested `Frame` in the generated
code is a heap-allocated `Box<Frame>`, creating a deep allocation tree. The
hand-rolled RESP3 parser uses flat `Vec::with_capacity` which is much more
efficient for Redis's array-heavy command responses.

## Why this is interesting

The performance story is mixed, but performance isn't the main point. The
protobuf schema is interesting as a foundation for:

**IDL-first client generation.** Define the Redis command set as protobuf
services and every language gets a correct, typed client from `protoc`. No more
reimplementing command builders and RESP parsing per language.

**gRPC integration.** Wrap the frame types in gRPC services to get:
- Typed request/response RPCs for commands
- Server-side streaming for SCAN, SUBSCRIBE, MONITOR
- Bidirectional streaming for pub/sub
- Connection multiplexing, flow control, and TLS from HTTP/2

**Schema evolution.** Adding new frame types is a backwards-compatible proto
change (new `oneof` fields). Old clients ignore unknown fields gracefully.

## Future direction

The natural next step is defining a `RedisService` proto that maps Redis
commands to typed RPCs:

```protobuf
service Redis {
  rpc Get(GetRequest) returns (GetResponse);
  rpc Set(SetRequest) returns (SetResponse);
  rpc Subscribe(SubscribeRequest) returns (stream Frame);
  rpc Pipeline(stream Frame) returns (stream Frame);
}
```

This would make the protocol self-describing and give every language a
complete, correct client implementation for free.
