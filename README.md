# resp-rs

Zero-copy RESP2 and RESP3 protocol parser and serializer for Rust.

[![Crates.io](https://img.shields.io/crates/v/resp-rs.svg)](https://crates.io/crates/resp-rs)
[![Documentation](https://docs.rs/resp-rs/badge.svg)](https://docs.rs/resp-rs)
[![CI](https://github.com/joshrotenberg/resp-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/joshrotenberg/resp-rs/actions)
[![License](https://img.shields.io/crates/l/resp-rs.svg)](LICENSE-MIT)

A high-performance Rust library for parsing and serializing the
[Redis Serialization Protocol](https://redis.io/docs/latest/develop/reference/protocol-spec/)
(RESP), supporting both RESP2 and RESP3.

## Features

- **Zero-copy parsing** -- uses `bytes::Bytes` to slice into the input buffer without copying
- **RESP2 and RESP3** -- full support for both protocol versions with separate frame types
- **Streaming parser** -- handles partial reads and pipelining for incremental TCP data
- **Serialization** -- convert frames back to wire format with `frame_to_bytes`
- **Tokio codec** -- optional `Decoder`/`Encoder` for async TCP via `tokio_util::codec::Framed`
- **Frame accessors** -- `as_str()`, `as_integer()`, `into_array()`, `is_null()`, and more
- **Cluster support** -- optional CRC16 hash slot calculation with hash tag extraction
- **High performance** -- up to 2-9x faster than `redis-protocol` (see [benchmarks](#benchmarks))
- **`no_std` compatible** -- works in embedded/WASM with just `alloc`
- **Minimal dependencies** -- only `bytes` and `thiserror` (both `no_std`-ready)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
resp-rs = "0.1"
```

### Parse a RESP3 frame

```rust
use bytes::Bytes;
use resp_rs::resp3;

let data = Bytes::from("+OK\r\n");
let (frame, remaining) = resp3::parse_frame(data).unwrap();
assert_eq!(frame, resp3::Frame::SimpleString(Bytes::from("OK")));
assert!(remaining.is_empty());
```

### Parse a RESP2 frame

```rust
use bytes::Bytes;
use resp_rs::resp2;

let data = Bytes::from("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
let (frame, _) = resp2::parse_frame(data).unwrap();
// frame is Array([BulkString("SET"), BulkString("key"), BulkString("value")])
```

### Serialize a frame

```rust
use bytes::Bytes;
use resp_rs::resp2::{Frame, frame_to_bytes};

let frame = Frame::Array(Some(vec![
    Frame::BulkString(Some(Bytes::from("GET"))),
    Frame::BulkString(Some(Bytes::from("mykey"))),
]));
let wire = frame_to_bytes(&frame);
assert_eq!(wire, Bytes::from("*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n"));
```

### Streaming parser (incremental TCP reads)

```rust
use bytes::Bytes;
use resp_rs::resp3::Parser;

let mut parser = Parser::new();

// Feed partial data
parser.feed(Bytes::from("+HEL"));
assert!(parser.next_frame().unwrap().is_none()); // incomplete

// Feed the rest
parser.feed(Bytes::from("LO\r\n"));
let frame = parser.next_frame().unwrap().unwrap(); // complete!
```

### RESP3 types

RESP3 adds several types beyond RESP2:

```rust
use bytes::Bytes;
use resp_rs::resp3::{self, Frame};

// Null
let (frame, _) = resp3::parse_frame(Bytes::from("_\r\n")).unwrap();
assert_eq!(frame, Frame::Null);

// Boolean
let (frame, _) = resp3::parse_frame(Bytes::from("#t\r\n")).unwrap();
assert_eq!(frame, Frame::Boolean(true));

// Double
let (frame, _) = resp3::parse_frame(Bytes::from(",3.14\r\n")).unwrap();
assert_eq!(frame, Frame::Double(3.14));

// Map
let data = Bytes::from("%2\r\n+key1\r\n:1\r\n+key2\r\n:2\r\n");
let (frame, _) = resp3::parse_frame(data).unwrap();
// frame is Map([(SimpleString("key1"), Integer(1)), (SimpleString("key2"), Integer(2))])
```

## Supported RESP3 types

| Type | Tag | Example |
|------|-----|---------|
| Simple String | `+` | `+OK\r\n` |
| Simple Error | `-` | `-ERR msg\r\n` |
| Integer | `:` | `:42\r\n` |
| Bulk String | `$` | `$5\r\nhello\r\n` |
| Null | `_` | `_\r\n` |
| Boolean | `#` | `#t\r\n` |
| Double | `,` | `,3.14\r\n` |
| Big Number | `(` | `(123456\r\n` |
| Blob Error | `!` | `!5\r\nERROR\r\n` |
| Verbatim String | `=` | `=15\r\ntxt:hello world\r\n` |
| Array | `*` | `*2\r\n:1\r\n:2\r\n` |
| Map | `%` | `%1\r\n+k\r\n+v\r\n` |
| Set | `~` | `~2\r\n:1\r\n:2\r\n` |
| Attribute | `\|` | `\|1\r\n+k\r\n+v\r\n` |
| Push | `>` | `>2\r\n+msg\r\n:1\r\n` |

Streaming variants (chunked strings, arrays, maps, sets, attributes, pushes)
are also fully supported.

## Optional Features

| Feature | Description | Dependencies |
|---------|-------------|-------------|
| `std` (default) | Standard library support | -- |
| `codec` | Tokio `Decoder`/`Encoder` for async TCP | `tokio`, `tokio-util` |
| `cluster` | CRC16 hash slot calculation | -- |
| `unsafe-internals` | Unchecked parser for pre-validated data | -- |

```toml
# Async Redis client
resp-rs = { version = "0.1", features = ["codec"] }

# Embedded / WASM
resp-rs = { version = "0.1", default-features = false }

# Everything
resp-rs = { version = "0.1", features = ["codec", "cluster", "unsafe-internals"] }
```

## Examples

### Async ping (Tokio codec)

Connect to Redis and send a PING using the async codec:

```sh
cargo run --example ping --features codec
cargo run --example ping --features codec -- localhost:6380
```

### Parse demo

A standalone demo of RESP2/RESP3 parsing, serialization, and the streaming parser:

```sh
cargo run --example parse
```

### Breadis

A bread-themed Redis-compatible TCP server that speaks RESP2 -- demonstrates
real-world usage with the streaming parser for incremental TCP reads.

```sh
cargo run --example breadis
# In another terminal:
redis-cli -p 6380

127.0.0.1:6380> KNEAD sourdough 10
Kneading sourdough... the gluten is developing!
127.0.0.1:6380> PROOF sourdough
Proofing sourdough... let it rise!
127.0.0.1:6380> BAKE sourdough 450
Baking sourdough at 450F... smells amazing!
127.0.0.1:6380> MENU
sourdough: baking at 450F
```

## Benchmarks

Comparative benchmarks against [`redis-protocol`](https://crates.io/crates/redis-protocol) v6
(run with `cargo bench --bench comparison`):

| Benchmark | resp-rs | redis-protocol | Speedup |
|-----------|---------|----------------|---------|
| resp2/simple_string | 12.6 ns | 20.8 ns | **1.7x** |
| resp2/bulk_string | 12.9 ns | 26.4 ns | **2.0x** |
| resp2/array (SET cmd) | 43.7 ns | 124.9 ns | **2.9x** |
| resp2/array (100 elems) | 828 ns | 3.08 us | **3.7x** |
| resp3/simple_string | 39.1 ns | 81.0 ns | **2.1x** |
| resp3/bulk_string | 41.5 ns | 90.8 ns | **2.2x** |
| resp3/array (SET cmd) | 83.9 ns | 366.8 ns | **4.4x** |
| resp3/integer (i64 max) | 48.1 ns | 94.3 ns | **2.0x** |
| resp3/array (100 elems) | 1.13 us | 9.76 us | **8.6x** |

Run the full benchmark suite:

```sh
cargo bench
```

## Minimum Supported Rust Version

The MSRV is **1.85** (Rust 2024 edition).

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

## Contributing

Contributions are welcome. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
