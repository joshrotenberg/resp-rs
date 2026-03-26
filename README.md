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
- **High performance** -- 4.8-8.0 GB/s throughput in benchmarks
- **Minimal dependencies** -- only `bytes` and `thiserror`
- **No async runtime** -- pure sync parsing that works in any context

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

## Benchmarks

Run benchmarks with:

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
