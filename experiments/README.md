# Experiments

Alternative protocol encodings for RESP, exploring the tradeoffs between
text, binary, and schema-based wire formats. These are research experiments,
not production code.

## The question

RESP is a text protocol: integers are ASCII digits, lengths are decimal strings,
frames are delimited by `\r\n`. What if it were binary? What if it were protobuf?
How much does the encoding actually matter?

## The experiments

### [BRESP](bresp/) -- Binary RESP

A hand-rolled binary encoding with the same frame types as RESP3. Fixed-width
tags, binary lengths (u32), no CRLF. Designed to answer: "how much faster is
binary framing?"

### [proto-resp](proto-resp/) -- Protobuf RESP

RESP3 frame types modeled as Protocol Buffers messages using `prost`. Designed
to answer: "what does RESP look like as an IDL?" and "how does protobuf encoding
compare?"

The protobuf model is particularly interesting as a foundation for a gRPC-based
Redis interface -- typed RPCs, bidirectional streaming for pub/sub, and
auto-generated clients for every language.

## Results

Three-way benchmark: same logical data, three wire formats.

| Command | RESP3 (text) | BRESP (binary) | Protobuf |
|---------|-------------|----------------|----------|
| Simple string "OK" | 40 ns | 41 ns | 39 ns |
| Integer (i64 max) | 48 ns | 35 ns | **9 ns** |
| Double | 53 ns | 35 ns | **8 ns** |
| SET key value | **87 ns** | **80 ns** | 192 ns |
| Array(100 strings) | **1.10 us** | **1.05 us** | 5.73 us |
| Map(2 pairs) | **104 ns** | **100 ns** | 254 ns |

### Wire sizes

| Command | RESP3 | BRESP | Protobuf |
|---------|-------|-------|----------|
| Simple string "OK" | 5 B | 7 B | 4 B |
| Integer (i64 max) | 22 B | 9 B | 10 B |
| SET key value | 33 B | 31 B | 33 B |
| Array(100 strings) | 1506 B | 1405 B | 1506 B |

## Key findings

**Binary framing barely helps for strings.** BRESP is ~7% faster than RESP3 on
a SET command, but the gap is noise for simple strings. The CRLF scanning and
ASCII length parsing that BRESP eliminates account for only ~5% of total parse
time.

**Protobuf destroys everything on scalars.** 9ns for an integer vs 48ns for
RESP3 (5x faster). This is because prost decodes into native Rust types with
no `Bytes` reference counting overhead.

**Protobuf is 2-5x slower on collections.** Every nested frame is a heap-allocated
`Box<Frame>` in prost's generated code. Our hand-rolled parsers use
`Vec::with_capacity` and flat recursive parsing, which is much more
allocation-efficient.

**The bottleneck is `Bytes`, not the wire format.** For string-heavy workloads
(which is most of Redis), the `Bytes::slice()` atomic reference count increment
costs ~3-5ns per frame -- more than the actual parsing work. A raw unsafe Rust
parser without `Bytes` parses `+OK\r\n` in 1.6ns, proving the wire format is
not the limiting factor.

## Running the benchmarks

```sh
cargo bench --package experiments-bench --bench three_way
```

## Implications

For a next-generation Redis protocol, the protobuf approach is compelling not
for its parsing speed but for its **ecosystem benefits**: IDL-defined schema,
auto-generated clients, gRPC streaming for pub/sub, and strong typing across
all languages. The parsing overhead for collections could likely be improved
with a custom protobuf runtime tuned for the RESP use case.

The binary encoding (BRESP) is a less interesting tradeoff: marginal speed
gains for the loss of human readability, with no ecosystem benefits.
