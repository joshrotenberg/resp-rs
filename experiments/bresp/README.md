# BRESP -- Binary RESP

A hypothetical binary encoding for the Redis Serialization Protocol.

## Wire format

Every frame starts with a 1-byte tag, followed by type-specific payload:

| Tag | Type | Payload |
|-----|------|---------|
| `0x01` | Integer | 8 bytes big-endian i64 |
| `0x02` | Double | 8 bytes IEEE 754 f64 |
| `0x03` | Boolean | 1 byte (0x00/0x01) |
| `0x04` | Null | (none) |
| `0x10` | String | 4-byte u32 length + data |
| `0x11` | Error | 4-byte u32 length + data |
| `0x12` | BlobError | 4-byte u32 length + data |
| `0x13` | Verbatim | 3-byte format + 4-byte u32 length + data |
| `0x14` | BigNumber | 4-byte u32 length + data |
| `0x20` | Array | 4-byte u32 count + items |
| `0x21` | Map | 4-byte u32 count + key-value pairs |
| `0x22` | Set | 4-byte u32 count + items |
| `0x23` | Attribute | 4-byte u32 count + key-value pairs |
| `0x24` | Push | 4-byte u32 count + items |
| `0x30` | NullString | (none) |
| `0x31` | NullArray | (none) |

## What it eliminates

- No CRLF scanning (fixed-width binary lengths)
- No ASCII integer parsing (`i64::from_be_bytes` instead)
- No float parsing (`f64::from_be_bytes` instead)
- No variable-width length encoding

## What it costs

- Not human-readable (can't `telnet` and type commands)
- Slightly larger wire size for short strings (4-byte length vs 1-2 digit ASCII)
- Needs tooling to inspect traffic

## Verdict

BRESP is ~7% faster than RESP3 for typical string commands (SET, GET) and
~40% faster for integer-heavy workloads. The gains are real but modest,
because the wire encoding is only ~5-10% of total parse time -- the rest is
`Bytes` reference counting and Frame construction overhead that both formats
share equally.
