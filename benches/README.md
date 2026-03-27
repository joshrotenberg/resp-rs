# Benchmarks

## Standard benchmarks

```bash
cargo bench --bench parsing        # resp-rs RESP2 + RESP3
cargo bench --bench comparison     # resp-rs vs redis-protocol crate
```

## Unsafe experiment

Requires the `unsafe-internals` feature:

```bash
cargo bench --bench unsafe_experiment --features unsafe-internals
```

## Redis C comparison (local only)

Compares resp-rs against Redis's actual C `resp_parser.c`. The Redis source
is not included in this repository due to license incompatibility (Redis is
RSALv2/SSPLv1/AGPLv3, resp-rs is MIT/Apache-2.0).

To reproduce locally:

```bash
# 1. Clone Redis source
git clone https://github.com/redis/redis.git tmp/redis

# 2. Create the C shim (extracts just the parser + dependencies)
./benches/setup_redis_c_bench.sh

# 3. Run the comparison
cargo bench --bench redis_c_comparison
```

The setup script extracts `resp_parser.c`, `string2ll()`, and the necessary
constants into a standalone `benches/redis_c/redis_resp_shim.c` with no-op
callbacks that count frames (matching Redis's internal usage pattern). A
`build.rs` is created to compile it via the `cc` crate.

Note: the `cc` build dependency and `redis_c_comparison` bench target are
only created by the setup script and are gitignored. They do not affect
normal builds.
