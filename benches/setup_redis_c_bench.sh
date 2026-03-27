#!/usr/bin/env bash
set -euo pipefail

# Sets up the Redis C comparison benchmark by extracting the minimal parser
# code from a local Redis clone. Run this after cloning Redis to tmp/redis.
#
# This script creates:
#   benches/redis_c/redis_resp_shim.c  -- standalone parser + no-op callbacks
#   benches/redis_c_comparison.rs      -- criterion bench (if not present)
#   build.rs                           -- cc compilation (if not present)
#
# These files are gitignored and not part of the resp-rs distribution.

REDIS_SRC="tmp/redis/src"

if [ ! -f "$REDIS_SRC/resp_parser.c" ]; then
    echo "Error: Redis source not found at $REDIS_SRC"
    echo "Clone it first: git clone https://github.com/redis/redis.git tmp/redis"
    exit 1
fi

mkdir -p benches/redis_c

cat > benches/redis_c/redis_resp_shim.c << 'SHIMEOF'
/*
 * Standalone shim for benchmarking Redis's RESP parser.
 *
 * Extracts the minimal code from Redis needed to run parseReply():
 * - resp_parser.c (callback-based RESP parser)
 * - string2ll() from util.c (integer parsing)
 * - Substitute strtod for fast_float_strtod (close enough for benchmarking)
 *
 * Original code is Copyright (c) Redis Ltd., licensed under RSALv2/SSPLv1/AGPLv3.
 * This shim is for local benchmarking only and must not be redistributed.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define C_OK  0
#define C_ERR -1
#define LONG_STR_SIZE 21
#define MAX_LONG_DOUBLE_CHARS (5*1024)

static double fast_float_strtod(const char *in, char **out) {
    return strtod(in, out);
}

/* --- string2ll from Redis util.c --- */

static int string2ll(const char *s, size_t slen, long long *value) {
    const char *p = s;
    size_t plen = 0;
    int negative = 0;
    unsigned long long v;

    if (plen == slen || slen >= LONG_STR_SIZE) return 0;
    if (slen == 1 && p[0] == '0') { if (value) *value = 0; return 1; }

    if (p[0] == '-') { negative = 1; p++; plen++; if (plen == slen) return 0; }

    if (p[0] >= '1' && p[0] <= '9') { v = p[0]-'0'; p++; plen++; }
    else return 0;

    while (plen < slen && p[0] >= '0' && p[0] <= '9') {
        if (v > (ULLONG_MAX / 10)) return 0;
        v *= 10;
        if (v > (ULLONG_MAX - (p[0]-'0'))) return 0;
        v += p[0]-'0';
        p++; plen++;
    }
    if (plen < slen) return 0;

    if (negative) {
        if (v > ((unsigned long long)(-(LLONG_MIN+1))+1)) return 0;
        if (value) *value = -v;
    } else {
        if (v > LLONG_MAX) return 0;
        if (value) *value = v;
    }
    return 1;
}

/* --- ReplyParser types (from resp_parser.h) --- */

typedef struct ReplyParser ReplyParser;

typedef struct ReplyParserCallbacks {
    void (*null_array_callback)(void *ctx, const char *proto, size_t proto_len);
    void (*null_bulk_string_callback)(void *ctx, const char *proto, size_t proto_len);
    void (*bulk_string_callback)(void *ctx, const char *str, size_t len, const char *proto, size_t proto_len);
    void (*error_callback)(void *ctx, const char *str, size_t len, const char *proto, size_t proto_len);
    void (*simple_str_callback)(void *ctx, const char *str, size_t len, const char *proto, size_t proto_len);
    void (*long_callback)(void *ctx, long long val, const char *proto, size_t proto_len);
    void (*array_callback)(struct ReplyParser *parser, void *ctx, size_t len, const char *proto);
    void (*set_callback)(struct ReplyParser *parser, void *ctx, size_t len, const char *proto);
    void (*map_callback)(struct ReplyParser *parser, void *ctx, size_t len, const char *proto);
    void (*bool_callback)(void *ctx, int val, const char *proto, size_t proto_len);
    void (*double_callback)(void *ctx, double val, const char *proto, size_t proto_len);
    void (*big_number_callback)(void *ctx, const char *str, size_t len, const char *proto, size_t proto_len);
    void (*verbatim_string_callback)(void *ctx, const char *format, const char *str, size_t len, const char *proto, size_t proto_len);
    void (*attribute_callback)(struct ReplyParser *parser, void *ctx, size_t len, const char *proto);
    void (*null_callback)(void *ctx, const char *proto, size_t proto_len);
    void (*error)(void *ctx);
} ReplyParserCallbacks;

struct ReplyParser {
    const char *curr_location;
    ReplyParserCallbacks callbacks;
};

int parseReply(ReplyParser *parser, void *p_ctx);

/* --- resp_parser.c (inlined from Redis source) --- */

static int parseBulk(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    long long bulklen;
    p->curr_location = cr + 2;
    string2ll(proto+1,cr-proto-1,&bulklen);
    if (bulklen == -1) {
        p->callbacks.null_bulk_string_callback(ctx, proto, p->curr_location - proto);
    } else {
        const char *str = p->curr_location;
        p->curr_location += bulklen + 2;
        p->callbacks.bulk_string_callback(ctx, str, bulklen, proto, p->curr_location - proto);
    }
    return C_OK;
}

static int parseSimpleString(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    p->curr_location = cr + 2;
    p->callbacks.simple_str_callback(ctx, proto+1, cr-proto-1, proto, p->curr_location - proto);
    return C_OK;
}

static int parseError(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    p->curr_location = cr + 2;
    p->callbacks.error_callback(ctx, proto+1, cr-proto-1, proto, p->curr_location - proto);
    return C_OK;
}

static int parseLong(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    p->curr_location = cr + 2;
    long long val;
    string2ll(proto+1,cr-proto-1,&val);
    p->callbacks.long_callback(ctx, val, proto, p->curr_location - proto);
    return C_OK;
}

static int parseArray(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    long long len;
    string2ll(proto+1,cr-proto-1,&len);
    cr += 2;
    p->curr_location = cr;
    if (len == -1) {
        p->callbacks.null_array_callback(ctx, proto, p->curr_location - proto);
    } else {
        p->callbacks.array_callback(p, ctx, len, proto);
    }
    return C_OK;
}

static int parseSet(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    long long len;
    string2ll(proto+1,cr-proto-1,&len);
    p->curr_location = cr + 2;
    p->callbacks.set_callback(p, ctx, len, proto);
    return C_OK;
}

static int parseMap(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    long long len;
    string2ll(proto+1,cr-proto-1,&len);
    p->curr_location = cr + 2;
    p->callbacks.map_callback(p, ctx, len, proto);
    return C_OK;
}

static int parseBool(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    p->curr_location = cr + 2;
    p->callbacks.bool_callback(ctx, proto[1] == 't', proto, p->curr_location - proto);
    return C_OK;
}

static int parseDouble(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    p->curr_location = cr + 2;
    char buf[MAX_LONG_DOUBLE_CHARS+1];
    size_t len = cr-proto-1;
    double d;
    if (len <= MAX_LONG_DOUBLE_CHARS) {
        memcpy(buf,proto+1,len);
        buf[len] = '\0';
        d = fast_float_strtod(buf,NULL);
    } else { d = 0; }
    p->callbacks.double_callback(ctx, d, proto, p->curr_location - proto);
    return C_OK;
}

static int parseNull(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    p->curr_location = cr + 2;
    p->callbacks.null_callback(ctx, proto, p->curr_location - proto);
    return C_OK;
}

static int parseBigNumber(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    p->curr_location = cr + 2;
    p->callbacks.big_number_callback(ctx, proto+1, cr-proto-1, proto, p->curr_location - proto);
    return C_OK;
}

static int parseVerbatimString(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    long long bulklen;
    p->curr_location = cr + 2;
    string2ll(proto+1,cr-proto-1,&bulklen);
    const char *fmt = p->curr_location;
    p->curr_location += bulklen + 2;
    p->callbacks.verbatim_string_callback(ctx, fmt, fmt+4, bulklen-4, proto, p->curr_location - proto);
    return C_OK;
}

static int parseAttributes(ReplyParser *p, void *ctx) {
    const char *proto = p->curr_location;
    char *cr = strchr(proto+1,'\r');
    long long len;
    string2ll(proto+1,cr-proto-1,&len);
    p->curr_location = cr + 2;
    p->callbacks.attribute_callback(p, ctx, len, proto);
    return C_OK;
}

int parseReply(ReplyParser *p, void *ctx) {
    switch (p->curr_location[0]) {
        case '$': return parseBulk(p, ctx);
        case '+': return parseSimpleString(p, ctx);
        case '-': return parseError(p, ctx);
        case ':': return parseLong(p, ctx);
        case '*': return parseArray(p, ctx);
        case '~': return parseSet(p, ctx);
        case '%': return parseMap(p, ctx);
        case '#': return parseBool(p, ctx);
        case ',': return parseDouble(p, ctx);
        case '_': return parseNull(p, ctx);
        case '(': return parseBigNumber(p, ctx);
        case '=': return parseVerbatimString(p, ctx);
        case '|': return parseAttributes(p, ctx);
        default: if (p->callbacks.error) p->callbacks.error(ctx);
    }
    return C_ERR;
}

/* --- No-op callbacks for benchmarking --- */

static void noop_null_array(void *ctx, const char *p, size_t l) { (void)p;(void)l; (*(int*)ctx)++; }
static void noop_null_bulk(void *ctx, const char *p, size_t l) { (void)p;(void)l; (*(int*)ctx)++; }
static void noop_bulk(void *ctx, const char *s, size_t l, const char *p, size_t pl) { (void)s;(void)l;(void)p;(void)pl; (*(int*)ctx)++; }
static void noop_error(void *ctx, const char *s, size_t l, const char *p, size_t pl) { (void)s;(void)l;(void)p;(void)pl; (*(int*)ctx)++; }
static void noop_simple(void *ctx, const char *s, size_t l, const char *p, size_t pl) { (void)s;(void)l;(void)p;(void)pl; (*(int*)ctx)++; }
static void noop_long(void *ctx, long long v, const char *p, size_t pl) { (void)v;(void)p;(void)pl; (*(int*)ctx)++; }
static void noop_array(ReplyParser *parser, void *ctx, size_t len, const char *p) {
    (void)p; (*(int*)ctx)++;
    for (size_t i = 0; i < len; i++) parseReply(parser, ctx);
}
static void noop_set(ReplyParser *parser, void *ctx, size_t len, const char *p) {
    (void)p; (*(int*)ctx)++;
    for (size_t i = 0; i < len; i++) parseReply(parser, ctx);
}
static void noop_map(ReplyParser *parser, void *ctx, size_t len, const char *p) {
    (void)p; (*(int*)ctx)++;
    for (size_t i = 0; i < len * 2; i++) parseReply(parser, ctx);
}
static void noop_bool(void *ctx, int v, const char *p, size_t pl) { (void)v;(void)p;(void)pl; (*(int*)ctx)++; }
static void noop_double(void *ctx, double v, const char *p, size_t pl) { (void)v;(void)p;(void)pl; (*(int*)ctx)++; }
static void noop_big_number(void *ctx, const char *s, size_t l, const char *p, size_t pl) { (void)s;(void)l;(void)p;(void)pl; (*(int*)ctx)++; }
static void noop_verbatim(void *ctx, const char *f, const char *s, size_t l, const char *p, size_t pl) { (void)f;(void)s;(void)l;(void)p;(void)pl; (*(int*)ctx)++; }
static void noop_attribute(ReplyParser *parser, void *ctx, size_t len, const char *p) {
    (void)p; (*(int*)ctx)++;
    for (size_t i = 0; i < len * 2; i++) parseReply(parser, ctx);
}
static void noop_null(void *ctx, const char *p, size_t pl) { (void)p;(void)pl; (*(int*)ctx)++; }

int redis_parse_resp(const char *buf, size_t len) {
    (void)len;
    int count = 0;
    ReplyParser parser;
    parser.curr_location = buf;
    parser.callbacks.null_array_callback = noop_null_array;
    parser.callbacks.null_bulk_string_callback = noop_null_bulk;
    parser.callbacks.bulk_string_callback = noop_bulk;
    parser.callbacks.error_callback = noop_error;
    parser.callbacks.simple_str_callback = noop_simple;
    parser.callbacks.long_callback = noop_long;
    parser.callbacks.array_callback = noop_array;
    parser.callbacks.set_callback = noop_set;
    parser.callbacks.map_callback = noop_map;
    parser.callbacks.bool_callback = noop_bool;
    parser.callbacks.double_callback = noop_double;
    parser.callbacks.big_number_callback = noop_big_number;
    parser.callbacks.verbatim_string_callback = noop_verbatim;
    parser.callbacks.attribute_callback = noop_attribute;
    parser.callbacks.null_callback = noop_null;
    parser.callbacks.error = NULL;
    if (parseReply(&parser, &count) != C_OK) return -1;
    return count;
}
SHIMEOF

# Create build.rs if it doesn't exist
if [ ! -f "build.rs" ]; then
    cat > build.rs << 'BUILDEOF'
fn main() {
    cc::Build::new()
        .file("benches/redis_c/redis_resp_shim.c")
        .opt_level(3)
        .compile("redis_resp_shim");
}
BUILDEOF
    echo "Created build.rs"
fi

# Add cc build dependency if not present
if ! grep -q '\[build-dependencies\]' Cargo.toml; then
    echo -e '\n[build-dependencies]\ncc = "1"' >> Cargo.toml
    echo "Added cc to build-dependencies in Cargo.toml"
fi

# Add bench target if not present
if ! grep -q 'redis_c_comparison' Cargo.toml; then
    echo -e '\n[[bench]]\nname = "redis_c_comparison"\nharness = false' >> Cargo.toml
    echo "Added redis_c_comparison bench target to Cargo.toml"
fi

echo ""
echo "Setup complete. Run: cargo bench --bench redis_c_comparison"
echo ""
echo "NOTE: The Redis C code is Copyright (c) Redis Ltd. (RSALv2/SSPLv1/AGPLv3)."
echo "Do not commit the generated files to the repository."
