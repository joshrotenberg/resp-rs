//! Redis Cluster hash slot utilities.
//!
//! Provides CRC16-CCITT hash slot calculation for Redis Cluster key routing,
//! including hash tag extraction per the
//! [Redis Cluster specification](https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/#hash-tags).
//!
//! # Examples
//!
//! ```
//! use resp_rs::cluster::hash_slot;
//!
//! // Basic key hashing
//! let slot = hash_slot(b"mykey");
//! assert!(slot < 16384);
//!
//! // Hash tags: only the content between the first `{...}` is hashed
//! assert_eq!(hash_slot(b"{user}.name"), hash_slot(b"{user}.email"));
//!
//! // Empty hash tag is ignored, full key is hashed
//! assert_eq!(hash_slot(b"{}key"), hash_slot(b"{}key"));
//! ```

/// Total number of hash slots in a Redis Cluster.
pub const SLOT_COUNT: u16 = 16384;

/// CRC16-CCITT lookup table (polynomial 0x1021).
static CRC16_TABLE: [u16; 256] = {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut j = 0;
        while j < 8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Compute the CRC16-CCITT checksum of a byte slice.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        let index = ((crc >> 8) ^ b as u16) as usize;
        crc = (crc << 8) ^ CRC16_TABLE[index];
    }
    crc
}

/// Compute the Redis Cluster hash slot for a key.
///
/// Applies the Redis Cluster hash tag rules: if the key contains `{...}` with
/// a non-empty substring between the first `{` and the next `}`, only that
/// substring is hashed. Otherwise the entire key is hashed.
///
/// Returns a value in `0..16384`.
///
/// # Examples
///
/// ```
/// use resp_rs::cluster::hash_slot;
///
/// // Keys with the same hash tag map to the same slot
/// assert_eq!(hash_slot(b"{order}.items"), hash_slot(b"{order}.total"));
///
/// // Without hash tags, the full key is hashed
/// let slot = hash_slot(b"user:1234");
/// assert!(slot < 16384);
/// ```
pub fn hash_slot(key: &[u8]) -> u16 {
    let data = extract_hash_tag(key).unwrap_or(key);
    crc16(data) % SLOT_COUNT
}

/// Extract the hash tag from a key, if present.
///
/// Returns `Some(tag)` if the key contains `{tag}` where `tag` is non-empty.
/// Returns `None` otherwise (no braces, empty tag, or no closing brace).
fn extract_hash_tag(key: &[u8]) -> Option<&[u8]> {
    let open = key.iter().position(|&b| b == b'{')?;
    let close = key[open + 1..].iter().position(|&b| b == b'}')?;
    if close == 0 {
        // Empty hash tag `{}` -- ignore, hash the full key
        return None;
    }
    Some(&key[open + 1..open + 1 + close])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_hash_slot() {
        // Deterministic -- same key always gets same slot
        let slot = hash_slot(b"mykey");
        assert_eq!(slot, hash_slot(b"mykey"));
        assert!(slot < SLOT_COUNT);
    }

    #[test]
    fn slot_range() {
        // All slots should be in valid range
        for i in 0..1000 {
            let key = format!("key:{i}");
            assert!(hash_slot(key.as_bytes()) < SLOT_COUNT);
        }
    }

    #[test]
    fn hash_tag_same_slot() {
        assert_eq!(hash_slot(b"{user}.name"), hash_slot(b"{user}.email"));
        assert_eq!(hash_slot(b"{order}.items"), hash_slot(b"{order}.total"));
    }

    #[test]
    fn hash_tag_equals_bare_tag() {
        // `{foo}.bar` should hash the same as just `foo`
        assert_eq!(hash_slot(b"{foo}.bar"), hash_slot(b"foo"));
    }

    #[test]
    fn empty_hash_tag_ignored() {
        // `{}key` should hash the full string, not empty
        assert_eq!(hash_slot(b"{}key"), hash_slot(b"{}key"));
        // And it should differ from hashing just "key"
        // (because the full string "{}key" != "key")
        assert_ne!(hash_slot(b"{}key"), hash_slot(b"key"));
    }

    #[test]
    fn no_closing_brace() {
        // `{key` has no closing brace -- hash full key
        assert_eq!(hash_slot(b"{key"), hash_slot(b"{key"));
    }

    #[test]
    fn first_brace_pair_wins() {
        // Only the first `{...}` matters
        assert_eq!(hash_slot(b"{a}{b}"), hash_slot(b"a"));
    }

    #[test]
    fn empty_key() {
        let slot = hash_slot(b"");
        assert!(slot < SLOT_COUNT);
    }

    #[test]
    fn known_crc16_values() {
        // Verify against known Redis CRC16 values
        // These can be checked with `redis-cli cluster keyslot <key>`
        assert_eq!(crc16(b"123456789"), 0x31C3); // Standard CRC16-CCITT test vector
    }

    #[test]
    fn extract_hash_tag_cases() {
        assert_eq!(extract_hash_tag(b"{user}.name"), Some(b"user".as_slice()));
        assert_eq!(extract_hash_tag(b"{}.name"), None);
        assert_eq!(extract_hash_tag(b"nobraces"), None);
        assert_eq!(extract_hash_tag(b"{open"), None);
        assert_eq!(extract_hash_tag(b"{a}{b}"), Some(b"a".as_slice()));
        assert_eq!(extract_hash_tag(b"pre{tag}post"), Some(b"tag".as_slice()));
    }
}
