//! Byte encodings, canonical JSON and digests shared by every Base module and
//! by Base callers. Each helper exists once; modules map `None` to their own
//! typed error.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Maximum length of a bounded wire text field, in bytes.
pub const MAX_TEXT_BYTES: usize = 256;

/// Lowercase hexadecimal encoding.
pub fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// True when `value` is exactly `bytes * 2` lowercase hexadecimal digits.
pub fn is_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Decode lowercase hexadecimal of any even length.
pub fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || !is_lower_hex(value, value.len() / 2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

/// Decode a 32-byte digest written as 64 lowercase hexadecimal digits.
pub fn decode_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    decode_hex(value)?.try_into().ok()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// RFC 8785 canonical JSON bytes.
pub fn canonical_json(value: &impl Serialize) -> Option<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value).ok()
}

/// RFC 8785 canonical JSON bytes and their SHA-256 digest.
pub fn canonical_digest(value: &impl Serialize) -> Option<(Vec<u8>, [u8; 32])> {
    let bytes = canonical_json(value)?;
    let digest = sha256(&bytes);
    Some((bytes, digest))
}

/// Non-empty, at most `MAX_TEXT_BYTES`, and free of control characters.
pub fn bounded_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_and_rejections() {
        let bytes: [u8; 32] = core::array::from_fn(|i| (i * 7) as u8);
        let text = hex_lower(&bytes);
        assert_eq!(text.len(), 64);
        assert_eq!(decode_hex32(&text), Some(bytes));
        assert_eq!(decode_hex32(&text.to_uppercase()), None);
        assert_eq!(decode_hex32(&text[..62]), None);
        assert_eq!(decode_hex32(&format!("{}g", &text[..63])), None);
        assert_eq!(decode_hex("00ff"), Some(vec![0, 255]));
        assert_eq!(decode_hex("0"), None);
        assert!(is_lower_hex("00ff", 2));
        assert!(!is_lower_hex("00FF", 2));
    }

    #[test]
    fn canonical_digest_is_order_independent() {
        let a = serde_json::json!({"b": 1, "a": [2, 3]});
        let b: serde_json::Value = serde_json::from_str(r#"{"a":[2,3],"b":1}"#).unwrap();
        let (bytes, digest) = canonical_digest(&a).unwrap();
        assert_eq!(bytes, br#"{"a":[2,3],"b":1}"#);
        assert_eq!(canonical_digest(&b).unwrap().1, digest);
        assert_eq!(sha256(&bytes), digest);
    }

    #[test]
    fn bounded_text_limits() {
        assert!(bounded_text("x"));
        assert!(bounded_text(&"x".repeat(MAX_TEXT_BYTES)));
        assert!(!bounded_text(""));
        assert!(!bounded_text(&"x".repeat(MAX_TEXT_BYTES + 1)));
        assert!(!bounded_text("a\nb"));
    }
}
