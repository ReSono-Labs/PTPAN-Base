//! Agent address envelope (D10). An address is
//! `<opaque part>.<provider domain>`. PTPAN routes by the provider domain
//! only and checks wire safety only. The opaque part is never parsed,
//! validated or interpreted: it is carried and digested byte for byte and
//! delivered unchanged to the owning platform, which alone resolves it. Its
//! format is the platform's choice (one platform uses 16-character short
//! codes; that is an example, not a PTPAN rule).

/// Maximum address length in bytes (the DNS name limit, RFC 1035).
pub const MAX_ADDRESS_LEN: usize = 253;
/// JSON Schema pattern for the address envelope; schemas use exactly this.
pub const ADDRESS_PATTERN: &str =
    "^(?=[A-Za-z0-9.-]*\\.)[A-Za-z0-9-][A-Za-z0-9.-]{0,251}[A-Za-z0-9-]$";

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// A provider domain in canonical form: lowercase ASCII (punycode for
/// internationalized names), at least two DNS labels, at most 253 bytes.
pub fn valid_provider_domain(domain: &str) -> bool {
    domain.len() <= MAX_ADDRESS_LEN && domain.contains('.') && domain.split('.').all(valid_dns_label)
}

/// Wire safety only: 1–253 bytes of ASCII letters, digits, hyphen and dot,
/// containing a dot, and not starting or ending with a dot.
pub fn valid_address(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= MAX_ADDRESS_LEN
        && address
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && address.contains('.')
        && !address.starts_with('.')
        && !address.ends_with('.')
}

/// True when `address` is a valid envelope ending in `.<domain>`. The domain
/// is compared without regard to ASCII case; the opaque part (which may
/// itself contain dots) must be non-empty and is not inspected.
pub fn address_in_domain(address: &str, domain: &str) -> bool {
    if !valid_address(address) || domain.is_empty() || address.len() <= domain.len() + 1 {
        return false;
    }
    let split = address.len() - domain.len();
    address.as_bytes()[split - 1] == b'.' && address[split..].eq_ignore_ascii_case(domain)
}

/// The longest provider domain from `domains` that `address` ends in.
/// Callers pass only verified, active peer domains (and their own domain).
pub fn match_domain<'a>(address: &str, domains: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    domains
        .into_iter()
        .filter(|domain| address_in_domain(address, domain))
        .max_by_key(|domain| domain.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_is_wire_safety_only() {
        for address in [
            "0123456789abcdef.provider-b.test",
            "Calendar.Team-7.provider-b.test",
            "a.b",
            &format!("{}.provider-b.test", "x".repeat(200)),
        ] {
            assert!(valid_address(address), "{address}");
        }
        for address in [
            "",
            "nodot",
            ".provider.test",
            "a.provider.test.",
            "a_b.provider.test",
            "a b.provider.test",
            "agent@provider.test",
            "\u{e9}.provider.test",
            &format!("{}.provider-b.test", "x".repeat(240)),
        ] {
            assert!(!valid_address(address), "{address}");
        }
    }

    #[test]
    fn domain_match_is_case_insensitive_and_needs_a_dot_boundary() {
        assert!(address_in_domain("Opaque.Part.PROVIDER-B.test", "provider-b.test"));
        assert!(!address_in_domain("provider-b.test", "provider-b.test"));
        assert!(!address_in_domain("x.evilprovider-b.test", "provider-b.test"));
        assert!(!address_in_domain("x.provider-b.test.evil", "provider-b.test"));
    }

    #[test]
    fn longest_trusted_domain_wins_and_the_opaque_part_may_contain_dots() {
        let trusted = ["example.com", "agents.example.com", "other.test"];
        assert_eq!(match_domain("a.b.agents.example.com", trusted), Some("agents.example.com"));
        assert_eq!(match_domain("a.b.example.com", trusted), Some("example.com"));
        assert_eq!(match_domain("a.unknown.test", trusted), None);
    }

    #[test]
    fn provider_domain_is_canonical_lowercase_ascii() {
        assert!(valid_provider_domain("provider-b.test"));
        assert!(valid_provider_domain("xn--bcher-kva.example"));
        assert!(!valid_provider_domain("Provider-B.test"));
        assert!(!valid_provider_domain("localhost"));
    }
}
