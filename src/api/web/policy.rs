//! Host, address and image-format restrictions for outbound favicon requests.
use std::net::IpAddr;

pub(super) fn normalize_host(raw: &str) -> Option<String> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && ![".local", ".internal", ".localhost", ".home.arpa"]
            .iter()
            .any(|s| host.ends_with(s))
        && host.parse::<IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    valid.then_some(host)
}

pub(super) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 192 && b == 88 && c == 99)
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224)
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            // Allow global unicast only, excluding IETF special-use, documentation
            // and 6to4 ranges. Mapped IPv4 and NAT64 are excluded by this prefix.
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && s[0] != 0x2002
                && s[0] != 0x3fff
        }
    }
}

pub(super) fn image_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.len() >= 6 && bytes[..4] == [0, 0, 1, 0] && bytes[4..6] != [0, 0] {
        Some("image/x-icon")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_cannot_supply_urls_ports_credentials_or_internal_names() {
        assert_eq!(normalize_host(" EXAMPLE.COM. "), Some("example.com".into()));
        for host in [
            "localhost",
            "metadata.google.internal",
            "foo.local",
            "foo.home.arpa",
            "127.0.0.1",
            "[::1]",
            "https://example.com",
            "example.com:443",
            "user@example.com",
            "example.com/path",
            "a..com",
            "-a.com",
            "a-.com",
            "example.com\nHost: localhost",
            "example.com?x=1",
        ] {
            assert_eq!(normalize_host(host), None, "{host}");
        }
    }

    #[test]
    fn rejects_private_metadata_reserved_and_transition_addresses() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "127.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.0.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.19.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002:7f00:1::",
            "3fff::1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(is_public_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn requires_recognized_image_bytes_and_excludes_active_content() {
        for body in [
            b"<svg></svg>".as_slice(),
            b"<html>error</html>",
            b"",
            b"RIFF1234FAKE",
            &[0, 0, 1, 0, 0, 0],
        ] {
            assert!(image_type(body).is_none());
        }
        assert_eq!(image_type(b"\x89PNG\r\n\x1a\n"), Some("image/png"));
        assert_eq!(image_type(b"\xff\xd8\xff"), Some("image/jpeg"));
        assert_eq!(image_type(b"GIF89a"), Some("image/gif"));
        assert_eq!(image_type(b"RIFF1234WEBP"), Some("image/webp"));
        assert_eq!(image_type(&[0, 0, 1, 0, 1, 0]), Some("image/x-icon"));
    }
}
