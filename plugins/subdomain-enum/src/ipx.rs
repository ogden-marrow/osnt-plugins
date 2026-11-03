//! IP and CIDR helpers: public-address check, CIDR parsing and containment.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4_public(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && (o[1] & 0xFE) == 18)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || o[0] >= 240)
}

fn v6_public(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_public(v4);
    }
    let s = ip.segments();
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    if (s[0] & 0xFE00) == 0xFC00 || (s[0] & 0xFFC0) == 0xFE80 || (s[0] & 0xFFC0) == 0xFEC0 {
        return false;
    }
    if s[..6] == [0; 6] || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return false;
    }
    if (s[0] == 0x2001 && s[1] == 0x0db8) || (s[0] == 0x2001 && s[1] == 0) {
        return false;
    }
    // Only global unicast 2000::/3 is routable on the public internet today.
    (s[0] & 0xE000) == 0x2000
}

/// True only for a globally routable public address.
pub fn ip_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v4_public(v),
        IpAddr::V6(v) => v6_public(v),
    }
}

fn bits(ip: IpAddr) -> (u128, u8) {
    match ip {
        IpAddr::V4(v) => (u32::from(v) as u128, 32),
        IpAddr::V6(v) => (u128::from(v), 128),
    }
}

/// Parse `a.b.c.d/len` or `v6/len`. Host bits are allowed (callers may normalise with `network_of`).
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, l) = s.trim().split_once('/')?;
    let ip: IpAddr = a.trim().parse().ok()?;
    let len: u8 = l.trim().parse().ok()?;
    (len <= bits(ip).1).then_some((ip, len))
}

/// Does `net/len` contain `ip`? Mixed address families never match.
pub fn cidr_contains(net: IpAddr, len: u8, ip: IpAddr) -> bool {
    let ((n, nb), (i, ib)) = (bits(net), bits(ip));
    if nb != ib || len > nb {
        return false;
    }
    if len == 0 {
        return true;
    }
    let shift = nb - len;
    (n >> shift) == (i >> shift)
}

/// The network address of `ip/len` (host bits cleared), as text.
pub fn network_of(ip: IpAddr, len: u8) -> String {
    let (v, b) = bits(ip);
    let masked = if len == 0 { 0 } else { (v >> (b - len)) << (b - len) };
    match ip {
        IpAddr::V4(_) => format!("{}/{len}", Ipv4Addr::from(masked as u32)),
        IpAddr::V6(_) => format!("{}/{len}", Ipv6Addr::from(masked)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_vs_reserved() {
        for p in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "193.0.0.1"] {
            assert!(ip_public(ip(p)), "{p}");
        }
        for r in ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::1", "2001:db8::1", "::ffff:10.0.0.1", "ff02::1", "203.0.113.5"] {
            assert!(!ip_public(ip(r)), "{r}");
        }
    }

    #[test]
    fn cidr_parse_and_contains() {
        assert_eq!(parse_cidr("193.0.0.0/21"), Some((ip("193.0.0.0"), 21)));
        assert!(parse_cidr("193.0.0.0/33").is_none());
        assert!(parse_cidr("2001::/129").is_none());
        assert!(parse_cidr("1.2.3.4").is_none());
        assert!(parse_cidr("x/8").is_none());
        let (n, l) = parse_cidr("193.0.0.0/21").unwrap();
        assert!(cidr_contains(n, l, ip("193.0.7.255")));
        assert!(!cidr_contains(n, l, ip("193.0.8.0")));
        assert!(cidr_contains(ip("0.0.0.0"), 0, ip("9.9.9.9")));
        assert!(!cidr_contains(n, l, ip("2001::1")), "families do not mix");
        let (n6, l6) = parse_cidr("2a00:1450::/32").unwrap();
        assert!(cidr_contains(n6, l6, ip("2a00:1450:4001::1")));
        assert!(!cidr_contains(n6, l6, ip("2a00:1451::1")));
    }

    #[test]
    fn network_normalisation() {
        assert_eq!(network_of(ip("193.0.7.9"), 21), "193.0.0.0/21");
        assert_eq!(network_of(ip("8.8.8.8"), 32), "8.8.8.8/32");
        assert_eq!(network_of(ip("2a00:1450:4001::1"), 32), "2a00:1450::/32");
    }
}
