//! IPv4/IPv6 networks as (family, base, prefix). Enough for membership, overlap and small expansions.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    pub v6: bool,
    pub base: u128,
    pub prefix: u8,
}

pub fn ip_bits(ip: IpAddr) -> (bool, u128) {
    match ip {
        IpAddr::V4(v) => (false, u32::from(v) as u128),
        IpAddr::V6(v) => (true, u128::from(v)),
    }
}

pub fn bits_ip(v6: bool, bits: u128) -> IpAddr {
    if v6 { IpAddr::V6(Ipv6Addr::from(bits)) } else { IpAddr::V4(Ipv4Addr::from(bits as u32)) }
}

impl Net {
    fn width(v6: bool) -> u32 {
        if v6 { 128 } else { 32 }
    }
    fn host_mask(v6: bool, prefix: u8) -> u128 {
        let host_bits = Self::width(v6) - prefix as u32;
        if host_bits >= 128 { u128::MAX } else { (1u128 << host_bits) - 1 }
    }
    pub fn new(ip: IpAddr, prefix: u8) -> Option<Net> {
        let (v6, bits) = ip_bits(ip);
        if prefix as u32 > Self::width(v6) {
            return None;
        }
        Some(Net { v6, base: bits & !Self::host_mask(v6, prefix), prefix })
    }
    /// "a.b.c.d/n", "v6/n" or a bare address (a host route). Host bits are cleared.
    pub fn parse(s: &str) -> Option<Net> {
        let s = s.trim();
        match s.split_once('/') {
            Some((ip, p)) => {
                if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                Net::new(ip.parse().ok()?, p.parse().ok()?)
            }
            None => {
                let ip: IpAddr = s.parse().ok()?;
                Net::new(ip, if ip.is_ipv6() { 128 } else { 32 })
            }
        }
    }
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        let (v6, bits) = ip_bits(ip);
        v6 == self.v6 && bits & !Self::host_mask(v6, self.prefix) == self.base
    }
    pub fn overlaps(&self, o: &Net) -> bool {
        if self.v6 != o.v6 {
            return false;
        }
        let p = self.prefix.min(o.prefix);
        let m = !Self::host_mask(self.v6, p);
        self.base & m == o.base & m
    }
    pub fn first(&self) -> IpAddr {
        bits_ip(self.v6, self.base)
    }
    pub fn last(&self) -> IpAddr {
        bits_ip(self.v6, self.base | Self::host_mask(self.v6, self.prefix))
    }
    /// Number of addresses, saturating at u64::MAX.
    pub fn size(&self) -> u64 {
        let hb = Self::width(self.v6) - self.prefix as u32;
        if hb >= 64 { u64::MAX } else { 1u64 << hb }
    }
}

impl std::fmt::Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.first(), self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_normalise() {
        assert_eq!(Net::parse("192.0.2.77/24").unwrap().to_string(), "192.0.2.0/24");
        assert_eq!(Net::parse("8.8.8.8").unwrap().prefix, 32);
        assert_eq!(Net::parse("2001:db8::1/32").unwrap().to_string(), "2001:db8::/32");
        for bad in ["", "1.2.3.4/33", "1.2.3.4/", "1.2.3.4/-1", "1.2.3.4/a", "::1/129", "1.2.3/24", "1.2.3.4/1/2", "x/8", "1.2.3.4/0033"] {
            assert!(Net::parse(bad).is_none(), "{bad}");
        }
        assert_eq!(Net::parse("0.0.0.0/0").unwrap().size(), 1 << 32);
    }

    #[test]
    fn contains_and_overlap() {
        let n = Net::parse("10.1.0.0/16").unwrap();
        assert!(n.contains_ip("10.1.255.255".parse().unwrap()));
        assert!(!n.contains_ip("10.2.0.0".parse().unwrap()));
        assert!(!n.contains_ip("::a01:0".parse().unwrap()), "families never mix");
        assert!(n.overlaps(&Net::parse("10.1.2.0/24").unwrap()));
        assert!(n.overlaps(&Net::parse("10.0.0.0/8").unwrap()));
        assert!(!n.overlaps(&Net::parse("10.2.0.0/16").unwrap()));
        assert_eq!(n.last().to_string(), "10.1.255.255");
        let v6 = Net::parse("2606:4700::/32").unwrap();
        assert!(v6.contains_ip("2606:4700:4700::1111".parse().unwrap()));
        assert_eq!(Net::parse("::/0").unwrap().size(), u64::MAX);
    }
}
