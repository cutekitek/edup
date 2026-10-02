use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}
impl Family {
    pub fn of(ip: IpAddr) -> Self {
        if ip.is_ipv4() { Self::V4 } else { Self::V6 }
    }
    pub fn bits(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
    pub fn max(self) -> u128 {
        match self {
            Self::V4 => u32::MAX.into(),
            Self::V6 => u128::MAX,
        }
    }
    pub fn addr(self, value: u128) -> IpAddr {
        match self {
            Self::V4 => Ipv4Addr::from(value as u32).into(),
            Self::V6 => Ipv6Addr::from(value).into(),
        }
    }
}
pub fn key(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(ip) => u32::from(ip).into(),
        IpAddr::V6(ip) => ip.into(),
    }
}

/// CIDR prefix with host bits cleared, as sing-box normalizes `ip_cidr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub addr: IpAddr,
    pub len: u8,
}
impl Prefix {
    pub fn new(addr: IpAddr, len: u8) -> Self {
        let family = Family::of(addr);
        let (first, _) = span(key(addr), len, family.bits());
        Self {
            addr: family.addr(first),
            len,
        }
    }
    pub fn host(addr: IpAddr) -> Self {
        Self::new(addr, Family::of(addr).bits())
    }
    pub fn family(&self) -> Family {
        Family::of(self.addr)
    }
    pub fn range(&self) -> (u128, u128) {
        span(key(self.addr), self.len, self.family().bits())
    }
}
fn span(value: u128, len: u8, bits: u8) -> (u128, u128) {
    let host = bits - len;
    let mask = if host == 128 {
        u128::MAX
    } else {
        (1u128 << host) - 1
    };
    (value & !mask, value | mask)
}
impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}
impl FromStr for Prefix {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let (addr, len) = s.split_once('/').unwrap_or((s, ""));
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("invalid IP address in {s:?}"))?;
        let bits = Family::of(addr).bits();
        let len = if len.is_empty() && !s.contains('/') {
            bits
        } else {
            len.parse::<u8>()
                .ok()
                .filter(|len| *len <= bits)
                .ok_or_else(|| format!("invalid prefix length in {s:?} (0..={bits})"))?
        };
        Ok(Self::new(addr, len))
    }
}

/// Addresses of one family as sorted, disjoint, non-adjacent inclusive ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpSet {
    ranges: Vec<(u128, u128)>,
}
impl IpSet {
    pub fn from_ranges(mut ranges: Vec<(u128, u128)>) -> Self {
        ranges.retain(|(from, to)| from <= to);
        ranges.sort_unstable();
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
        for (from, to) in ranges {
            match merged.last_mut() {
                Some(last) if from <= last.1.saturating_add(1) => last.1 = last.1.max(to),
                _ => merged.push((from, to)),
            }
        }
        Self { ranges: merged }
    }
    pub fn range(from: u128, to: u128) -> Self {
        Self::from_ranges(vec![(from, to)])
    }
    pub fn full(family: Family) -> Self {
        Self::range(0, family.max())
    }
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
    pub fn contains(&self, value: u128) -> bool {
        let i = self.ranges.partition_point(|(_, to)| *to < value);
        self.ranges.get(i).is_some_and(|(from, _)| *from <= value)
    }
    pub fn union(&self, other: &Self) -> Self {
        Self::from_ranges(self.ranges.iter().chain(&other.ranges).copied().collect())
    }
    pub fn intersection(&self, other: &Self) -> Self {
        let (mut i, mut j, mut out) = (0, 0, Vec::new());
        while i < self.ranges.len() && j < other.ranges.len() {
            let (a, b) = (self.ranges[i], other.ranges[j]);
            let (from, to) = (a.0.max(b.0), a.1.min(b.1));
            if from <= to {
                out.push((from, to));
            }
            if a.1 < b.1 { i += 1 } else { j += 1 }
        }
        Self { ranges: out }
    }
    pub fn complement(&self, family: Family) -> Self {
        let mut out = Vec::new();
        let mut next = Some(0u128);
        for &(from, to) in &self.ranges {
            if let Some(start) = next
                && start < from
            {
                out.push((start, from - 1));
            }
            next = to.checked_add(1);
        }
        if let Some(start) = next
            && start <= family.max()
        {
            out.push((start, family.max()));
        }
        Self { ranges: out }
    }
    pub fn difference(&self, other: &Self, family: Family) -> Self {
        self.intersection(&other.complement(family))
    }
    /// Minimal CIDR cover of exactly this set.
    pub fn prefixes(&self, family: Family) -> Vec<Prefix> {
        let bits = family.bits();
        let mut out = Vec::new();
        for &(mut from, to) in &self.ranges {
            loop {
                let mut host = if from == 0 {
                    bits
                } else {
                    (from.trailing_zeros() as u8).min(bits)
                };
                let last = |host: u8| {
                    from + if host == 128 {
                        u128::MAX
                    } else {
                        (1 << host) - 1
                    }
                };
                while host > 0 && (to - from < last(host) - from) {
                    host -= 1;
                }
                out.push(Prefix {
                    addr: family.addr(from),
                    len: bits - host,
                });
                if last(host) == to {
                    break;
                }
                from = last(host) + 1;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(prefixes: &[&str]) -> IpSet {
        IpSet::from_ranges(
            prefixes
                .iter()
                .map(|p| p.parse::<Prefix>().unwrap().range())
                .collect(),
        )
    }
    fn text(prefixes: Vec<Prefix>) -> Vec<String> {
        prefixes.iter().map(Prefix::to_string).collect()
    }

    #[test]
    fn prefixes_parse_and_normalize() {
        assert_eq!(
            "192.168.1.7/24".parse::<Prefix>().unwrap().to_string(),
            "192.168.1.0/24"
        );
        assert_eq!(
            "10.0.0.1".parse::<Prefix>().unwrap().to_string(),
            "10.0.0.1/32"
        );
        assert_eq!(
            "2001:db8::1/32".parse::<Prefix>().unwrap().to_string(),
            "2001:db8::/32"
        );
        assert_eq!("::/0".parse::<Prefix>().unwrap().range(), (0, u128::MAX));
        for bad in [
            "192.168.1.0/235",
            "192.168.1.0/33",
            "::/129",
            "x/8",
            "1.2.3.4/",
            "1.2.3/8",
        ] {
            assert!(bad.parse::<Prefix>().is_err(), "{bad}");
        }
    }

    #[test]
    fn set_algebra() {
        let a = set(&["10.0.0.0/8", "11.0.0.0/8", "192.168.0.0/16"]);
        assert_eq!(
            text(a.prefixes(Family::V4)),
            ["10.0.0.0/7", "192.168.0.0/16"]
        );
        let b = set(&["10.1.0.0/16"]);
        assert_eq!(
            text(a.intersection(&b).prefixes(Family::V4)),
            ["10.1.0.0/16"]
        );
        let d = a.difference(&b, Family::V4);
        assert!(d.contains(key("10.0.255.255".parse().unwrap())));
        assert!(!d.contains(key("10.1.0.0".parse().unwrap())));
        assert!(d.contains(key("10.2.0.0".parse().unwrap())));
        assert_eq!(d.union(&b), a);
        assert_eq!(
            text(IpSet::default().complement(Family::V4).prefixes(Family::V4)),
            ["0.0.0.0/0"]
        );
        assert_eq!(
            IpSet::full(Family::V6).complement(Family::V6),
            IpSet::default()
        );
        assert_eq!(text(IpSet::full(Family::V6).prefixes(Family::V6)), ["::/0"]);
        let without_one = IpSet::full(Family::V4).difference(&set(&["192.0.2.1"]), Family::V4);
        assert_eq!(without_one.prefixes(Family::V4).len(), 32);
        let edge = IpSet::range(u128::MAX - 2, u128::MAX);
        assert_eq!(
            text(edge.prefixes(Family::V6)),
            [
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffd/128",
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127"
            ]
        );
    }
}
