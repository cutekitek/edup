//! sing-box binary rule-sets (`.srs`, versions 1-5) reduced to IP sets and
//! domain matchers.
//!
//! Routes see destination addresses, and DNS answers add the queried name.
//! `ip_cidr` and the domain items form one OR group in sing-box, so both stay
//! usable together; any other condition (port, network, process...) makes the
//! rule unusable. Inversion is applied only to rules that are exactly IP-based,
//! and AND only combines addresses.
use crate::{
    domain::DomainMatcher,
    ipset::{Family, IpSet},
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

const MAX_DOWNLOAD: u64 = 64 << 20;
const MAX_DECOMPRESSED: u64 = 256 << 20;
const MAX_DEPTH: usize = 100;

#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    pub v4: IpSet,
    pub v6: IpSet,
    pub domains: DomainMatcher,
    pub rules: usize,
    /// Top-level rules with conditions that routes and DNS cannot express.
    pub ignored: usize,
}
impl RuleSet {
    pub fn set(&self, family: Family) -> &IpSet {
        match family {
            Family::V4 => &self.v4,
            Family::V6 => &self.v6,
        }
    }
}

/// Reads a local file (relative to `base`) or downloads an http(s) URL. A good
/// download is cached under `base/rule-sets` and used when a later download fails.
pub fn load(source: &str, base: &Path) -> Result<RuleSet> {
    if !is_url(source) {
        let path = base.join(source);
        let data = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        return parse(&data).with_context(|| format!("rule-set {}", path.display()));
    }
    let cache = cache_path(source, base);
    let fresh = download(source).and_then(|data| Ok((parse(&data)?, data)));
    match fresh {
        Ok((rules, data)) => {
            if let Err(error) = store(&cache, &data) {
                eprintln!("warning: cannot cache rule-set {source}: {error:#}");
            }
            Ok(rules)
        }
        Err(error) => {
            let data = std::fs::read(&cache)
                .map_err(|_| error.context(format!("download rule-set {source}")))?;
            eprintln!(
                "warning: download of rule-set {source} failed; using cached {}",
                cache.display()
            );
            parse(&data).with_context(|| format!("cached rule-set {}", cache.display()))
        }
    }
}

pub fn is_url(source: &str) -> bool {
    source.starts_with("http://") || source.starts_with("https://")
}

fn download(url: &str) -> Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    Ok(agent
        .get(url)
        .call()?
        .body_mut()
        .with_config()
        .limit(MAX_DOWNLOAD)
        .read_to_vec()?)
}

fn cache_path(url: &str, base: &Path) -> PathBuf {
    use blake2::{Blake2s256, Digest};
    let hash = Blake2s256::digest(url.as_bytes());
    let name: String = url
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "._-".contains(*c))
        .take(64)
        .collect();
    let hash: String = hash[..8].iter().map(|b| format!("{b:02x}")).collect();
    base.join("rule-sets").join(format!("{hash}-{name}"))
}

fn store(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::create_dir_all(path.parent().unwrap())?;
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, data)?;
    std::fs::rename(&temp, path)?;
    Ok(())
}

pub fn parse(data: &[u8]) -> Result<RuleSet> {
    ensure!(
        data.len() >= 4 && &data[..3] == b"SRS",
        "not a sing-box binary rule-set (.srs)"
    );
    ensure!(
        (1..=5).contains(&data[3]),
        "unsupported rule-set version {}",
        data[3]
    );
    let mut raw = Vec::new();
    flate2::read::ZlibDecoder::new(&data[4..])
        .take(MAX_DECOMPRESSED)
        .read_to_end(&mut raw)
        .context("decompress rule-set")?;
    let mut reader = Reader { data: &raw, pos: 0 };
    let count = reader.uvarint()?;
    let mut result = RuleSet::default();
    for i in 0..count {
        let rule = reader.rule(0).with_context(|| format!("rule {i}"))?;
        result.v4 = result.v4.union(&rule.v4);
        result.v6 = result.v6.union(&rule.v6);
        result.domains.extend(&rule.domains);
        result.rules += 1;
        result.ignored += usize::from(!rule.exact);
    }
    Ok(result)
}

/// Addresses and names for which a rule surely matches; `exact` if it
/// matches nothing else.
struct Match {
    v4: IpSet,
    v6: IpSet,
    domains: DomainMatcher,
    exact: bool,
}
impl Match {
    fn none() -> Self {
        Self {
            v4: IpSet::default(),
            v6: IpSet::default(),
            domains: DomainMatcher::default(),
            exact: false,
        }
    }
    fn invert(self, invert: bool) -> Self {
        match (invert, self.exact && self.domains.is_empty()) {
            (false, _) => self,
            (true, true) => Self {
                v4: self.v4.complement(Family::V4),
                v6: self.v6.complement(Family::V6),
                domains: DomainMatcher::default(),
                exact: true,
            },
            (true, false) => Self::none(),
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}
impl Reader<'_> {
    fn bytes(&mut self, n: u64) -> Result<&[u8]> {
        let end = usize::try_from(n)
            .ok()
            .and_then(|n| self.pos.checked_add(n))
            .filter(|end| *end <= self.data.len())
            .context("truncated rule-set")?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    fn bool(&mut self) -> Result<bool> {
        Ok(self.byte()? != 0)
    }
    fn uvarint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        bail!("invalid varint")
    }
    fn skip_slice(&mut self, size: u64) -> Result<()> {
        let n = self.uvarint()?;
        self.bytes(n.checked_mul(size).context("invalid length")?)?;
        Ok(())
    }
    fn skip_strings(&mut self) -> Result<()> {
        for _ in 0..self.uvarint()? {
            self.skip_slice(1)?;
        }
        Ok(())
    }
    fn strings(&mut self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for _ in 0..self.uvarint()? {
            let n = self.uvarint()?;
            out.push(String::from_utf8_lossy(self.bytes(n)?).into_owned());
        }
        Ok(out)
    }
    fn words(&mut self) -> Result<Vec<u64>> {
        let n = self.uvarint()?;
        let data = self.bytes(n.checked_mul(8).context("invalid length")?)?;
        Ok(data
            .chunks(8)
            .map(|w| u64::from_be_bytes(w.try_into().unwrap()))
            .collect())
    }
    fn succinct_set(&mut self) -> Result<DomainMatcher> {
        self.byte()?;
        let leaves = self.words()?;
        let bitmap = self.words()?;
        let n = self.uvarint()?;
        let labels = self.bytes(n)?.to_vec();
        DomainMatcher::from_succinct(&leaves, &bitmap, &labels)
    }
    fn skip_succinct_set(&mut self) -> Result<()> {
        self.byte()?;
        self.skip_slice(8)?;
        self.skip_slice(8)?;
        self.skip_slice(1)
    }
    fn skip_prefixes(&mut self) -> Result<()> {
        for _ in 0..self.uvarint()? {
            self.skip_slice(1)?;
            self.byte()?;
        }
        Ok(())
    }
    fn ip_set(&mut self) -> Result<(IpSet, IpSet)> {
        ensure!(self.byte()? == 1, "unsupported IP set version");
        let count = u64::from_be_bytes(self.bytes(8)?.try_into().unwrap());
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for _ in 0..count {
            let mut address = || -> Result<(usize, u128)> {
                let len = self.uvarint()?;
                ensure!(len == 4 || len == 16, "invalid IP address length");
                let mut value = [0; 16];
                value[16 - len as usize..].copy_from_slice(self.bytes(len)?);
                Ok((len as usize, u128::from_be_bytes(value)))
            };
            let (from_len, from) = address()?;
            let (to_len, to) = address()?;
            ensure!(from_len == to_len && from <= to, "invalid IP range");
            if from_len == 4 { &mut v4 } else { &mut v6 }.push((from, to));
        }
        Ok((IpSet::from_ranges(v4), IpSet::from_ranges(v6)))
    }

    fn rule(&mut self, depth: usize) -> Result<Match> {
        ensure!(depth <= MAX_DEPTH, "logical rules nested too deep");
        match self.byte()? {
            0 => self.default_rule(),
            1 => self.logical_rule(depth),
            t => bail!("unknown rule type {t}"),
        }
    }

    fn default_rule(&mut self) -> Result<Match> {
        let (mut v4, mut v6) = (IpSet::default(), IpSet::default());
        let mut domains = DomainMatcher::default();
        let (mut has_destination, mut unusable, mut conditions) = (false, false, false);
        loop {
            match self.byte()? {
                6 => {
                    let (a, b) = self.ip_set()?;
                    (v4, v6) = (v4.union(&a), v6.union(&b));
                    has_destination = true;
                }
                // domain and domain_suffix.
                2 => {
                    domains.extend(&self.succinct_set()?);
                    has_destination = true;
                }
                3 => {
                    for keyword in self.strings()? {
                        domains.add_keyword(&keyword)?;
                    }
                    has_destination = true;
                }
                // domain_regex: unsupported, names are compared as strings.
                4 => {
                    self.skip_strings()?;
                    unusable = true;
                }
                // AdGuard filter syntax.
                16 => {
                    self.skip_succinct_set()?;
                    unusable = true;
                }
                // query_type, port, source_port.
                0 | 7 | 9 => {
                    self.skip_slice(2)?;
                    conditions = true;
                }
                // network, port ranges, process, package, Wi-Fi.
                1 | 8 | 10..=15 | 17 | 23 => {
                    self.skip_strings()?;
                    conditions = true;
                }
                5 => {
                    self.ip_set()?;
                    conditions = true;
                }
                18 => {
                    self.skip_slice(1)?;
                    conditions = true;
                }
                19 | 20 => conditions = true,
                21 => {
                    for _ in 0..self.uvarint()? {
                        self.byte()?;
                        self.skip_prefixes()?;
                    }
                    conditions = true;
                }
                22 => {
                    self.skip_prefixes()?;
                    conditions = true;
                }
                0xff => {
                    let invert = self.bool()?;
                    let result = if conditions || !has_destination {
                        Match::none()
                    } else {
                        Match {
                            v4,
                            v6,
                            domains,
                            exact: !unusable,
                        }
                    };
                    return Ok(result.invert(invert));
                }
                t => bail!("unknown rule item type {t}"),
            }
        }
    }

    fn logical_rule(&mut self, depth: usize) -> Result<Match> {
        let and = match self.byte()? {
            0 => true,
            1 => false,
            m => bail!("unknown logical mode {m}"),
        };
        let count = self.uvarint()?;
        let mut result: Option<Match> = None;
        for _ in 0..count {
            let rule = self.rule(depth + 1)?;
            result = Some(match result {
                None => rule,
                // A name and an address are never known to belong together.
                Some(r) if and => Match {
                    v4: r.v4.intersection(&rule.v4),
                    v6: r.v6.intersection(&rule.v6),
                    domains: DomainMatcher::default(),
                    exact: r.exact && rule.exact && r.domains.is_empty() && rule.domains.is_empty(),
                },
                Some(mut r) => {
                    r.domains.extend(&rule.domains);
                    Match {
                        v4: r.v4.union(&rule.v4),
                        v6: r.v6.union(&rule.v6),
                        domains: r.domains,
                        exact: r.exact && rule.exact,
                    }
                }
            });
        }
        let invert = self.bool()?;
        Ok(result.unwrap_or_else(Match::none).invert(invert))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::ipset::{Prefix, key};
    use std::io::Write;

    /// Minimal SRS writer for tests, following sing-box common/srs.
    pub fn srs(version: u8, rules: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![rules.len() as u8];
        rules.iter().for_each(|r| body.extend(r));
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), Default::default());
        z.write_all(&body).unwrap();
        let mut out = b"SRS".to_vec();
        out.push(version);
        out.extend(z.finish().unwrap());
        out
    }
    pub fn ip_item(prefixes: &[&str]) -> Vec<u8> {
        let mut out = vec![6, 1];
        out.extend((prefixes.len() as u64).to_be_bytes());
        for p in prefixes {
            let (from, to) = p.parse::<Prefix>().unwrap().range();
            let len = if p.contains(':') { 16 } else { 4 };
            for v in [from, to] {
                out.push(len as u8);
                out.extend(&v.to_be_bytes()[16 - len..]);
            }
        }
        out
    }
    pub fn rule(items: &[Vec<u8>], invert: bool) -> Vec<u8> {
        let mut out = vec![0];
        items.iter().for_each(|i| out.extend(i));
        out.extend([0xff, invert as u8]);
        out
    }
    fn has(set: &IpSet, ip: &str) -> bool {
        set.contains(key(ip.parse().unwrap()))
    }

    #[test]
    fn files_load_relative_to_the_configuration_or_absolute() {
        let dir = std::env::temp_dir().join(format!("edup-ruleset-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("lists")).unwrap();
        let data = srs(1, &[rule(&[ip_item(&["203.0.113.0/24"])], false)]);
        std::fs::write(dir.join("lists").join("test.srs"), &data).unwrap();
        let absolute = dir.join("lists").join("test.srs");
        for (source, base) in [
            ("lists/test.srs", dir.as_path()),
            (absolute.to_str().unwrap(), Path::new("elsewhere")),
        ] {
            let rules = load(source, base).unwrap();
            assert!(
                has(rules.set(crate::ipset::Family::V4), "203.0.113.9"),
                "{source}"
            );
        }
        let missing = load("lists/missing.srs", &dir).err().unwrap();
        assert!(
            format!("{missing:#}").contains("missing.srs"),
            "{missing:#}"
        );
        // Local files are never cached.
        assert!(!dir.join("rule-sets").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// domain/domain_suffix item from keys in sing's unreversed form.
    pub fn domain_item(keys: &[&str]) -> Vec<u8> {
        let (leaves, bitmap, labels) = crate::domain::tests::succinct(keys);
        let mut out = vec![2, 0];
        for words in [leaves, bitmap] {
            out.push(words.len() as u8);
            words.iter().for_each(|w| out.extend(w.to_be_bytes()));
        }
        out.push(labels.len() as u8);
        out.extend(labels);
        out
    }

    #[test]
    fn ip_rules_domains_and_conditions() {
        let keyword = vec![3, 1, 3, b'f', b'o', b'o'];
        let regex = vec![4, 2, 4, b'^', b'a', b'd', b'.', 1, b'('];
        let port = vec![9, 1, 1, 187];
        let data = srs(
            3,
            &[
                rule(&[ip_item(&["198.51.100.0/24", "2001:db8::/32"])], false),
                rule(
                    &[domain_item(&["example.com"]), ip_item(&["203.0.113.0/24"])],
                    false,
                ),
                rule(&[keyword, port.clone(), ip_item(&["192.0.2.0/24"])], false),
                rule(&[domain_item(&["\r.ru", "\nexample.org"])], false),
                rule(&[vec![19], vec![1, 1, 3, b't', b'c', b'p']], false),
                rule(&[regex], false),
                rule(&[vec![16, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0]], false),
                rule(&[domain_item(&["inverted.com"])], true),
            ],
        );
        let set = parse(&data).unwrap();
        // Conditions, regular expressions, AdGuard syntax and an inverted name.
        assert_eq!((set.rules, set.ignored), (8, 5));
        assert!(has(&set.v4, "198.51.100.200"));
        assert!(has(&set.v6, "2001:db8:ffff::1"));
        assert!(has(&set.v4, "203.0.113.1"));
        assert!(!has(&set.v4, "192.0.2.1"));
        assert_eq!(set.v4.prefixes(Family::V4).len(), 2);
        for (name, hit) in [
            ("example.com", true),
            ("a.ru", true),
            ("example.org", true),
            ("x.example.org", true),
            ("food.com", false),
            ("adx.com", false),
            ("inverted.com", false),
        ] {
            assert_eq!(set.domains.matches(name), hit, "{name}");
        }
    }

    #[test]
    fn inversion_and_logical_rules() {
        let inverted = parse(&srs(1, &[rule(&[ip_item(&["0.0.0.0/1", "::/0"])], true)])).unwrap();
        assert_eq!(
            inverted.v4.prefixes(Family::V4)[0].to_string(),
            "128.0.0.0/1"
        );
        assert!(inverted.v6.is_empty());
        let mut logical = vec![1, 0, 2];
        logical.extend(rule(&[ip_item(&["10.0.0.0/8"])], false));
        logical.extend(rule(&[ip_item(&["10.1.0.0/16", "11.0.0.0/8"])], false));
        logical.push(0);
        let mut or = vec![1, 1, 2];
        or.extend(rule(&[ip_item(&["10.0.0.0/8"])], false));
        or.extend(rule(&[vec![9, 1, 0, 80], ip_item(&["12.0.0.0/8"])], false));
        or.push(1); // inverted inexact OR matches no address for certain
        let set = parse(&srs(5, &[logical, or])).unwrap();
        assert_eq!(set.v4.prefixes(Family::V4)[0].to_string(), "10.1.0.0/16");
        assert_eq!(set.ignored, 1);
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert!(parse(b"SRS").is_err());
        assert!(parse(b"XYZ\x01").is_err());
        assert!(parse(&srs(6, &[])).is_err());
        let good = srs(2, &[rule(&[ip_item(&["10.0.0.0/8"])], false)]);
        assert!(parse(&good).is_ok());
        // Unknown item type, then an IP set announcing more ranges than present.
        assert!(parse(&srs(1, &[vec![0, 99, 0xff, 0]])).is_err());
        assert!(parse(&srs(1, &[vec![0, 6, 1, 0, 0, 0, 0, 0, 0, 0, 9]])).is_err());
    }

    #[test]
    fn cache_names_are_stable_and_safe() {
        let base = Path::new("cfg");
        let a = cache_path("https://example.com/x/geoip-ru.srs", base);
        assert_eq!(a, cache_path("https://example.com/x/geoip-ru.srs", base));
        assert_ne!(a, cache_path("https://example.org/x/geoip-ru.srs", base));
        let name = a.file_name().unwrap().to_str().unwrap();
        assert!(
            name.ends_with("-geoip-ru.srs") && name.len() == 17 + 12,
            "{name}"
        );
        let odd = cache_path("https://e/..%2f..?q=/../a b", base);
        assert_eq!(odd.parent().unwrap(), base.join("rule-sets"));
    }
}
