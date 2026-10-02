//! Domain name matching with sing-box semantics, by plain string comparison.
use anyhow::{Result, ensure};
use std::collections::HashSet;

#[derive(Clone, Debug, Default)]
pub struct DomainMatcher {
    exact: HashSet<String>,
    /// The domain itself and its subdomains (`domain_suffix: "ru"`).
    suffix: HashSet<String>,
    /// Subdomains only (`domain_suffix: ".ru"`).
    subdomain: HashSet<String>,
    /// Plain string suffixes from rule-sets, not aligned to labels.
    raw_suffix: Vec<String>,
    keyword: Vec<String>,
}

/// Lowercase without the root dot, as names are compared.
pub fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl DomainMatcher {
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn len(&self) -> usize {
        self.exact.len()
            + self.suffix.len()
            + self.subdomain.len()
            + self.raw_suffix.len()
            + self.keyword.len()
    }
    pub fn add_domain(&mut self, domain: &str) -> Result<()> {
        let domain = normalize(domain);
        ensure!(valid(&domain), "invalid domain {domain:?}");
        self.exact.insert(domain);
        Ok(())
    }
    /// `".ru"` matches subdomains of ru; `"ru"` also ru itself.
    pub fn add_suffix(&mut self, suffix: &str) -> Result<()> {
        let suffix = normalize(suffix);
        let (set, name) = match suffix.strip_prefix('.') {
            Some(name) => (&mut self.subdomain, name),
            None => (&mut self.suffix, suffix.as_str()),
        };
        ensure!(valid(name), "invalid domain suffix {suffix:?}");
        set.insert(name.to_string());
        Ok(())
    }
    pub fn add_keyword(&mut self, keyword: &str) -> Result<()> {
        ensure!(!keyword.is_empty(), "empty domain keyword");
        self.keyword.push(keyword.to_ascii_lowercase());
        Ok(())
    }
    pub fn extend(&mut self, other: &Self) {
        self.exact.extend(other.exact.iter().cloned());
        self.suffix.extend(other.suffix.iter().cloned());
        self.subdomain.extend(other.subdomain.iter().cloned());
        self.raw_suffix.extend(other.raw_suffix.iter().cloned());
        self.keyword.extend(other.keyword.iter().cloned());
    }
    /// `name` must be normalized.
    pub fn matches(&self, name: &str) -> bool {
        if self.exact.contains(name) || self.suffix.contains(name) {
            return true;
        }
        let mut parent = name;
        while let Some(i) = parent.find('.') {
            parent = &parent[i + 1..];
            if self.suffix.contains(parent) || self.subdomain.contains(parent) {
                return true;
            }
        }
        self.raw_suffix.iter().any(|s| name.ends_with(s.as_str()))
            || self.keyword.iter().any(|k| name.contains(k.as_str()))
    }

    /// Reads a sing-box domain matcher: a LOUDS-encoded trie of reversed keys.
    /// A key starting with `\r` is a plain suffix, with `\n` a label suffix
    /// matching the domain itself too; other keys are exact domains.
    pub fn from_succinct(leaves: &[u64], bitmap: &[u64], labels: &[u8]) -> Result<Self> {
        let bit =
            |words: &[u64], i: usize| words.get(i >> 6).is_some_and(|w| w >> (i & 63) & 1 != 0);
        // Node n's children are consecutive node ids; each 0 bit is one child edge
        // labeled in order, each 1 bit ends the current node's child list.
        let end = (0..bitmap.len() * 64)
            .rev()
            .find(|&i| bit(bitmap, i))
            .map_or(0, |i| i + 1);
        let (mut first, mut count) = (Vec::new(), Vec::new());
        let (mut zeros, mut start) = (0usize, 0usize);
        for i in 0..end {
            if bit(bitmap, i) {
                first.push(start + 1);
                count.push(zeros - start);
                start = zeros;
            } else {
                zeros += 1;
            }
        }
        ensure!(
            zeros == labels.len() && first.len() == zeros + 1,
            "malformed domain matcher"
        );
        let mut matcher = Self::default();
        let mut add = |key: &[u8]| {
            let key: String = String::from_utf8_lossy(key).chars().rev().collect();
            match key.chars().next() {
                Some('\r') if key[1..].starts_with('.') => {
                    matcher.subdomain.insert(key[2..].to_string())
                }
                Some('\r') => {
                    matcher.raw_suffix.push(key[1..].to_string());
                    true
                }
                Some('\n') => matcher.suffix.insert(key[1..].to_string()),
                _ => matcher.exact.insert(key),
            };
        };
        let mut stack = vec![(0usize, 0usize)];
        let mut key = Vec::new();
        while let Some(top) = stack.last_mut() {
            let (node, next) = *top;
            if next == count[node] {
                stack.pop();
                key.pop();
                continue;
            }
            top.1 += 1;
            let child = first[node] + next;
            // BFS ids always grow; this also rules out cycles.
            ensure!(
                child > node && child < first.len(),
                "malformed domain matcher"
            );
            key.push(labels[child - 1]);
            if bit(leaves, child) {
                add(&key);
            }
            stack.push((child, 0));
        }
        Ok(matcher)
    }
}

fn valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// LOUDS encoding as sing's newSuccinctSet, for sorted keys.
    pub fn succinct(keys: &[&str]) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
        let mut keys: Vec<Vec<u8>> = keys.iter().map(|k| k.bytes().rev().collect()).collect();
        keys.sort();
        keys.dedup();
        let (mut leaves, mut bitmap, mut labels) = (Vec::new(), Vec::new(), Vec::new());
        let set = |bm: &mut Vec<u64>, i: usize| {
            bm.resize(bm.len().max(i / 64 + 1), 0);
            bm[i / 64] |= 1 << (i % 64);
        };
        let mut queue = vec![(0, keys.len(), 0)];
        let mut l = 0;
        let mut i = 0;
        while i < queue.len() {
            let (mut s, e, col) = queue[i];
            if col == keys[s].len() {
                s += 1;
                set(&mut leaves, i);
            }
            let mut j = s;
            while j < e {
                let from = j;
                while j < e && keys[j][col] == keys[from][col] {
                    j += 1;
                }
                queue.push((from, j, col + 1));
                labels.push(keys[from][col]);
                l += 1;
            }
            set(&mut bitmap, l);
            l += 1;
            i += 1;
        }
        (leaves, bitmap, labels)
    }

    #[test]
    fn config_semantics() {
        let mut m = DomainMatcher::default();
        m.add_domain("Example.RU.").unwrap();
        m.add_suffix(".ru").unwrap();
        m.add_suffix(".Example.COM").unwrap();
        m.add_suffix("org").unwrap();
        m.add_keyword("tracker").unwrap();
        for (name, hit) in [
            ("example.ru", true),
            ("www.example.ru", true),
            ("ru", false),
            ("x.ru", true),
            ("org", true),
            ("a.b.org", true),
            ("borg", false),
            ("mytracker.com", true),
            ("a.b.example.com", true),
            ("example.com", false),
            ("badexample.com", false),
        ] {
            assert_eq!(m.matches(name), hit, "{name}");
        }
        for bad in ["", "a..b", "*", "a b.com", "*.ru"] {
            assert!(m.add_domain(bad).is_err(), "{bad}");
        }
        for bad in [".", "*.ru", "..ru", ""] {
            assert!(m.add_suffix(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn succinct_trie_round_trip() {
        // Keys as sing's NewMatcher builds them (unreversed form).
        let (leaves, bitmap, labels) =
            succinct(&["example.com", "\r.ru", "\nexample.org", "\rfoo", "a.b"]);
        let m = DomainMatcher::from_succinct(&leaves, &bitmap, &labels).unwrap();
        assert!(m.matches("example.com") && !m.matches("www.example.com"));
        assert!(m.matches("x.ru") && !m.matches("ru"));
        assert!(m.matches("example.org") && m.matches("a.example.org"));
        assert!(m.matches("barfoo") && m.matches("a.b"));
        assert_eq!(m.len(), 5);
        assert!(DomainMatcher::from_succinct(&leaves, &bitmap, &labels[1..]).is_err());
        let empty = succinct(&[""]);
        assert!(DomainMatcher::from_succinct(&empty.0, &empty.1, &empty.2).is_ok());
    }
}
