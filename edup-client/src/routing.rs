//! Turns `routing` rules into system routes for the tunnel's address family:
//! static routes for addresses, host routes for DNS answers of matched names.
use crate::{
    config::{Action, Settings},
    domain::DomainMatcher,
    ipset::{Family, IpSet, Prefix, key},
    ruleset,
};
use anyhow::{Context, Result};
use std::{collections::HashMap, net::IpAddr};

pub struct Rule {
    pub ip: IpSet,
    pub domains: DomainMatcher,
    pub action: Action,
}

pub struct Rules {
    pub rules: Vec<Rule>,
    pub default: Action,
    pub server: IpAddr,
}
impl Rules {
    pub fn uses_dns(&self) -> bool {
        self.rules.iter().any(|r| !r.domains.is_empty())
    }
    pub fn domain_count(&self) -> usize {
        self.rules.iter().map(|r| r.domains.len()).sum()
    }
    pub fn plan(&self) -> Plan {
        plan(self.server, self.default, &self.rules)
    }
    /// The host route `ip` needs as an answer for the normalized `name`, if the
    /// static routes do not already send it the same way. As in sing-box, the
    /// first rule matching either the name or the address decides.
    pub fn host_action(&self, name: &str, ip: IpAddr) -> Option<Action> {
        if Family::of(ip) != Family::of(self.server) || ip == self.server {
            return None;
        }
        let address = key(ip);
        let by_address = |r: &Rule| r.ip.contains(address);
        let first = self
            .rules
            .iter()
            .find(|r| by_address(r) || r.domains.matches(name))?;
        if by_address(first) {
            return None;
        }
        (first.action != self.address_action(ip)).then_some(first.action)
    }
    /// The route the address rules alone give `ip`: the first rule containing
    /// it, otherwise the default.
    pub fn address_action(&self, ip: IpAddr) -> Action {
        let address = key(ip);
        self.rules
            .iter()
            .find(|r| r.ip.contains(address))
            .map_or(self.default, |r| r.action)
    }
}

/// Routes to install. Destinations outside `tunnel` keep the system's own
/// routes, except `bypass`, which overrides a broader tunnel route.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub tunnel: Vec<Prefix>,
    pub bypass: Vec<Prefix>,
    /// A tunnel route covers the server: pin it to the physical route.
    pub server_exception: bool,
}

/// The configured rules, in order. Rule-sets are downloaded here.
pub fn resolve(cfg: &Settings) -> Result<Rules> {
    let family = Family::of(cfg.server.ip());
    let mut loaded: HashMap<&str, (IpSet, DomainMatcher)> = HashMap::new();
    let mut rules = Vec::new();
    for (i, rule) in cfg.routing.routes.iter().enumerate() {
        let mut set = IpSet::from_ranges(
            rule.ip
                .iter()
                .filter(|p| p.family() == family)
                .map(Prefix::range)
                .collect(),
        );
        let mut domains = rule
            .domains()
            .with_context(|| format!("routing.routes[{i}]"))?;
        for source in &rule.rules {
            if !loaded.contains_key(source.as_str()) {
                let rules = ruleset::load(source, &cfg.base)?;
                if rules.ignored != 0 {
                    eprintln!(
                        "rule-set {source}: ignoring {} of {} rules with port, network, process or other conditions",
                        rules.ignored, rules.rules
                    );
                }
                loaded.insert(source, (rules.set(family).clone(), rules.domains));
            }
            let (ip, names) = &loaded[source.as_str()];
            set = set.union(ip);
            domains.extend(names);
        }
        rules.push(Rule {
            ip: set,
            domains,
            action: rule.to,
        });
    }
    Ok(Rules {
        rules,
        default: cfg.routing.default_route,
        server: cfg.server.ip(),
    })
}

pub fn plan(server: IpAddr, default: Action, rules: &[Rule]) -> Plan {
    let family = Family::of(server);
    let mut remaining = IpSet::full(family);
    let mut proxy = IpSet::default();
    for rule in rules {
        if rule.action == Action::Proxy {
            proxy = proxy.union(&rule.ip.intersection(&remaining));
        }
        remaining = remaining.difference(&rule.ip, family);
    }
    if default == Action::Proxy {
        proxy = proxy.union(&remaining);
    }
    let address = key(server);
    let server = IpSet::range(address, address);
    let proxy = proxy.difference(&server, family);

    // Per address-space half, either route the proxied prefixes into the tunnel,
    // or route the whole /1 there and carve out the rest via the physical
    // gateway, whichever needs fewer routes. A /1 never replaces a default route.
    let mut plan = Plan::default();
    let half = 1u128 << (family.bits() - 1);
    for (from, to) in [(0, half - 1), (half, family.max())] {
        let space = IpSet::range(from, to);
        let proxied = proxy.intersection(&space);
        if proxied.is_empty() {
            continue;
        }
        let direct = proxied.prefixes(family);
        let rest = space.difference(&proxy, family).difference(&server, family);
        let carved = rest.prefixes(family);
        if direct.len() <= carved.len() + 1 {
            plan.tunnel.extend(direct);
        } else {
            plan.tunnel.push(Prefix::new(family.addr(from), 1));
            plan.bypass.extend(carved);
            plan.server_exception |= space.contains(address);
        }
    }
    plan
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
    fn text(prefixes: &[Prefix]) -> Vec<String> {
        prefixes.iter().map(Prefix::to_string).collect()
    }
    fn server() -> IpAddr {
        "192.0.2.1".parse().unwrap()
    }
    fn rules(rules: &[(IpSet, Action)]) -> Vec<Rule> {
        rules
            .iter()
            .map(|(ip, action)| Rule {
                ip: ip.clone(),
                domains: DomainMatcher::default(),
                action: *action,
            })
            .collect()
    }
    fn plan_of(server: IpAddr, default: Action, list: &[(IpSet, Action)]) -> Plan {
        super::plan(server, default, &rules(list))
    }

    #[test]
    fn default_proxy_keeps_split_default_routes() {
        let plan = plan_of(server(), Action::Proxy, &[]);
        assert_eq!(text(&plan.tunnel), ["0.0.0.0/1", "128.0.0.0/1"]);
        assert!(plan.bypass.is_empty() && plan.server_exception);
        let plan = plan_of(
            "[2001:db8::1]:1"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .ip(),
            Action::Proxy,
            &[],
        );
        assert_eq!(text(&plan.tunnel), ["::/1", "8000::/1"]);
        assert!(plan.bypass.is_empty() && plan.server_exception);
    }

    #[test]
    fn manual_routing_changes_nothing() {
        assert_eq!(plan_of(server(), Action::Bypass, &[]), Plan::default());
        // Rules for the other family never produce routes.
        let rules = [(IpSet::default(), Action::Proxy)];
        assert_eq!(plan_of(server(), Action::Bypass, &rules), Plan::default());
    }

    #[test]
    fn first_matching_rule_wins() {
        let rules = [
            (set(&["10.1.0.0/16"]), Action::Bypass),
            (set(&["10.0.0.0/8", "192.0.2.0/24"]), Action::Proxy),
            (set(&["10.2.0.0/16"]), Action::Bypass),
        ];
        let plan = plan_of(server(), Action::Bypass, &rules);
        assert!(plan.bypass.is_empty() && !plan.server_exception);
        let tunnel = IpSet::from_ranges(plan.tunnel.iter().map(Prefix::range).collect());
        for (ip, proxied) in [
            ("10.0.0.1", true),
            ("10.1.2.3", false),
            ("10.2.0.1", true),
            ("192.0.2.1", false),
            ("192.0.2.2", true),
            ("11.0.0.1", false),
        ] {
            assert_eq!(tunnel.contains(key(ip.parse().unwrap())), proxied, "{ip}");
        }
    }

    #[test]
    fn bypass_rules_carve_tunnel_routes() {
        let rules = [
            (set(&["10.0.0.0/8", "192.168.0.0/16"]), Action::Bypass),
            (set(&["198.51.100.0/24"]), Action::Bypass),
        ];
        let plan = plan_of(server(), Action::Proxy, &rules);
        assert_eq!(text(&plan.tunnel), ["0.0.0.0/1", "128.0.0.0/1"]);
        assert_eq!(
            text(&plan.bypass),
            ["10.0.0.0/8", "192.168.0.0/16", "198.51.100.0/24"]
        );
        assert!(plan.server_exception);
        // A bypassed server needs no separate exception.
        let rules = [(set(&["128.0.0.0/1"]), Action::Bypass)];
        let plan = plan_of(server(), Action::Proxy, &rules);
        assert_eq!(text(&plan.tunnel), ["0.0.0.0/1"]);
        assert!(plan.bypass.is_empty() && !plan.server_exception);
    }

    #[test]
    fn dns_answers_follow_the_first_matching_rule() {
        let named = |suffix: &str, action| {
            let mut domains = DomainMatcher::default();
            domains.add_suffix(suffix).unwrap();
            Rule {
                ip: IpSet::default(),
                domains,
                action,
            }
        };
        let mut list = rules(&[(set(&["198.51.100.0/24"]), Action::Proxy)]);
        list.push(named("ru", Action::Bypass));
        list.push(named("proxied.ru", Action::Proxy));
        list.extend(rules(&[(set(&["192.168.0.0/16"]), Action::Bypass)]));
        let rules = Rules {
            rules: list,
            default: Action::Proxy,
            server: server(),
        };
        assert!(rules.uses_dns());
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for (name, address, expected) in [
            ("a.ru", "203.0.113.5", Some(Action::Bypass)),
            ("proxied.ru", "203.0.113.5", Some(Action::Bypass)),
            ("a.ru", "198.51.100.7", None),
            ("a.ru", "192.168.1.1", None),
            ("example.com", "203.0.113.5", None),
            ("a.ru", "192.0.2.1", None),
            ("a.ru", "2001:db8::1", None),
        ] {
            assert_eq!(
                rules.host_action(name, ip(address)),
                expected,
                "{name} {address}"
            );
        }
        let rules = Rules {
            rules: vec![named("x.com", Action::Proxy)],
            default: Action::Bypass,
            server: server(),
        };
        assert_eq!(
            rules.host_action("x.com", ip("1.2.3.4")),
            Some(Action::Proxy)
        );
        assert_eq!(rules.plan(), Plan::default());
    }

    #[test]
    fn address_action_follows_the_first_matching_rule() {
        let rules = Rules {
            rules: rules(&[
                (set(&["10.1.0.0/16"]), Action::Bypass),
                (set(&["10.0.0.0/8"]), Action::Proxy),
            ]),
            default: Action::Bypass,
            server: server(),
        };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(rules.address_action(ip("10.1.2.3")), Action::Bypass);
        assert_eq!(rules.address_action(ip("10.2.0.1")), Action::Proxy);
        assert_eq!(rules.address_action(ip("11.0.0.1")), Action::Bypass);
    }
}
