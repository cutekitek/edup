//! Turns `routing` rules into system routes for the tunnels' address family:
//! static routes for addresses, host routes for DNS answers of matched names.
//! `from` rules form the client table of XDP mode instead.
use crate::{
    config::{Action, Settings, Target},
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
    /// Server addresses by index; they always keep the physical route.
    pub servers: Vec<IpAddr>,
}
impl Rules {
    pub fn family(&self) -> Family {
        Family::of(self.servers[0])
    }
    pub fn uses_dns(&self) -> bool {
        self.rules.iter().any(|r| !r.domains.is_empty())
    }
    pub fn domain_count(&self) -> usize {
        self.rules.iter().map(|r| r.domains.len()).sum()
    }
    pub fn plan(&self) -> Plan {
        plan(&self.servers, self.default, &self.rules)
    }
    /// The host route `ip` needs as an answer for the normalized `name`, if the
    /// static routes do not already send it the same way. As in sing-box, the
    /// first rule matching either the name or the address decides.
    pub fn host_action(&self, name: &str, ip: IpAddr) -> Option<Action> {
        if Family::of(ip) != self.family() || self.servers.contains(&ip) {
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

/// Routes to install. Destinations outside every tunnel's prefixes keep the
/// system's own routes, except `bypass`, which overrides a broader tunnel route.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Prefixes routed into each server's tunnel, by server index.
    pub tunnel: Vec<Vec<Prefix>>,
    pub bypass: Vec<Prefix>,
    /// Servers inside a tunnel route, by index: pin each address to its
    /// physical route. One index per address.
    pub exceptions: Vec<usize>,
}
impl Plan {
    pub fn tunnel_routes(&self) -> usize {
        self.tunnel.iter().map(Vec::len).sum()
    }
}

/// The configured rules, in order. Rule-sets are downloaded here.
pub fn resolve(cfg: &Settings) -> Result<Rules> {
    let servers = cfg.server_ips();
    let family = Family::of(servers[0]);
    let mut loaded: HashMap<&str, (IpSet, DomainMatcher)> = HashMap::new();
    let mut rules = Vec::new();
    for (i, rule) in cfg.routing.routes.iter().enumerate() {
        if rule.is_client() {
            continue;
        }
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
            action: rule.action(),
        });
    }
    // Ahead of every rule; the forwarder runs only for domain rules.
    if let Some(server) = cfg.dns.proxy
        && rules.iter().any(|r| !r.domains.is_empty())
    {
        let ip = IpSet::from_ranges(
            cfg.dns_servers()
                .iter()
                .map(|s| s.ip())
                .filter(|&ip| Family::of(ip) == family && public(ip))
                .map(|ip| Prefix::host(ip).range())
                .collect(),
        );
        rules.insert(
            0,
            Rule {
                ip,
                domains: DomainMatcher::default(),
                action: Action::Server(server),
            },
        );
    }
    Ok(Rules {
        rules,
        default: cfg.routing.default_route,
        servers,
    })
}

/// Not a private, loopback or link-local address: a resolver on the local
/// network stays reachable only directly.
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let shared = ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64;
            !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || shared)
        }
        IpAddr::V6(ip) => {
            let segment = ip.segments()[0];
            !(ip.is_loopback() || segment & 0xfe00 == 0xfc00 || segment & 0xffc0 == 0xfe80)
        }
    }
}

/// The `from` rules of the tunnels' family flattened into disjoint source
/// sets, first match first. Sources in none of them follow the destination
/// rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Clients {
    pub direct: IpSet,
    /// Sources sent through each server, by index.
    pub servers: Vec<IpSet>,
    /// Every source any `from` rule names, whatever its target.
    pub listed: IpSet,
}
#[cfg_attr(not(all(target_os = "linux", feature = "xdp")), allow(dead_code))]
impl Clients {
    pub fn is_empty(&self) -> bool {
        self.listed.is_empty()
    }
    /// The target the client table gives `ip`.
    pub fn target(&self, ip: IpAddr) -> Target {
        let address = key(ip);
        if let Some(i) = self.servers.iter().position(|s| s.contains(address)) {
            Target::Server(i)
        } else if self.direct.contains(address) {
            Target::Direct
        } else {
            Target::Rules
        }
    }
    /// Disjoint prefixes with their target; `rules` sources have none.
    pub fn entries(&self, family: Family) -> Vec<(Prefix, Target)> {
        let mut out: Vec<_> = self
            .direct
            .prefixes(family)
            .into_iter()
            .map(|p| (p, Target::Direct))
            .collect();
        for (i, set) in self.servers.iter().enumerate() {
            out.extend(
                set.prefixes(family)
                    .into_iter()
                    .map(|p| (p, Target::Server(i))),
            );
        }
        out
    }
}

pub fn clients(cfg: &Settings) -> Clients {
    let family = Family::of(cfg.servers[0].address.ip());
    let mut remaining = IpSet::full(family);
    let mut clients = Clients {
        servers: vec![IpSet::default(); cfg.servers.len()],
        ..Clients::default()
    };
    for rule in cfg.routing.routes.iter().filter(|r| r.is_client()) {
        let set = IpSet::from_ranges(
            rule.from
                .iter()
                .filter(|p| p.family() == family)
                .map(Prefix::range)
                .collect(),
        );
        let matched = set.intersection(&remaining);
        match rule.to {
            Target::Server(i) => clients.servers[i] = clients.servers[i].union(&matched),
            Target::Direct => clients.direct = clients.direct.union(&matched),
            Target::Rules => {}
        }
        remaining = remaining.difference(&set, family);
        clients.listed = clients.listed.union(&set);
    }
    clients
}

pub fn plan(servers: &[IpAddr], default: Action, rules: &[Rule]) -> Plan {
    let family = Family::of(servers[0]);
    let mut remaining = IpSet::full(family);
    let mut sets = vec![IpSet::default(); servers.len()];
    for rule in rules {
        if let Action::Server(i) = rule.action {
            sets[i] = sets[i].union(&rule.ip.intersection(&remaining));
        }
        remaining = remaining.difference(&rule.ip, family);
    }
    if let Action::Server(i) = default {
        sets[i] = sets[i].union(&remaining);
    }
    // Server addresses never enter a tunnel.
    let excluded = IpSet::from_ranges(servers.iter().map(|&s| (key(s), key(s))).collect());
    let mut proxied = IpSet::default();
    for set in &mut sets {
        *set = set.difference(&excluded, family);
        proxied = proxied.union(set);
    }

    // Per address-space half, either route each server's prefixes into its
    // tunnel, or route the whole /1 into one tunnel and carve out the rest via
    // the physical gateway and the other tunnels, whichever needs the fewest
    // routes. A /1 never replaces a default route.
    let mut plan = Plan {
        tunnel: vec![Vec::new(); servers.len()],
        ..Plan::default()
    };
    let half = 1u128 << (family.bits() - 1);
    for (from, to) in [(0, half - 1), (half, family.max())] {
        let space = IpSet::range(from, to);
        let prefixes: Vec<Vec<Prefix>> = sets
            .iter()
            .map(|s| s.intersection(&space).prefixes(family))
            .collect();
        if prefixes.iter().all(Vec::is_empty) {
            continue;
        }
        let rest = space
            .difference(&proxied, family)
            .difference(&excluded, family)
            .prefixes(family);
        // The tunnel taking the /1 saves its own prefixes and costs the /1
        // and the carved direct routes.
        let base = (0..servers.len())
            .filter(|&i| rest.len() + 1 < prefixes[i].len())
            .max_by_key(|&i| prefixes[i].len());
        for (i, list) in prefixes.into_iter().enumerate() {
            if Some(i) == base {
                plan.tunnel[i].push(Prefix::new(family.addr(from), 1));
            } else {
                plan.tunnel[i].extend(list);
            }
        }
        if base.is_some() {
            plan.bypass.extend(rest);
            for (i, &server) in servers.iter().enumerate() {
                if space.contains(key(server)) && !servers[..i].contains(&server) {
                    plan.exceptions.push(i);
                }
            }
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
    const PROXY: Action = Action::Server(0);
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
        super::plan(&[server], default, &rules(list))
    }
    fn single(prefixes: &[&str]) -> Vec<Vec<Prefix>> {
        vec![prefixes.iter().map(|p| p.parse().unwrap()).collect()]
    }

    #[test]
    fn default_proxy_keeps_split_default_routes() {
        let plan = plan_of(server(), PROXY, &[]);
        assert_eq!(plan.tunnel, single(&["0.0.0.0/1", "128.0.0.0/1"]));
        assert!(plan.bypass.is_empty());
        assert_eq!(plan.exceptions, [0]);
        let plan = plan_of("2001:db8::1".parse().unwrap(), PROXY, &[]);
        assert_eq!(plan.tunnel, single(&["::/1", "8000::/1"]));
        assert!(plan.bypass.is_empty());
        assert_eq!(plan.exceptions, [0]);
    }

    #[test]
    fn manual_routing_changes_nothing() {
        let empty = Plan {
            tunnel: vec![Vec::new()],
            ..Plan::default()
        };
        assert_eq!(plan_of(server(), Action::Direct, &[]), empty);
        // Rules for the other family never produce routes.
        let rules = [(IpSet::default(), PROXY)];
        assert_eq!(plan_of(server(), Action::Direct, &rules), empty);
    }

    #[test]
    fn first_matching_rule_wins() {
        let rules = [
            (set(&["10.1.0.0/16"]), Action::Direct),
            (set(&["10.0.0.0/8", "192.0.2.0/24"]), PROXY),
            (set(&["10.2.0.0/16"]), Action::Direct),
        ];
        let plan = plan_of(server(), Action::Direct, &rules);
        assert!(plan.bypass.is_empty() && plan.exceptions.is_empty());
        let tunnel = IpSet::from_ranges(plan.tunnel[0].iter().map(Prefix::range).collect());
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
            (set(&["10.0.0.0/8", "192.168.0.0/16"]), Action::Direct),
            (set(&["198.51.100.0/24"]), Action::Direct),
        ];
        let plan = plan_of(server(), PROXY, &rules);
        assert_eq!(plan.tunnel, single(&["0.0.0.0/1", "128.0.0.0/1"]));
        assert_eq!(
            text(&plan.bypass),
            ["10.0.0.0/8", "192.168.0.0/16", "198.51.100.0/24"]
        );
        assert_eq!(plan.exceptions, [0]);
        // A bypassed server needs no separate exception.
        let rules = [(set(&["128.0.0.0/1"]), Action::Direct)];
        let plan = plan_of(server(), PROXY, &rules);
        assert_eq!(plan.tunnel, single(&["0.0.0.0/1"]));
        assert!(plan.bypass.is_empty() && plan.exceptions.is_empty());
    }

    /// The server whose routes in `plan` send `ip` into its tunnel, the
    /// longest prefix winning; None for the physical network.
    fn routed(plan: &Plan, ip: &str) -> Option<usize> {
        let address = key(ip.parse().unwrap());
        let longest = |prefixes: &[Prefix]| {
            prefixes
                .iter()
                .filter(|p| (p.range().0..=p.range().1).contains(&address))
                .map(|p| p.len)
                .max()
        };
        let (server, len) = (0..plan.tunnel.len())
            .filter_map(|i| Some((i, longest(&plan.tunnel[i])?)))
            .max_by_key(|&(_, len)| len)?;
        (longest(&plan.bypass) < Some(len)).then_some(server)
    }

    #[test]
    fn servers_share_the_address_space() {
        let servers: [IpAddr; 3] = [
            "192.0.2.1".parse().unwrap(),
            "198.51.100.1".parse().unwrap(),
            "203.0.113.1".parse().unwrap(),
        ];
        // Per half, the server with the most prefixes takes the /1; the others
        // get their prefixes, more specific than the /1 routes.
        let list = rules(&[
            (set(&["10.0.0.0/8"]), Action::Direct),
            (set(&["8.8.8.0/24", "9.9.9.9/32"]), Action::Server(2)),
            (set(&["8.0.0.0/7"]), Action::Server(1)),
        ]);
        let plan = super::plan(&servers, Action::Server(0), &list);
        assert_eq!(text(&plan.tunnel[1]), ["0.0.0.0/1"]);
        assert!(text(&plan.tunnel[0]).contains(&"128.0.0.0/1".to_string()));
        assert_eq!(text(&plan.tunnel[2]), ["8.8.8.0/24", "9.9.9.9/32"]);
        assert_eq!(text(&plan.bypass), ["10.0.0.0/8"]);
        // Every server address keeps its physical route.
        assert_eq!(plan.exceptions, [0, 1, 2]);
        for (ip, expected) in [
            ("8.8.8.8", Some(2)),
            ("9.9.9.9", Some(2)),
            ("9.9.9.8", Some(1)),
            ("8.1.1.1", Some(1)),
            ("10.1.1.1", None),
            ("1.1.1.1", Some(0)),
            ("200.1.1.1", Some(0)),
        ] {
            assert_eq!(routed(&plan, ip), expected, "{ip}");
        }
        // Direct by default: the second server's many prefixes still make a
        // /1 with carved direct routes cheaper; no server lies inside it.
        let plan = super::plan(&servers, Action::Direct, &list);
        assert!(plan.tunnel[0].is_empty());
        assert_eq!(text(&plan.tunnel[1]), ["0.0.0.0/1"]);
        assert_eq!(text(&plan.tunnel[2]), ["8.8.8.0/24", "9.9.9.9/32"]);
        assert!(plan.exceptions.is_empty());
        for (ip, expected) in [
            ("1.1.1.1", None),
            ("10.1.1.1", None),
            ("200.1.1.1", None),
            ("8.1.1.1", Some(1)),
            ("8.8.8.8", Some(2)),
        ] {
            assert_eq!(routed(&plan, ip), expected, "{ip}");
        }
        // A second server's address is never tunnelled through the first.
        let plan = super::plan(
            &servers,
            Action::Direct,
            &rules(&[(set(&["198.51.100.0/24"]), Action::Server(0))]),
        );
        assert_eq!(routed(&plan, "198.51.100.1"), None);
        assert_eq!(routed(&plan, "198.51.100.2"), Some(0));
        // A /1 for the second server when it routes most of a half.
        let plan = super::plan(
            &servers,
            Action::Server(0),
            &rules(&[(set(&["128.0.0.0/2", "192.0.0.0/3"]), Action::Server(1))]),
        );
        assert_eq!(text(&plan.tunnel[1]), ["128.0.0.0/1"]);
        assert_eq!(text(&plan.tunnel[0]), ["0.0.0.0/1", "224.0.0.0/3"]);
        assert_eq!(routed(&plan, "230.1.1.1"), Some(0));
        assert_eq!(routed(&plan, "130.1.1.1"), Some(1));
        assert_eq!(plan.exceptions, [0, 1, 2]);
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
        let mut list = rules(&[(set(&["198.51.100.0/24"]), PROXY)]);
        list.push(named("ru", Action::Direct));
        list.push(named("proxied.ru", PROXY));
        list.push(named("other.com", Action::Server(1)));
        list.extend(rules(&[(set(&["192.168.0.0/16"]), Action::Direct)]));
        let rules = Rules {
            rules: list,
            default: PROXY,
            servers: vec![server(), "192.0.2.9".parse().unwrap()],
        };
        assert!(rules.uses_dns());
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for (name, address, expected) in [
            ("a.ru", "203.0.113.5", Some(Action::Direct)),
            ("proxied.ru", "203.0.113.5", Some(Action::Direct)),
            ("a.other.com", "203.0.113.5", Some(Action::Server(1))),
            ("a.ru", "198.51.100.7", None),
            ("a.ru", "192.168.1.1", None),
            ("example.com", "203.0.113.5", None),
            ("a.ru", "192.0.2.1", None),
            ("a.other.com", "192.0.2.9", None),
            ("a.ru", "2001:db8::1", None),
        ] {
            assert_eq!(
                rules.host_action(name, ip(address)),
                expected,
                "{name} {address}"
            );
        }
        let rules = Rules {
            rules: vec![named("x.com", PROXY)],
            default: Action::Direct,
            servers: vec![server()],
        };
        assert_eq!(rules.host_action("x.com", ip("1.2.3.4")), Some(PROXY));
        assert_eq!(rules.plan(), plan_of(server(), Action::Direct, &[]));
    }

    #[test]
    fn client_rules_flatten_first_match_first() {
        let cfg: Settings = edup_common::json::parse(
            r#"{"mode": "xdp", "servers": [
                {"tag": "a", "server": "192.0.2.1:7777", "user": 1, "password": "test"},
                {"tag": "b", "server": "192.0.2.2:7777", "user": 1, "password": "test"}],
            "routing": {"routes": [
                {"from": "192.168.1.50", "to": "direct"},
                {"from": ["192.168.1.60", "192.168.1.61"], "to": "a"},
                {"from": "192.168.1.62", "to": "b"},
                {"from": ["192.168.1.70", "2001:db8::/64"], "to": "rules"},
                {"from": "192.168.1.0/24", "to": "direct"},
                {"from": "192.168.1.0/25", "to": "a"},
                {"ip": "10.0.0.0/8", "to": "direct"}
            ]}}"#,
        )
        .unwrap();
        let clients = clients(&cfg);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for (address, target) in [
            ("192.168.1.50", Target::Direct),
            ("192.168.1.60", Target::Server(0)),
            ("192.168.1.61", Target::Server(0)),
            ("192.168.1.62", Target::Server(1)),
            ("192.168.1.70", Target::Rules),
            ("192.168.1.10", Target::Direct),
            ("192.168.1.200", Target::Direct),
            ("192.168.2.1", Target::Rules),
            ("192.0.2.1", Target::Rules),
        ] {
            assert_eq!(clients.target(ip(address)), target, "{address}");
        }
        assert_eq!(
            text(&clients.servers[0].prefixes(Family::V4)),
            ["192.168.1.60/31"]
        );
        assert!(clients.listed.contains(key(ip("192.168.1.70"))));
        let entries = clients.entries(Family::V4);
        assert!(entries.contains(&("192.168.1.62/32".parse().unwrap(), Target::Server(1))));
        assert!(entries.iter().all(|(p, _)| p.family() == Family::V4));
        assert!(
            !entries
                .iter()
                .any(|(p, _)| p.range().0 <= key(ip("192.168.1.70"))
                    && key(ip("192.168.1.70")) <= p.range().1)
        );
        // Destination rules ignore the client table.
        let rules = resolve(&cfg).unwrap();
        assert_eq!(rules.rules.len(), 1);
        assert_eq!(rules.address_action(ip("10.1.1.1")), Action::Direct);
        assert!(super::clients(&parse_default()).is_empty());
    }
    fn parse_default() -> Settings {
        edup_common::json::parse(r#"{"server": "192.0.2.1:7777", "user": 1, "password": "test"}"#)
            .unwrap()
    }

    #[test]
    fn address_action_follows_the_first_matching_rule() {
        let rules = Rules {
            rules: rules(&[
                (set(&["10.1.0.0/16"]), Action::Direct),
                (set(&["10.0.0.0/8"]), PROXY),
            ]),
            default: Action::Direct,
            servers: vec![server()],
        };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(rules.address_action(ip("10.1.2.3")), Action::Direct);
        assert_eq!(rules.address_action(ip("10.2.0.1")), PROXY);
        assert_eq!(rules.address_action(ip("11.0.0.1")), Action::Direct);
    }

    #[test]
    fn dns_proxy_sends_public_resolvers_through_the_tunnel() {
        let settings = |dns: &str, routes: &str| -> Settings {
            edup_common::json::parse(&format!(
                r#"{{"servers": [
                    {{"tag": "a", "server": "192.0.2.1:7777", "user": 1, "password": "test"}},
                    {{"tag": "b", "server": "192.0.2.2:7777", "user": 1, "password": "test"}}],
                "routing": {{"default_route": "direct", "routes": [{routes}]}}, "dns": {dns}}}"#
            ))
            .unwrap()
        };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let routes =
            r#"{"ip": "0.0.0.0/0", "to": "direct"}, {"domain_suffix": ".ru", "to": "direct"}"#;
        let servers = r#""servers": ["9.9.9.9", "192.168.1.10", "100.64.0.53", "2620:fe::fe"]"#;
        let rules = resolve(&settings(
            &format!("{{{servers}, \"proxy\": \"b\"}}"),
            routes,
        ))
        .unwrap();
        assert_eq!(rules.address_action(ip("9.9.9.9")), Action::Server(1));
        // Local resolvers stay direct, as does everything else.
        for address in ["192.168.1.10", "100.64.0.53", "8.8.8.8"] {
            assert_eq!(
                rules.address_action(ip(address)),
                Action::Direct,
                "{address}"
            );
        }
        // Default upstreams; true picks the first server for a direct default.
        let rules = resolve(&settings(r#"{"proxy": true}"#, routes)).unwrap();
        assert_eq!(rules.address_action(ip("1.1.1.1")), Action::Server(0));
        assert_eq!(rules.address_action(ip("8.8.8.8")), Action::Server(0));
        // Off, or without domain rules (no forwarder): the rules decide.
        for (dns, routes) in [
            (format!("{{{servers}}}"), routes),
            (
                format!("{{{servers}, \"proxy\": \"a\"}}"),
                r#"{"ip": "9.0.0.0/8", "to": "direct"}"#,
            ),
        ] {
            let rules = resolve(&settings(&dns, routes)).unwrap();
            assert_eq!(rules.address_action(ip("9.9.9.9")), Action::Direct, "{dns}");
        }
    }
}
