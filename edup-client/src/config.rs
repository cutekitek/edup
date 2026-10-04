use crate::{domain::DomainMatcher, ipset::Prefix};
use anyhow::{Context, Result, ensure};
use edup_common::wire;
use serde::{Deserialize, Deserializer, de};
use std::{
    fmt,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Datapath: `tun` (default) or, on Linux, `xdp`.
    #[serde(default)]
    pub mode: Mode,
    /// How XDP attaches to the physical interface in `xdp` mode.
    #[serde(default)]
    #[cfg_attr(not(all(target_os = "linux", feature = "xdp")), allow(dead_code))]
    pub xdp_mode: XdpMode,
    pub server: SocketAddr,
    pub user: i64,
    pub password: String,
    #[serde(default = "tunnel_ip")]
    pub tunnel_ip: Ipv4Addr,
    #[serde(default = "tunnel_ip6")]
    pub tunnel_ip6: Ipv6Addr,
    #[serde(default = "interface")]
    pub interface: String,
    #[serde(default = "mtu")]
    pub mtu: u16,
    #[serde(default = "keepalive")]
    pub keepalive_secs: u64,
    /// Opportunistic UDP segmentation/coalescing (GSO/GRO or USO/URO).
    #[serde(default = "offload")]
    pub offload: bool,
    /// Windows: absolute DLL path. Default is beside the executable, never CWD.
    pub wintun_dll: Option<PathBuf>,
    #[serde(default)]
    pub routing: Routing,
    /// DNS forwarder, active only when routing uses domain rules.
    #[serde(default)]
    pub dns: Dns,
    /// Directory of the configuration file: base for rule-set paths and cache.
    #[serde(skip)]
    pub base: PathBuf,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Routes send traffic into the TUN device; userspace encapsulates it.
    #[default]
    Tun,
    /// eBPF on the physical interface encapsulates traffic and decides routes
    /// per destination, asking userspace about new ones.
    Xdp,
}

/// Native XDP when the driver supports it, otherwise generic (skb) XDP.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    #[default]
    Auto,
    Driver,
    Skb,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    /// Destination for addresses no rule matches.
    #[serde(default)]
    pub default_route: Action,
    /// Ordered rules; the first rule containing an address decides its route.
    #[serde(default)]
    pub routes: Vec<RouteRule>,
}
impl Routing {
    /// No system routes are changed; the user routes traffic into the TUN.
    pub fn is_manual(&self) -> bool {
        self.default_route == Action::Bypass && self.routes.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Proxy,
    Bypass,
}
impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::Bypass => "bypass",
        }
    }
}

/// Where a rule sends what it matches; `rules` only on `from` rules.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    Proxy,
    Bypass,
    /// The destination rules decide.
    Rules,
}
impl Target {
    pub fn action(self) -> Option<Action> {
        match self {
            Self::Proxy => Some(Action::Proxy),
            Self::Bypass => Some(Action::Bypass),
            Self::Rules => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    /// Source prefixes (xdp mode): clients whose traffic `to` decides,
    /// whatever its destination.
    #[serde(default, deserialize_with = "one_or_many")]
    pub from: Vec<Prefix>,
    /// CIDR prefixes or single addresses.
    #[serde(default, deserialize_with = "one_or_many")]
    pub ip: Vec<Prefix>,
    /// sing-box binary rule-sets: http(s) URLs or paths relative to the config.
    #[serde(default, deserialize_with = "one_or_many")]
    pub rules: Vec<String>,
    /// Exact names.
    #[serde(default, deserialize_with = "one_or_many")]
    pub domain: Vec<String>,
    /// `".ru"`: subdomains of ru; `"ru"`: ru itself too.
    #[serde(default, deserialize_with = "one_or_many")]
    pub domain_suffix: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    pub domain_keyword: Vec<String>,
    pub to: Target,
}
impl RouteRule {
    pub fn is_client(&self) -> bool {
        !self.from.is_empty()
    }
    /// The action of a destination rule.
    pub fn action(&self) -> Action {
        self.to.action().unwrap_or(Action::Proxy)
    }
    pub fn domains(&self) -> Result<DomainMatcher> {
        let mut matcher = DomainMatcher::default();
        self.domain.iter().try_for_each(|d| matcher.add_domain(d))?;
        self.domain_suffix
            .iter()
            .try_for_each(|d| matcher.add_suffix(d))?;
        self.domain_keyword
            .iter()
            .try_for_each(|d| matcher.add_keyword(d))?;
        Ok(matcher)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    /// Upstream resolvers, `"1.1.1.1"` or `"1.1.1.1:53"`; routed like any traffic.
    #[serde(default, deserialize_with = "one_or_many")]
    pub servers: Vec<Upstream>,
    /// Point the system resolver at the forwarder through the TUN interface.
    #[serde(default = "set_system")]
    pub set_system: bool,
    /// Send the forwarder's queries to public `servers` through the tunnel,
    /// whatever the routing rules say about their addresses.
    #[serde(default)]
    pub proxy: bool,
    /// Forwarder port on the tunnel address. Another one avoids a resolver
    /// that binds port 53 on every address, as OpenWrt's dnsmasq does.
    #[serde(default = "dns_port")]
    pub port: u16,
}
impl Default for Dns {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            set_system: true,
            proxy: false,
            port: dns_port(),
        }
    }
}
fn dns_port() -> u16 {
    53
}
fn set_system() -> bool {
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Upstream(pub SocketAddr);
impl FromStr for Upstream {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        s.parse::<SocketAddr>()
            .or_else(|_| s.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
            .map(Self)
            .map_err(|_| format!("invalid DNS server {s:?}"))
    }
}

/// Accepts `"value"` or `["value", ...]`, keeping parse errors positioned.
fn one_or_many<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr<Err: fmt::Display>,
{
    struct Visitor<T>(PhantomData<T>);
    impl<'de, T: FromStr<Err: fmt::Display>> de::Visitor<'de> for Visitor<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a string or an array of strings")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<T>, E> {
            Ok(vec![v.parse().map_err(E::custom)?])
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut out = Vec::new();
            while let Some(v) = seq.next_element::<String>()? {
                out.push(v.parse().map_err(de::Error::custom)?);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_any(Visitor(PhantomData))
}

fn tunnel_ip() -> Ipv4Addr {
    Ipv4Addr::new(10, 66, 0, 1)
}
fn tunnel_ip6() -> Ipv6Addr {
    "fd66::1".parse().unwrap()
}
fn interface() -> String {
    "edup0".into()
}
fn mtu() -> u16 {
    1473
}
fn keepalive() -> u64 {
    15
}
fn offload() -> bool {
    true
}

impl Settings {
    pub fn load(path: &Path) -> Result<Self> {
        let input =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let mut cfg: Self = edup_common::json::parse(&input).map_err(|e| {
            let hint = if path.extension().is_some_and(|e| e == "toml") {
                " (configuration files are JSON now; see config/client.example.json)"
            } else {
                ""
            };
            anyhow::anyhow!("invalid configuration {}: {e}{hint}", path.display())
        })?;
        cfg.base = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf();
        cfg.validate()?;
        Ok(cfg)
    }
    pub fn address(&self) -> Result<Ipv4Addr> {
        ensure!(unicast(self.tunnel_ip), "tunnel_ip must be unicast IPv4");
        ensure!(
            self.server.ip() != IpAddr::V4(self.tunnel_ip),
            "server and tunnel_ip must differ"
        );
        Ok(self.tunnel_ip)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            match self.server.ip() {
                IpAddr::V4(ip) => unicast(ip),
                IpAddr::V6(ip) => edup_common::ipv6::unicast(ip.octets()),
            } && self.server.port() != 0,
            "server must be a global/ULA unicast address and nonzero port"
        );
        if let SocketAddr::V6(server) = self.server {
            ensure!(
                server.scope_id() == 0,
                "scoped server addresses are unsupported"
            );
        }
        if let Some(address) = self.address6()? {
            ensure!(self.mtu >= 1280, "IPv6 tunnel MTU must be at least 1280");
            ensure!(
                self.server.ip() != IpAddr::V6(address),
                "server and tunnel_ip6 must differ"
            );
        }
        ensure!(!self.password.is_empty(), "password must not be empty");
        ensure!(
            !self.interface.is_empty()
                && self.interface.len() < 16
                && self
                    .interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "invalid interface name (use 1..15 ASCII letters, digits, _ or -)"
        );
        let max_mtu = wire::MAX_KS_WORDS as usize * 8 - wire::CONTROL_LEN
            + if self.server.is_ipv6() {
                wire::IPV6_SAVING
            } else {
                wire::IPV4_SAVING
            };
        ensure!(
            (576..=max_mtu).contains(&(self.mtu as usize)),
            "MTU must be 576..{max_mtu}"
        );
        ensure!(
            (1..=60).contains(&self.keepalive_secs),
            "keepalive_secs must be 1..60"
        );
        if let Some(path) = &self.wintun_dll {
            ensure!(path.is_absolute(), "wintun_dll must be an absolute path");
        }
        if self.mode == Mode::Xdp {
            ensure!(
                cfg!(all(target_os = "linux", feature = "xdp")),
                "mode \"xdp\" needs Linux and a build with --features xdp"
            );
            // The segmentation veth pair is named after the TUN device.
            ensure!(
                self.interface.len() < 15,
                "interface names in xdp mode have at most 14 characters"
            );
            ensure!(
                !self.routing.is_manual(),
                "xdp mode routes by rules: set routing.routes or default_route \"proxy\""
            );
        }
        self.address()?;
        let mut destinations = false;
        for (i, rule) in self.routing.routes.iter().enumerate() {
            let domains = rule
                .domains()
                .with_context(|| format!("routing.routes[{i}]"))?;
            let destination = !rule.ip.is_empty() || !rule.rules.is_empty() || !domains.is_empty();
            if rule.is_client() {
                ensure!(
                    self.mode == Mode::Xdp,
                    "routing.routes[{i}]: \"from\" needs mode \"xdp\""
                );
                ensure!(
                    !destination,
                    "routing.routes[{i}]: \"from\" cannot be combined with \"ip\", \"rules\" or domain items"
                );
                ensure!(
                    !destinations,
                    "routing.routes[{i}]: \"from\" rules must precede destination rules"
                );
                continue;
            }
            destinations = true;
            ensure!(
                destination,
                "routing.routes[{i}] needs \"ip\", \"rules\", a domain item or \"from\""
            );
            ensure!(
                rule.to != Target::Rules,
                "routing.routes[{i}]: \"to\": \"rules\" needs \"from\""
            );
            for source in &rule.rules {
                ensure!(
                    crate::ruleset::is_url(source)
                        || !(source.is_empty() || source.contains("://")),
                    "routing.routes[{i}]: rules must be an http(s) URL or a file path"
                );
            }
        }
        ensure!(self.dns.port != 0, "dns.port must not be 0");
        for Upstream(server) in &self.dns.servers {
            ensure!(
                !server.ip().is_unspecified() && server.port() != 0,
                "invalid DNS server {server}"
            );
        }
        Ok(())
    }

    /// Upstream resolvers; public resolvers of the tunnel's family by default.
    pub fn dns_servers(&self) -> Vec<SocketAddr> {
        if !self.dns.servers.is_empty() {
            return self.dns.servers.iter().map(|u| u.0).collect();
        }
        let defaults: [IpAddr; 2] = if self.server.is_ipv6() {
            [
                "2606:4700:4700::1111".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
            ]
        } else {
            [
                Ipv4Addr::new(1, 1, 1, 1).into(),
                Ipv4Addr::new(8, 8, 8, 8).into(),
            ]
        };
        defaults.map(|ip| SocketAddr::new(ip, 53)).to_vec()
    }

    pub fn address6(&self) -> Result<Option<Ipv6Addr>> {
        if !self.server.is_ipv6() {
            return Ok(None);
        }
        ensure!(
            edup_common::ipv6::unicast(self.tunnel_ip6.octets()),
            "tunnel_ip6 must be global/ULA unicast"
        );
        Ok(Some(self.tunnel_ip6))
    }
}
fn unicast(ip: Ipv4Addr) -> bool {
    let first = ip.octets()[0];
    first != 0 && first != 127 && first < 224
}

#[cfg(test)]
mod tests {
    use super::*;
    const EXAMPLE: &str = include_str!("../../config/client.example.json");
    fn parse(text: &str) -> Result<Settings, String> {
        edup_common::json::parse(text)
    }
    fn cfg() -> Settings {
        parse(EXAMPLE).unwrap()
    }
    #[test]
    fn example_defaults_and_address() {
        let c = cfg();
        c.validate().unwrap();
        assert_eq!(c.address().unwrap(), Ipv4Addr::new(10, 66, 0, 7));
        assert_eq!(c.mtu, 1473);
        assert!(c.offload);
        let legacy = parse(&EXAMPLE.replace("\"offload\": true,", "")).unwrap();
        assert!(legacy.offload);
        let disabled = parse(&EXAMPLE.replace("\"offload\": true", "\"offload\": false")).unwrap();
        assert!(!disabled.offload);
        assert_eq!(c.routing.default_route, Action::Proxy);
        assert_eq!(c.routing.routes.len(), 1);
        assert_eq!(c.routing.routes[0].ip.len(), 3);
        assert_eq!(c.routing.routes[0].to, Target::Bypass);
        assert_eq!((c.mode, c.xdp_mode), (Mode::Tun, XdpMode::Auto));
    }
    #[test]
    fn xdp_mode() {
        let xdp = |extra: &str| parse(&EXAMPLE.replacen('{', &format!("{{{extra},"), 1));
        let c = xdp(r#""mode": "xdp", "xdp_mode": "skb""#).unwrap();
        assert_eq!((c.mode, c.xdp_mode), (Mode::Xdp, XdpMode::Skb));
        assert_eq!(
            c.validate().is_ok(),
            cfg!(all(target_os = "linux", feature = "xdp"))
        );
        assert!(xdp(r#""mode": "xdp", "xdp_mode": "native""#).is_err());
        assert!(xdp(r#""mode": "wireguard""#).is_err());
        let mut long = xdp(r#""mode": "xdp""#).unwrap();
        long.interface = "edup-interface0".into();
        assert!(long.validate().is_err());
        long.mode = Mode::Tun;
        long.validate().unwrap();
        let mut manual = xdp(r#""mode": "xdp""#).unwrap();
        manual.routing = Routing {
            default_route: Action::Bypass,
            routes: Vec::new(),
        };
        assert!(manual.validate().is_err());
    }
    #[test]
    fn addresses_are_local_and_independent_of_user_identity() {
        let mut c = cfg();
        c.tunnel_ip = "172.19.8.23".parse().unwrap();
        for id in [i64::MIN, 0, i64::MAX] {
            c.user = id;
            c.validate().unwrap();
            assert_eq!(c.address().unwrap().to_string(), "172.19.8.23");
        }
        let defaults =
            parse(r#"{"server": "192.0.2.1:7777", "user": 1, "password": "test"}"#).unwrap();
        assert_eq!(defaults.address().unwrap(), tunnel_ip());
        assert_eq!(defaults.routing.default_route, Action::Proxy);
        assert!(defaults.routing.routes.is_empty());
        // Former fields must fail instead of being silently ignored.
        for field in [
            r#""tunnel_id": 7"#,
            r#""tunnel_net": "10.66.0.0/16""#,
            r#""routes": false"#,
        ] {
            assert!(parse(&EXAMPLE.replacen('{', &format!("{{{field},"), 1)).is_err());
        }
    }
    #[test]
    fn routing_rules() {
        let c = parse(
            r#"{"server": "192.0.2.1:7777", "user": 1, "password": "test",
            "routing": {"default_route": "bypass", "routes": [
                {"ip": "192.168.1.0/24", "to": "proxy"},
                {"rules": "https://example.com/geoip-ru.srs", "to": "bypass"},
                {"rules": ["local.srs", "C:\\rules\\a.srs"], "ip": ["2001:db8::/32"], "to": "proxy"}
            ]}}"#,
        )
        .unwrap();
        c.validate().unwrap();
        assert_eq!(c.routing.default_route, Action::Bypass);
        assert_eq!(c.routing.routes[0].ip[0].to_string(), "192.168.1.0/24");
        assert_eq!(c.routing.routes[2].rules, ["local.srs", "C:\\rules\\a.srs"]);
        let rule = |r: &str| {
            format!(
                r#"{{"server": "192.0.2.1:7777", "user": 1, "password": "secret", "routing": {{"routes": [{r}]}}}}"#
            )
        };
        let manual = parse(&rule("").replace("\"routes\": []", "\"default_route\": \"bypass\""));
        assert!(manual.unwrap().routing.is_manual());
        let Err(error) = parse(&rule(r#"{"ip": "192.168.1.0/235", "to": "proxy"}"#)) else {
            panic!("invalid prefix accepted");
        };
        assert!(
            error.contains("invalid prefix length") && error.contains("line 1"),
            "{error}"
        );
        for bad in [
            r#"{"ip": "192.168.1.0/24", "to": "tunnel"}"#,
            r#"{"ip": "192.168.1.0/24"}"#,
            r#"{"ip": 5, "to": "proxy"}"#,
            r#"{"ip": "x", "to": "proxy"}"#,
            r#"{"ip": "10.0.0.0/8", "to": "proxy", "port": 80}"#,
        ] {
            assert!(parse(&rule(bad)).is_err(), "{bad}");
        }
        for bad in [
            r#"{"to": "proxy"}"#,
            r#"{"ip": [], "rules": [], "to": "proxy"}"#,
            r#"{"rules": "ftp://example.com/a.srs", "to": "proxy"}"#,
            r#"{"rules": "", "to": "proxy"}"#,
            r#"{"domain": "a..ru", "to": "proxy"}"#,
            r#"{"domain": "*.ru", "to": "proxy"}"#,
            r#"{"domain_suffix": "*.", "to": "proxy"}"#,
            r#"{"domain_suffix": "*.ru", "to": "proxy"}"#,
            r#"{"domain": [], "to": "proxy"}"#,
        ] {
            assert!(parse(&rule(bad)).unwrap().validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn client_rules() {
        let config = |mode: &str, routes: &str| {
            parse(&format!(
                r#"{{{mode} "server": "192.0.2.1:7777", "user": 1, "password": "test", "routing": {{"routes": [{routes}]}}}}"#
            ))
        };
        let xdp = r#""mode": "xdp","#;
        let good = r#"{"from": "192.168.1.50", "to": "bypass"},
            {"from": ["192.168.1.0/24", "fd00::/8"], "to": "rules"},
            {"ip": "10.0.0.0/8", "to": "bypass"}"#;
        let c = config(xdp, good).unwrap();
        assert_eq!(
            c.validate().is_ok(),
            cfg!(all(target_os = "linux", feature = "xdp"))
        );
        assert!(c.routing.routes[0].is_client() && !c.routing.routes[2].is_client());
        assert_eq!(c.routing.routes[1].to, Target::Rules);
        assert_eq!(c.routing.routes[1].from.len(), 2);
        // TUN mode has no client table.
        assert!(config("", good).unwrap().validate().is_err());
        assert!(config(xdp, r#"{"from": "192.168.1.0/33", "to": "proxy"}"#).is_err());
        if cfg!(all(target_os = "linux", feature = "xdp")) {
            for bad in [
                r#"{"from": "192.168.1.50", "ip": "1.1.1.1", "to": "proxy"}"#,
                r#"{"from": "192.168.1.50", "domain": "a.ru", "to": "proxy"}"#,
                r#"{"ip": "1.1.1.1", "to": "rules"}"#,
                r#"{"ip": "1.1.1.1", "to": "proxy"}, {"from": "192.168.1.50", "to": "bypass"}"#,
                r#"{"from": [], "to": "bypass"}"#,
            ] {
                assert!(config(xdp, bad).unwrap().validate().is_err(), "{bad}");
            }
            config(xdp, r#"{"from": "192.168.1.0/24", "to": "proxy"}"#)
                .unwrap()
                .validate()
                .unwrap();
        }
    }

    #[test]
    fn domain_rules_and_dns() {
        let c = parse(
            r#"{"server": "192.0.2.1:7777", "user": 1, "password": "test",
            "routing": {"routes": [
                {"domain_suffix": ".ru", "domain": "example.ru", "to": "bypass"},
                {"domain_keyword": "ads", "domain_suffix": [".cdn.example.com"], "to": "proxy"}
            ]},
            "dns": {"servers": ["9.9.9.9", "[2620:fe::fe]:5353"], "set_system": false,
                    "port": 10053}}"#,
        )
        .unwrap();
        c.validate().unwrap();
        let first = c.routing.routes[0].domains().unwrap();
        assert!(first.matches("example.ru") && first.matches("a.b.ru") && !first.matches("ru"));
        let second = c.routing.routes[1].domains().unwrap();
        assert!(second.matches("myads.com") && second.matches("a.cdn.example.com"));
        assert!(!second.matches("cdn.example.com"));
        assert_eq!(
            c.dns_servers(),
            [
                "9.9.9.9:53".parse::<SocketAddr>().unwrap(),
                "[2620:fe::fe]:5353".parse().unwrap()
            ]
        );
        assert!(!c.dns.set_system);
        assert_eq!(c.dns.port, 10053);
        let defaults = cfg();
        assert!(defaults.dns.set_system);
        assert_eq!(defaults.dns.port, 53);
        assert!(!defaults.dns.proxy);
        assert_eq!(defaults.dns_servers()[0].to_string(), "1.1.1.1:53");
        assert!(parse(&EXAMPLE.replacen('{', r#"{"dns": {"servers": "dns.google"},"#, 1)).is_err());
        let port_zero = EXAMPLE.replacen('{', r#"{"dns": {"port": 0},"#, 1);
        assert!(parse(&port_zero).is_ok_and(|c| c.validate().is_err()));
    }
    #[test]
    fn invalid_configuration() {
        for mtu in [0, 575, 1546] {
            let mut c = cfg();
            c.mtu = mtu;
            assert!(c.validate().is_err());
        }
        for ip in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"] {
            let mut c = cfg();
            c.tunnel_ip = ip.parse().unwrap();
            assert!(c.validate().is_err());
        }
        let mut c = cfg();
        c.interface = "x';bad".into();
        assert!(c.validate().is_err());
        let mut c = cfg();
        c.server = "10.66.0.7:7777".parse().unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn ipv6_configuration_and_mtu() {
        let mut c = cfg();
        c.server = "[2001:db8::1]:7777".parse().unwrap();
        c.tunnel_ip6 = "fd66::7".parse().unwrap();
        c.mtu = 1461;
        c.validate().unwrap();
        assert_eq!(
            c.address6().unwrap().unwrap(),
            "fd66::7".parse::<Ipv6Addr>().unwrap()
        );
        c.mtu = 1279;
        assert!(c.validate().is_err());
        c.mtu = 1280;
        c.validate().unwrap();
        for ip in ["ff00::1", "fe80::1", "::", "::1", "::ffff:192.0.2.1"] {
            c.tunnel_ip6 = ip.parse().unwrap();
            assert!(c.validate().is_err(), "{ip}");
        }
        c.tunnel_ip6 = "fd66::7".parse().unwrap();
        for server in [
            "[fd66::7]:7777",
            "[::1]:7777",
            "[::ffff:192.0.2.1]:7777",
            "[fe80::1%3]:7777",
            "[ff02::1]:7777",
            "[2001:db8::1]:0",
        ] {
            c.server = server.parse().unwrap();
            assert!(c.validate().is_err(), "{server}");
        }
    }
}
