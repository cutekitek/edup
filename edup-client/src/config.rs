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

/// Tunnels one client runs at most; XDP mode keeps their keys in eBPF.
pub const MAX_SERVERS: usize = edup_common::maps::MAX_SERVERS as usize;

#[derive(Deserialize)]
#[serde(try_from = "RawSettings")]
pub struct Settings {
    /// Datapath: `tun` (default) or, on Linux, `xdp`.
    pub mode: Mode,
    /// How XDP attaches to the physical interface in `xdp` mode.
    #[cfg_attr(not(all(target_os = "linux", feature = "xdp")), allow(dead_code))]
    pub xdp_mode: XdpMode,
    /// Tunnel servers, all of one address family. Routing names them by tag.
    pub servers: Vec<Server>,
    /// Local tunnel address of the first server; the others count up from it.
    pub tunnel_ip: Ipv4Addr,
    pub tunnel_ip6: Ipv6Addr,
    /// TUN device of the first server; the others count up from its number.
    pub interface: String,
    pub mtu: u16,
    pub keepalive_secs: u64,
    /// Opportunistic UDP segmentation/coalescing (GSO/GRO or USO/URO).
    pub offload: bool,
    /// Windows: absolute DLL path. Default is beside the executable, never CWD.
    pub wintun_dll: Option<PathBuf>,
    pub routing: Routing,
    /// DNS forwarder, active only when routing uses domain rules.
    pub dns: Dns,
    /// Directory of the configuration file: base for rule-set paths and cache.
    pub base: PathBuf,
}

/// The configuration as written: a `servers` list, or the single server of
/// earlier versions as top-level `server`, `user` and `password` (tag
/// `"proxy"`). Route targets are names until the servers are known.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSettings {
    #[serde(default)]
    mode: Mode,
    #[serde(default)]
    xdp_mode: XdpMode,
    #[serde(default)]
    servers: Vec<Server>,
    server: Option<SocketAddr>,
    user: Option<i64>,
    password: Option<String>,
    #[serde(default = "tunnel_ip")]
    tunnel_ip: Ipv4Addr,
    #[serde(default = "tunnel_ip6")]
    tunnel_ip6: Ipv6Addr,
    #[serde(default = "interface")]
    interface: String,
    #[serde(default = "mtu")]
    mtu: u16,
    #[serde(default = "keepalive")]
    keepalive_secs: u64,
    #[serde(default = "offload")]
    offload: bool,
    wintun_dll: Option<PathBuf>,
    #[serde(default)]
    routing: RawRouting,
    #[serde(default)]
    dns: RawDns,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// Name that routing rules use; not "direct", "bypass" or "rules".
    pub tag: String,
    /// Address and port.
    #[serde(rename = "server")]
    pub address: SocketAddr,
    pub user: i64,
    pub password: String,
}
/// Tag of the server written in the single-server form.
pub const LEGACY_TAG: &str = "proxy";

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

pub struct Routing {
    /// Destination for addresses no rule matches.
    pub default_route: Action,
    /// Ordered rules; the first rule containing an address decides its route.
    pub routes: Vec<RouteRule>,
}
impl Routing {
    /// No system routes are changed; the user routes traffic into the TUN.
    pub fn is_manual(&self) -> bool {
        self.default_route == Action::Direct && self.routes.is_empty()
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouting {
    /// A server tag or "direct"; the first server by default.
    default_route: Option<String>,
    #[serde(default)]
    routes: Vec<RouteRule<String>>,
}

/// Where traffic goes: the physical network or one server's tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    Direct,
    /// Index into `Settings::servers`.
    Server(usize),
}

/// Where a rule sends what it matches; `rules` only on `from` rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Direct,
    Server(usize),
    /// The destination rules decide.
    Rules,
}
impl Target {
    pub fn action(self) -> Option<Action> {
        match self {
            Self::Direct => Some(Action::Direct),
            Self::Server(i) => Some(Action::Server(i)),
            Self::Rules => None,
        }
    }
}

/// `"direct"` (or `"bypass"`), `"rules"` or a server tag.
fn target(servers: &[Server], name: &str) -> Result<Target, String> {
    match name {
        "direct" | "bypass" => Ok(Target::Direct),
        "rules" => Ok(Target::Rules),
        _ => servers
            .iter()
            .position(|s| s.tag == name)
            .map(Target::Server)
            .ok_or_else(|| {
                let tags: Vec<String> = servers.iter().map(|s| format!("{:?}", s.tag)).collect();
                format!(
                    "unknown route {name:?}: use \"direct\" or a server tag ({})",
                    tags.join(", ")
                )
            }),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule<T = Target> {
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
    pub to: T,
}
impl<T> RouteRule<T> {
    pub fn is_client(&self) -> bool {
        !self.from.is_empty()
    }
    fn map<U>(self, f: impl FnOnce(T) -> Result<U, String>) -> Result<RouteRule<U>, String> {
        Ok(RouteRule {
            from: self.from,
            ip: self.ip,
            rules: self.rules,
            domain: self.domain,
            domain_suffix: self.domain_suffix,
            domain_keyword: self.domain_keyword,
            to: f(self.to)?,
        })
    }
}
impl RouteRule {
    /// The action of a destination rule.
    pub fn action(&self) -> Action {
        self.to.action().unwrap_or(Action::Direct)
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

pub struct Dns {
    /// Upstream resolvers, `"1.1.1.1"` or `"1.1.1.1:53"`; routed like any traffic.
    pub servers: Vec<Upstream>,
    /// Point the system resolver at the forwarder through the TUN interface.
    pub set_system: bool,
    /// The server whose tunnel carries the forwarder's queries to public
    /// `servers`, whatever the routing rules say about their addresses.
    pub proxy: Option<usize>,
    /// Forwarder port on the tunnel address. Another one avoids a resolver
    /// that binds port 53 on every address, as OpenWrt's dnsmasq does.
    pub port: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDns {
    #[serde(default, deserialize_with = "one_or_many")]
    servers: Vec<Upstream>,
    #[serde(default = "set_system")]
    set_system: bool,
    /// A tag, or `true` for the default route's server.
    #[serde(default, deserialize_with = "dns_proxy")]
    proxy: String,
    #[serde(default = "dns_port")]
    port: u16,
}
impl Default for RawDns {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            set_system: true,
            proxy: String::new(),
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
/// `false`, `true` or a tag; empty means off.
fn dns_proxy<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Proxy {
        Flag(bool),
        Tag(String),
    }
    Ok(match Proxy::deserialize(deserializer)? {
        Proxy::Flag(false) => String::new(),
        Proxy::Flag(true) => "true".into(),
        Proxy::Tag(tag) => tag,
    })
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

impl TryFrom<RawSettings> for Settings {
    type Error = String;
    fn try_from(raw: RawSettings) -> Result<Self, String> {
        let mut servers = raw.servers;
        match (raw.server, raw.user, raw.password) {
            (None, None, None) => {}
            (Some(address), Some(user), Some(password)) if servers.is_empty() => {
                servers.push(Server {
                    tag: LEGACY_TAG.into(),
                    address,
                    user,
                    password,
                })
            }
            (Some(_), Some(_), Some(_)) => {
                return Err(
                    "use either \"servers\" or \"server\", \"user\" and \"password\"".into(),
                );
            }
            _ => return Err("\"server\", \"user\" and \"password\" go together".into()),
        }
        if servers.is_empty() {
            return Err("missing \"servers\"".into());
        }
        if servers.len() > MAX_SERVERS {
            return Err(format!("at most {MAX_SERVERS} servers are supported"));
        }
        for (i, server) in servers.iter().enumerate() {
            let tag = &server.tag;
            if tag.is_empty()
                || tag.len() > 32
                || !tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
            {
                return Err(format!(
                    "invalid server tag {tag:?} (use 1..32 ASCII letters, digits, _, - or .)"
                ));
            }
            if ["direct", "bypass", "rules"].contains(&tag.as_str()) {
                return Err(format!("server tag {tag:?} is reserved"));
            }
            if servers[..i].iter().any(|s| s.tag == *tag) {
                return Err(format!("duplicate server tag {tag:?}"));
            }
        }
        let default_route = match &raw.routing.default_route {
            None => Action::Server(0),
            Some(name) => target(&servers, name)?
                .action()
                .ok_or("default_route must be \"direct\" or a server tag")?,
        };
        let routes = raw
            .routing
            .routes
            .into_iter()
            .enumerate()
            .map(|(i, rule)| {
                rule.map(|to| target(&servers, &to))
                    .map_err(|e| format!("routing.routes[{i}]: {e}"))
            })
            .collect::<Result<_, _>>()?;
        let proxy = match raw.dns.proxy.as_str() {
            "" => None,
            "true" => Some(match default_route {
                Action::Server(i) => i,
                Action::Direct => 0,
            }),
            tag => match target(&servers, tag) {
                Ok(Target::Server(i)) => Some(i),
                _ => return Err(format!("dns.proxy: {tag:?} is not a server tag")),
            },
        };
        Ok(Self {
            mode: raw.mode,
            xdp_mode: raw.xdp_mode,
            servers,
            tunnel_ip: raw.tunnel_ip,
            tunnel_ip6: raw.tunnel_ip6,
            interface: raw.interface,
            mtu: raw.mtu,
            keepalive_secs: raw.keepalive_secs,
            offload: raw.offload,
            wintun_dll: raw.wintun_dll,
            routing: Routing {
                default_route,
                routes,
            },
            dns: Dns {
                servers: raw.dns.servers,
                set_system: raw.dns.set_system,
                proxy,
                port: raw.dns.port,
            },
            base: PathBuf::new(),
        })
    }
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
    /// The tunnels' address family, that of every server.
    pub fn ipv6(&self) -> bool {
        self.servers[0].address.is_ipv6()
    }
    /// Server addresses, by index.
    pub fn server_ips(&self) -> Vec<IpAddr> {
        self.servers.iter().map(|s| s.address.ip()).collect()
    }
    /// "direct" or the server's tag.
    pub fn name(&self, action: Action) -> &str {
        match action {
            Action::Direct => "direct",
            Action::Server(i) => &self.servers[i].tag,
        }
    }
    /// The local IPv4 address of server `i`'s tunnel.
    pub fn address_of(&self, i: usize) -> Result<Ipv4Addr> {
        let address = u32::from(self.tunnel_ip)
            .checked_add(i as u32)
            .map(Ipv4Addr::from)
            .filter(|&ip| unicast(ip))
            .context("tunnel_ip must be unicast IPv4, with room for one address per server")?;
        ensure!(
            !self.server_ips().contains(&IpAddr::V4(address)),
            "server and tunnel addresses must differ"
        );
        Ok(address)
    }
    #[cfg(test)]
    pub fn address(&self) -> Result<Ipv4Addr> {
        self.address_of(0)
    }
    /// The local IPv6 address of server `i`'s tunnel, in IPv6 mode.
    pub fn address6_of(&self, i: usize) -> Result<Option<Ipv6Addr>> {
        if !self.ipv6() {
            return Ok(None);
        }
        let address = u128::from(self.tunnel_ip6)
            .checked_add(i as u128)
            .map(Ipv6Addr::from)
            .filter(|ip| edup_common::ipv6::unicast(ip.octets()))
            .context(
                "tunnel_ip6 must be global/ULA unicast, with room for one address per server",
            )?;
        ensure!(
            !self.server_ips().contains(&IpAddr::V6(address)),
            "server and tunnel addresses must differ"
        );
        Ok(Some(address))
    }
    #[cfg(test)]
    pub fn address6(&self) -> Result<Option<Ipv6Addr>> {
        self.address6_of(0)
    }
    /// TUN device of server `i`: `interface`, then counting up from its
    /// trailing number, edup0, edup1, ...
    pub fn interface_of(&self, i: usize) -> String {
        if i == 0 {
            return self.interface.clone();
        }
        let stem = self
            .interface
            .trim_end_matches(|c: char| c.is_ascii_digit());
        let number: usize = self.interface[stem.len()..].parse().unwrap_or(0);
        format!("{stem}{}", number + i)
    }
    pub fn validate(&self) -> Result<()> {
        let v6 = self.ipv6();
        for (i, server) in self.servers.iter().enumerate() {
            let tag = &server.tag;
            ensure!(
                match server.address.ip() {
                    IpAddr::V4(ip) => unicast(ip),
                    IpAddr::V6(ip) => edup_common::ipv6::unicast(ip.octets()),
                } && server.address.port() != 0,
                "server {tag:?} must be a global/ULA unicast address and nonzero port"
            );
            if let SocketAddr::V6(address) = server.address {
                ensure!(
                    address.scope_id() == 0,
                    "server {tag:?}: scoped addresses are unsupported"
                );
            }
            ensure!(
                server.address.is_ipv6() == v6,
                "servers must all use IPv4 or all IPv6; {tag:?} differs"
            );
            ensure!(
                !self.servers[..i]
                    .iter()
                    .any(|s| s.address == server.address),
                "server {tag:?} repeats the address of another server"
            );
            ensure!(
                !server.password.is_empty(),
                "server {tag:?}: password must not be empty"
            );
        }
        let tunnels = if self.mode == Mode::Xdp {
            1
        } else {
            self.servers.len()
        };
        for i in 0..tunnels {
            self.address_of(i)?;
            if self.address6_of(i)?.is_some() {
                ensure!(self.mtu >= 1280, "IPv6 tunnel MTU must be at least 1280");
            }
            let name = self.interface_of(i);
            ensure!(
                !name.is_empty()
                    && name.len() < 16
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
                "invalid interface name {name:?} (use 1..15 ASCII letters, digits, _ or -)"
            );
        }
        let max_mtu = wire::MAX_KS_WORDS as usize * 8 - wire::CONTROL_LEN
            + if v6 {
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
                "xdp mode routes by rules: set routing.routes or a server as default_route"
            );
        }
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
        let defaults: [IpAddr; 2] = if self.ipv6() {
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
    /// A configuration with these servers and routing.
    fn servers(servers: &str, routing: &str) -> Result<Settings, String> {
        parse(&format!(
            r#"{{"servers": [{servers}], "routing": {{{routing}}}}}"#
        ))
    }
    const TWO: &str = r#"{"tag": "nl", "server": "192.0.2.1:7777", "user": 1, "password": "a"},
        {"tag": "de", "server": "198.51.100.1:7777", "user": -2, "password": "b"}"#;

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
        assert_eq!(c.servers.len(), 1);
        assert_eq!(c.servers[0].tag, "main");
        assert_eq!(c.routing.default_route, Action::Server(0));
        assert_eq!(c.routing.routes.len(), 1);
        assert_eq!(c.routing.routes[0].ip.len(), 3);
        assert_eq!(c.routing.routes[0].to, Target::Direct);
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
            default_route: Action::Direct,
            routes: Vec::new(),
        };
        assert!(manual.validate().is_err());
    }
    #[test]
    fn addresses_are_local_and_independent_of_user_identity() {
        let mut c = cfg();
        c.tunnel_ip = "172.19.8.23".parse().unwrap();
        for id in [i64::MIN, 0, i64::MAX] {
            c.servers[0].user = id;
            c.validate().unwrap();
            assert_eq!(c.address().unwrap().to_string(), "172.19.8.23");
        }
        let defaults =
            parse(r#"{"server": "192.0.2.1:7777", "user": 1, "password": "test"}"#).unwrap();
        assert_eq!(defaults.address().unwrap(), tunnel_ip());
        assert_eq!(defaults.servers[0].tag, LEGACY_TAG);
        assert_eq!(defaults.routing.default_route, Action::Server(0));
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
    fn single_server_form_keeps_proxy_and_bypass() {
        let c = parse(
            r#"{"server": "192.0.2.1:7777", "user": 1, "password": "test",
            "routing": {"default_route": "bypass", "routes": [
                {"ip": "192.168.1.0/24", "to": "proxy"},
                {"ip": "10.0.0.0/8", "to": "bypass"}
            ]}}"#,
        )
        .unwrap();
        c.validate().unwrap();
        assert_eq!(c.routing.default_route, Action::Direct);
        assert_eq!(c.routing.routes[0].to, Target::Server(0));
        assert_eq!(c.routing.routes[1].to, Target::Direct);
        for bad in [
            r#"{"server": "192.0.2.1:7777", "user": 1}"#,
            r#"{"user": 1, "password": "x"}"#,
            r#"{"server": "192.0.2.1:7777", "user": 1, "password": "x",
                "servers": [{"tag": "a", "server": "192.0.2.2:1", "user": 1, "password": "y"}]}"#,
            r#"{}"#,
            r#"{"servers": []}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn servers_are_named_by_tag() {
        let c = servers(
            TWO,
            r#""default_route": "de", "routes": [
                {"ip": "10.0.0.0/8", "to": "direct"},
                {"domain_suffix": ".nl", "to": "nl"}
            ]"#,
        )
        .unwrap();
        c.validate().unwrap();
        assert_eq!(c.routing.default_route, Action::Server(1));
        assert_eq!(c.routing.routes[0].to, Target::Direct);
        assert_eq!(c.routing.routes[1].to, Target::Server(0));
        assert_eq!(c.name(Action::Server(1)), "de");
        assert_eq!(c.name(Action::Direct), "direct");
        // Each server has its own tunnel address and device.
        assert_eq!(c.address_of(1).unwrap(), Ipv4Addr::new(10, 66, 0, 2));
        assert_eq!(c.interface_of(1), "edup1");
        let mut named = servers(TWO, "").unwrap();
        named.interface = "tun".into();
        assert_eq!(named.interface_of(2), "tun2");
        named.interface = "wg9".into();
        assert_eq!(named.interface_of(1), "wg10");
        // The first server by default.
        assert_eq!(
            servers(TWO, "").unwrap().routing.default_route,
            Action::Server(0)
        );
        let Err(error) = servers(TWO, r#""routes": [{"ip": "10.0.0.0/8", "to": "proxy"}]"#) else {
            panic!("unknown tag accepted");
        };
        assert!(error.contains("\"nl\", \"de\""), "{error}");
        for (list, routing) in [
            (TWO.replace("\"de\"", "\"nl\""), ""),
            (TWO.replace("\"de\"", "\"direct\""), ""),
            (TWO.replace("\"de\"", "\"a b\""), ""),
            (TWO.replace("\"de\"", "\"\""), ""),
            (TWO.into(), r#""default_route": "rules""#),
            (TWO.into(), r#""default_route": "fr""#),
        ] {
            assert!(servers(&list, routing).is_err(), "{list} {routing}");
        }
        for list in [
            // Mixed families, a repeated endpoint, an empty password.
            TWO.replace("198.51.100.1:7777", "[2001:db8::1]:7777"),
            TWO.replace("198.51.100.1:7777", "192.0.2.1:7777"),
            TWO.replace("\"b\"", "\"\""),
            // A tunnel address of the second server.
            TWO.replace("198.51.100.1", "10.66.0.2"),
        ] {
            assert!(servers(&list, "").unwrap().validate().is_err(), "{list}");
        }
        let many: Vec<String> = (0..=MAX_SERVERS)
            .map(|i| {
                format!(
                    r#"{{"tag": "s{i}", "server": "192.0.2.{i}:1", "user": 1, "password": "x"}}"#
                )
            })
            .collect();
        assert!(servers(&many.join(","), "").is_err());
    }
    #[test]
    fn routing_rules() {
        let c = parse(
            r#"{"server": "192.0.2.1:7777", "user": 1, "password": "test",
            "routing": {"default_route": "direct", "routes": [
                {"ip": "192.168.1.0/24", "to": "proxy"},
                {"rules": "https://example.com/geoip-ru.srs", "to": "direct"},
                {"rules": ["local.srs", "C:\\rules\\a.srs"], "ip": ["2001:db8::/32"], "to": "proxy"}
            ]}}"#,
        )
        .unwrap();
        c.validate().unwrap();
        assert_eq!(c.routing.default_route, Action::Direct);
        assert_eq!(c.routing.routes[0].ip[0].to_string(), "192.168.1.0/24");
        assert_eq!(c.routing.routes[2].rules, ["local.srs", "C:\\rules\\a.srs"]);
        let rule = |r: &str| {
            format!(
                r#"{{"server": "192.0.2.1:7777", "user": 1, "password": "secret", "routing": {{"routes": [{r}]}}}}"#
            )
        };
        let manual = parse(&rule("").replace("\"routes\": []", "\"default_route\": \"direct\""));
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
            servers(TWO, &format!(r#""routes": [{routes}]"#)).map(|mut c| {
                if !mode.is_empty() {
                    c.mode = Mode::Xdp;
                }
                c
            })
        };
        let xdp = "xdp";
        let good = r#"{"from": "192.168.1.50", "to": "direct"},
            {"from": "192.168.1.51", "to": "de"},
            {"from": ["192.168.1.0/24", "fd00::/8"], "to": "rules"},
            {"ip": "10.0.0.0/8", "to": "direct"}"#;
        let c = config(xdp, good).unwrap();
        assert_eq!(
            c.validate().is_ok(),
            cfg!(all(target_os = "linux", feature = "xdp"))
        );
        assert!(c.routing.routes[0].is_client() && !c.routing.routes[3].is_client());
        assert_eq!(c.routing.routes[1].to, Target::Server(1));
        assert_eq!(c.routing.routes[2].to, Target::Rules);
        assert_eq!(c.routing.routes[2].from.len(), 2);
        // TUN mode has no client table.
        assert!(config("", good).unwrap().validate().is_err());
        assert!(config(xdp, r#"{"from": "192.168.1.0/33", "to": "nl"}"#).is_err());
        assert!(config(xdp, r#"{"from": "192.168.1.5", "to": "fr"}"#).is_err());
        if cfg!(all(target_os = "linux", feature = "xdp")) {
            for bad in [
                r#"{"from": "192.168.1.50", "ip": "1.1.1.1", "to": "nl"}"#,
                r#"{"from": "192.168.1.50", "domain": "a.ru", "to": "nl"}"#,
                r#"{"ip": "1.1.1.1", "to": "rules"}"#,
                r#"{"ip": "1.1.1.1", "to": "nl"}, {"from": "192.168.1.50", "to": "direct"}"#,
                r#"{"from": [], "to": "direct"}"#,
            ] {
                assert!(config(xdp, bad).unwrap().validate().is_err(), "{bad}");
            }
            config(xdp, r#"{"from": "192.168.1.0/24", "to": "nl"}"#)
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
        assert_eq!(c.dns.proxy, None);
        let defaults = cfg();
        assert!(defaults.dns.set_system);
        assert_eq!(defaults.dns.port, 53);
        assert_eq!(defaults.dns.proxy, None);
        assert_eq!(defaults.dns_servers()[0].to_string(), "1.1.1.1:53");
        assert!(parse(&EXAMPLE.replacen('{', r#"{"dns": {"servers": "dns.google"},"#, 1)).is_err());
        let port_zero = EXAMPLE.replacen('{', r#"{"dns": {"port": 0},"#, 1);
        assert!(parse(&port_zero).is_ok_and(|c| c.validate().is_err()));
        // The proxy server: a tag, or the default route's server.
        let proxy = |dns: &str, default: &str| {
            parse(&format!(
                r#"{{"servers": [{TWO}], "routing": {{"default_route": "{default}"}}, "dns": {{"proxy": {dns}}}}}"#
            ))
            .map(|c| c.dns.proxy)
        };
        assert_eq!(proxy("true", "de"), Ok(Some(1)));
        assert_eq!(proxy("true", "direct"), Ok(Some(0)));
        assert_eq!(proxy(r#""de""#, "nl"), Ok(Some(1)));
        assert_eq!(proxy("false", "de"), Ok(None));
        assert!(proxy(r#""direct""#, "de").is_err());
        assert!(proxy(r#""fr""#, "de").is_err());
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
        c.servers[0].address = "10.66.0.7:7777".parse().unwrap();
        assert!(c.validate().is_err());
        // The second server's device name is too long.
        let mut c = servers(TWO, "").unwrap();
        c.interface = "edup-interface9".into();
        assert_eq!(c.interface_of(1), "edup-interface10");
        assert!(c.validate().is_err());
        c.mode = Mode::Xdp;
        c.interface = "edup-interfac".into();
        assert_eq!(
            c.validate().is_ok(),
            cfg!(all(target_os = "linux", feature = "xdp"))
        );
    }

    #[test]
    fn ipv6_configuration_and_mtu() {
        let mut c = cfg();
        c.servers[0].address = "[2001:db8::1]:7777".parse().unwrap();
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
            c.servers[0].address = server.parse().unwrap();
            assert!(c.validate().is_err(), "{server}");
        }
    }
}
