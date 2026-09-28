use anyhow::{Context, Result, ensure};
use edup_common::wire;
use serde::Deserialize;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
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
    #[serde(default = "routes")]
    pub routes: bool,
    /// Opportunistic UDP segmentation/coalescing (GSO/GRO or USO/URO).
    #[serde(default = "offload")]
    pub offload: bool,
    /// Windows: absolute DLL path. Default is beside the executable, never CWD.
    pub wintun_dll: Option<PathBuf>,
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
fn routes() -> bool {
    true
}
fn offload() -> bool {
    true
}

impl Settings {
    pub fn load(path: &Path) -> Result<Self> {
        let input =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let cfg: Self = toml::from_str(&input).map_err(|e| {
            let line = e.span().map(|s| {
                input.as_bytes()[..s.start.min(input.len())]
                    .iter()
                    .filter(|b| **b == b'\n')
                    .count()
                    + 1
            });
            anyhow::anyhow!(
                "invalid TOML/schema in {} at line {line:?}; check names and types",
                path.display()
            )
        })?;
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
        self.address()?;
        Ok(())
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
    fn cfg() -> Settings {
        toml::from_str(include_str!("../../config/client.example.toml")).unwrap()
    }
    #[test]
    fn example_defaults_and_address() {
        let c = cfg();
        c.validate().unwrap();
        assert_eq!(c.address().unwrap(), Ipv4Addr::new(10, 66, 0, 7));
        assert_eq!(c.mtu, 1473);
        assert!(c.offload);
        let legacy: Settings = toml::from_str(
            &include_str!("../../config/client.example.toml").replace("offload = true", ""),
        )
        .unwrap();
        assert!(legacy.offload);
        let disabled: Settings = toml::from_str(
            &include_str!("../../config/client.example.toml")
                .replace("offload = true", "offload = false"),
        )
        .unwrap();
        assert!(!disabled.offload);
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
        let defaults: Settings =
            toml::from_str("server = '192.0.2.1:7777'\nuser = 1\npassword = 'test'").unwrap();
        assert_eq!(defaults.address().unwrap(), tunnel_ip());
        // Former addressing fields must fail instead of being silently ignored.
        for field in ["tunnel_id = 7", "tunnel_net = '10.66.0.0/16'"] {
            assert!(
                toml::from_str::<Settings>(&format!(
                    "{}\n{field}",
                    include_str!("../../config/client.example.toml")
                ))
                .is_err()
            );
        }
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
