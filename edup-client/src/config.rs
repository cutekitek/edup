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
    pub user: u16,
    pub password: String,
    #[serde(default = "tunnel_net")]
    pub tunnel_net: String,
    pub tunnel_net6: Option<String>,
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
fn tunnel_net() -> String {
    "10.66.0.0/16".into()
}
fn interface() -> String {
    "edup0".into()
}
fn mtu() -> u16 {
    1464
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
        let (net, prefix) = self
            .tunnel_net
            .split_once('/')
            .context("tunnel_net must be IPv4/prefix")?;
        let net = u32::from(net.parse::<Ipv4Addr>().context("invalid tunnel network")?);
        let prefix: u32 = prefix.parse().context("invalid tunnel prefix")?;
        ensure!((1..=16).contains(&prefix), "tunnel prefix must be /1../16");
        let mask = u32::MAX << (32 - prefix);
        ensure!(net & mask == net, "tunnel network has nonzero host bits");
        ensure!(
            unicast(Ipv4Addr::from(net)) && unicast(Ipv4Addr::from(net | !mask)),
            "invalid tunnel network"
        );
        if let IpAddr::V4(server) = self.server.ip() {
            ensure!(
                u32::from(server) & mask != net,
                "server must be outside tunnel network"
            );
        }
        ensure!(
            self.user != 0 && (self.server.is_ipv6() || self.user as u32 != !mask),
            "user is a network/broadcast address"
        );
        Ok(Ipv4Addr::from(net + self.user as u32))
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
        ensure!(
            self.server.is_ipv6() == self.tunnel_net6.is_some(),
            "IPv6 server requires tunnel_net6; IPv4 server uses tunnel_net only"
        );
        if let Some(address) = self.address6()? {
            ensure!(self.mtu >= 1280, "IPv6 tunnel MTU must be at least 1280");
            if let IpAddr::V6(server) = self.server.ip() {
                ensure!(
                    server.octets()[..14] != address.octets()[..14],
                    "server must be outside tunnel_net6"
                );
            }
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
        ensure!(
            (576..=wire::MAX_KS_WORDS as usize * 8 - 4).contains(&(self.mtu as usize)),
            "MTU must be 576..1532"
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
        self.tunnel_net6
            .as_deref()
            .map(|net| {
                let net = edup_common::ipv6::network(net).context(
                    "tunnel_net6 must be a global/ULA IPv6 /112 network with zero host bits",
                )?;
                Ok(Ipv6Addr::from(edup_common::ipv6::address(net, self.user)))
            })
            .transpose()
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
        assert_eq!(c.mtu, 1464);
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
    fn invalid_configuration() {
        for mtu in [0, 575, 1533] {
            let mut c = cfg();
            c.mtu = mtu;
            assert!(c.validate().is_err());
        }
        for user in [0, 65535] {
            let mut c = cfg();
            c.user = user;
            assert!(c.validate().is_err());
        }
        for net in ["10.66.0.1/16", "10.66.0.0/24", "0.0.0.0/0", "224.0.0.0/8"] {
            let mut c = cfg();
            c.tunnel_net = net.into();
            assert!(c.validate().is_err());
        }
        let mut c = cfg();
        c.interface = "x';bad".into();
        assert!(c.validate().is_err());
        let mut c = cfg();
        c.server = "10.66.0.8:7777".parse().unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn ipv6_configuration_and_mtu() {
        let mut c = cfg();
        c.server = "[2001:db8::1]:7777".parse().unwrap();
        c.tunnel_net6 = Some("fd66::/112".into());
        c.mtu = 1444;
        c.validate().unwrap();
        assert_eq!(
            c.address6().unwrap().unwrap(),
            "fd66::7".parse::<Ipv6Addr>().unwrap()
        );
        c.mtu = 1279;
        assert!(c.validate().is_err());
        c.mtu = 1280;
        c.validate().unwrap();
        for net in [
            "fd66::1/112",
            "fd66::/64",
            "ff00::/112",
            "fe80::/112",
            "::/112",
            "10.0.0.0/16",
        ] {
            c.tunnel_net6 = Some(net.into());
            assert!(c.validate().is_err(), "{net}");
        }
        c.tunnel_net6 = Some("fd66::/112".into());
        for server in [
            "[fd66::8]:7777",
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
