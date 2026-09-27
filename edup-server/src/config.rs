use anyhow::{Context, Result, ensure};
use edup_common::wire;
#[cfg(target_os = "linux")]
use edup_common::{key::derive_key, maps::Config};
use serde::Deserialize;
use std::{collections::BTreeSet, net::Ipv4Addr, path::Path};

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Driver,
    Skb,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Driver => "driver",
            Self::Skb => "skb",
        }
    }
    #[cfg(target_os = "linux")]
    pub fn flags(self) -> u32 {
        match self {
            Self::Driver => 1 << 2,
            Self::Skb => 1 << 1,
        }
    }
}

// Deliberately no Debug: the password must not enter diagnostics.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub interface: String,
    pub server_ip: Ipv4Addr,
    pub nat_ip: Ipv4Addr,
    pub port: u16,
    pub password: String,
    pub tunnel_net: String,
    pub nat_port_min: u16,
    pub nat_port_max: u16,
    #[serde(default = "default_frame")]
    pub max_frame: u16,
    #[serde(default)]
    pub xdp_mode: Mode,
    pub users: Vec<u16>,
}
fn default_frame() -> u16 {
    1500
}

impl Settings {
    pub fn load(path: &Path) -> Result<Self> {
        let input =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let cfg: Self = toml::from_str(&input).map_err(|e| {
            // toml::Error's Display includes the original source, potentially the password.
            let line = e.span().map(|s| {
                input.as_bytes()[..s.start.min(input.len())]
                    .iter()
                    .filter(|b| **b == b'\n')
                    .count()
                    + 1
            });
            anyhow::anyhow!(
                "invalid TOML/schema in {} at line {:?}; check field names and types",
                path.display(),
                line
            )
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.interface.is_empty()
                && self.interface.len() < 16
                && self
                    .interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b)),
            "invalid interface name"
        );
        ensure!(
            self.interface != "." && self.interface != "..",
            "invalid interface name"
        );
        for (name, ip) in [("server_ip", self.server_ip), ("nat_ip", self.nat_ip)] {
            ensure!(unicast(ip), "{name} must be a unicast IPv4 address");
        }
        ensure!(self.port != 0, "port must be nonzero");
        ensure!(!self.password.is_empty(), "password must not be empty");
        ensure!(
            self.nat_port_min > 0 && self.nat_port_min <= self.nat_port_max,
            "invalid NAT port range"
        );
        ensure!(
            !(self.nat_port_min..=self.nat_port_max).contains(&self.port),
            "NAT range overlaps the tunnel port"
        );
        let max = wire::MAX_KS_WORDS as usize * 8 + 32;
        ensure!(
            (576 + wire::OVERHEAD_V4..=max).contains(&(self.max_frame as usize)),
            "max_frame must be between {} and {max}",
            576 + wire::OVERHEAD_V4
        );
        let (net, mask) = self.network()?;
        ensure!(
            u32::from(self.server_ip) & mask != net && u32::from(self.nat_ip) & mask != net,
            "outer addresses must be outside tunnel_net"
        );
        let mut ids = BTreeSet::new();
        for &id in &self.users {
            ensure!(ids.insert(id), "duplicate user ID {id}");
            ensure!(
                id != 0 && id as u32 != !mask,
                "user ID {id} is a network or broadcast address"
            );
        }
        Ok(())
    }

    pub fn network(&self) -> Result<(u32, u32)> {
        let (ip, prefix) = self
            .tunnel_net
            .split_once('/')
            .context("tunnel_net must be IPv4/prefix")?;
        let ip: Ipv4Addr = ip.parse().context("invalid tunnel_net address")?;
        let prefix: u32 = prefix.parse().context("invalid tunnel_net prefix")?;
        ensure!(
            (1..=16).contains(&prefix),
            "tunnel_net prefix must be between /1 and /16"
        );
        let mask = u32::MAX << (32 - prefix);
        let net = u32::from(ip);
        ensure!(
            net & mask == net,
            "tunnel_net must be a network address with zero host bits"
        );
        ensure!(unicast(ip), "tunnel_net must be unicast");
        // Large prefixes must not span reserved/multicast ranges either.
        ensure!(
            unicast(Ipv4Addr::from(net | !mask)),
            "tunnel_net spans non-unicast addresses"
        );
        Ok((net, mask))
    }

    #[cfg(target_os = "linux")]
    pub fn check_local_ports(&self, input: &str) -> Result<()> {
        let values = input
            .split_whitespace()
            .map(str::parse::<u16>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            values.len() == 2 && values[0] <= values[1],
            "invalid ip_local_port_range"
        );
        ensure!(
            self.nat_port_max < values[0] || self.nat_port_min > values[1],
            "NAT range overlaps net.ipv4.ip_local_port_range ({}..{}); move the host ephemeral range outside the NAT range",
            values[0],
            values[1]
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn map_config(&self) -> Result<Config> {
        let key = derive_key(&self.password);
        let (tun_net, tun_mask) = self.network()?;
        Ok(Config {
            key0: key.k0,
            key1: key.k1,
            server_ip_be: u32::from_ne_bytes(self.server_ip.octets()),
            nat_ip_be: u32::from_ne_bytes(self.nat_ip.octets()),
            tun_net,
            tun_mask,
            port_be: self.port.to_be(),
            nat_port_min: self.nat_port_min,
            nat_port_max: self.nat_port_max,
            max_frame: self.max_frame,
        })
    }
}

fn unicast(ip: Ipv4Addr) -> bool {
    let first = ip.octets()[0];
    first != 0 && first != 127 && first < 224 && !ip.is_broadcast()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Settings {
        toml::from_str(include_str!("../../config/server.example.toml")).unwrap()
    }
    #[test]
    fn example_and_byte_order() {
        let cfg = config();
        cfg.validate().unwrap();
        assert_eq!(cfg.network().unwrap(), (0x0a420000, 0xffff0000));
        #[cfg(target_os = "linux")]
        {
            let raw = cfg.map_config().unwrap();
            assert_eq!(raw.server_ip_be.to_ne_bytes(), [192, 0, 2, 1]);
            assert_eq!(u16::from_be(raw.port_be), 7777);
        }
    }
    #[test]
    fn rejects_invalid_user_ids_and_duplicates() {
        for ids in [vec![0], vec![65535], vec![7, 7]] {
            let mut cfg = config();
            cfg.users = ids;
            assert!(cfg.validate().is_err());
        }
        let mut cfg = config();
        cfg.tunnel_net = "10.64.0.0/15".into();
        cfg.users = vec![65535];
        cfg.validate().unwrap();
    }
    #[test]
    fn rejects_bad_networks_and_addresses() {
        for net in [
            "10.66.0.1/16",
            "10.66.0.0/24",
            "0.0.0.0/0",
            "224.0.0.0/8",
            "10.0.0.0/33",
        ] {
            let mut cfg = config();
            cfg.tunnel_net = net.into();
            assert!(cfg.validate().is_err(), "{net}");
        }
        let mut cfg = config();
        cfg.server_ip = "10.66.0.1".parse().unwrap();
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn rejects_ports_mtu_and_unsafe_interface() {
        let mut cfg = config();
        cfg.port = cfg.nat_port_min;
        assert!(cfg.validate().is_err());
        let mut cfg = config();
        cfg.nat_port_min = cfg.nat_port_max + 1;
        assert!(cfg.validate().is_err());
        for mtu in [0, 611, 1569] {
            let mut cfg = config();
            cfg.max_frame = mtu;
            assert!(cfg.validate().is_err());
        }
        for interface in ["../eth0", "eth0\0", "abcdefghijklmnop", ".."] {
            let mut cfg = config();
            cfg.interface = interface.into();
            assert!(cfg.validate().is_err());
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn host_ports_cannot_overlap() {
        let cfg = config();
        cfg.check_local_ports("32768\t60999\n").unwrap();
        for range in [
            "19999 20000",
            "29999 30000",
            "1000 40000",
            "20001 20002",
            "1",
            "90 80",
        ] {
            assert!(cfg.check_local_ports(range).is_err());
        }
    }
}
