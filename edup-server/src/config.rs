use anyhow::{Context, Result, ensure};
#[cfg(target_os = "linux")]
use edup_common::maps::Config;
use edup_common::wire;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};

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
    pub server_ip6: Option<Ipv6Addr>,
    pub nat_ip6: Option<Ipv6Addr>,
    pub gateway_mac: Option<String>,
    pub gateway6_mac: Option<String>,
    pub port: u16,
    pub nat_port_min: u16,
    pub nat_port_max: u16,
    #[serde(default = "default_frame")]
    pub max_frame: u16,
    #[serde(default)]
    pub xdp_mode: Mode,
    pub users: Vec<UserSettings>,
}
// No Debug: credentials must not appear in diagnostics.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSettings {
    pub id: i64,
    pub password: String,
}

fn default_frame() -> u16 {
    1500
}

impl Settings {
    pub fn load(path: &Path) -> Result<Self> {
        let input =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let cfg: Self = edup_common::json::parse(&input).map_err(|e| {
            let hint = if path.extension().is_some_and(|e| e == "toml") {
                " (configuration files are JSON now; see config/server.example.json)"
            } else {
                ""
            };
            anyhow::anyhow!("invalid configuration {}: {e}{hint}", path.display())
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        for ip in [self.server_ip6, self.nat_ip6].into_iter().flatten() {
            ensure!(
                edup_common::ipv6::unicast(ip.octets()),
                "IPv6 addresses must be global/ULA unicast"
            );
        }
        ensure!(
            self.server_ip6.is_some() == self.nat_ip6.is_some(),
            "server_ip6 and nat_ip6 must be configured together"
        );
        if self.server_ip6.is_some() {
            ensure!(
                self.max_frame as usize >= 1280 + wire::OVERHEAD_V6,
                "max_frame is too small for IPv6 tunnel MTU 1280"
            );
        }
        parse_mac(self.gateway_mac.as_deref())?;
        parse_mac(self.gateway6_mac.as_deref())?;
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
        ensure!(
            self.nat_port_min > 0 && self.nat_port_min <= self.nat_port_max,
            "invalid NAT port range"
        );
        ensure!(
            !(self.nat_port_min..=self.nat_port_max).contains(&self.port),
            "NAT range overlaps the tunnel port"
        );
        let max = wire::MAX_KS_WORDS as usize * 8
            + if self.server_ip6.is_some() {
                wire::OVERHEAD_V6 + wire::IPV6_SAVING
            } else {
                wire::OVERHEAD_V4 + wire::IPV4_SAVING
            }
            - wire::CONTROL_LEN;
        ensure!(
            (576 + wire::OVERHEAD_V4..=max).contains(&(self.max_frame as usize)),
            "max_frame must be between {} and {max}",
            576 + wire::OVERHEAD_V4
        );
        ensure!(
            self.users.len() < edup_common::maps::MAX_USERS as usize,
            "at most 65535 users are supported"
        );
        let mut ids = BTreeSet::new();
        for user in &self.users {
            ensure!(ids.insert(user.id), "duplicate user ID {}", user.id);
            ensure!(!user.password.is_empty(), "user password must not be empty");
        }
        Ok(())
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
        Ok(Config {
            server_ip_be: u32::from_ne_bytes(self.server_ip.octets()),
            nat_ip_be: u32::from_ne_bytes(self.nat_ip.octets()),
            port_be: self.port.to_be(),
            nat_port_min: self.nat_port_min,
            nat_port_max: self.nat_port_max,
            max_frame: self.max_frame,
            server_ip6: self.server_ip6.unwrap_or(Ipv6Addr::UNSPECIFIED).octets(),
            nat_ip6: self.nat_ip6.unwrap_or(Ipv6Addr::UNSPECIFIED).octets(),
            gateway_mac: parse_mac(self.gateway_mac.as_deref())?,
            gateway6_mac: parse_mac(self.gateway6_mac.as_deref())?,
            _pad: [0; 4],
        })
    }
}

fn parse_mac(value: Option<&str>) -> Result<[u8; 6]> {
    let Some(value) = value else {
        return Ok([0; 6]);
    };
    let bytes = value
        .split(':')
        .map(|s| {
            ensure!(s.len() == 2, "MAC must have six hexadecimal octets");
            Ok(u8::from_str_radix(s, 16)?)
        })
        .collect::<Result<Vec<_>>>()?;
    let mac: [u8; 6] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("MAC must have six octets"))?;
    ensure!(
        mac != [0; 6] && mac[0] & 1 == 0,
        "gateway MAC must be nonzero unicast"
    );
    Ok(mac)
}

fn unicast(ip: Ipv4Addr) -> bool {
    let first = ip.octets()[0];
    first != 0 && first != 127 && first < 224 && !ip.is_broadcast()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Settings {
        edup_common::json::parse(include_str!("../../config/server.example.json")).unwrap()
    }
    #[test]
    fn example_and_byte_order() {
        let cfg = config();
        cfg.validate().unwrap();
        #[cfg(target_os = "linux")]
        {
            let raw = cfg.map_config().unwrap();
            assert_eq!(raw.server_ip_be.to_ne_bytes(), [192, 0, 2, 1]);
            assert_eq!(u16::from_be(raw.port_be), 7777);
        }
    }
    #[test]
    fn user_ids_and_capacity() {
        let mut cfg = config();
        cfg.users[0].id = i64::MIN;
        cfg.users[1].id = i64::MAX;
        cfg.validate().unwrap();
        cfg.users[1].id = cfg.users[0].id;
        assert!(cfg.validate().is_err());
        cfg.users[1].id = 0;
        cfg.users[1].password.clear();
        assert!(cfg.validate().is_err());
        cfg.users = (0..65535)
            .map(|id| UserSettings {
                id,
                password: "test".into(),
            })
            .collect();
        cfg.validate().unwrap();
        cfg.users.push(UserSettings {
            id: 65535,
            password: "test".into(),
        });
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn rejects_bad_addresses() {
        for ip in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"] {
            let mut cfg = config();
            cfg.server_ip = ip.parse().unwrap();
            assert!(cfg.validate().is_err());
        }
    }
    #[test]
    fn rejects_ports_mtu_and_unsafe_interface() {
        let mut cfg = config();
        cfg.port = cfg.nat_port_min;
        assert!(cfg.validate().is_err());
        let mut cfg = config();
        cfg.nat_port_min = cfg.nat_port_max + 1;
        assert!(cfg.validate().is_err());
        for mtu in [0, 602, 1573] {
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

    #[test]
    fn ipv6_settings_require_consistent_addresses_and_mtu() {
        let mut c = config();
        c.server_ip6 = Some("2001:db8::1".parse().unwrap());
        assert!(c.validate().is_err());
        c.nat_ip6 = c.server_ip6;
        c.gateway6_mac = Some("02:01:02:03:04:05".into());
        c.validate().unwrap();
        #[cfg(target_os = "linux")]
        {
            let raw = c.map_config().unwrap();
            assert_eq!(raw.nat_ip6, c.nat_ip6.unwrap().octets());
            assert_eq!(raw.gateway6_mac, [2, 1, 2, 3, 4, 5]);
        }
        c.max_frame = 1318;
        assert!(c.validate().is_err());
        c.max_frame = 1319;
        c.validate().unwrap();
        for mac in [
            "",
            "00:00:00:00:00:00",
            "01:02:03:04:05:06",
            "02:01:02:03:04",
            "02:01:02:03:04:gg",
        ] {
            c.gateway6_mac = Some(mac.into());
            assert!(c.validate().is_err(), "{mac}");
        }
        c.gateway6_mac = None;
        c.nat_ip6 = Some("fd66::8".parse().unwrap());
        c.validate().unwrap();
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
