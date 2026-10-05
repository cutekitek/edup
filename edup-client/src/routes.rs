#[cfg(target_os = "linux")]
#[path = "routes_linux.rs"]
mod platform;
#[cfg(target_os = "windows")]
#[path = "routes_windows.rs"]
mod platform;
#[cfg(all(target_os = "linux", feature = "xdp"))]
pub use platform::{Gateway, device_prefixes, dnsmasq_upstreams, interface_prefixes};
pub use platform::{PhysicalRoute, clean_dns, ensure_available, set_dns};

use crate::{config::Action, ipset::Prefix, routing::Plan};
use anyhow::{Result, bail};
use std::{collections::HashMap, net::IpAddr};

/// Bounds the routes DNS answers can add over a long session.
const MAX_HOSTS: usize = 65536;

pub struct Routes {
    table: platform::Table,
    created: Vec<platform::Route>,
    /// TUN interface index of each server.
    tunnels: Vec<u32>,
    ipv6: bool,
    gateway: Option<platform::Gateway>,
    /// Host routes for DNS answers, with their current direction.
    hosts: HashMap<IpAddr, (Action, platform::Route)>,
}
impl Routes {
    /// Installs the server exceptions, then bypass routes, then tunnel
    /// routes, so traffic never loops into a tunnel while the table is
    /// incomplete. `physical` and `tunnels` are by server index.
    pub fn install(
        physical: &[PhysicalRoute],
        tunnels: &[u32],
        servers: &[IpAddr],
        plan: &Plan,
    ) -> Result<Self> {
        for prefix in plan.tunnel.iter().flatten().filter(|p| p.len <= 1) {
            if platform::existing(prefix)? {
                bail!("route {prefix} already exists; stop the other tunnel or route manually");
            }
        }
        let mut guard = Self {
            table: platform::Table::new()?,
            created: Vec::new(),
            tunnels: tunnels.to_vec(),
            ipv6: servers[0].is_ipv6(),
            gateway: None,
            hosts: HashMap::new(),
        };
        for &i in &plan.exceptions {
            let host = Prefix::host(servers[i]);
            // A pre-existing server route belongs to its owner and stays untouched.
            if !platform::existing(&host)? {
                guard.add(physical[i].route(host), true)?;
            }
        }
        for &prefix in &plan.bypass {
            // Identical bypass routes may survive a crash; leave them to their owner.
            let route = guard.gateway()?.route(prefix);
            guard.add(route, false)?;
        }
        for (prefixes, &index) in plan.tunnel.iter().zip(tunnels) {
            for &prefix in prefixes {
                guard.add(platform::Route::tunnel(prefix, index), true)?;
            }
        }
        Ok(guard)
    }
    fn add(&mut self, route: platform::Route, exclusive: bool) -> Result<()> {
        if self.table.add(&route)? {
            self.created.push(route);
        } else if exclusive {
            bail!("route {route} already exists");
        }
        Ok(())
    }
    fn gateway(&mut self) -> Result<&platform::Gateway> {
        if self.gateway.is_none() {
            self.gateway = Some(platform::Gateway::discover(self.ipv6)?);
        }
        Ok(self.gateway.as_ref().unwrap())
    }
    /// Sends `ip` through a tunnel or the default route with a host route,
    /// replacing an earlier host route in another direction.
    pub fn host(&mut self, ip: IpAddr, action: Action) -> Result<()> {
        match self.hosts.get(&ip) {
            Some((current, _)) if *current == action => return Ok(()),
            None if self.hosts.len() >= MAX_HOSTS => {
                bail!("{MAX_HOSTS} DNS host routes exist; not adding {ip}")
            }
            _ => {}
        }
        if let Some((current, old)) = self.hosts.remove(&ip)
            && let Err(error) = self.table.remove(&old)
        {
            self.hosts.insert(ip, (current, old));
            return Err(error);
        }
        let prefix = Prefix::host(ip);
        let route = match action {
            Action::Server(i) => platform::Route::tunnel(prefix, self.tunnels[i]),
            Action::Direct => self.gateway()?.route(prefix),
        };
        // An identical route from elsewhere already sends it the same way.
        if self.table.add(&route)? {
            self.hosts.insert(ip, (action, route));
        }
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.created.len() + self.hosts.len()
    }
    pub fn hosts(&self) -> usize {
        self.hosts.len()
    }
    pub fn clear(&mut self) -> Result<()> {
        self.created
            .extend(self.hosts.drain().map(|(_, (_, route))| route));
        let mut first = None;
        let mut failed = 0;
        // Retain failed deletions so Drop can retry; never delete routes we reused.
        for i in (0..self.created.len()).rev() {
            match self.table.remove(&self.created[i]) {
                Ok(()) => {
                    self.created.remove(i);
                }
                Err(error) => {
                    failed += 1;
                    if first.is_none() {
                        eprintln!("route cleanup failed: {error:#}");
                        first = Some(error);
                    }
                }
            }
        }
        match first {
            Some(e) if failed > 1 => Err(e.context(format!("{failed} routes were not removed"))),
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
impl Drop for Routes {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}
