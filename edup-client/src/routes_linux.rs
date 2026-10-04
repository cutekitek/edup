use crate::ipset::Prefix;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
    process::Command,
};

fn ip(args: &[String]) -> Result<String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .context("run iproute2 (ip)")?;
    ensure!(
        out.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8(out.stdout)?)
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}
/// Any route for exactly this prefix in the main table, whatever its metric.
pub fn existing(prefix: &Prefix) -> Result<bool> {
    let json = ip(&args(&[
        "-j",
        if prefix.addr.is_ipv6() { "-6" } else { "-4" },
        "route",
        "show",
        "exact",
        &prefix.to_string(),
    ]))?;
    Ok(!serde_json::from_str::<Vec<serde_json::Value>>(&json)?.is_empty())
}

#[derive(Deserialize)]
pub struct PhysicalRoute {
    dev: String,
    gateway: Option<IpAddr>,
    #[serde(alias = "src")]
    prefsrc: IpAddr,
    table: Option<serde_json::Value>,
    #[serde(skip)]
    index: u32,
}
impl PhysicalRoute {
    pub fn discover(server: IpAddr) -> Result<Self> {
        let json = ip(&args(&[
            "-j",
            if server.is_ipv6() { "-6" } else { "-4" },
            "route",
            "get",
            &server.to_string(),
        ]))?;
        let mut routes: Vec<Self> = serde_json::from_str(&json).context("read physical route")?;
        ensure!(routes.len() == 1, "expected one physical route");
        let mut route = routes.remove(0);
        ensure!(
            route.dev != "lo",
            "server must be reached through a physical interface"
        );
        ensure!(
            route.table.as_ref().is_none_or(|t| t == "main" || t == 254),
            "automatic routing supports the main route table only"
        );
        route.index = if_index(&route.dev)?;
        Ok(route)
    }
    pub fn source(&self) -> IpAddr {
        self.prefsrc
    }
    #[cfg_attr(not(feature = "xdp"), allow(dead_code))]
    pub fn device(&self) -> (&str, u32) {
        (&self.dev, self.index)
    }
    pub fn route(&self, prefix: Prefix) -> Route {
        Route {
            prefix,
            index: self.index,
            gateway: self.gateway,
        }
    }
}
/// The main table's preferred default route: bypassed destinations keep
/// using it, as they would without the tunnel's broader routes.
pub struct Gateway {
    index: u32,
    gateway: Option<IpAddr>,
}
impl Gateway {
    pub fn discover(ipv6: bool) -> Result<Self> {
        #[derive(Deserialize)]
        struct Default {
            dev: Option<String>,
            gateway: Option<IpAddr>,
            metric: Option<u32>,
        }
        let json = ip(&args(&[
            "-j",
            if ipv6 { "-6" } else { "-4" },
            "route",
            "show",
            "default",
        ]))?;
        let routes: Vec<Default> = serde_json::from_str(&json).context("read default route")?;
        let route = routes
            .into_iter()
            .filter(|r| r.dev.is_some())
            .min_by_key(|r| r.metric.unwrap_or(0))
            .context("bypass routes require a default route")?;
        let dev = route.dev.unwrap();
        Ok(Self {
            index: if_index(&dev)?,
            gateway: route.gateway,
        })
    }
    pub fn route(&self, prefix: Prefix) -> Route {
        Route {
            prefix,
            index: self.index,
            gateway: self.gateway,
        }
    }
    #[cfg_attr(not(feature = "xdp"), allow(dead_code))]
    pub fn index(&self) -> u32 {
        self.index
    }
}
/// Main-table routes through `dev` other than default routes: the local
/// network and other specific system routes.
#[cfg_attr(not(feature = "xdp"), allow(dead_code))]
pub fn device_prefixes(dev: &str, ipv6: bool) -> Result<Vec<Prefix>> {
    #[derive(Deserialize)]
    struct Entry {
        dst: String,
        #[serde(rename = "type")]
        kind: Option<String>,
    }
    let json = ip(&args(&[
        "-j",
        if ipv6 { "-6" } else { "-4" },
        "route",
        "show",
        "table",
        "main",
        "dev",
        dev,
    ]))?;
    let routes: Vec<Entry> = serde_json::from_str(&json).context("read interface routes")?;
    Ok(routes
        .into_iter()
        .filter(|r| r.kind.as_deref().is_none_or(|k| k == "unicast"))
        .filter_map(|r| r.dst.parse::<Prefix>().ok())
        .filter(|p| p.len != 0)
        .collect())
}
/// Main-table device routes of every interface, without default routes:
/// the networks each interface reaches directly.
#[cfg_attr(not(feature = "xdp"), allow(dead_code))]
pub fn interface_prefixes(ipv6: bool) -> Result<Vec<(String, Prefix)>> {
    #[derive(Deserialize)]
    struct Entry {
        dst: String,
        dev: Option<String>,
        gateway: Option<IpAddr>,
        #[serde(rename = "type")]
        kind: Option<String>,
    }
    let json = ip(&args(&[
        "-j",
        if ipv6 { "-6" } else { "-4" },
        "route",
        "show",
        "table",
        "main",
    ]))?;
    let routes: Vec<Entry> = serde_json::from_str(&json).context("read routes")?;
    Ok(routes
        .into_iter()
        .filter(|r| r.gateway.is_none() && r.kind.as_deref().is_none_or(|k| k == "unicast"))
        .filter_map(|r| Some((r.dev?, r.dst.parse::<Prefix>().ok()?)))
        .filter(|(_, p)| p.len != 0)
        .collect())
}
fn if_index(name: &str) -> Result<u32> {
    let c = std::ffi::CString::new(name)?;
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    ensure!(index != 0, "interface {name} not found");
    Ok(index)
}
/// Sends all names to `forwarder` through systemd-resolved's settings for the
/// TUN link, which disappear with the link even if the client crashes. On
/// OpenWrt, dnsmasq forwards to `forwarder` until the result is dropped.
pub fn set_dns(interface: &str, _index: u32, forwarder: SocketAddr) -> Result<Option<DnsRestore>> {
    if openwrt() {
        return dnsmasq(forwarder).map(Some);
    }
    // systemd 246 and newer take a port.
    let server = if forwarder.port() == 53 {
        forwarder.ip().to_string()
    } else {
        forwarder.to_string()
    };
    let resolvectl = |args: &[&str]| -> Result<()> {
        let out = Command::new("resolvectl")
            .args(args)
            .output()
            .context("run resolvectl")?;
        ensure!(
            out.status.success(),
            "resolvectl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(())
    };
    resolvectl(&["dns", interface, &server])
        .and_then(|()| resolvectl(&["domain", interface, "~."]))
        .context(
            "configure systemd-resolved; set dns.set_system to false to configure DNS manually",
        )?;
    // Older systemd lacks default-route; "~." already routes every name.
    let _ = resolvectl(&["default-route", interface, "yes"]);
    let _ = resolvectl(&["flush-caches"]);
    let stub = std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .any(|l| l.split_whitespace().eq(["nameserver", "127.0.0.53"]));
    if !stub {
        eprintln!(
            "warning: /etc/resolv.conf does not use the systemd-resolved stub; programs reading it bypass the DNS forwarder at {forwarder}"
        );
    }
    Ok(None)
}

/// File in each dnsmasq instance's `conf-dir` (OpenWrt: /tmp, gone at reboot).
const DNSMASQ_FILE: &str = "edup.conf";

/// OpenWrt's dnsmasq forwarding every name to the forwarder. A crashed
/// client leaves the file behind; [`clean_dns`] removes it at the next start.
pub struct DnsRestore {
    files: Vec<PathBuf>,
}
impl Drop for DnsRestore {
    fn drop(&mut self) {
        for file in &self.files {
            if let Err(error) = std::fs::remove_file(file)
                && error.kind() != io::ErrorKind::NotFound
            {
                eprintln!("remove {}: {error}", file.display());
            }
        }
        if let Err(error) = restart_dnsmasq() {
            eprintln!("DNS cleanup failed: {error:#}");
        }
    }
}

fn openwrt() -> bool {
    Path::new("/etc/openwrt_release").exists()
}

/// Lines of the configurations /etc/init.d/dnsmasq writes, one per instance.
fn dnsmasq_settings() -> Result<Vec<String>> {
    let mut lines = Vec::new();
    for entry in std::fs::read_dir("/var/etc").context("read /var/etc")? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("dnsmasq.conf."))
        {
            lines.extend(std::fs::read_to_string(&path)?.lines().map(String::from));
        }
    }
    Ok(lines)
}

fn dnsmasq_dirs() -> Result<Vec<PathBuf>> {
    Ok(dnsmasq_settings()?
        .iter()
        .filter_map(|line| line.strip_prefix("conf-dir="))
        // conf-dir=<dir>[,<extension filter>...]
        .map(|dir| PathBuf::from(dir.split(',').next().unwrap_or_default()))
        .collect())
}

/// On OpenWrt, removes the dnsmasq settings a crashed client left behind:
/// dnsmasq would otherwise keep forwarding to a forwarder that is gone.
pub fn clean_dns() -> Result<()> {
    if !openwrt() {
        return Ok(());
    }
    let mut removed = false;
    for dir in dnsmasq_dirs()? {
        let file = dir.join(DNSMASQ_FILE);
        match std::fs::remove_file(&file) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("remove {}", file.display())),
        }
    }
    if removed {
        eprintln!("removing dnsmasq settings left by an earlier client");
        restart_dnsmasq()?;
    }
    Ok(())
}

/// Plain upstream addresses dnsmasq forwards to on OpenWrt: from the WAN
/// (resolv.conf.auto) and configured forwards, not per-domain servers.
#[cfg_attr(not(feature = "xdp"), allow(dead_code))]
pub fn dnsmasq_upstreams() -> Vec<IpAddr> {
    if !openwrt() {
        return Vec::new();
    }
    let mut out: Vec<IpAddr> = std::fs::read_to_string("/tmp/resolv.conf.d/resolv.conf.auto")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.strip_prefix("nameserver")?.trim().parse().ok())
        .collect();
    for line in dnsmasq_settings().unwrap_or_default() {
        // server=<address>[#port]; server=/<domain>/... only serves its domains.
        if let Some(server) = line.strip_prefix("server=")
            && let Ok(ip) = server.split('#').next().unwrap_or_default().parse()
        {
            out.push(ip);
        }
    }
    out.sort();
    out.dedup();
    out
}

fn dnsmasq(forwarder: SocketAddr) -> Result<DnsRestore> {
    let dirs = dnsmasq_dirs()?;
    ensure!(
        !dirs.is_empty(),
        "no running dnsmasq instance with a conf-dir; set dns.set_system to false to configure DNS manually"
    );
    let text = format!(
        "# edup-client: every name through its DNS forwarder\nno-resolv\nserver={}#{}\n",
        forwarder.ip(),
        forwarder.port()
    );
    let mut restore = DnsRestore { files: Vec::new() };
    for dir in dirs {
        let file = dir.join(DNSMASQ_FILE);
        std::fs::create_dir_all(&dir)
            .and_then(|()| std::fs::write(&file, &text))
            .with_context(|| format!("write {}", file.display()))?;
        restore.files.push(file);
    }
    // A restart also empties dnsmasq's cache.
    restart_dnsmasq().context("set dns.set_system to false to configure DNS manually")?;
    Ok(restore)
}

fn restart_dnsmasq() -> Result<()> {
    let out = Command::new("/etc/init.d/dnsmasq")
        .arg("restart")
        .output()
        .context("run /etc/init.d/dnsmasq")?;
    ensure!(
        out.status.success(),
        "/etc/init.d/dnsmasq restart: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(())
}
pub fn ensure_available(name: &str) -> Result<()> {
    let json = ip(&args(&["-j", "link", "show"]))?;
    let links: Vec<serde_json::Value> = serde_json::from_str(&json)?;
    ensure!(
        !links.iter().any(|l| l["ifname"] == name),
        "interface {name} already exists; refusing to reuse it"
    );
    Ok(())
}

pub struct Route {
    prefix: Prefix,
    index: u32,
    gateway: Option<IpAddr>,
}
impl Route {
    pub fn tunnel(prefix: Prefix, index: u32) -> Self {
        Self {
            prefix,
            index,
            gateway: None,
        }
    }
}
impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix)?;
        if let Some(gateway) = self.gateway {
            write!(f, " via {gateway}")?;
        }
        write!(f, " ifindex {}", self.index)
    }
}

// rtnetlink, one acknowledged request per route: rule-sets can produce
// thousands of routes, and ownership stays exact if a request fails midway.
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RT_SCOPE_NOWHERE: u8 = 255;
const RTN_UNICAST: u8 = 1;
const METRIC: u32 = 42760;

pub struct Table {
    fd: OwnedFd,
    seq: u32,
}
impl Table {
    pub fn new() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        ensure!(
            fd >= 0,
            "open route netlink socket: {}",
            io::Error::last_os_error()
        );
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const timeout).cast(),
                size_of_val(&timeout) as _,
            )
        };
        ensure!(
            rc == 0,
            "set netlink timeout: {}",
            io::Error::last_os_error()
        );
        Ok(Self { fd, seq: 0 })
    }
    /// Ok(false): a route with this prefix and metric already exists.
    pub fn add(&mut self, route: &Route) -> Result<bool> {
        match self.request(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, route) {
            Ok(()) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(false),
            Err(e) => Err(e).with_context(|| format!("add route {route}")),
        }
    }
    pub fn remove(&mut self, route: &Route) -> Result<()> {
        match self.request(RTM_DELROUTE, 0, route) {
            // Already gone, possibly together with its interface.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ESRCH | libc::ENODEV)) => Ok(()),
            result => result.with_context(|| format!("delete route {route}")),
        }
    }
    fn request(&mut self, kind: u16, flags: u16, route: &Route) -> io::Result<()> {
        self.seq = self.seq.wrapping_add(1);
        let add = kind == RTM_NEWROUTE;
        // As iproute2: deletion matches any scope; on-link IPv4 routes are link scope.
        let scope = match route.prefix.addr {
            _ if !add => RT_SCOPE_NOWHERE,
            IpAddr::V4(_) if route.gateway.is_none() => RT_SCOPE_LINK,
            _ => RT_SCOPE_UNIVERSE,
        };
        let family = if route.prefix.addr.is_ipv6() {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };
        let mut msg = Vec::with_capacity(80);
        // struct nlmsghdr; the length is patched below.
        msg.extend(0u32.to_ne_bytes());
        msg.extend(kind.to_ne_bytes());
        msg.extend((NLM_F_REQUEST | NLM_F_ACK | flags).to_ne_bytes());
        msg.extend(self.seq.to_ne_bytes());
        msg.extend(0u32.to_ne_bytes());
        // struct rtmsg
        msg.extend([
            family as u8,
            route.prefix.len,
            0,
            0,
            RT_TABLE_MAIN,
            RTPROT_STATIC,
            scope,
            if add { RTN_UNICAST } else { 0 },
        ]);
        msg.extend(0u32.to_ne_bytes());
        if route.prefix.len != 0 {
            attribute(&mut msg, RTA_DST, &octets(route.prefix.addr));
        }
        if let Some(gateway) = route.gateway {
            attribute(&mut msg, RTA_GATEWAY, &octets(gateway));
        }
        attribute(&mut msg, RTA_OIF, &route.index.to_ne_bytes());
        attribute(&mut msg, RTA_PRIORITY, &METRIC.to_ne_bytes());
        let len = msg.len() as u32;
        msg[..4].copy_from_slice(&len.to_ne_bytes());
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                msg.as_ptr().cast(),
                msg.len(),
                0,
                (&raw const kernel).cast(),
                size_of_val(&kernel) as _,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = [0u8; 8192];
        loop {
            let n =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let mut data = &buf[..n as usize];
            while data.len() >= 16 {
                let len = u32::from_ne_bytes(data[..4].try_into().unwrap()) as usize;
                let typ = u16::from_ne_bytes(data[4..6].try_into().unwrap());
                let seq = u32::from_ne_bytes(data[8..12].try_into().unwrap());
                if !(16..=data.len()).contains(&len) {
                    break;
                }
                if typ == NLMSG_ERROR && seq == self.seq && len >= 20 {
                    // struct nlmsgerr: a negative errno, or 0 for the acknowledgement.
                    let code = i32::from_ne_bytes(data[16..20].try_into().unwrap());
                    return match code {
                        0 => Ok(()),
                        code => Err(io::Error::from_raw_os_error(-code)),
                    };
                }
                data = &data[((len + 3) & !3).min(data.len())..];
            }
        }
    }
}
fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}
fn attribute(msg: &mut Vec<u8>, kind: u16, data: &[u8]) {
    msg.extend((4 + data.len() as u16).to_ne_bytes());
    msg.extend(kind.to_ne_bytes());
    msg.extend(data);
    msg.resize((msg.len() + 3) & !3, 0);
}
