use crate::ipset::Prefix;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::windows::process::CommandExt,
    process::Command,
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS},
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    },
    Networking::WinSock::{AF_INET, AF_INET6, MIB_IPPROTO_NETMGMT, SOCKADDR_INET},
};

// Scripts interpolate only parsed IP addresses, integer indices and a validated
// ASCII interface name. Passwords and paths never enter PowerShell command text.
fn ps(script: &str) -> Result<String> {
    let output=Command::new("powershell.exe").args(["-NoProfile","-NonInteractive","-Command",&format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); {script}")])
        .creation_flags(0x08000000).output().context("run Windows NetTCPIP PowerShell commands")?;
    ensure!(
        output.status.success(),
        "route command failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)?
        .trim_start_matches('\u{feff}')
        .trim()
        .to_string())
}
#[derive(Deserialize)]
pub struct PhysicalRoute {
    index: u32,
    source: IpAddr,
    gateway: IpAddr,
}
impl PhysicalRoute {
    pub fn discover(server: IpAddr) -> Result<Self> {
        let text = ps(&format!(
            "$r=@(Find-NetRoute -RemoteIPAddress '{server}'); $a=$r | Where-Object {{$_.PSObject.Properties.Name -contains 'IPAddress'}} | Select-Object -First 1; $n=$r | Where-Object {{$_.PSObject.Properties.Name -contains 'NextHop'}} | Select-Object -First 1; if (!$a -or !$n) {{throw 'No physical route'}}; @{{index=[uint32]$n.InterfaceIndex; source=[string]$a.IPAddress; gateway=[string]$n.NextHop}} | ConvertTo-Json -Compress"
        ))?;
        serde_json::from_str(&text).context("read physical Windows route")
    }
    pub fn source(&self) -> IpAddr {
        self.source
    }
    pub fn route(&self, prefix: Prefix) -> Route {
        Route {
            prefix,
            index: self.index,
            gateway: self.gateway,
        }
    }
}
/// The preferred active default route: bypassed destinations keep using it,
/// as they would without the tunnel's broader routes.
#[derive(Deserialize)]
pub struct Gateway {
    index: u32,
    gateway: IpAddr,
}
impl Gateway {
    pub fn discover(ipv6: bool) -> Result<Self> {
        let (prefix, family) = if ipv6 {
            ("::/0", "IPv6")
        } else {
            ("0.0.0.0/0", "IPv4")
        };
        let text = ps(&format!(
            "$r=@(Get-NetRoute -DestinationPrefix '{prefix}' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | ForEach-Object {{$i=Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily {family} -ErrorAction SilentlyContinue; if ($i -and $i.ConnectionState -eq 'Connected') {{[pscustomobject]@{{index=[uint32]$_.InterfaceIndex; gateway=[string]$_.NextHop; metric=[uint32]($_.RouteMetric + $i.InterfaceMetric)}}}}}}) | Sort-Object metric | Select-Object -First 1; if (!$r) {{throw 'bypass routes require a default route'}}; $r | Select-Object index,gateway | ConvertTo-Json -Compress"
        ))?;
        serde_json::from_str(&text).context("read Windows default route")
    }
    pub fn route(&self, prefix: Prefix) -> Route {
        Route {
            prefix,
            index: self.index,
            gateway: self.gateway,
        }
    }
}
/// Makes the Wintun adapter the preferred DNS interface with `address` as its
/// server. Both settings disappear with the adapter, even after a crash.
/// Nothing to restore: the settings disappear with the adapter.
pub enum DnsRestore {}
pub fn clean_dns() -> Result<()> {
    Ok(())
}

pub fn set_dns(_interface: &str, index: u32, forwarder: SocketAddr) -> Result<Option<DnsRestore>> {
    // Adapter DNS servers have no port.
    ensure!(
        forwarder.port() == 53,
        "dns.port must be 53 for dns.set_system on Windows"
    );
    let address = forwarder.ip();
    let family = if address.is_ipv6() { "IPv6" } else { "IPv4" };
    ps(&format!(
        "Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses '{address}'; Set-NetIPInterface -InterfaceIndex {index} -AddressFamily {family} -InterfaceMetric 1; Clear-DnsClientCache"
    ))
    .context("configure Windows DNS; set dns.set_system to false to configure DNS manually")?;
    Ok(None)
}
pub fn ensure_available(name: &str) -> Result<()> {
    let count = ps(&format!(
        "@(Get-NetAdapter -IncludeHidden | Where-Object {{$_.Name -eq '{name}'}}).Count"
    ))?;
    ensure!(
        count == "0",
        "adapter {name} already exists; refusing to reuse it"
    );
    Ok(())
}
/// Any active route for exactly this prefix, on any interface.
pub fn existing(prefix: &Prefix) -> Result<bool> {
    let count = ps(&format!(
        "@(Get-NetRoute -PolicyStore ActiveStore | Where-Object {{$_.DestinationPrefix -eq '{prefix}'}}).Count"
    ))?;
    Ok(count.parse::<u32>()? != 0)
}

pub struct Route {
    prefix: Prefix,
    index: u32,
    gateway: IpAddr,
}
impl Route {
    pub fn tunnel(prefix: Prefix, index: u32) -> Self {
        let gateway = if prefix.addr.is_ipv6() {
            Ipv6Addr::UNSPECIFIED.into()
        } else {
            Ipv4Addr::UNSPECIFIED.into()
        };
        Self {
            prefix,
            index,
            gateway,
        }
    }
    fn row(&self) -> MIB_IPFORWARD_ROW2 {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceIndex = self.index;
        row.DestinationPrefix.Prefix = sockaddr(self.prefix.addr);
        row.DestinationPrefix.PrefixLength = self.prefix.len;
        row.NextHop = sockaddr(self.gateway);
        row.Metric = METRIC;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row
    }
}
impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} via {} ifindex {}",
            self.prefix, self.gateway, self.index
        )
    }
}
fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    let mut address = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(ip) => {
            address.Ipv4.sin_family = AF_INET;
            address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        }
        IpAddr::V6(ip) => {
            address.Ipv6.sin6_family = AF_INET6;
            address.Ipv6.sin6_addr.u.Byte = ip.octets();
        }
    }
    address
}

const METRIC: u32 = 42760;

/// Active-store routes through the IP Helper API; they vanish on reboot and
/// with the Wintun adapter, and rule-sets may need thousands of them.
pub struct Table;
impl Table {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
    /// Ok(false): this interface already has the route with the same next hop.
    pub fn add(&mut self, route: &Route) -> Result<bool> {
        match unsafe { CreateIpForwardEntry2(&route.row()) } {
            0 => Ok(true),
            ERROR_OBJECT_ALREADY_EXISTS => Ok(false),
            code => Err(std::io::Error::from_raw_os_error(code as i32))
                .with_context(|| format!("add route {route}")),
        }
    }
    pub fn remove(&mut self, route: &Route) -> Result<()> {
        match unsafe { DeleteIpForwardEntry2(&route.row()) } {
            0 | ERROR_NOT_FOUND | ERROR_FILE_NOT_FOUND => Ok(()),
            code => Err(std::io::Error::from_raw_os_error(code as i32))
                .with_context(|| format!("delete route {route}")),
        }
    }
}
