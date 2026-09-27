use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{net::Ipv4Addr, os::windows::process::CommandExt, process::Command};

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
    source: Ipv4Addr,
    gateway: Ipv4Addr,
}
impl PhysicalRoute {
    pub fn discover(server: Ipv4Addr) -> Result<Self> {
        let text = ps(&format!(
            "$r=@(Find-NetRoute -RemoteIPAddress '{server}'); $a=$r | Where-Object {{$_.PSObject.Properties.Name -contains 'IPAddress'}} | Select-Object -First 1; $n=$r | Where-Object {{$_.PSObject.Properties.Name -contains 'NextHop'}} | Select-Object -First 1; if (!$a -or !$n) {{throw 'No physical IPv4 route'}}; @{{index=[uint32]$n.InterfaceIndex; source=[string]$a.IPAddress; gateway=[string]$n.NextHop}} | ConvertTo-Json -Compress"
        ))?;
        serde_json::from_str(&text).context("read physical Windows route")
    }
    pub fn source(&self) -> Ipv4Addr {
        self.source
    }
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
fn existing(prefix: &str) -> Result<bool> {
    let count = ps(&format!(
        "@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object {{$_.DestinationPrefix -eq '{prefix}'}}).Count"
    ))?;
    Ok(count.parse::<u32>()? != 0)
}
pub struct Route {
    prefix: String,
    index: u32,
    gateway: Ipv4Addr,
}
impl Route {
    pub fn add(&self) -> Result<()> {
        ps(&format!(
            "New-NetRoute -DestinationPrefix '{}' -InterfaceIndex {} -NextHop '{}' -RouteMetric 42760 -PolicyStore ActiveStore | Out-Null",
            self.prefix, self.index, self.gateway
        ))?;
        Ok(())
    }
    pub fn remove(&self) -> Result<()> {
        ps(&format!(
            "Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object {{$_.DestinationPrefix -eq '{}' -and $_.InterfaceIndex -eq {} -and $_.NextHop -eq '{}' -and $_.RouteMetric -eq 42760}} | Remove-NetRoute -Confirm:$false",
            self.prefix, self.index, self.gateway
        ))?;
        Ok(())
    }
}
pub fn plan(
    physical: &PhysicalRoute,
    _interface: &str,
    index: u32,
    server: Ipv4Addr,
) -> Result<Vec<Route>> {
    for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
        ensure!(
            !existing(prefix)?,
            "route {prefix} already exists; stop the other tunnel or use routes=false"
        );
    }
    let mut result = Vec::new();
    let host = format!("{server}/32");
    if !existing(&host)? {
        result.push(Route {
            prefix: host,
            index: physical.index,
            gateway: physical.gateway,
        });
    }
    for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
        result.push(Route {
            prefix: prefix.into(),
            index,
            gateway: Ipv4Addr::UNSPECIFIED,
        });
    }
    Ok(result)
}
