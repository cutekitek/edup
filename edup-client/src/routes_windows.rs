use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{net::IpAddr, os::windows::process::CommandExt, process::Command};

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
        "@(Get-NetRoute -PolicyStore ActiveStore | Where-Object {{$_.DestinationPrefix -eq '{prefix}'}}).Count"
    ))?;
    Ok(count.parse::<u32>()? != 0)
}
pub struct Route {
    prefix: String,
    index: u32,
    gateway: IpAddr,
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
            "Get-NetRoute -PolicyStore ActiveStore | Where-Object {{$_.DestinationPrefix -eq '{}' -and $_.InterfaceIndex -eq {} -and $_.NextHop -eq '{}' -and $_.RouteMetric -eq 42760}} | Remove-NetRoute -Confirm:$false",
            self.prefix, self.index, self.gateway
        ))?;
        Ok(())
    }
}
pub fn plan(
    physical: &PhysicalRoute,
    _interface: &str,
    index: u32,
    server: IpAddr,
) -> Result<Vec<Route>> {
    let prefixes = if server.is_ipv6() {
        ["::/1", "8000::/1"]
    } else {
        ["0.0.0.0/1", "128.0.0.0/1"]
    };
    for prefix in prefixes {
        ensure!(
            !existing(prefix)?,
            "route {prefix} already exists; stop the other tunnel or use routes=false"
        );
    }
    let mut result = Vec::new();
    let host = format!("{server}/{}", if server.is_ipv6() { 128 } else { 32 });
    if !existing(&host)? {
        result.push(Route {
            prefix: host,
            index: physical.index,
            gateway: physical.gateway,
        });
    }
    for prefix in prefixes {
        result.push(Route {
            prefix: prefix.into(),
            index,
            gateway: if prefix.contains(':') {
                "::".parse().unwrap()
            } else {
                "0.0.0.0".parse().unwrap()
            },
        });
    }
    Ok(result)
}
