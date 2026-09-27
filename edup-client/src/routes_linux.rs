use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{net::IpAddr, process::Command};

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
fn existing(prefix: &str) -> Result<bool> {
    let json = ip(&args(&[
        "-j",
        if prefix.contains(':') { "-6" } else { "-4" },
        "route",
        "show",
        "exact",
        prefix,
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
        let route = routes.remove(0);
        ensure!(
            route.dev != "lo",
            "server must be reached through a physical interface"
        );
        ensure!(
            route.table.as_ref().is_none_or(|t| t == "main" || t == 254),
            "automatic routing supports the main route table only"
        );
        Ok(route)
    }
    pub fn source(&self) -> IpAddr {
        self.prefsrc
    }
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
    prefix: String,
    dev: String,
    gateway: Option<IpAddr>,
}
impl Route {
    fn command(&self, verb: &str) -> Vec<String> {
        let mut a = args(&[
            if self.prefix.contains(':') {
                "-6"
            } else {
                "-4"
            },
            "route",
            verb,
            &self.prefix,
        ]);
        if let Some(gateway) = self.gateway {
            a.extend(args(&["via", &gateway.to_string()]));
        }
        a.extend(args(&[
            "dev", &self.dev, "metric", "42760", "proto", "static",
        ]));
        a
    }
    pub fn add(&self) -> Result<()> {
        ip(&self.command("add"))?;
        Ok(())
    }
    pub fn remove(&self) -> Result<()> {
        ip(&self.command("del"))?;
        Ok(())
    }
}
pub fn plan(
    physical: &PhysicalRoute,
    interface: &str,
    _index: u32,
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
    let host = format!("{server}/{}", if server.is_ipv6() { 128 } else { 32 });
    let mut result = Vec::new();
    if !existing(&host)? {
        result.push(Route {
            prefix: host,
            dev: physical.dev.clone(),
            gateway: physical.gateway,
        });
    }
    for prefix in prefixes {
        result.push(Route {
            prefix: prefix.into(),
            dev: interface.into(),
            gateway: None,
        });
    }
    Ok(result)
}
