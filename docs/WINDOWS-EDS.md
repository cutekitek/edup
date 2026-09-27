# Windows client: eds.cutekitek.dev

The server is deployed at **45.151.73.43:7777 (UDP)**. The ready-to-run Windows
x64 package is `local/edup-windows-eds.zip`; its unpacked copy is at
`C:\projects\edup\local\windows-client-eds`.

The package includes the current client, Wintun DLL and license, and a matching
`client.toml` with a separate generated password. Keep this configuration private.
The previous server and its client folder remain available.

## Connect

Stop the old edup client with **Ctrl+C** and disable other VPN TUN modes before
switching. Open **PowerShell as Administrator**, then run:

```powershell
Set-Location C:\projects\edup\local\windows-client-eds
.\edup-client.exe --config .\client.toml check
.\edup-client.exe --config .\client.toml run
```

Leave the window open. The configured user is **8**, tunnel address
**10.66.0.8**, adapter **edup0**, and MTU **1400**. The endpoint is pinned to the
server's IPv4 address in the configuration. Use this profile on one device at a
time. To move it to another directory, copy the entire folder and adjust the
`Set-Location` command; keep `wintun.dll` beside the executable.

In another PowerShell window:

```powershell
ping -4 1.1.1.1
curl.exe --noproxy "*" -4 https://1.1.1.1/cdn-cgi/trace
```

Expect `ip=45.151.73.43`. Stop with **Ctrl+C** so the client removes its routes.
The client tunnels IPv4 and leaves DNS settings and IPv6 unchanged. It does not
provide a kill switch. The protocol uses password-based obfuscation, not encryption.

## Server administration

```powershell
ssh root@eds.cutekitek.dev "systemctl status edup-server --no-pager"
ssh root@eds.cutekitek.dev "/usr/local/sbin/edup-server stats"
ssh root@eds.cutekitek.dev "/usr/local/sbin/edup-server users"
```

The root-only configuration is `/etc/edup/server.toml`. The systemd service is
enabled at boot. Use `systemctl stop edup-server` or `systemctl start edup-server`
on the server to stop/start it. After editing its configuration, use
`systemctl reload edup-server`; reloading resets NAT and active connections.

Native XDP runs on `ens3`; the NAT port range is 20000–29999. Existing sing-box
services remain active. A successful deployment check included a service restart,
kernel packet regressions, and Windows traffic with the expected public IP.
No server reboot was performed.

## Troubleshooting

- `adapter edup0 already exists`: stop the old client first.
- `route ... already exists`: stop the conflicting VPN and retry.
- Missing `wintun.dll`: restore the DLL from this package beside the executable.
- Access denied: use an Administrator PowerShell window.
- No traffic: verify UDP 7777 reachability and use the matching configuration.
  `Test-NetConnection -Port 7777` tests TCP and cannot validate this UDP service.
- For periodic client counters, set `$env:EDUP_DIAGNOSTICS = '1'` before running.
  Remove it afterward with `Remove-Item Env:\EDUP_DIAGNOSTICS`.

More background and recovery instructions: [Windows guide](WINDOWS.md).
That guide's old endpoint `195.58.134.147` applies to the previous deployment;
use `45.151.73.43` for this profile.
