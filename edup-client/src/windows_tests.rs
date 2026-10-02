use super::*;
use std::{os::windows::process::CommandExt, process::Command};

pub(super) fn ps(script: &str) {
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("$ErrorActionPreference='Stop'; {script}"),
        ])
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

struct TestRoute(u32);
impl Drop for TestRoute {
    fn drop(&mut self) {
        ps(&format!(
            "Get-NetRoute -AddressFamily IPv4 -InterfaceIndex {} -DestinationPrefix 203.0.113.7/32 -PolicyStore ActiveStore | Remove-NetRoute -Confirm:$false",
            self.0
        ));
    }
}

#[test]
#[ignore = "requires Administrator and EDUP_TEST_WINTUN_DLL; temporary adapter and TEST-NET host route"]
fn queued_wintun_bursts_are_drained() {
    let mut cfg: config::Settings =
        edup_common::json::parse(include_str!("../../config/client.example.json")).unwrap();
    cfg.interface = "edup-burst-test".into();
    cfg.wintun_dll = Some(
        std::env::var_os("EDUP_TEST_WINTUN_DLL")
            .expect("set DLL path")
            .into(),
    );
    routes::ensure_available(&cfg.interface).unwrap();
    ps(
        "if (@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object DestinationPrefix -eq '203.0.113.7/32').Count) {throw 'test destination already has a host route'}",
    );
    let tun = create_device(&cfg).unwrap();
    let index = tun.if_index().unwrap();
    ps(&format!(
        "New-NetRoute -DestinationPrefix 203.0.113.7/32 -InterfaceIndex {index} -NextHop 0.0.0.0 -PolicyStore ActiveStore | Out-Null"
    ));
    let route = TestRoute(index);
    ps(&format!(
        "$until=(Get-Date).AddSeconds(8); while (!(Get-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv4 | Where-Object AddressState -eq Preferred)) {{if ((Get-Date) -gt $until) {{throw 'IPv4 address not ready'}}; Start-Sleep -Milliseconds 100}}"
    ));
    let socket = UdpSocket::bind((cfg.address().unwrap(), 0)).unwrap();
    let event = InterruptEvent::new().unwrap();
    let mut buf = vec![0; 65536];
    for burst in 0..2u8 {
        // Exhaust the ring, which also arms Wintun's notification for the next burst.
        while tun.try_recv(&mut buf).is_ok() {}
        for n in 0..32u8 {
            let mut data = [0x5au8; 256];
            data[..4].copy_from_slice(&[0xed, 0x75, burst, n]);
            socket.send_to(&data, "203.0.113.7:53000").unwrap();
        }
        let until = Instant::now() + Duration::from_secs(2);
        let mut seen = [false; 32];
        while seen.contains(&false) {
            assert!(Instant::now() < until, "queued packets stranded: {seen:?}");
            match receive_tun(&tun, &mut buf, &event) {
                Ok(n)
                    if n >= 32
                        && buf[0] == 0x45
                        && buf[9] == 17
                        && buf[16..20] == [203, 0, 113, 7]
                        && buf[28..31] == [0xed, 0x75, burst] =>
                {
                    seen[buf[31] as usize] = true;
                }
                Ok(_) => {}
                Err(e) if temporary(&e) => {}
                Err(e) => panic!("{e}"),
            }
        }
    }
    drop(socket);
    drop(route);
    drop(tun);
    routes::ensure_available(&cfg.interface).unwrap();
}

#[test]
#[ignore = "requires Administrator and EDUP_TEST_WINTUN_DLL; creates a temporary adapter, no tunnel routes"]
fn ipv4_mtu_below_ipv6_minimum() {
    let mut cfg: config::Settings =
        edup_common::json::parse(include_str!("../../config/client.example.json")).unwrap();
    cfg.interface = "edup-mtu-test".into();
    cfg.mtu = 1200;
    cfg.wintun_dll = Some(
        std::env::var_os("EDUP_TEST_WINTUN_DLL")
            .expect("set DLL path")
            .into(),
    );
    cfg.validate().unwrap();
    routes::ensure_available(&cfg.interface).unwrap();
    let tun = create_device(&cfg).unwrap();
    assert_eq!(tun.mtu().unwrap(), 1200);
    assert!(tun.mtu_v6().unwrap() >= 1280);
    drop(tun);
    routes::ensure_available(&cfg.interface).unwrap();
}

#[test]
#[ignore = "requires Administrator and EDUP_LIVE_CONFIG for a dedicated server user; temporary /32 routes to 1.1.1.1 and 104.16.0.35"]
fn live_offload() -> Result<()> {
    let path = std::env::var_os("EDUP_LIVE_CONFIG").context("set EDUP_LIVE_CONFIG")?;
    let mut cfg = config::Settings::load(std::path::Path::new(&path))?;
    ensure!(
        cfg.routing.is_manual(),
        "live test requires default_route=bypass without routes"
    );
    ensure!(cfg.mtu == 1400, "live test requires MTU 1400");
    cfg.interface = "edup-offload".into();
    cfg.offload = true;
    routes::ensure_available(&cfg.interface)?;
    ps(
        "foreach ($p in @('1.1.1.1/32','104.16.0.35/32')) {if (@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object DestinationPrefix -eq $p).Count) {throw 'live test destination already has a host route'}}",
    );
    let physical = routes::PhysicalRoute::discover(cfg.server.ip())?;
    let socket = UdpSocket::bind((physical.source(), 0))?;
    socket.connect(cfg.server)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    socket.set_write_timeout(Some(Duration::from_millis(200)))?;
    socket2::SockRef::from(&socket).set_recv_buffer_size(4 * 1024 * 1024)?;
    let socket = udp::Transport::new(socket, true)?;
    let tun = create_device(&cfg)?;
    let index = tun.if_index()?;
    struct LiveRoutes(u32);
    impl Drop for LiveRoutes {
        fn drop(&mut self) {
            ps(&format!(
                "Get-NetRoute -InterfaceIndex {} -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object {{$_.RouteMetric -eq 42761 -and $_.DestinationPrefix -in @('1.1.1.1/32','104.16.0.35/32')}} | Remove-NetRoute -Confirm:$false",
                self.0
            ));
        }
    }
    let route_guard = LiveRoutes(index);
    ps(&format!(
        "foreach ($p in @('1.1.1.1/32','104.16.0.35/32')) {{New-NetRoute -DestinationPrefix $p -InterfaceIndex {index} -NextHop 0.0.0.0 -RouteMetric 42761 -PolicyStore ActiveStore | Out-Null}}; $until=(Get-Date).AddSeconds(8); while (!(Get-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv4 | Where-Object AddressState -eq Preferred)) {{if ((Get-Date) -gt $until) {{throw 'IPv4 address not ready'}}; Start-Sleep -Milliseconds 100}}"
    ));
    let key = derive_key(&cfg.password);
    let counts = Counters::default();
    let stop = AtomicBool::new(false);
    let event = InterruptEvent::new()?;
    let result = std::thread::scope(|scope| -> Result<()> {
        let send = scope.spawn(|| send_loop(&tun, &socket, &cfg, &key, &counts, &stop, &event));
        let receive =
            scope.spawn(|| receive_loop(&tun, &socket, &cfg, &key, &counts, &stop, &event));
        let test = (|| -> Result<()> {
            let dns = UdpSocket::bind((cfg.address()?, 0))?;
            dns.set_read_timeout(Some(Duration::from_secs(5)))?;
            dns.connect("1.1.1.1:53")?;
            dns.send(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")?;
            let mut response = [0; 2048];
            let len = dns.recv(&mut response)?;
            ensure!(
                len >= 12 && response[..2] == [0x12, 0x34] && response[3] & 15 == 0,
                "DNS response failed"
            );
            let output = Command::new("ping.exe")
                .args([
                    "-4",
                    "-S",
                    &cfg.address()?.to_string(),
                    "-f",
                    "-l",
                    "1372",
                    "-n",
                    "2",
                    "1.1.1.1",
                ])
                .creation_flags(0x08000000)
                .output()?;
            ensure!(output.status.success(), "MTU ping failed");
            println!("PASS: live UDP DNS and ICMP MTU 1400");
            let mut curl = Command::new("curl.exe");
            let output = curl
                .args([
                    "--ipv4",
                    "--noproxy",
                    "*",
                    "--interface",
                    &cfg.address()?.to_string(),
                    "--resolve",
                    "speed.cloudflare.com:443:104.16.0.35",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "30",
                    "--output",
                    "NUL",
                    "--write-out",
                    "HTTP %{http_code}, downloaded %{size_download} bytes in %{time_total}s\n",
                    "https://speed.cloudflare.com/__down?bytes=10000000",
                ])
                .creation_flags(0x08000000)
                .output()?;
            ensure!(
                output.status.success(),
                "HTTPS download: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            println!("{}", String::from_utf8_lossy(&output.stdout));
            Ok(())
        })();
        stop.store(true, Relaxed);
        let _ = event.trigger();
        let tx = send
            .join()
            .map_err(|_| anyhow::anyhow!("sender panicked"))?;
        let rx = receive
            .join()
            .map_err(|_| anyhow::anyhow!("receiver panicked"))?;
        test.and(tx).and(rx)
    });
    counts.report();
    report_offload(&socket);
    drop(route_guard);
    drop(tun);
    routes::ensure_available(&cfg.interface)?;
    result
}
