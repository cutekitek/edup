//! Real Wintun + remote UDP peer validation, without default-route changes.
use super::*;
use crate::windows_tests::ps;

#[test]
#[ignore = "requires Administrator, EDUP_TEST_WINTUN_DLL, and EDUP_LAN_PEER running check-windows-lan-server.sh"]
fn lan_roundtrip() -> Result<()> {
    let mut cfg: config::Settings =
        edup_common::json::parse(include_str!("../../config/client.example.json"))
            .map_err(anyhow::Error::msg)?;
    cfg.servers[0].address = std::env::var("EDUP_LAN_PEER")
        .context("set EDUP_LAN_PEER")?
        .parse()?;
    cfg.interface = "edup-lan-test".into();
    cfg.routing = config::Routing {
        default_route: config::Action::Direct,
        routes: Vec::new(),
    };
    cfg.keepalive_secs = 1;
    cfg.offload = std::env::var("EDUP_TEST_OFFLOAD").as_deref() != Ok("false");
    cfg.wintun_dll = Some(
        std::env::var_os("EDUP_TEST_WINTUN_DLL")
            .context("set DLL path")?
            .into(),
    );
    cfg.validate()?;
    routes::ensure_available(&cfg.interface)?;
    ps(
        "if (@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object DestinationPrefix -eq '198.18.0.1/32').Count) {throw 'test destination already has a host route'}",
    );
    let (tunnel, _) = Tunnel::open(&cfg, 0)?;
    let index = tunnel.tun.if_index()?;
    struct Route(u32);
    impl Drop for Route {
        fn drop(&mut self) {
            ps(&format!(
                "Get-NetRoute -InterfaceIndex {} -AddressFamily IPv4 -PolicyStore ActiveStore | Where-Object {{$_.RouteMetric -eq 42762 -and $_.DestinationPrefix -eq '198.18.0.1/32'}} | Remove-NetRoute -Confirm:$false",
                self.0
            ));
        }
    }
    let route = Route(index);
    ps(&format!(
        "New-NetRoute -DestinationPrefix 198.18.0.1/32 -InterfaceIndex {index} -NextHop 0.0.0.0 -RouteMetric 42762 -PolicyStore ActiveStore | Out-Null; $until=(Get-Date).AddSeconds(8); while (!(Get-NetIPAddress -InterfaceIndex {index} -AddressFamily IPv4 | Where-Object AddressState -eq Preferred)) {{if ((Get-Date) -gt $until) {{throw 'IPv4 address not ready'}}; Start-Sleep -Milliseconds 100}}"
    ));
    let counts = &tunnel.counts;
    let stop = AtomicBool::new(false);
    let event = InterruptEvent::new()?;
    let result = std::thread::scope(|scope| -> Result<()> {
        let tx = scope.spawn(|| send_loop(&tunnel, &cfg, &stop, &event));
        let rx = scope.spawn(|| receive_loop(&tunnel, &cfg, &stop, &event));
        let test = (|| -> Result<()> {
            let app = UdpSocket::bind((cfg.address()?, 0))?;
            socket2::SockRef::from(&app).set_recv_buffer_size(4 * 1024 * 1024)?;
            app.connect("198.18.0.1:5209")?;
            app.set_read_timeout(Some(Duration::from_secs(3)))?;
            let mut reply = [0; 2048];
            let mut rtts = Vec::new();
            for seq in 0..100u32 {
                let data = seq.to_le_bytes();
                let start = Instant::now();
                app.send(&data)?;
                let n = app
                    .recv(&mut reply)
                    .context("LAN peer did not echo through Wintun")?;
                ensure!(reply[..n] == data, "small packet mismatch");
                rtts.push(start.elapsed().as_secs_f64() * 1000.0);
            }
            rtts.sort_by(f64::total_cmp);
            println!(
                "LAN offload={} idle RTT p50={:.3} p95={:.3} p99={:.3} ms",
                cfg.offload, rtts[50], rtts[95], rtts[99]
            );
            // Bounded windows avoid an unbounded offered load. Sequence checks
            // detect duplicate, missing, truncated, or corrupted payloads.
            let start = Instant::now();
            let mut total = 0u64;
            let mut windows = Vec::new();
            while start.elapsed() < Duration::from_secs(8) {
                let batch_start = Instant::now();
                for seq in 0..64u64 {
                    let mut data = [0x5a; 1360];
                    data[..8].copy_from_slice(&(total + seq).to_le_bytes());
                    app.send(&data)?;
                }
                let mut seen = [false; 64];
                for _ in 0..64 {
                    let n = app
                        .recv(&mut reply)
                        .context("missing packet in LAN burst")?;
                    ensure!(
                        n == 1360 && reply[8..n].iter().all(|&b| b == 0x5a),
                        "bulk payload mismatch"
                    );
                    let seq = u64::from_le_bytes(reply[..8].try_into()?);
                    ensure!(
                        (total..total + 64).contains(&seq),
                        "unexpected sequence {seq}"
                    );
                    let i = (seq - total) as usize;
                    ensure!(!seen[i], "duplicate sequence {seq}");
                    seen[i] = true;
                }
                total += 64;
                windows.push(batch_start.elapsed().as_secs_f64() * 1000.0);
            }
            let mbps = total as f64 * 1360.0 * 8.0 / start.elapsed().as_secs_f64() / 1e6;
            windows.sort_by(f64::total_cmp);
            println!(
                "LAN packets={total} echo_goodput={mbps:.2} Mbit/s per direction, 64-packet window p99={:.3} ms",
                windows[windows.len() * 99 / 100]
            );
            // Exercise the same delivery path with TCP, including checksums,
            // segmentation, ACKs, and sustained bidirectional payloads.
            use std::io::{Read, Write};
            let mut tcp = std::net::TcpStream::connect_timeout(
                &"198.18.0.1:5209".parse()?,
                Duration::from_secs(5),
            )?;
            tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
            tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
            tcp.set_nodelay(true)?;
            let data = vec![0xa5; 64 * 1024];
            let mut returned = vec![0; data.len()];
            let tcp_start = Instant::now();
            for _ in 0..128 {
                tcp.write_all(&data)?;
                tcp.read_exact(&mut returned)?;
                ensure!(data == returned, "TCP payload mismatch");
            }
            println!(
                "LAN TCP echoed 8 MiB, goodput={:.2} Mbit/s per direction",
                8.0 * 1024.0 * 1024.0 * 8.0 / tcp_start.elapsed().as_secs_f64() / 1e6
            );
            ensure!(
                counts.keepalive_received.load(Relaxed) >= 2,
                "KEEPALIVE stalled"
            );
            Ok(())
        })();
        let shutdown = Instant::now();
        stop.store(true, Relaxed);
        event.trigger()?;
        let sent = tx.join().map_err(|_| anyhow::anyhow!("sender panicked"))?;
        let received = rx
            .join()
            .map_err(|_| anyhow::anyhow!("receiver panicked"))?;
        println!(
            "LAN shutdown={:.1} ms",
            shutdown.elapsed().as_secs_f64() * 1000.0
        );
        test.and(sent).and(received)
    });
    tunnel.report();
    drop(route);
    drop(tunnel);
    routes::ensure_available(&cfg.interface)?;
    result
}
