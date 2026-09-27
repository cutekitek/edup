mod config;
mod packet;
mod routes;

#[cfg(target_os = "windows")]
use anyhow::ensure;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use edup_common::{
    key::derive_key,
    wire::{self, Key},
};
use std::{
    io,
    net::UdpSocket,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};
use tun_rs::{DeviceBuilder, InterruptEvent, Layer, SyncDevice};

#[derive(Parser)]
#[command(version, about = "edup IPv4 TUN client for Linux and Windows")]
struct Cli {
    #[arg(short, long, global = true, default_value = "client.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Check,
    Run,
}

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    received: AtomicU64,
    dropped: AtomicU64,
    keepalive_sent: AtomicU64,
    keepalive_received: AtomicU64,
}
impl Counters {
    fn report(&self) {
        eprintln!(
            "tx={} rx={} dropped={} keepalive_tx={} keepalive_rx={}",
            self.sent.load(Relaxed),
            self.received.load(Relaxed),
            self.dropped.load(Relaxed),
            self.keepalive_sent.load(Relaxed),
            self.keepalive_received.load(Relaxed)
        );
    }
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = config::Settings::load(&cli.config)?;
    match cli.command {
        Command::Check => {
            println!(
                "Configuration valid: {} -> {}, MTU={}, routes={}",
                cfg.address()?,
                cfg.server,
                cfg.mtu,
                cfg.routes
            );
            Ok(())
        }
        Command::Run => run(cfg),
    }
}
fn run(cfg: config::Settings) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let event = Arc::new(InterruptEvent::new()?);
    let signal_stop = stop.clone();
    let signal_event = event.clone();
    ctrlc::set_handler(move || {
        signal_stop.store(true, Relaxed);
        let _ = signal_event.trigger();
    })
    .context("install shutdown handler")?;
    routes::ensure_available(&cfg.interface)?;
    let physical = routes::PhysicalRoute::discover(*cfg.server.ip())?;
    let socket =
        UdpSocket::bind((physical.source(), 0)).context("bind UDP on physical source address")?;
    // Windows defaults to a small UDP queue. XDP returns bursts directly from
    // the NIC; retain them while this thread decrypts and writes into Wintun.
    let socket_options = socket2::SockRef::from(&socket);
    socket_options
        .set_recv_buffer_size(4 * 1024 * 1024)
        .context("set UDP receive buffer")?;
    socket_options
        .set_send_buffer_size(1024 * 1024)
        .context("set UDP send buffer")?;
    socket.connect(cfg.server)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    socket.set_write_timeout(Some(Duration::from_millis(200)))?;
    let address = cfg.address()?;
    let tun = create_device(&cfg)?;
    let mut routes = if cfg.routes {
        Some(routes::Routes::install(
            &physical,
            &cfg.interface,
            tun.if_index()?,
            *cfg.server.ip(),
        )?)
    } else {
        None
    };
    let mut random = [0; 4];
    getrandom::fill(&mut random).map_err(|e| anyhow::anyhow!("nonce seed: {e}"))?;
    let nonce = AtomicU32::new(u32::from_ne_bytes(random));
    let counts = Counters::default();
    let key = derive_key(&cfg.password);
    println!(
        "edup client ready: {} {}, server={}, MTU={}",
        cfg.interface, address, cfg.server, cfg.mtu
    );
    let result = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let result = send_loop(&tun, &socket, &cfg, &key, &nonce, &counts, &stop, &event);
            stop.store(true, Relaxed);
            let _ = event.trigger();
            result
        });
        let result = receive_loop(&tun, &socket, &cfg, &key, &nonce, &counts, &stop, &event);
        stop.store(true, Relaxed);
        let _ = event.trigger();
        let sent = worker
            .join()
            .map_err(|_| anyhow::anyhow!("TUN sender panicked"))?;
        result.and(sent)
    });
    let cleanup = if let Some(routes) = &mut routes {
        routes.clear()
    } else {
        Ok(())
    };
    counts.report();
    result.and(cleanup)
}

fn create_device(cfg: &config::Settings) -> Result<SyncDevice> {
    let builder = DeviceBuilder::new()
        .name(&cfg.interface)
        .layer(Layer::L3)
        .ipv4(cfg.address()?, 32, None)
        .enable(true);
    #[cfg(target_os = "linux")]
    let builder = builder.mtu(cfg.mtu).offload(false);
    #[cfg(target_os = "windows")]
    let builder = {
        let dll = cfg
            .wintun_dll
            .clone()
            .unwrap_or(std::env::current_exe()?.with_file_name("wintun.dll"));
        ensure!(dll.is_file(), "wintun.dll missing: {}", dll.display());
        // DeviceBuilder::mtu sets both IP families on Windows. IPv6 rejects
        // MTU <1280 (ERROR_INVALID_PARAMETER), even for this IPv4-only tunnel.
        builder
            .mtu_v4(cfg.mtu)
            .wintun_file(dll.to_str().context("DLL path must be Unicode")?.to_owned())
    };
    builder.build_sync().context("create/configure TUN adapter")
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::*;
    use std::{os::windows::process::CommandExt, process::Command};

    fn ps(script: &str) {
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
            toml::from_str(include_str!("../../config/client.example.toml")).unwrap();
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
            toml::from_str(include_str!("../../config/client.example.toml")).unwrap();
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
}

#[allow(clippy::too_many_arguments)]
fn send_loop(
    tun: &SyncDevice,
    socket: &UdpSocket,
    cfg: &config::Settings,
    key: &Key,
    nonce: &AtomicU32,
    counts: &Counters,
    stop: &AtomicBool,
    event: &InterruptEvent,
) -> Result<()> {
    let mut buf = vec![0; 65536 + wire::HDR_LEN];
    let address = cfg.address()?.octets();
    while !stop.load(Relaxed) {
        let len = match receive_tun(tun, &mut buf[wire::HDR_LEN..], event) {
            Ok(n) => n,
            Err(e) if temporary(&e) => continue,
            Err(e) if stop.load(Relaxed) => {
                let _ = e;
                break;
            }
            Err(e) => return Err(e).context("read TUN"),
        };
        let payload = &mut buf[wire::HDR_LEN..wire::HDR_LEN + len];
        let Some(ihl) = packet::validate(payload, address, true, cfg.mtu) else {
            counts.dropped.fetch_add(1, Relaxed);
            continue;
        };
        packet::clamp_mss(payload, ihl, cfg.mtu);
        let data = &mut buf[..wire::HDR_LEN + len];
        wire::seal(
            key,
            nonce.fetch_add(1, Relaxed),
            wire::TYPE_DATA,
            cfg.user,
            data,
        );
        match socket.send(data) {
            Ok(n) if n == data.len() => {
                counts.sent.fetch_add(1, Relaxed);
            }
            Ok(_) => anyhow::bail!("partial UDP datagram"),
            Err(e) if temporary(&e) => {
                counts.dropped.fetch_add(1, Relaxed);
            }
            Err(e) => return Err(e).context("send UDP"),
        }
    }
    Ok(())
}

fn receive_tun(tun: &SyncDevice, buf: &mut [u8], event: &InterruptEvent) -> io::Result<usize> {
    #[cfg(target_os = "windows")]
    {
        // Wintun's event is a wakeup, not a packet count. Always drain its ring
        // before waiting. tun-rs 2.8's recv_intr_timeout waits before trying a
        // read, which can strand queued TCP ACKs after a burst.
        match tun.try_recv(buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                tun.wait_readable_intr_timeout(event, Some(Duration::from_millis(200)))?;
                tun.try_recv(buf)
            }
            result => result,
        }
    }
    #[cfg(not(target_os = "windows"))]
    tun.recv_intr_timeout(buf, event, Some(Duration::from_millis(200)))
}
#[allow(clippy::too_many_arguments)]
fn receive_loop(
    tun: &SyncDevice,
    socket: &UdpSocket,
    cfg: &config::Settings,
    key: &Key,
    nonce: &AtomicU32,
    counts: &Counters,
    stop: &AtomicBool,
    event: &InterruptEvent,
) -> Result<()> {
    let mut buf = vec![0; 65536];
    let address = cfg.address()?.octets();
    let mut next = Instant::now();
    let diagnostics = std::env::var_os("EDUP_DIAGNOSTICS").is_some();
    let mut report_at = Instant::now() + Duration::from_secs(5);
    while !stop.load(Relaxed) {
        if diagnostics && Instant::now() >= report_at {
            counts.report();
            report_at = Instant::now() + Duration::from_secs(5);
        }
        if Instant::now() >= next {
            let mut keepalive = [0; wire::HDR_LEN];
            wire::seal(
                key,
                nonce.fetch_add(1, Relaxed),
                wire::TYPE_KEEPALIVE,
                cfg.user,
                &mut keepalive,
            );
            match socket.send(&keepalive) {
                Ok(_) => {
                    counts.keepalive_sent.fetch_add(1, Relaxed);
                }
                Err(e) if temporary(&e) => {}
                Err(e) => return Err(e).context("send KEEPALIVE"),
            }
            next = Instant::now() + Duration::from_secs(cfg.keepalive_secs);
        }
        let len = match socket.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if temporary(&e) => continue,
            Err(e) => return Err(e).context("receive UDP"),
        };
        if len > cfg.mtu as usize + wire::HDR_LEN {
            counts.dropped.fetch_add(1, Relaxed);
            continue;
        }
        let Some(opened) = wire::open(key, &mut buf[..len]) else {
            counts.dropped.fetch_add(1, Relaxed);
            continue;
        };
        if opened.user != cfg.user || opened.flags != 0 {
            counts.dropped.fetch_add(1, Relaxed);
            continue;
        }
        if opened.typ == wire::TYPE_KEEPALIVE && len == wire::HDR_LEN {
            counts.keepalive_received.fetch_add(1, Relaxed);
            continue;
        }
        if opened.typ != wire::TYPE_DATA {
            counts.dropped.fetch_add(1, Relaxed);
            continue;
        }
        let payload = &mut buf[wire::HDR_LEN..len];
        let Some(ihl) = packet::validate(payload, address, false, cfg.mtu) else {
            counts.dropped.fetch_add(1, Relaxed);
            continue;
        };
        packet::clamp_mss(payload, ihl, cfg.mtu);
        match tun.send_intr(payload, event) {
            Ok(n) if n == payload.len() => {
                counts.received.fetch_add(1, Relaxed);
            }
            Ok(_) => anyhow::bail!("partial TUN packet"),
            Err(e) if stop.load(Relaxed) => {
                let _ = e;
                break;
            }
            Err(e) if temporary(&e) => {
                counts.dropped.fetch_add(1, Relaxed);
            }
            Err(e) => return Err(e).context("write TUN"),
        }
    }
    Ok(())
}
fn temporary(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
    )
}
