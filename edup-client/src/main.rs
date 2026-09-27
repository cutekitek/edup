mod config;
mod packet;
mod routes;
mod tun_io;
mod udp;
#[cfg(target_os = "windows")]
mod windows_delivery;

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
    tun_segmented_reads: AtomicU64,
    tun_coalesced_writes: AtomicU64,
    #[cfg(target_os = "windows")]
    tun_backpressure_drops: AtomicU64,
}
impl Counters {
    fn report(&self) {
        eprintln!(
            "tx={} rx={} dropped={} keepalive_tx={} keepalive_rx={} tun_segmented_reads={} tun_coalesced_writes={}",
            self.sent.load(Relaxed),
            self.received.load(Relaxed),
            self.dropped.load(Relaxed),
            self.keepalive_sent.load(Relaxed),
            self.keepalive_received.load(Relaxed),
            self.tun_segmented_reads.load(Relaxed),
            self.tun_coalesced_writes.load(Relaxed)
        );
        #[cfg(target_os = "windows")]
        eprintln!(
            "tun_backpressure_drops={}",
            self.tun_backpressure_drops.load(Relaxed)
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
    let socket = udp::Transport::new(socket, cfg.offload).context("configure UDP offload")?;
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
    report_offload(&socket);
    result.and(cleanup)
}

fn create_device(cfg: &config::Settings) -> Result<SyncDevice> {
    let builder = DeviceBuilder::new()
        .name(&cfg.interface)
        .layer(Layer::L3)
        .ipv4(cfg.address()?, 32, None)
        .enable(true);
    #[cfg(target_os = "linux")]
    let builder = builder.mtu(cfg.mtu).offload(cfg.offload);
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
    let tun = builder
        .build_sync()
        .context("create/configure TUN adapter")?;
    #[cfg(target_os = "linux")]
    {
        // Nonblocking reads let the sender drain only packets already queued.
        tun.set_nonblocking(true)?;
        if cfg.offload && !tun.tcp_gso() {
            // tun-rs can retain IFF_VNET_HDR after TUNSETOFFLOAD fails. Recreate
            // without it instead of interpreting virtio bytes as an IP header.
            drop(tun);
            eprintln!("TUN offload unavailable; creating an ordinary TUN");
            let tun = DeviceBuilder::new()
                .name(&cfg.interface)
                .layer(Layer::L3)
                .ipv4(cfg.address()?, 32, None)
                .enable(true)
                .mtu(cfg.mtu)
                .offload(false)
                .build_sync()?;
            tun.set_nonblocking(true)?;
            return Ok(tun);
        }
        eprintln!("TUN offload: tcp={}, udp={}", tun.tcp_gso(), tun.udp_gso());
    }
    Ok(tun)
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests;

#[cfg(all(test, target_os = "windows"))]
mod windows_lan_tests;

#[allow(clippy::too_many_arguments)]
fn send_loop(
    tun: &SyncDevice,
    socket: &udp::Transport,
    cfg: &config::Settings,
    key: &Key,
    nonce: &AtomicU32,
    counts: &Counters,
    stop: &AtomicBool,
    event: &InterruptEvent,
) -> Result<()> {
    let mut reader = tun_io::Reader::new();
    let mut batch = udp::Batch::new();
    let address = cfg.address()?.octets();
    while !stop.load(Relaxed) {
        let mut processed = 0;
        while processed < udp::MAX_SEGMENTS && !stop.load(Relaxed) {
            let num = match reader.recv(tun, event, processed == 0) {
                Ok(n) => n,
                Err(e) if temporary(&e) || stop.load(Relaxed) => break,
                Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                    processed += 1;
                    counts.dropped.fetch_add(1, Relaxed);
                    continue;
                }
                Err(e) => return Err(e).context("read TUN"),
            };
            processed += num;
            if num > 1 {
                counts.tun_segmented_reads.fetch_add(1, Relaxed);
            }
            for i in 0..num {
                let len = reader.sizes[i];
                let data = &mut reader.packets[i][..wire::HDR_LEN + len];
                let payload = &mut data[wire::HDR_LEN..];
                let Some(ihl) = packet::validate(payload, address, true, cfg.mtu) else {
                    counts.dropped.fetch_add(1, Relaxed);
                    continue;
                };
                packet::clamp_mss(payload, ihl, cfg.mtu);
                wire::seal(
                    key,
                    nonce.fetch_add(1, Relaxed),
                    wire::TYPE_DATA,
                    cfg.user,
                    data,
                );
                if !batch.push(data) {
                    flush_udp(socket, &mut batch, counts, stop)?;
                    assert!(batch.push(data));
                }
            }
        }
        flush_udp(socket, &mut batch, counts, stop)?;
    }
    Ok(())
}

fn flush_udp(
    socket: &udp::Transport,
    batch: &mut udp::Batch,
    counts: &Counters,
    stop: &AtomicBool,
) -> Result<()> {
    let (sent, dropped) = socket.send_batch(batch, stop).context("send UDP batch")?;
    counts.sent.fetch_add(sent, Relaxed);
    counts.dropped.fetch_add(dropped, Relaxed);
    batch.clear();
    Ok(())
}

#[cfg(target_os = "windows")]
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
    socket: &udp::Transport,
    cfg: &config::Settings,
    key: &Key,
    nonce: &AtomicU32,
    counts: &Counters,
    stop: &AtomicBool,
    event: &InterruptEvent,
) -> Result<()> {
    let mut buf = vec![0; udp::RECEIVE_CAPACITY];
    #[cfg(target_os = "windows")]
    let _ = event;
    #[cfg(target_os = "linux")]
    let mut writer = tun_io::Writer::new();
    let address = cfg.address()?.octets();
    let mut next = Instant::now();
    let diagnostics = std::env::var_os("EDUP_DIAGNOSTICS").is_some();
    let mut report_at = Instant::now() + Duration::from_secs(5);
    while !stop.load(Relaxed) {
        if diagnostics && Instant::now() >= report_at {
            counts.report();
            report_offload(socket);
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
        let (len, stride) = match socket.recv(&mut buf) {
            Ok(v) => v,
            Err(e) if temporary(&e) => continue,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                counts.dropped.fetch_add(1, Relaxed);
                continue;
            }
            Err(e) => return Err(e).context("receive UDP"),
        };
        if len == 0 {
            counts.dropped.fetch_add(1, Relaxed);
            continue;
        }
        #[cfg(target_os = "windows")]
        let (mut delivered, mut dropped, mut congested) = (0, 0, 0);
        for data in buf[..len].chunks_mut(stride) {
            if stop.load(Relaxed) {
                break;
            }
            if let Some(payload) = decode_packet(data, cfg, key, address, counts) {
                #[cfg(target_os = "linux")]
                {
                    writer.push(payload);
                    if writer.full() {
                        flush_tun(&mut writer, tun, event, counts, stop)?;
                    }
                }
                #[cfg(target_os = "windows")]
                {
                    // Copy directly from the decrypted UDP buffer into Wintun.
                    // Never sleep on ring pressure while holding up UDP reads.
                    use windows_delivery::Delivery;
                    match windows_delivery::deliver(payload, stop, |p| tun.try_send(p))
                        .context("write Wintun")?
                    {
                        Delivery::Sent => delivered += 1,
                        Delivery::Congested => {
                            dropped += 1;
                            congested += 1;
                        }
                        Delivery::Dropped => dropped += 1,
                        Delivery::Stopped => break,
                    }
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            if delivered != 0 {
                counts.received.fetch_add(delivered, Relaxed);
            }
            if dropped != 0 {
                counts.dropped.fetch_add(dropped, Relaxed);
            }
            if congested != 0 {
                counts.tun_backpressure_drops.fetch_add(congested, Relaxed);
            }
        }
        #[cfg(target_os = "linux")]
        flush_tun(&mut writer, tun, event, counts, stop)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn flush_tun(
    writer: &mut tun_io::Writer,
    tun: &SyncDevice,
    event: &InterruptEvent,
    counts: &Counters,
    stop: &AtomicBool,
) -> Result<()> {
    match writer.flush(tun, event) {
        Ok((received, dropped)) => {
            counts.received.fetch_add(received, Relaxed);
            counts.dropped.fetch_add(dropped, Relaxed);
            counts
                .tun_coalesced_writes
                .store(writer.coalesced_writes, Relaxed);
        }
        Err(_) if stop.load(Relaxed) => {}
        Err(e) => return Err(e).context("write TUN batch"),
    }
    Ok(())
}

fn decode_packet<'a>(
    data: &'a mut [u8],
    cfg: &config::Settings,
    key: &Key,
    address: [u8; 4],
    counts: &Counters,
) -> Option<&'a mut [u8]> {
    let len = data.len();
    if len > cfg.mtu as usize + wire::HDR_LEN {
        counts.dropped.fetch_add(1, Relaxed);
        return None;
    }
    let Some(opened) = wire::open(key, data) else {
        counts.dropped.fetch_add(1, Relaxed);
        return None;
    };
    if opened.user != cfg.user || opened.flags != 0 {
        counts.dropped.fetch_add(1, Relaxed);
        return None;
    }
    if opened.typ == wire::TYPE_KEEPALIVE && len == wire::HDR_LEN {
        counts.keepalive_received.fetch_add(1, Relaxed);
        return None;
    }
    if opened.typ != wire::TYPE_DATA {
        counts.dropped.fetch_add(1, Relaxed);
        return None;
    }
    let payload = &mut data[wire::HDR_LEN..];
    let Some(ihl) = packet::validate(payload, address, false, cfg.mtu) else {
        counts.dropped.fetch_add(1, Relaxed);
        return None;
    };
    packet::clamp_mss(payload, ihl, cfg.mtu);
    Some(payload)
}
fn report_offload(socket: &udp::Transport) {
    eprintln!(
        "udp_segmented_sends={} udp_coalesced_receives={} udp_offload_fallbacks={}",
        socket.segmented_sends.load(Relaxed),
        socket.coalesced_receives.load(Relaxed),
        socket.fallbacks.load(Relaxed)
    );
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

#[cfg(test)]
mod receive_tests {
    use super::*;

    #[test]
    fn coalesced_messages_are_validated_independently() {
        let cfg: config::Settings =
            toml::from_str(include_str!("../../config/client.example.toml")).unwrap();
        let key = derive_key(&cfg.password);
        let address = cfg.address().unwrap().octets();
        let mut aggregate = Vec::new();
        for (nonce, user) in [(1, 7), (2, 42), (3, 7), (4, 7)] {
            let mut data = vec![0; wire::HDR_LEN + 40];
            let ip = &mut data[wire::HDR_LEN..];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&40u16.to_be_bytes());
            ip[9] = 17;
            ip[12..16].copy_from_slice(&[203, 0, 113, 9]);
            ip[16..20].copy_from_slice(&address);
            ip[24..26].copy_from_slice(&20u16.to_be_bytes());
            wire::seal(&key, nonce, wire::TYPE_DATA, user, &mut data);
            if nonce == 3 {
                data[5] ^= 1;
            } // corrupt magic in the third segment
            aggregate.extend(data);
        }
        let mut keepalive = [0; wire::HDR_LEN];
        wire::seal(&key, 5, wire::TYPE_KEEPALIVE, cfg.user, &mut keepalive);
        aggregate.extend(keepalive);
        let counts = Counters::default();
        let mut accepted = 0;
        for packet in aggregate.chunks_mut(wire::HDR_LEN + 40) {
            accepted += usize::from(decode_packet(packet, &cfg, &key, address, &counts).is_some());
        }
        assert_eq!(accepted, 2);
        assert_eq!(counts.dropped.load(Relaxed), 2);
        assert_eq!(counts.keepalive_received.load(Relaxed), 1);
        // Concatenation without kernel segment metadata is never decoded as a batch.
        assert!(decode_packet(&mut aggregate, &cfg, &key, address, &counts).is_none());
    }
}
