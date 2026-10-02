//! Linux `"mode": "xdp"`: eBPF programs on the physical interface carry the
//! tunnel (see edup-ebpf-client) and keep a route per destination address.
//! Userspace installs no routes. It answers route lookups for destinations
//! the cache does not know yet, which arrive as packets through the TUN
//! device, re-injects those packets, sends KEEPALIVE and runs the DNS
//! forwarder for domain rules. Without its heartbeat, eBPF leaves all
//! traffic to the standard route.
use crate::{
    config::{Action, Settings, XdpMode},
    create_device, dns,
    ipset::{Family, IpSet, Prefix, key},
    routes,
    routing::{self, Rules},
    shutdown_signal, temporary, tun_io, tunnel_address,
};
use anyhow::{Context, Result, bail, ensure};
use aya::{
    Ebpf, Pod,
    maps::{Array, HashMap, MapData, PerCpuArray},
    programs::{SchedClassifier, TcAttachType, Xdp, tc, tc::SchedClassifierLink, xdp::XdpLink},
    util::KernelVersion,
};
use edup_common::{
    key::derive_key,
    maps::{CLIENT_MARK, ClientConfig, ROUTE_BYPASS, ROUTE_PROXY, RouteEntry, client_stat},
    wire::{self, Key},
};
use std::{
    fs, io,
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    path::Path,
    process::Command,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};
use tun_rs::{InterruptEvent, SyncDevice};

const OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/edup-ebpf-client"));
/// Bounds the addresses DNS answers can pin over a long session.
const MAX_HOSTS: usize = 65536;

#[repr(transparent)]
#[derive(Clone, Copy)]
struct Config(ClientConfig);
unsafe impl Pod for Config {}
#[repr(transparent)]
#[derive(Clone, Copy)]
struct Route(RouteEntry);
unsafe impl Pod for Route {}

#[derive(Default)]
struct Counters {
    lookups: AtomicU64,
    dropped: AtomicU64,
    keepalive_sent: AtomicU64,
    keepalive_received: AtomicU64,
}

pub fn run(cfg: Settings) -> Result<()> {
    let (stop, event) = shutdown_signal()?;
    routes::ensure_available(&cfg.interface)?;
    // Rule-sets download before the datapath can capture any traffic.
    let rules = routing::resolve(&cfg)?;
    let v6 = cfg.server.is_ipv6();
    let physical = routes::PhysicalRoute::discover(cfg.server.ip())?;
    let (dev, physical_index) = physical.device();
    let dev = dev.to_owned();
    let local = physical.source();
    let link = Path::new("/sys/class/net").join(&dev);
    let kind: u32 = fs::read_to_string(link.join("type"))?.trim().parse()?;
    ensure!(
        kind == 1,
        "xdp mode needs an Ethernet interface; {dev} is not one"
    );
    let link_mtu: usize = fs::read_to_string(link.join("mtu"))?.trim().parse()?;
    let overhead = if v6 {
        wire::OVERHEAD_V6
    } else {
        wire::OVERHEAD_V4
    };
    ensure!(
        cfg.mtu as usize + overhead <= link_mtu,
        "mtu {} plus {overhead} bytes of tunnel overhead exceeds the {dev} MTU {link_mtu}",
        cfg.mtu
    );
    match routes::Gateway::discover(v6) {
        Ok(gateway) if gateway.index() == physical_index => {}
        Ok(_) => eprintln!(
            "warning: the default route does not use {dev}; only traffic through {dev} is routed"
        ),
        Err(error) => {
            eprintln!("warning: {error:#}; only traffic through {dev} is routed")
        }
    }
    let system = IpSet::from_ranges(
        routes::device_prefixes(&dev, v6)?
            .iter()
            .map(Prefix::range)
            .collect(),
    );
    // Replies carry no local address: one address represents the client.
    let others = other_addresses(&dev, local)?;
    if !others.is_empty() {
        eprintln!(
            "warning: only traffic from {local} is routed; traffic from {} keeps the standard route",
            others.join(", ")
        );
    }

    // KEEPALIVE and the datapath share this socket's port.
    let socket = UdpSocket::bind((local, 0)).context("bind UDP on physical source address")?;
    set_mark(&socket, CLIENT_MARK)?;
    socket.connect(cfg.server)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    socket.set_write_timeout(Some(Duration::from_millis(200)))?;
    let reinject = Reinject::new(v6, CLIENT_MARK)?;
    let tun = create_device(&cfg)?;
    let segment = Segment::create(&cfg.interface, link_mtu)?;

    let mut bpf = Ebpf::load(OBJECT).context("load embedded eBPF object")?;
    let key = derive_key(&cfg.password);
    let mut config = ClientConfig {
        key0: key.k0,
        key1: key.k1,
        user: cfg.user,
        server_port_be: cfg.server.port().to_be(),
        local_port_be: socket.local_addr()?.port().to_be(),
        mtu: cfg.mtu,
        v6: v6.into(),
        physical: physical_index,
        segment: segment.index,
        tun: tun.if_index()?,
        mark: CLIENT_MARK,
        ..ClientConfig::default()
    };
    config.local[..octets(local).len()].copy_from_slice(&octets(local));
    let server = octets(cfg.server.ip());
    config.server[..server.len()].copy_from_slice(&server);
    Array::<_, Config>::try_from(
        bpf.map_mut("CLIENT_CONFIG")
            .context("missing CLIENT_CONFIG")?,
    )?
    .set(0, Config(config), 0)?;
    let cache: HashMap<_, [u8; 16], Route> =
        HashMap::try_from(bpf.take_map("ROUTES").context("missing ROUTES")?)?;
    let mut heartbeat: Array<_, u64> =
        Array::try_from(bpf.take_map("HEARTBEAT").context("missing HEARTBEAT")?)?;
    let stats: PerCpuArray<_, u64> = PerCpuArray::try_from(
        bpf.take_map("CLIENT_STATS")
            .context("missing CLIENT_STATS")?,
    )?;
    heartbeat.set(0, monotonic_ns(), 0)?;
    let datapath = Datapath::attach(&mut bpf, cfg.xdp_mode, &dev, &segment.inner, v6)?;

    let router = Router {
        rules: &rules,
        system,
        hosts: Mutex::new(std::collections::HashMap::new()),
        cache: Mutex::new(cache),
    };
    let address = tunnel_address(&cfg)?;
    let dns = if rules.uses_dns() {
        let listener = dns::Listener::bind(address)?;
        if cfg.dns.set_system {
            routes::set_dns(&cfg.interface, config.tun, address)?;
        }
        Some((
            dns::Forwarder::new(&rules, &router, cfg.dns_servers()),
            listener,
        ))
    } else {
        None
    };
    let counts = Counters::default();
    println!(
        "edup client ready: {} {}, server={}, MTU={}, mode=xdp ({} XDP on {dev}, source {local}){}",
        cfg.interface,
        address,
        cfg.server,
        cfg.mtu,
        datapath.mode,
        if dns.is_some() {
            format!(", DNS={}", SocketAddr::new(address, 53))
        } else {
            String::new()
        }
    );
    let report = || {
        eprintln!(
            "lookups={} dropped={} keepalive_tx={} keepalive_rx={}",
            counts.lookups.load(Relaxed),
            counts.dropped.load(Relaxed),
            counts.keepalive_sent.load(Relaxed),
            counts.keepalive_received.load(Relaxed),
        );
        let values: Vec<String> = client_stat::NAMES
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let total = stats
                    .get(&(i as u32), 0)
                    .map_or(0, |v| v.iter().fold(0u64, |a, b| a.wrapping_add(*b)));
                format!("{name}={total}")
            })
            .collect();
        eprintln!("{}", values.join(" "));
    };
    let result = std::thread::scope(|scope| {
        if let Some((forwarder, listener)) = &dns {
            forwarder.spawn(scope, listener, &stop);
        }
        let worker = scope.spawn(|| {
            let result = lookups(
                &tun,
                // Redirected packets may use the whole physical MTU.
                tun_io::Reader::with_segment_size((wire::HDR_LEN + link_mtu).max(2048)),
                &router,
                &reinject,
                &mut heartbeat,
                local,
                &counts,
                &stop,
                &event,
            );
            stop.store(true, Relaxed);
            let _ = event.trigger();
            result
        });
        let result = keepalive(&socket, &cfg, &key, &counts, &stop, &report);
        stop.store(true, Relaxed);
        let _ = event.trigger();
        let looked_up = worker
            .join()
            .map_err(|_| anyhow::anyhow!("route lookup thread panicked"))?;
        result.and(looked_up)
    });
    // Detach the egress hook first: nothing may be redirected to the veth or
    // TUN device while they disappear.
    drop(datapath);
    if let Some((forwarder, _)) = dns {
        eprintln!(
            "dns_queries={} dns_failures={} dns_routes={}",
            forwarder.queries.load(Relaxed),
            forwarder.failures.load(Relaxed),
            router.hosts.lock().unwrap_or_else(|e| e.into_inner()).len()
        );
    }
    report();
    result
}

/// Attached programs, detached in field order.
struct Datapath {
    _egress: SchedClassifierLink,
    _ingress: XdpLink,
    _encap: SchedClassifierLink,
    mode: &'static str,
}
impl Datapath {
    /// Loads every program before attaching any, and attaches the egress hook
    /// last, when the encapsulation and decapsulation paths already work.
    fn attach(bpf: &mut Ebpf, mode: XdpMode, dev: &str, encap: &str, v6: bool) -> Result<Self> {
        let family = if v6 { 6 } else { 4 };
        let egress_name = format!("edup_egress{family}");
        let encap_name = format!("edup_encap{family}");
        let ingress_name = format!("edup_ingress{family}");
        for name in [&egress_name, &encap_name] {
            classifier(bpf, name)?
                .load()
                .with_context(|| format!("kernel rejected {name}"))?;
        }
        xdp(bpf, &ingress_name)?
            .load()
            .with_context(|| format!("kernel rejected {ingress_name}"))?;
        // Before Linux 6.6 (no TCX), programs attach to clsact qdiscs and
        // outlive a crashed client. Its egress hook falls back to the
        // standard route without heartbeat; replace it.
        if !KernelVersion::current().is_ok_and(|v| v >= KernelVersion::new(6, 6, 0)) {
            for name in [dev, encap] {
                let _ = tc::qdisc_add_clsact(name);
            }
            let _ = tc::qdisc_detach_program(dev, TcAttachType::Egress, &egress_name);
        }
        let program = classifier(bpf, &encap_name)?;
        let id = program
            .attach(encap, TcAttachType::Ingress)
            .with_context(|| format!("attach {encap_name} to {encap}"))?;
        let encap_link = program.take_link(id)?;
        let program = xdp(bpf, &ingress_name)?;
        let attach = |program: &mut Xdp, mode| program.attach(dev, mode);
        let (id, mode) = match mode {
            XdpMode::Driver => (attach(program, aya::programs::XdpMode::Driver)?, "driver"),
            XdpMode::Skb => (attach(program, aya::programs::XdpMode::Skb)?, "skb"),
            XdpMode::Auto => match attach(program, aya::programs::XdpMode::Driver) {
                Ok(id) => (id, "driver"),
                Err(error) => {
                    eprintln!("native XDP unavailable on {dev} ({error}); using generic XDP");
                    (attach(program, aya::programs::XdpMode::Skb)?, "skb")
                }
            },
        };
        let ingress_link = program.take_link(id)?;
        let program = classifier(bpf, &egress_name)?;
        let id = program
            .attach(dev, TcAttachType::Egress)
            .with_context(|| format!("attach {egress_name} to {dev}"))?;
        Ok(Self {
            _egress: program.take_link(id)?,
            _ingress: ingress_link,
            _encap: encap_link,
            mode,
        })
    }
}
fn classifier<'a>(bpf: &'a mut Ebpf, name: &str) -> Result<&'a mut SchedClassifier> {
    Ok(bpf
        .program_mut(name)
        .with_context(|| format!("missing program {name}"))?
        .try_into()?)
}
fn xdp<'a>(bpf: &'a mut Ebpf, name: &str) -> Result<&'a mut Xdp> {
    Ok(bpf
        .program_mut(name)
        .with_context(|| format!("missing program {name}"))?
        .try_into()?)
}

/// Route decisions for single destinations, stored in the eBPF cache.
struct Router<'a> {
    rules: &'a Rules,
    /// The local network and other specific routes through the physical
    /// interface keep precedence, as they do over TUN mode's broader routes.
    system: IpSet,
    /// Addresses from DNS answers whose name rule overrides the address rules.
    hosts: Mutex<std::collections::HashMap<IpAddr, Action>>,
    cache: Mutex<HashMap<MapData, [u8; 16], Route>>,
}
impl Router<'_> {
    fn decide(&self, ip: IpAddr) -> Action {
        if Family::of(ip) != Family::of(self.rules.server)
            || ip == self.rules.server
            || !unicast(ip)
            || self.system.contains(key(ip))
        {
            return Action::Bypass;
        }
        let hosts = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        hosts
            .get(&ip)
            .copied()
            .unwrap_or_else(|| self.rules.address_action(ip))
    }
    fn publish(&self, ip: IpAddr) -> Result<()> {
        let action = match self.decide(ip) {
            Action::Proxy => ROUTE_PROXY,
            Action::Bypass => ROUTE_BYPASS,
        };
        let mut address = [0; 16];
        address[..octets(ip).len()].copy_from_slice(&octets(ip));
        let route = Route(RouteEntry {
            since_ns: 0,
            action,
            _pad: 0,
        });
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(address, route, 0)
            .with_context(|| format!("store route for {ip}"))
    }
}
impl dns::HostRoutes for Router<'_> {
    /// Applies to connections already in the cache too.
    fn host(&self, ip: IpAddr, action: Action) -> Result<()> {
        {
            let mut hosts = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
            if hosts.len() >= MAX_HOSTS && !hosts.contains_key(&ip) {
                bail!("{MAX_HOSTS} DNS host routes exist; not adding {ip}");
            }
            hosts.insert(ip, action);
        }
        self.publish(ip)
    }
}
fn unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !(ip.is_unspecified() || ip.is_loopback() || ip.octets()[0] >= 224),
        IpAddr::V6(ip) => {
            !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast())
                && ip.segments()[0] & 0xffc0 != 0xfe80
        }
    }
}
fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

/// Answers route lookups: each packet from the TUN device is a destination
/// the cache did not know. Stores its route, then sends the packet again.
#[allow(clippy::too_many_arguments)]
fn lookups(
    tun: &SyncDevice,
    mut reader: tun_io::Reader,
    router: &Router,
    reinject: &Reinject,
    heartbeat: &mut Array<MapData, u64>,
    local: IpAddr,
    counts: &Counters,
    stop: &AtomicBool,
    event: &InterruptEvent,
) -> Result<()> {
    let mut stored = Vec::with_capacity(tun_io::BATCH_SIZE);
    while !stop.load(Relaxed) {
        // Idle reads time out after 200 ms, well within the eBPF timeout.
        heartbeat
            .set(0, monotonic_ns(), 0)
            .context("update heartbeat")?;
        let num = match reader.recv(tun, event, true) {
            Ok(n) => n,
            Err(e) if temporary(&e) || stop.load(Relaxed) => continue,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                counts.dropped.fetch_add(1, Relaxed);
                continue;
            }
            Err(e) => return Err(e).context("read TUN"),
        };
        stored.clear();
        for i in 0..num {
            let packet = &reader.packets[i][wire::HDR_LEN..wire::HDR_LEN + reader.sizes[i]];
            counts.lookups.fetch_add(1, Relaxed);
            let Some(destination) = destination(packet, local) else {
                counts.dropped.fetch_add(1, Relaxed);
                continue;
            };
            // Segments of one GSO packet share a destination.
            if !stored.contains(&destination) {
                if let Err(error) = router.publish(destination) {
                    eprintln!("{error:#}");
                }
                stored.push(destination);
            }
            if reinject.send(packet, destination).is_err() {
                counts.dropped.fetch_add(1, Relaxed);
            }
        }
    }
    Ok(())
}
/// The destination of a packet the local stack sent from the physical address.
fn destination(packet: &[u8], local: IpAddr) -> Option<IpAddr> {
    match (packet.first()? >> 4, local) {
        (4, IpAddr::V4(local)) if packet.len() >= 20 && packet[12..16] == local.octets() => {
            Some(IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?))
        }
        (6, IpAddr::V6(local)) if packet.len() >= 40 && packet[8..24] == local.octets() => {
            Some(IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?))
        }
        _ => None,
    }
}

/// KEEPALIVE keeps the server's endpoint for this socket current; the server
/// answers each one. Tunnel data never reaches the socket: XDP takes it first.
fn keepalive(
    socket: &UdpSocket,
    cfg: &Settings,
    key: &Key,
    counts: &Counters,
    stop: &AtomicBool,
    report: &dyn Fn(),
) -> Result<()> {
    let mut buf = [0u8; 2048];
    let mut next = Instant::now();
    let diagnostics = std::env::var_os("EDUP_DIAGNOSTICS").is_some();
    let mut report_at = Instant::now() + Duration::from_secs(5);
    while !stop.load(Relaxed) {
        if diagnostics && Instant::now() >= report_at {
            report();
            report_at = Instant::now() + Duration::from_secs(5);
        }
        if Instant::now() >= next {
            let mut keepalive = [0; wire::HDR_LEN];
            wire::seal(key, wire::TYPE_KEEPALIVE, cfg.user, &mut keepalive);
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
            Ok(len) => len,
            Err(e) if temporary(&e) => continue,
            Err(e) => return Err(e).context("receive UDP"),
        };
        let data = &mut buf[..len];
        let keepalive = len == wire::HDR_LEN
            && wire::user_id(data) == Some(cfg.user)
            && wire::open(key, data).is_some_and(|o| o.typ == wire::TYPE_KEEPALIVE);
        if keepalive {
            counts.keepalive_received.fetch_add(1, Relaxed);
        } else {
            counts.dropped.fetch_add(1, Relaxed);
        }
    }
    Ok(())
}

/// Raw socket sending looked-up packets again. Its mark makes the egress
/// hook apply the stored route and never ask about the packet twice.
struct Reinject(socket2::Socket);
impl Reinject {
    fn new(v6: bool, mark: u32) -> Result<Self> {
        let domain = if v6 {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let socket = socket2::Socket::new(
            domain,
            socket2::Type::from(libc::SOCK_RAW),
            Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
        )
        .context("open raw socket")?;
        set_mark(&socket, mark)?;
        if !v6 {
            // Directed broadcasts to the local network are looked up too.
            socket.set_broadcast(true)?;
        }
        Ok(Self(socket))
    }
    fn send(&self, packet: &[u8], destination: IpAddr) -> io::Result<()> {
        self.0
            .send_to(packet, &SocketAddr::new(destination, 0).into())
            .map(|_| ())
    }
}

fn set_mark(socket: &impl AsRawFd, mark: u32) -> Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&raw const mark).cast(),
            size_of_val(&mark) as _,
        )
    };
    ensure!(rc == 0, "set SO_MARK: {}", io::Error::last_os_error());
    Ok(())
}

fn monotonic_ns() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_MONOTONIC is bpf_ktime_get_ns's clock.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
}

/// Global addresses of `local`'s family on `dev` other than `local`, such as
/// IPv6 temporary addresses.
fn other_addresses(dev: &str, local: IpAddr) -> Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Link {
        addr_info: Vec<Address>,
    }
    #[derive(serde::Deserialize)]
    struct Address {
        // iproute2 splits some entries; lifetimes may come without an address.
        local: Option<IpAddr>,
    }
    let family = if local.is_ipv6() { "-6" } else { "-4" };
    let json = ip(&["-j", family, "addr", "show", "dev", dev, "scope", "global"])?;
    let links: Vec<Link> = serde_json::from_str(&json).context("read interface addresses")?;
    Ok(links
        .iter()
        .flat_map(|l| &l.addr_info)
        .filter_map(|a| a.local.filter(|&a| a != local))
        .map(|a| a.to_string())
        .collect())
}

fn ip(args: &[&str]) -> Result<String> {
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

/// Veth pair named after the TUN device. The egress hook redirects proxied
/// packets into `<interface>s`, whose disabled offloads make the kernel
/// segment GSO packets and finish checksums; the encapsulation hook runs on
/// `<interface>e` ingress. Unlike the TUN device it outlives a crash, so a
/// stale pair is replaced.
struct Segment {
    outer: String,
    inner: String,
    index: u32,
}
impl Segment {
    fn create(interface: &str, mtu: usize) -> Result<Self> {
        let outer = format!("{interface}s");
        let inner = format!("{interface}e");
        for (name, peer) in [(&outer, &inner), (&inner, &outer)] {
            if Path::new("/sys/class/net").join(name).exists() {
                #[derive(serde::Deserialize)]
                struct Link {
                    link: Option<String>,
                    linkinfo: Option<serde_json::Value>,
                }
                let links: Vec<Link> =
                    serde_json::from_str(&ip(&["-j", "-d", "link", "show", "dev", name])?)?;
                ensure!(
                    links.iter().any(|l| l.link.as_ref() == Some(peer)
                        && l.linkinfo
                            .as_ref()
                            .is_some_and(|i| i["info_kind"] == "veth")),
                    "interface {name} already exists; refusing to reuse it"
                );
                eprintln!("removing veth pair {outer}/{inner} left by an earlier client");
                ip(&["link", "del", name])?;
            }
        }
        let mtu = mtu.to_string();
        ip(&[
            "link", "add", &outer, "mtu", &mtu, "type", "veth", "peer", "name", &inner, "mtu", &mtu,
        ])?;
        let mut guard = Self {
            outer,
            inner,
            index: 0,
        };
        for name in [&guard.outer, &guard.inner] {
            // Neither end needs addresses; avoid IPv6 autoconfiguration noise.
            let _ = fs::write(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"), "1");
        }
        // Without checksum offload the kernel completes checksums, and without
        // TSO or GSO it segments packets, before they cross the pair.
        for command in [ETHTOOL_STXCSUM, ETHTOOL_STSO, ETHTOOL_SGSO] {
            ethtool_set(&guard.outer, command, 0)
                .with_context(|| format!("disable offloads on {}", guard.outer))?;
        }
        ip(&["link", "set", &guard.inner, "up"])?;
        ip(&["link", "set", &guard.outer, "up"])?;
        let name = std::ffi::CString::new(guard.outer.as_str())?;
        guard.index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        ensure!(guard.index != 0, "interface {} vanished", guard.outer);
        Ok(guard)
    }
}
impl Drop for Segment {
    fn drop(&mut self) {
        // Deleting one end removes its peer.
        if let Err(error) = ip(&["link", "del", &self.outer]) {
            eprintln!("veth cleanup failed: {error:#}");
        }
    }
}

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_STXCSUM: u32 = 0x17;
const ETHTOOL_STSO: u32 = 0x1f;
const ETHTOOL_SGSO: u32 = 0x24;

/// Legacy single-feature ethtool request, as `ethtool -K <name> tx off`.
fn ethtool_set(name: &str, command: u32, value: u32) -> Result<()> {
    #[repr(C)]
    struct Value {
        cmd: u32,
        data: u32,
    }
    #[repr(C)]
    struct Request {
        name: [u8; 16],
        data: *mut libc::c_void,
        _pad: [u8; 16],
    }
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let mut value = Value {
        cmd: command,
        data: value,
    };
    let mut request = Request {
        name: [0; 16],
        data: (&raw mut value).cast(),
        _pad: [0; 16],
    };
    ensure!(name.len() < 16, "interface name too long");
    request.name[..name.len()].copy_from_slice(name.as_bytes());
    let rc = unsafe { libc::ioctl(socket.as_raw_fd(), SIOCETHTOOL as _, &raw mut request) };
    ensure!(rc == 0, "ethtool: {}", io::Error::last_os_error());
    Ok(())
}

#[cfg(test)]
#[path = "xdp_tests.rs"]
mod tests;
