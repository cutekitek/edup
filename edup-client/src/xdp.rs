//! Linux `"mode": "xdp"`: eBPF programs on the physical interface carry the
//! tunnels to every server (see edup-ebpf-client) and keep a route, a server
//! or direct, per destination address. Userspace installs no routes. It
//! answers route lookups for destinations the cache does not know yet, which
//! arrive as packets through the TUN device, re-injects those packets, sends
//! KEEPALIVE to each server and runs the DNS forwarder for domain rules.
//! Without its heartbeat, eBPF leaves all traffic to the standard route.
//!
//! On a router, `from` rules form a permanent client table in eBPF: LAN
//! interfaces classify each source before masquerading, and the egress hook
//! sends those clients through their server or direct without lookups.
//! SIGHUP reloads the table from the configuration file.
use crate::{
    config::{Action, Settings, Target, XdpMode},
    create_device, dns,
    ipset::{Family, IpSet, Prefix, key},
    routes,
    routing::{self, Clients, Rules},
    shutdown_signal, temporary, tun_io, tunnel_address,
};
use anyhow::{Context, Result, bail, ensure};
use aya::{
    Ebpf, Pod,
    maps::{Array, HashMap, MapData, PerCpuArray, lpm_trie},
    programs::{SchedClassifier, TcAttachType, Xdp, tc, tc::SchedClassifierLink, xdp::XdpLink},
    util::KernelVersion,
};
use edup_common::{
    key::derive_key,
    maps::{
        CLIENT_ENTRIES, CLIENT_MARK, ClientConfig, Keystream, MODE_DIRECT, MODE_RULES, MODE_SERVER,
        MODE_SHIFT, MODE_TUNNEL, RouteEntry, SYSTEM_ENTRIES, ServerConfig, TunnelKey, client_stat,
    },
    wire::{self, Key},
};
use std::{
    collections::BTreeMap,
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
#[repr(transparent)]
#[derive(Clone, Copy)]
struct Stream(Keystream);
unsafe impl Pod for Stream {}
#[repr(transparent)]
#[derive(Clone, Copy)]
struct Server(ServerConfig);
unsafe impl Pod for Server {}
#[repr(transparent)]
#[derive(Clone, Copy)]
struct Tunnel(TunnelKey);
unsafe impl Pod for Tunnel {}

/// Mark of the tunnels' own packets: keepalives and encapsulated packets.
const TUNNEL_MARK: u32 = CLIENT_MARK | (MODE_TUNNEL as u32) << MODE_SHIFT;

/// Stores server `index`: its address, user and key stream words, which
/// eBPF XORs with every packet.
fn set_server(bpf: &mut Ebpf, index: u32, address: SocketAddr, user: i64, key: &Key) -> Result<()> {
    let mut stream: Array<_, Stream> =
        Array::try_from(bpf.map_mut("KEYSTREAM").context("missing KEYSTREAM")?)?;
    stream.set(index, Stream(Keystream::new(key)), 0)?;
    let mut server = ServerConfig {
        user,
        port_be: address.port().to_be(),
        ..ServerConfig::default()
    };
    let ip = octets(address.ip());
    server.address[..ip.len()].copy_from_slice(&ip);
    let mut servers: Array<_, Server> =
        Array::try_from(bpf.map_mut("SERVERS").context("missing SERVERS")?)?;
    servers.set(index, Server(server), 0)?;
    let tunnel = TunnelKey {
        address: server.address,
        port_be: server.port_be,
        _pad: [0; 2],
    };
    let mut tunnels: HashMap<_, Tunnel, u32> =
        HashMap::try_from(bpf.map_mut("TUNNELS").context("missing TUNNELS")?)?;
    tunnels.insert(Tunnel(tunnel), index, 0)?;
    Ok(())
}

#[derive(Default)]
struct Counters {
    lookups: AtomicU64,
    dropped: AtomicU64,
    keepalive_sent: AtomicU64,
    keepalive_received: AtomicU64,
}

/// SIGHUP: reload the client table.
static RELOAD: AtomicBool = AtomicBool::new(false);
extern "C" fn reload_requested(_: libc::c_int) {
    RELOAD.store(true, Relaxed);
}

pub fn run(cfg: Settings, path: &Path) -> Result<()> {
    let (stop, event) = shutdown_signal()?;
    let handler: extern "C" fn(libc::c_int) = reload_requested;
    ensure!(
        unsafe { libc::signal(libc::SIGHUP, handler as libc::sighandler_t) } != libc::SIG_ERR,
        "install SIGHUP handler: {}",
        io::Error::last_os_error()
    );
    routes::ensure_available(&cfg.interface)?;
    // Not while another client runs: its TUN interface would exist.
    routes::clean_dns()?;
    // Rule-sets download before the datapath can capture any traffic.
    let rules = routing::resolve(&cfg)?;
    let clients = routing::clients(&cfg);
    let v6 = cfg.ipv6();
    let family = rules.family();
    let servers = cfg.server_ips();
    let physical = routes::PhysicalRoute::discover(servers[0])?;
    let (dev, physical_index) = physical.device();
    let dev = dev.to_owned();
    let local = physical.source();
    // One egress hook and one socket carry every tunnel.
    for (server, &ip) in cfg.servers.iter().zip(&servers).skip(1) {
        let route = routes::PhysicalRoute::discover(ip)?;
        ensure!(
            route.device().1 == physical_index && route.source() == local,
            "server {:?} is reached through {} from {}, but {:?} through {dev} from {local}; xdp mode needs every server on one interface and source address",
            server.tag,
            route.device().0,
            route.source(),
            cfg.servers[0].tag,
        );
    }
    let link = Path::new("/sys/class/net").join(&dev);
    let l3 = link_layer(&dev)?;
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
    warn_flowtables();
    if !(rules.uses_dns() && cfg.dns.set_system) {
        warn_proxied_resolvers(&rules, &clients, local, &system, v6)?;
    }

    // KEEPALIVE and every tunnel share this socket's port. Its mark keeps
    // the keepalives on the standard route.
    let socket = UdpSocket::bind((local, 0)).context("bind UDP on physical source address")?;
    set_mark(&socket, TUNNEL_MARK)?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    socket.set_write_timeout(Some(Duration::from_millis(200)))?;
    let reinject = Reinject::new(v6, CLIENT_MARK)?;
    let tun = create_device(&cfg, 0)?;
    let segment = Segment::create(&cfg.interface, link_mtu)?;

    let mut bpf = Ebpf::load(OBJECT).context("load embedded eBPF object")?;
    let keys: Vec<Key> = cfg
        .servers
        .iter()
        .map(|s| derive_key(&s.password))
        .collect();
    for (i, (server, key)) in cfg.servers.iter().zip(&keys).enumerate() {
        set_server(&mut bpf, i as u32, server.address, server.user, key)?;
    }
    let mut config = ClientConfig {
        local_port_be: socket.local_addr()?.port().to_be(),
        mtu: cfg.mtu,
        v6: v6.into(),
        local_mode: mode(clients.target(local)),
        physical: physical_index,
        segment: segment.index,
        tun: tun.if_index()?,
        mark: CLIENT_MARK,
        ..ClientConfig::default()
    };
    // XDP decapsulates before GRO; TC on interfaces without a link-layer
    // header runs after it.
    if l3 {
        match segment.inbound(v6) {
            Ok(Some((index, mac))) => {
                config.inbound = index;
                config.inbound_mac = mac;
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!("warning: {error:#}; decapsulated packets skip GRO and use one CPU")
            }
        }
    }
    config.local[..octets(local).len()].copy_from_slice(&octets(local));
    let mut client_config: Array<_, Config> = Array::try_from(
        bpf.take_map("CLIENT_CONFIG")
            .context("missing CLIENT_CONFIG")?,
    )?;
    client_config.set(0, Config(config), 0)?;
    let cache: HashMap<_, [u8; 16], Route> =
        HashMap::try_from(bpf.take_map("ROUTES").context("missing ROUTES")?)?;
    let mut heartbeat: Array<_, u64> =
        Array::try_from(bpf.take_map("HEARTBEAT").context("missing HEARTBEAT")?)?;
    let stats: PerCpuArray<_, u64> = PerCpuArray::try_from(
        bpf.take_map("CLIENT_STATS")
            .context("missing CLIENT_STATS")?,
    )?;
    let mut direct = PrefixTable::new(bpf.take_map("SYSTEM").context("missing SYSTEM")?)?;
    direct.update(
        direct_prefixes(v6, &servers)?,
        SYSTEM_ENTRIES,
        "local networks and addresses",
    )?;
    let mut table = PrefixTable::new(bpf.take_map("CLIENTS").context("missing CLIENTS")?)?;
    table.update(
        client_entries(&clients, family),
        CLIENT_ENTRIES,
        "\"from\" prefixes",
    )?;
    heartbeat.set(0, monotonic_ns(), 0)?;
    let datapath = Datapath::attach(&mut bpf, cfg.xdp_mode, &dev, l3, &segment.inner, v6)?;
    // Driver XDP sees packets before GRO merges them.
    let _gro = (datapath.mode != "driver XDP").then(|| UdpGro::disable(&dev));
    let _steering = if l3 { Steering::pipeline(&dev) } else { None };
    let excluded = [
        dev.clone(),
        cfg.interface.clone(),
        segment.outer.clone(),
        segment.inner.clone(),
        "lo".into(),
    ];
    let mut lan = Lan::default();
    lan.update(&mut bpf, &clients, family, &excluded, v6)?;

    let router = Router {
        rules: &rules,
        system,
        hosts: Mutex::new(std::collections::HashMap::new()),
        cache: Mutex::new(cache),
    };
    let address = tunnel_address(&cfg, 0)?;
    let forwarder = SocketAddr::new(address, cfg.dns.port);
    let mut _system_dns = None;
    let dns = if rules.uses_dns() {
        let listener = dns::Listener::bind(forwarder)?;
        if cfg.dns.set_system {
            _system_dns = routes::set_dns(&cfg.interface, config.tun, forwarder)?;
        }
        Some((
            dns::Forwarder::new(&rules, &router, cfg.dns_servers()),
            listener,
        ))
    } else {
        None
    };
    let counts = Counters::default();
    let server_text = match &cfg.servers[..] {
        [server] => format!("server={}", server.address),
        all => {
            let list: Vec<String> = all
                .iter()
                .map(|s| format!("{} {}", s.tag, s.address))
                .collect();
            format!("servers={}", list.join(", "))
        }
    };
    println!(
        "edup client ready: {} {}, {server_text}, MTU={}, mode=xdp ({} on {dev}, source {local}){}{}",
        cfg.interface,
        address,
        cfg.mtu,
        datapath.mode,
        clients_text(&cfg, &table, &lan, local, config.local_mode),
        if dns.is_some() {
            format!(", DNS={forwarder}")
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
    let core = configuration_core(path)?;
    let mut reload = || {
        let result = (|| -> Result<()> {
            let next = Settings::load(path)?;
            if configuration_core(path)? != core {
                eprintln!(
                    "warning: the configuration changed beyond \"from\" rules; restart edup-client to apply it"
                );
            }
            // The client table names servers by their index in eBPF.
            let same = |a: &crate::config::Server, b: &crate::config::Server| {
                (a.tag.as_str(), a.address, a.user, a.password.as_str())
                    == (b.tag.as_str(), b.address, b.user, b.password.as_str())
            };
            ensure!(
                next.servers.len() == cfg.servers.len()
                    && next
                        .servers
                        .iter()
                        .zip(&cfg.servers)
                        .all(|(a, b)| same(a, b)),
                "the servers changed; restart edup-client to apply them"
            );
            let clients = routing::clients(&next);
            direct.update(
                direct_prefixes(v6, &servers)?,
                SYSTEM_ENTRIES,
                "local networks and addresses",
            )?;
            table.update(
                client_entries(&clients, family),
                CLIENT_ENTRIES,
                "\"from\" prefixes",
            )?;
            config.local_mode = mode(clients.target(local));
            client_config.set(0, Config(config), 0)?;
            lan.update(&mut bpf, &clients, family, &excluded, v6)?;
            println!(
                "edup client reloaded{}",
                clients_text(&cfg, &table, &lan, local, config.local_mode)
            );
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("reload failed, keeping the previous client table: {error:#}");
        }
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
        let result = keepalive(&socket, &cfg, &keys, &counts, &stop, &report, &mut reload);
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
    drop(lan);
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

/// Whether `dev` carries IP packets without a link-layer header, as PPP;
/// otherwise it must be Ethernet.
fn link_layer(dev: &str) -> Result<bool> {
    const ETHER: u32 = 1;
    const PPP: u32 = 512;
    const IPGRE: u32 = 778;
    const NONE: u32 = 65534;
    let path = Path::new("/sys/class/net").join(dev).join("type");
    let kind: u32 = fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?
        .trim()
        .parse()?;
    match kind {
        ETHER => Ok(false),
        PPP | IPGRE | NONE => Ok(true),
        _ => bail!(
            "xdp mode needs an Ethernet, PPP or other IP-level interface; {dev} is type {kind}"
        ),
    }
}

/// Offloaded flows leave the stack before the egress hook sees them.
fn warn_flowtables() {
    let Ok(out) = Command::new("nft").args(["list", "flowtables"]).output() else {
        return;
    };
    if out.status.success() && String::from_utf8_lossy(&out.stdout).contains("flowtable") {
        eprintln!(
            "warning: nftables flow offloading is active; offloaded connections bypass edup (OpenWrt: disable flow offloading in the firewall settings)"
        );
    }
}

/// The host's own DNS upstreams follow the rules like its other traffic.
/// Through a tunnel they see the server's address, which resolvers that
/// only answer their own network, as ISP resolvers often do, refuse.
fn warn_proxied_resolvers(
    rules: &Rules,
    clients: &Clients,
    local: IpAddr,
    system: &IpSet,
    v6: bool,
) -> Result<()> {
    let mut direct: IpSet = system.clone();
    for (_, prefix) in routes::interface_prefixes(v6)? {
        direct = direct.union(&IpSet::from_ranges(vec![prefix.range()]));
    }
    for ip in routes::dnsmasq_upstreams() {
        if Family::of(ip) != rules.family()
            || rules.servers.contains(&ip)
            || !unicast(ip)
            || direct.contains(key(ip))
        {
            continue;
        }
        let proxied = match clients.target(local) {
            Target::Server(_) => true,
            Target::Direct => false,
            Target::Rules => rules.address_action(ip) != Action::Direct,
        };
        if proxied {
            eprintln!(
                "warning: dnsmasq's upstream DNS server {ip} is reached through a tunnel; if it only answers its own network (as ISP resolvers often do), add a direct rule for it or use another resolver"
            );
        }
    }
    Ok(())
}

/// The configuration without `from` rules: a SIGHUP applies only those.
fn configuration_core(path: &Path) -> Result<serde_json::Value> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut value: serde_json::Value = edup_common::json::parse(&text)
        .map_err(|e| anyhow::anyhow!("invalid configuration {}: {e}", path.display()))?;
    if let Some(routes) = value
        .pointer_mut("/routing/routes")
        .and_then(|r| r.as_array_mut())
    {
        routes.retain(|r| r.get("from").is_none());
    }
    Ok(value)
}

/// The eBPF mode of a client table target.
fn mode(target: Target) -> u8 {
    match target {
        Target::Server(i) => MODE_SERVER + i as u8,
        Target::Direct => MODE_DIRECT,
        Target::Rules => MODE_RULES,
    }
}

fn clients_text(
    cfg: &Settings,
    table: &PrefixTable,
    lan: &Lan,
    local: IpAddr,
    local_mode: u8,
) -> String {
    if table.entries.is_empty() && lan.links.is_empty() {
        return String::new();
    }
    let interfaces: Vec<&str> = lan.links.keys().map(String::as_str).collect();
    format!(
        ", clients: {} prefixes on {}{}",
        table.entries.len(),
        if interfaces.is_empty() {
            "no interface".to_string()
        } else {
            interfaces.join(", ")
        },
        match local_mode {
            MODE_DIRECT => format!(", {local} direct"),
            MODE_RULES => String::new(),
            mode => format!(
                ", {local} through {}",
                cfg.name(Action::Server((mode - MODE_SERVER).into()))
            ),
        }
    )
}

type Entries = BTreeMap<(u8, [u8; 16]), u32>;

fn entry(prefix: &Prefix) -> (u8, [u8; 16]) {
    let mut data = [0; 16];
    let address = octets(prefix.addr);
    data[..address.len()].copy_from_slice(&address);
    (prefix.len, data)
}

fn client_entries(clients: &Clients, family: Family) -> Entries {
    clients
        .entries(family)
        .iter()
        .map(|(prefix, target)| (entry(prefix), u32::from(mode(*target))))
        .collect()
}

/// Destinations that need no route: every interface's networks, the host's
/// own addresses and the servers.
fn direct_prefixes(v6: bool, servers: &[IpAddr]) -> Result<Entries> {
    let mut entries: Entries = routes::interface_prefixes(v6)?
        .iter()
        .map(|(_, prefix)| (entry(prefix), 1))
        .collect();
    for &address in local_addresses(v6)?.iter().chain(servers) {
        entries.insert(entry(&Prefix::host(address)), 1);
    }
    Ok(entries)
}

/// An eBPF LPM trie and the entries userspace stored in it.
struct PrefixTable {
    map: lpm_trie::LpmTrie<MapData, [u8; 16], u32>,
    entries: Entries,
}
impl PrefixTable {
    fn new(map: aya::maps::Map) -> Result<Self> {
        Ok(Self {
            map: lpm_trie::LpmTrie::try_from(map)?,
            entries: Entries::new(),
        })
    }
    /// Inserts new and changed entries before removing old ones.
    fn update(&mut self, wanted: Entries, limit: u32, what: &str) -> Result<()> {
        ensure!(
            wanted.len() <= limit as usize,
            "{} {what}; at most {limit} are supported",
            wanted.len()
        );
        for (&(len, data), value) in &wanted {
            if self.entries.get(&(len, data)) != Some(value) {
                self.map
                    .insert(&lpm_trie::Key::new(len.into(), data), value, 0)
                    .with_context(|| format!("store {what}"))?;
            }
        }
        for &(len, data) in self.entries.keys() {
            if !wanted.contains_key(&(len, data)) {
                self.map
                    .remove(&lpm_trie::Key::new(len.into(), data))
                    .with_context(|| format!("remove {what}"))?;
            }
        }
        self.entries = wanted;
        Ok(())
    }
}

/// Classifiers on the LAN interfaces whose networks contain clients.
#[derive(Default)]
struct Lan {
    links: BTreeMap<String, SchedClassifierLink>,
}
impl Lan {
    fn update(
        &mut self,
        bpf: &mut Ebpf,
        clients: &Clients,
        family: Family,
        excluded: &[String],
        v6: bool,
    ) -> Result<()> {
        let mut wanted = Vec::new();
        if !clients.is_empty() {
            for (dev, prefix) in routes::interface_prefixes(v6)? {
                let network = IpSet::from_ranges(vec![prefix.range()]);
                if prefix.family() == family
                    && !excluded.contains(&dev)
                    && !wanted.contains(&dev)
                    && !network.intersection(&clients.listed).is_empty()
                {
                    wanted.push(dev);
                }
            }
            if wanted.is_empty() {
                eprintln!(
                    "warning: no interface network contains a \"from\" source; only this host's own traffic follows the client table"
                );
            }
        }
        self.links.retain(|dev, _| wanted.contains(dev));
        for dev in wanted {
            if self.links.contains_key(&dev) {
                continue;
            }
            let name = format!(
                "edup_classify{}{}",
                if v6 { 6 } else { 4 },
                if link_layer(&dev)? { "_l3" } else { "" }
            );
            let program = classifier(bpf, &name)?;
            if program.fd().is_err() {
                program
                    .load()
                    .with_context(|| format!("kernel rejected {name}"))?;
            }
            // Before Linux 6.6 (no TCX), programs attach to clsact qdiscs.
            if !KernelVersion::current().is_ok_and(|v| v >= KernelVersion::new(6, 6, 0)) {
                let _ = tc::qdisc_add_clsact(&dev);
                let _ = tc::qdisc_detach_program(&dev, TcAttachType::Ingress, &name);
            }
            let id = program
                .attach(&dev, TcAttachType::Ingress)
                .with_context(|| format!("attach {name} to {dev}"))?;
            self.links.insert(dev, program.take_link(id)?);
        }
        Ok(())
    }
}

/// Attached programs, detached in field order.
struct Datapath {
    _egress: SchedClassifierLink,
    _ingress: Ingress,
    _encap: SchedClassifierLink,
    mode: &'static str,
}
enum Ingress {
    Xdp(#[allow(dead_code)] XdpLink),
    Tc(#[allow(dead_code)] SchedClassifierLink),
}
impl Datapath {
    /// Loads every program before attaching any, and attaches the egress hook
    /// last, when the encapsulation and decapsulation paths already work.
    fn attach(
        bpf: &mut Ebpf,
        mode: XdpMode,
        dev: &str,
        l3: bool,
        encap: &str,
        v6: bool,
    ) -> Result<Self> {
        let family = if v6 { 6 } else { 4 };
        let suffix = if l3 { "_l3" } else { "" };
        let egress_name = format!("edup_egress{family}{suffix}");
        let encap_name = format!("edup_encap{family}");
        let ingress_name = if l3 {
            format!("edup_decap{family}_l3")
        } else {
            format!("edup_ingress{family}")
        };
        let mut classifiers = vec![&egress_name, &encap_name];
        if l3 {
            classifiers.push(&ingress_name);
        } else {
            xdp(bpf, &ingress_name)?
                .load()
                .with_context(|| format!("kernel rejected {ingress_name}"))?;
        }
        for name in classifiers {
            classifier(bpf, name)?
                .load()
                .with_context(|| format!("kernel rejected {name}"))?;
        }
        // Before Linux 6.6 (no TCX), programs attach to clsact qdiscs and
        // outlive a crashed client. Its egress hook falls back to the
        // standard route without heartbeat; replace it.
        if !KernelVersion::current().is_ok_and(|v| v >= KernelVersion::new(6, 6, 0)) {
            for name in [dev, encap] {
                let _ = tc::qdisc_add_clsact(name);
            }
            let _ = tc::qdisc_detach_program(dev, TcAttachType::Egress, &egress_name);
            if l3 {
                let _ = tc::qdisc_detach_program(dev, TcAttachType::Ingress, &ingress_name);
            }
        }
        let program = classifier(bpf, &encap_name)?;
        let id = program
            .attach(encap, TcAttachType::Ingress)
            .with_context(|| format!("attach {encap_name} to {encap}"))?;
        let encap_link = program.take_link(id)?;
        let (ingress, mode) = if l3 {
            if mode != XdpMode::Auto {
                eprintln!("{dev} has no link-layer header; decapsulating in TC, not XDP");
            }
            let program = classifier(bpf, &ingress_name)?;
            let id = program
                .attach(dev, TcAttachType::Ingress)
                .with_context(|| format!("attach {ingress_name} to {dev}"))?;
            (Ingress::Tc(program.take_link(id)?), "TC")
        } else {
            let program = xdp(bpf, &ingress_name)?;
            let attach = |program: &mut Xdp, mode| program.attach(dev, mode);
            let (id, mode) = match mode {
                XdpMode::Driver => (
                    attach(program, aya::programs::XdpMode::Driver)?,
                    "driver XDP",
                ),
                XdpMode::Skb => (attach(program, aya::programs::XdpMode::Skb)?, "skb XDP"),
                XdpMode::Auto => match attach(program, aya::programs::XdpMode::Driver) {
                    Ok(id) => (id, "driver XDP"),
                    Err(error) => {
                        eprintln!("native XDP unavailable on {dev} ({error}); using generic XDP");
                        (attach(program, aya::programs::XdpMode::Skb)?, "skb XDP")
                    }
                },
            };
            (Ingress::Xdp(program.take_link(id)?), mode)
        };
        let program = classifier(bpf, &egress_name)?;
        let id = program
            .attach(dev, TcAttachType::Egress)
            .with_context(|| format!("attach {egress_name} to {dev}"))?;
        Ok(Self {
            _egress: program.take_link(id)?,
            _ingress: ingress,
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
        if Family::of(ip) != self.rules.family()
            || self.rules.servers.contains(&ip)
            || !unicast(ip)
            || self.system.contains(key(ip))
        {
            return Action::Direct;
        }
        let hosts = self.hosts.lock().unwrap_or_else(|e| e.into_inner());
        hosts
            .get(&ip)
            .copied()
            .unwrap_or_else(|| self.rules.address_action(ip))
    }
    fn publish(&self, ip: IpAddr) -> Result<()> {
        let action = match self.decide(ip) {
            Action::Server(i) => mode(Target::Server(i)),
            Action::Direct => MODE_DIRECT,
        };
        let mut address = [0; 16];
        address[..octets(ip).len()].copy_from_slice(&octets(ip));
        let route = Route(RouteEntry {
            since_ns: 0,
            action: action.into(),
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
            let Some(destination) = destination(packet, local.is_ipv6()) else {
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
/// The destination of a looked-up packet: one the local stack sent, or one
/// a LAN client sent, before masquerading.
fn destination(packet: &[u8], v6: bool) -> Option<IpAddr> {
    match (packet.first()? >> 4, v6) {
        (4, false) if packet.len() >= 20 => {
            Some(IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?))
        }
        (6, true) if packet.len() >= 40 => {
            Some(IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?))
        }
        _ => None,
    }
}

/// KEEPALIVE keeps each server's endpoint for this socket current; the
/// servers answer each one. Tunnel data never reaches the socket: eBPF takes
/// it first. Reload requests run here, between receive timeouts.
fn keepalive(
    socket: &UdpSocket,
    cfg: &Settings,
    keys: &[Key],
    counts: &Counters,
    stop: &AtomicBool,
    report: &dyn Fn(),
    reload: &mut dyn FnMut(),
) -> Result<()> {
    let mut buf = [0u8; 2048];
    let mut next = Instant::now();
    let diagnostics = std::env::var_os("EDUP_DIAGNOSTICS").is_some();
    let mut report_at = Instant::now() + Duration::from_secs(5);
    while !stop.load(Relaxed) {
        if RELOAD.swap(false, Relaxed) {
            reload();
        }
        if diagnostics && Instant::now() >= report_at {
            report();
            report_at = Instant::now() + Duration::from_secs(5);
        }
        if Instant::now() >= next {
            for (server, key) in cfg.servers.iter().zip(keys) {
                let mut keepalive = [0; wire::HDR_LEN];
                wire::seal(key, wire::TYPE_KEEPALIVE, server.user, &mut keepalive);
                match socket.send_to(&keepalive, server.address) {
                    Ok(_) => {
                        counts.keepalive_sent.fetch_add(1, Relaxed);
                    }
                    Err(e) if temporary(&e) => {}
                    Err(e) => return Err(e).context("send KEEPALIVE"),
                }
            }
            next = Instant::now() + Duration::from_secs(cfg.keepalive_secs);
        }
        let (len, from) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(e) if temporary(&e) => continue,
            Err(e) => return Err(e).context("receive UDP"),
        };
        let data = &mut buf[..len];
        let sender = cfg
            .servers
            .iter()
            .zip(keys)
            .find(|(s, _)| s.address.ip() == from.ip() && s.address.port() == from.port());
        let keepalive = sender.is_some_and(|(server, key)| {
            len == wire::HDR_LEN
                && wire::user_id(data) == Some(server.user)
                && wire::open(key, data).is_some_and(|o| o.typ == wire::TYPE_KEEPALIVE)
        });
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

/// Every address of the family on any interface.
fn local_addresses(v6: bool) -> Result<Vec<IpAddr>> {
    #[derive(serde::Deserialize)]
    struct Link {
        addr_info: Vec<Address>,
    }
    #[derive(serde::Deserialize)]
    struct Address {
        local: Option<IpAddr>,
    }
    let json = ip(&["-j", if v6 { "-6" } else { "-4" }, "addr", "show"])?;
    let links: Vec<Link> = serde_json::from_str(&json).context("read addresses")?;
    Ok(links
        .iter()
        .flat_map(|l| &l.addr_info)
        .filter_map(|a| a.local)
        .collect())
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
        ])
        .context("create the segmentation veth pair (needs the veth module; OpenWrt: kmod-veth)")?;
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

    /// Prepares the reverse direction for TC decapsulation, which runs after
    /// GRO: inner packets sent into `<interface>e` reach the stack through
    /// `<interface>s`, whose GRO merges TCP segments and whose packet
    /// steering spreads inner flows over all CPUs. Returns the sending end's
    /// index and the receiving end's MAC address, or None where reverse path
    /// filtering would drop packets arriving there.
    fn inbound(&self, v6: bool) -> Result<Option<(u32, [u8; 6])>> {
        let strict = |path: &str| fs::read_to_string(path).is_ok_and(|v| v.trim() == "1");
        if !v6 && strict("/proc/sys/net/ipv4/conf/all/rp_filter") {
            eprintln!(
                "note: strict reverse path filtering (net.ipv4.conf.all.rp_filter=1) keeps tunnel packets on the plain receive path"
            );
            return Ok(None);
        }
        let outer = &self.outer;
        let conf = |family: &str, key: &str, value: &str| {
            fs::write(format!("/proc/sys/net/{family}/conf/{outer}/{key}"), value)
                .with_context(|| format!("set {family} {key} on {outer}"))
        };
        if v6 {
            // Receive IPv6 without addresses of its own.
            conf("ipv6", "addr_gen_mode", "1")?;
            conf("ipv6", "accept_ra", "0")?;
            conf("ipv6", "disable_ipv6", "0")?;
        } else {
            conf("ipv4", "rp_filter", "0")?;
        }
        // Without receive checksum offload GRO verifies the inner checksums,
        // which merging would otherwise hide from the receiver. Veth skips GRO
        // for packets from a sender with TSO.
        ethtool_set(outer, ETHTOOL_SRXCSUM, 0)
            .and_then(|()| ethtool_set(outer, ETHTOOL_SGRO, 1))
            .and_then(|()| ethtool_set(&self.inner, ETHTOOL_STSO, 0))
            .with_context(|| format!("enable GRO on {outer}"))?;
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get().min(32));
        if cpus > 1 {
            let mask = format!("{:x}", (1u64 << cpus) - 1);
            let path = format!("/sys/class/net/{outer}/queues/rx-0/rps_cpus");
            if let Err(error) = fs::write(&path, mask) {
                eprintln!("warning: packet steering on {outer}: {error}");
            }
        }
        let address = fs::read_to_string(format!("/sys/class/net/{outer}/address"))?;
        let mut mac = [0u8; 6];
        for (byte, part) in mac.iter_mut().zip(address.trim().split(':')) {
            *byte = u8::from_str_radix(part, 16)?;
        }
        let name = std::ffi::CString::new(self.inner.as_str())?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        ensure!(index != 0, "interface {} vanished", self.inner);
        Ok(Some((index, mac)))
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

/// UDP receive offloads that merge consecutive datagrams of one flow into
/// one packet. Decapsulation after GRO (TC, generic XDP) takes only single
/// tunnel datagrams; merged ones would reach the client's socket and be lost.
const UDP_GRO: [&str; 2] = ["rx-gro-list", "rx-udp-gro-forwarding"];

/// Turns UDP GRO off on the physical interface and the devices below it,
/// where GRO runs, and back on when dropped. A crashed client leaves it off.
struct UdpGro(Vec<(String, Vec<u32>)>);
impl UdpGro {
    fn disable(dev: &str) -> Self {
        let mut disabled = Vec::new();
        for name in lower_devices(dev) {
            let result = active_features(&name, &UDP_GRO)
                .and_then(|bits| set_features(&name, &bits, false).map(|()| bits));
            match result {
                Ok(bits) if !bits.is_empty() => disabled.push((name, bits)),
                Ok(_) => {}
                Err(error) => eprintln!(
                    "warning: cannot turn off UDP GRO on {name} ({error:#}); merged tunnel packets will be dropped"
                ),
            }
        }
        if !disabled.is_empty() {
            let names: Vec<&str> = disabled.iter().map(|(name, _)| name.as_str()).collect();
            eprintln!(
                "UDP GRO ({}) off on {} while the client runs",
                UDP_GRO.join(", "),
                names.join(", ")
            );
        }
        Self(disabled)
    }
}
impl Drop for UdpGro {
    fn drop(&mut self) {
        for (name, bits) in &self.0 {
            if let Err(error) = set_features(name, bits, true) {
                eprintln!("cannot turn UDP GRO back on for {name}: {error:#}");
            }
        }
    }
}

/// Packet steering of an interface without a link-layer header, restored
/// when dropped. All tunnel packets form one flow and steer to one CPU, which
/// then receives, decapsulates and merges them. Steering the interface to the
/// CPUs that do not process the devices below it splits that work in two.
struct Steering {
    path: String,
    previous: String,
}
impl Steering {
    fn pipeline(dev: &str) -> Option<Self> {
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get().min(32));
        let all = (1u64 << cpus) - 1;
        let read = |dev: &str| {
            let path = format!("/sys/class/net/{dev}/queues/rx-0/rps_cpus");
            let text = fs::read_to_string(&path).ok()?;
            let mask = u64::from_str_radix(&text.trim().replace(',', ""), 16).ok()?;
            Some((path, text.trim().to_owned(), mask))
        };
        let (path, previous, current) = read(dev)?;
        // The lower devices' CPUs, when their steering names some but not all.
        let lower = lower_devices(dev)
            .iter()
            .skip(1)
            .filter_map(|d| read(d))
            .fold(0, |mask, (_, _, m)| mask | (m & all));
        let wanted = all & !lower;
        if cpus < 2 || lower == 0 || wanted == 0 || current == wanted {
            return None;
        }
        if let Err(error) = fs::write(&path, format!("{wanted:x}")) {
            eprintln!("warning: packet steering on {dev}: {error}");
            return None;
        }
        eprintln!("{dev} steered to CPU mask {wanted:x} (was {previous}) while the client runs");
        Some(Self { path, previous })
    }
}
impl Drop for Steering {
    fn drop(&mut self) {
        let _ = fs::write(&self.path, &self.previous);
    }
}

/// `dev` and the devices it receives through: PPPoE's Ethernet devices and
/// `lower_*` links (VLAN, macvlan, bond, DSA).
fn lower_devices(dev: &str) -> Vec<String> {
    let mut out = vec![dev.to_owned()];
    let mut i = 0;
    while i < out.len() {
        let link = Path::new("/sys/class/net").join(&out[i]);
        let mut found = Vec::new();
        if fs::read_to_string(link.join("type")).is_ok_and(|t| t.trim() == "512") {
            // Id Address Device
            let sessions = fs::read_to_string("/proc/net/pppoe").unwrap_or_default();
            found.extend(
                sessions
                    .lines()
                    .skip(1)
                    .filter_map(|l| Some(l.split_whitespace().nth(2)?.to_owned())),
            );
        }
        for entry in fs::read_dir(&link).into_iter().flatten().flatten() {
            if let Some(name) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.strip_prefix("lower_"))
            {
                found.push(name.to_owned());
            }
        }
        for name in found {
            if !out.contains(&name) {
                out.push(name);
            }
        }
        i += 1;
    }
    out
}

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_SRXCSUM: u32 = 0x15;
const ETHTOOL_STXCSUM: u32 = 0x17;
const ETHTOOL_GSTRINGS: u32 = 0x1b;
const ETHTOOL_STSO: u32 = 0x1f;
const ETHTOOL_SGSO: u32 = 0x24;
const ETHTOOL_SGRO: u32 = 0x2c;
const ETHTOOL_GSSET_INFO: u32 = 0x37;
const ETHTOOL_GFEATURES: u32 = 0x3a;
const ETHTOOL_SFEATURES: u32 = 0x3b;
const ETH_SS_FEATURES: u32 = 4;
const ETH_GSTRING_LEN: usize = 32;

/// SIOCETHTOOL with `data` as the command structure.
fn ethtool<T: ?Sized>(name: &str, data: &mut T) -> Result<()> {
    #[repr(C)]
    struct Request {
        name: [u8; 16],
        data: *mut libc::c_void,
        _pad: [u8; 16],
    }
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    let mut request = Request {
        name: [0; 16],
        data: (data as *mut T).cast(),
        _pad: [0; 16],
    };
    ensure!(name.len() < 16, "interface name too long");
    request.name[..name.len()].copy_from_slice(name.as_bytes());
    // Feature requests may return flags above zero.
    let rc = unsafe { libc::ioctl(socket.as_raw_fd(), SIOCETHTOOL as _, &raw mut request) };
    ensure!(rc >= 0, "ethtool: {}", io::Error::last_os_error());
    Ok(())
}

/// Legacy single-feature ethtool request, as `ethtool -K <name> tx off`.
fn ethtool_set(name: &str, command: u32, value: u32) -> Result<()> {
    #[repr(C)]
    struct Value {
        cmd: u32,
        data: u32,
    }
    ethtool(
        name,
        &mut Value {
            cmd: command,
            data: value,
        },
    )
}

/// Feature names in bit order, which differs between kernels, and the
/// active features, one word per 32 of them.
fn features(name: &str) -> Result<(Vec<String>, Vec<u32>)> {
    #[repr(C)]
    struct SetInfo {
        cmd: u32,
        reserved: u32,
        mask: u64,
        count: u32,
    }
    let mut info = SetInfo {
        cmd: ETHTOOL_GSSET_INFO,
        reserved: 0,
        mask: 1 << ETH_SS_FEATURES,
        count: 0,
    };
    ethtool(name, &mut info)?;
    ensure!(info.mask != 0, "no feature names");
    let count = info.count as usize;
    // struct ethtool_gstrings: cmd, string_set, len, then the names.
    let mut strings = vec![0u32; 3 + count * ETH_GSTRING_LEN / 4];
    strings[..3].copy_from_slice(&[ETHTOOL_GSTRINGS, ETH_SS_FEATURES, count as u32]);
    ethtool(name, &mut strings[..])?;
    let bytes: Vec<u8> = strings[3..].iter().flat_map(|w| w.to_ne_bytes()).collect();
    let names = bytes
        .chunks(ETH_GSTRING_LEN)
        .map(|s| {
            let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
            String::from_utf8_lossy(&s[..end]).into_owned()
        })
        .collect();
    // struct ethtool_gfeatures: cmd, size, then per 32 features available,
    // requested, active and never_changed.
    let blocks = count.div_ceil(32);
    let mut get = vec![0u32; 2 + blocks * 4];
    get[..2].copy_from_slice(&[ETHTOOL_GFEATURES, blocks as u32]);
    ethtool(name, &mut get[..])?;
    let active = (0..blocks).map(|b| get[2 + b * 4 + 2]).collect();
    Ok((names, active))
}
fn is_active(active: &[u32], bit: u32) -> bool {
    active
        .get(bit as usize / 32)
        .is_some_and(|word| word & (1 << (bit % 32)) != 0)
}

/// Bit numbers of the `wanted` features active on `name`.
fn active_features(name: &str, wanted: &[&str]) -> Result<Vec<u32>> {
    let (names, active) = features(name)?;
    Ok((0..names.len() as u32)
        .filter(|&bit| wanted.contains(&names[bit as usize].as_str()) && is_active(&active, bit))
        .collect())
}

fn set_features(name: &str, bits: &[u32], on: bool) -> Result<()> {
    let Some(&last) = bits.iter().max() else {
        return Ok(());
    };
    let blocks = last as usize / 32 + 1;
    // struct ethtool_sfeatures: cmd, size, then per 32 features valid and
    // requested.
    let mut set = vec![0u32; 2 + blocks * 2];
    set[..2].copy_from_slice(&[ETHTOOL_SFEATURES, blocks as u32]);
    for &bit in bits {
        let block = 2 + bit as usize / 32 * 2;
        set[block] |= 1 << (bit % 32);
        if on {
            set[block + 1] |= 1 << (bit % 32);
        }
    }
    ethtool(name, &mut set[..])?;
    let (_, active) = features(name)?;
    ensure!(
        bits.iter().all(|&bit| is_active(&active, bit) == on),
        "the kernel kept the previous setting"
    );
    Ok(())
}

#[cfg(test)]
#[path = "xdp_tests.rs"]
mod tests;
