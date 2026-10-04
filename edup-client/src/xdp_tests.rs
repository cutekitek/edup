//! Kernel verifier and BPF_PROG_TEST_RUN checks of the XDP mode programs
//! against the userspace wire implementation. No interface is attached.
use super::*;
use aya::programs::{Program, TestRun, TestRunOptions};
use edup_common::maps::{HEARTBEAT_TIMEOUT_NS, LOOKUP_RETRY_NS, LOOKUP_WAIT_NS, ROUTE_PENDING};

const LOCAL: [u8; 4] = [198, 51, 100, 7];
const REMOTE: [u8; 4] = [203, 0, 113, 9];
const SERVER: [u8; 4] = [192, 0, 2, 1];
const LOCAL6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
const REMOTE6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
const SERVER6: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const USER: i64 = 4829017365182049271;
const KEY: Key = Key { k0: 123, k1: 456 };
const PORT: u16 = 40000;
const MTU: u16 = 1400;
const MAC: [u8; 12] = [2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2];
const REDIRECT: u32 = 7;
const SHOT: u32 = 2;
const UNSPEC: u32 = u32::MAX;
const XDP_PASS: u32 = 2;

fn csum(data: &[u8]) -> u16 {
    let mut sum: u64 = data
        .chunks(2)
        .map(|w| (u64::from(w[0]) << 8) | u64::from(*w.get(1).unwrap_or(&0)))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn pseudo(src: &[u8], dst: &[u8], proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut p = [src, dst].concat();
    if src.len() == 4 {
        p.extend([0, proto]);
        p.extend((l4.len() as u16).to_be_bytes());
    } else {
        p.extend((l4.len() as u32).to_be_bytes());
        p.extend([0, 0, 0, proto]);
    }
    p.extend(l4);
    p
}
/// IPv4 or IPv6 packet with valid checksums around `l4`.
fn ip(src: &[u8], dst: &[u8], proto: u8, mut l4: Vec<u8>) -> Vec<u8> {
    let check = match proto {
        6 => 16,
        17 => 6,
        _ => 2,
    };
    l4[check..check + 2].fill(0);
    let mut c = if proto == 1 {
        csum(&l4)
    } else {
        csum(&pseudo(src, dst, proto, &l4))
    };
    if proto == 17 && c == 0 {
        c = 0xffff;
    }
    l4[check..check + 2].copy_from_slice(&c.to_be_bytes());
    if src.len() == 4 {
        let mut h = vec![0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, proto, 0, 0];
        h[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
        h.extend(src);
        h.extend(dst);
        let c = csum(&h);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        h.extend(l4);
        h
    } else {
        let mut h = vec![0x60, 0x0a, 0xbc, 0xde];
        h.extend((l4.len() as u16).to_be_bytes());
        h.extend([proto, 64]);
        h.extend(src);
        h.extend(dst);
        h.extend(l4);
        h
    }
}
fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut l4 = sport.to_be_bytes().to_vec();
    l4.extend(dport.to_be_bytes());
    l4.extend(((8 + payload.len()) as u16).to_be_bytes());
    l4.extend([0, 0]);
    l4.extend(payload);
    l4
}
fn syn(flags: u8) -> Vec<u8> {
    let mut l4 = vec![0; 24];
    l4[..4].copy_from_slice(&[0x9c, 0x40, 1, 0xbb]);
    l4[12] = 0x60;
    l4[13] = flags;
    l4[20..].copy_from_slice(&[2, 4, 0x05, 0xb4]);
    l4
}
fn echo(kind: u8) -> Vec<u8> {
    vec![kind, 0, 0, 0, 0, 1, 0, 1, 1, 2, 3, 4]
}
fn frame(ip: &[u8]) -> Vec<u8> {
    let ether: [u8; 2] = if ip[0] >> 4 == 6 {
        [0x86, 0xdd]
    } else {
        [8, 0]
    };
    [&MAC[..], &ether, ip].concat()
}

fn load(v6: bool) -> Ebpf {
    let mut bpf = Ebpf::load(OBJECT).unwrap();
    set_keystream(&mut bpf, &KEY).unwrap();
    let mut config = ClientConfig {
        key0: KEY.k0,
        key1: KEY.k1,
        user: USER,
        server_port_be: 7777u16.to_be(),
        local_port_be: PORT.to_be(),
        mtu: MTU,
        v6: v6.into(),
        physical: 1,
        segment: 2,
        tun: 3,
        mark: CLIENT_MARK,
        ..ClientConfig::default()
    };
    if v6 {
        config.local = LOCAL6;
        config.server = SERVER6;
    } else {
        config.local[..4].copy_from_slice(&LOCAL);
        config.server[..4].copy_from_slice(&SERVER);
    }
    Array::<_, Config>::try_from(bpf.map_mut("CLIENT_CONFIG").unwrap())
        .unwrap()
        .set(0, Config(config), 0)
        .unwrap();
    let family = if v6 { 6 } else { 4 };
    // The verifier accepts the variants for interfaces without a link-layer
    // header too; BPF_PROG_TEST_RUN always passes Ethernet frames.
    for name in [
        format!("edup_egress{family}"),
        format!("edup_encap{family}"),
        format!("edup_classify{family}"),
        format!("edup_egress{family}_l3"),
        format!("edup_classify{family}_l3"),
        format!("edup_decap{family}_l3"),
    ] {
        classifier(&mut bpf, &name)
            .unwrap()
            .load()
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
    xdp(&mut bpf, &format!("edup_ingress{family}"))
        .unwrap()
        .load()
        .unwrap();
    bpf
}
fn run(bpf: &Ebpf, name: &str, input: &[u8], mark: u32) -> (u32, Vec<u8>) {
    let (code, out, _) = run_marked(bpf, name, input, mark);
    (code, out)
}
/// Also returns the mark the program leaves.
fn run_marked(bpf: &Ebpf, name: &str, input: &[u8], mark: u32) -> (u32, Vec<u8>, u32) {
    let mut out = vec![0; 4096];
    // struct __sk_buff starts with len, pkt_type and mark.
    let mut ctx = [0u8; 12];
    ctx[8..].copy_from_slice(&mark.to_ne_bytes());
    // The kernel writes back the whole struct __sk_buff.
    let mut ctx_out = [0u8; 256];
    let result = match bpf.program(name).unwrap() {
        Program::SchedClassifier(p) => p.test_run(TestRunOptions {
            data_in: Some(input),
            data_out: Some(&mut out),
            ctx_in: Some(&ctx),
            ctx_out: Some(&mut ctx_out),
            ..Default::default()
        }),
        Program::Xdp(p) => p.test_run(TestRunOptions {
            data_in: Some(input),
            data_out: Some(&mut out),
            ..Default::default()
        }),
        _ => unreachable!(),
    }
    .unwrap();
    out.truncate(result.data_size_out as usize);
    let mark = u32::from_ne_bytes(ctx_out[8..12].try_into().unwrap());
    (result.return_value, out, mark)
}
fn sealed(inner: &[u8], to_server: bool) -> Vec<u8> {
    let mut data = vec![0; wire::HDR_LEN];
    data.extend(inner);
    let len = wire::seal_data(&KEY, USER, &mut data, to_server).unwrap();
    data.truncate(len);
    data
}
fn clamped(mut inner: Vec<u8>) -> Vec<u8> {
    let ihl = if inner[0] >> 4 == 6 {
        40
    } else {
        (inner[0] & 15) as usize * 4
    };
    crate::packet::clamp_mss(&mut inner, ihl, MTU);
    inner
}
fn addresses(v6: bool) -> (&'static [u8], &'static [u8], &'static [u8]) {
    if v6 {
        (&LOCAL6, &REMOTE6, &SERVER6)
    } else {
        (&LOCAL, &REMOTE, &SERVER)
    }
}

#[test]
#[ignore = "requires root; loads eBPF programs into the kernel"]
fn encapsulation_matches_userspace_sealing() {
    for v6 in [false, true] {
        let bpf = load(v6);
        let (local, remote, server) = addresses(v6);
        let hlen = if v6 { 40 } else { 20 };
        let name = if v6 { "edup_encap6" } else { "edup_encap4" };
        let ping = if v6 { (58, 128) } else { (1, 8) };
        let largest = MTU as usize - hlen - 8;
        for (proto, l4) in [
            (17, udp(1234, 53, &[0x5a; 100])),
            (17, udp(1234, 53, &vec![0x6b; largest])),
            (17, udp(1234, 53, &[1, 2, 3])),
            (6, syn(2)),
            (ping.0, echo(ping.1)),
        ] {
            let inner = ip(local, remote, proto, l4);
            let (code, out) = run(&bpf, name, &frame(&inner), 0);
            assert_eq!(code, REDIRECT, "v6={v6} proto={proto}");
            assert_eq!(&out[..12], &MAC);
            let outer = &out[14..];
            if v6 {
                assert_eq!(&out[12..14], &[0x86, 0xdd]);
                assert_eq!(&outer[8..24], local);
                assert_eq!(&outer[24..40], server);
                let len = u16::from_be_bytes([outer[4], outer[5]]);
                assert_eq!(usize::from(len) + 40, outer.len());
            } else {
                assert_eq!(csum(&outer[..20]), 0, "outer IPv4 checksum");
                assert_eq!(&outer[12..16], local);
                assert_eq!(&outer[16..20], server);
                let len = u16::from_be_bytes([outer[2], outer[3]]);
                assert_eq!(usize::from(len), outer.len());
            }
            let udp = &outer[hlen..];
            assert_eq!(&udp[..4], &[0x9c, 0x40, 0x1e, 0x61]);
            assert_eq!(usize::from(u16::from_be_bytes([udp[4], udp[5]])), udp.len());
            assert_eq!(
                csum(&pseudo(local, server, 17, udp)),
                0,
                "outer UDP checksum"
            );
            assert_eq!(
                &udp[8..],
                sealed(&clamped(inner), true),
                "v6={v6} proto={proto}"
            );
        }
        // Too big, unsupported ICMP and a foreign source.
        let big = ip(local, remote, 17, udp(1, 2, &vec![0; largest + 1]));
        let unreachable = ip(
            local,
            remote,
            ping.0,
            vec![if v6 { 1 } else { 3 }, 0, 0, 0, 0, 0, 0, 0],
        );
        let foreign = ip(remote, remote, 17, udp(1, 2, &[0; 8]));
        for packet in [big, unreachable, foreign] {
            assert_eq!(run(&bpf, name, &frame(&packet), 0).0, SHOT);
        }
        if !v6 {
            let mut fragment = ip(local, remote, 17, udp(1, 2, &[0; 8]));
            fragment[6] = 0x20;
            assert_eq!(run(&bpf, name, &frame(&fragment), 0).0, SHOT);
        }
    }
}

#[test]
#[ignore = "requires root; loads eBPF programs into the kernel"]
fn decapsulation_matches_userspace_unpacking() {
    for v6 in [false, true] {
        let bpf = load(v6);
        let (local, remote, server) = addresses(v6);
        let name = if v6 { "edup_ingress6" } else { "edup_ingress4" };
        let ping = if v6 { (58, 129) } else { (1, 0) };
        let datagram =
            |data: &[u8], sport, dport| frame(&ip(server, local, 17, udp(sport, dport, data)));
        for (proto, l4) in [
            (17, udp(53, 1234, &[0x5a; 100])),
            (17, udp(53, 1234, &[7; 1])),
            (6, syn(0x12)),
            (ping.0, echo(ping.1)),
        ] {
            let inner = ip(remote, local, proto, l4);
            let input = datagram(&sealed(&inner, false), 7777, PORT);
            let (code, out) = run(&bpf, name, &input, 0);
            assert_eq!(code, XDP_PASS, "v6={v6} proto={proto}");
            assert_eq!(out, frame(&clamped(inner)), "v6={v6} proto={proto}");
        }
        // Everything else reaches the socket unchanged.
        let inner = ip(remote, local, 17, udp(53, 1234, &[1; 20]));
        let mut keepalive = [0; wire::HDR_LEN];
        wire::seal(&KEY, wire::TYPE_KEEPALIVE, USER, &mut keepalive);
        let mut stranger = sealed(&inner, false);
        stranger[..8].copy_from_slice(&42i64.to_be_bytes());
        for input in [
            datagram(&keepalive, 7777, PORT),
            datagram(&stranger, 7777, PORT),
            datagram(&sealed(&inner, false), 7777, PORT + 1),
            datagram(&sealed(&inner, false), 7778, PORT),
            frame(&ip(
                remote,
                local,
                17,
                udp(7777, PORT, &sealed(&inner, false)),
            )),
        ] {
            assert_eq!(run(&bpf, name, &input, 0), (XDP_PASS, input));
        }
    }
}

#[test]
#[ignore = "requires root; loads eBPF programs into the kernel"]
fn egress_asks_userspace_once_and_falls_back() {
    let mut bpf = load(false);
    let packet = frame(&ip(&LOCAL, &REMOTE, 17, udp(1, 2, &[0; 8])));
    let mut key = [0; 16];
    key[..4].copy_from_slice(&REMOTE);
    let set_heartbeat = |bpf: &mut Ebpf, value: u64| {
        Array::<_, u64>::try_from(bpf.map_mut("HEARTBEAT").unwrap())
            .unwrap()
            .set(0, value, 0)
            .unwrap();
    };
    let set_route = |bpf: &mut Ebpf, action, since_ns| {
        let route = Route(RouteEntry {
            since_ns,
            action,
            _pad: 0,
        });
        HashMap::<_, [u8; 16], Route>::try_from(bpf.map_mut("ROUTES").unwrap())
            .unwrap()
            .insert(key, route, 0)
            .unwrap();
    };
    let route = |bpf: &Ebpf| {
        HashMap::<_, [u8; 16], Route>::try_from(bpf.map("ROUTES").unwrap())
            .unwrap()
            .get(&key, 0)
            .ok()
            .map(|r| r.0)
    };
    // No heartbeat: the standard route, without a lookup.
    assert_eq!(run(&bpf, "edup_egress4", &packet, 0).0, UNSPEC);
    assert_eq!(route(&bpf), None);
    let now = monotonic_ns();
    set_heartbeat(&mut bpf, now);
    // Other families, sources, the server and multicast never look up.
    let other_family = frame(&ip(&LOCAL6, &REMOTE6, 17, udp(1, 2, &[0; 8])));
    let other_source = frame(&ip(&REMOTE, &REMOTE, 17, udp(1, 2, &[0; 8])));
    let to_server = frame(&ip(&LOCAL, &SERVER, 17, udp(PORT, 7777, &[0; 9])));
    let multicast = frame(&ip(&LOCAL, &[224, 0, 0, 251], 17, udp(5353, 5353, &[0; 8])));
    for input in [&other_family, &other_source, &to_server, &multicast] {
        assert_eq!(run(&bpf, "edup_egress4", input, 0).0, UNSPEC);
    }
    // A re-injected packet without a route is not asked about again.
    assert_eq!(run(&bpf, "edup_egress4", &packet, CLIENT_MARK).0, UNSPEC);
    assert_eq!(route(&bpf), None);
    // Unknown: ask, and keep asking while the answer is pending.
    assert_eq!(run(&bpf, "edup_egress4", &packet, 0).0, REDIRECT);
    let pending = route(&bpf).unwrap();
    assert_eq!(pending.action, ROUTE_PENDING);
    assert!(pending.since_ns >= now);
    assert_eq!(run(&bpf, "edup_egress4", &packet, 0).0, REDIRECT);
    assert_eq!(run(&bpf, "edup_egress4", &packet, CLIENT_MARK).0, UNSPEC);
    // Unanswered: the standard route, until the lookup is retried.
    let stale = monotonic_ns() - LOOKUP_WAIT_NS - 1;
    set_route(&mut bpf, ROUTE_PENDING, stale);
    assert_eq!(run(&bpf, "edup_egress4", &packet, 0).0, UNSPEC);
    assert_eq!(route(&bpf).unwrap().since_ns, stale);
    let old = monotonic_ns() - LOOKUP_RETRY_NS - 1;
    set_route(&mut bpf, ROUTE_PENDING, old);
    assert_eq!(run(&bpf, "edup_egress4", &packet, 0).0, REDIRECT);
    assert!(route(&bpf).unwrap().since_ns > old);
    // Answers, including for re-injected packets.
    set_route(&mut bpf, ROUTE_PROXY, 0);
    assert_eq!(run(&bpf, "edup_egress4", &packet, 0).0, REDIRECT);
    assert_eq!(run(&bpf, "edup_egress4", &packet, CLIENT_MARK).0, REDIRECT);
    set_route(&mut bpf, ROUTE_BYPASS, 0);
    assert_eq!(run(&bpf, "edup_egress4", &packet, 0).0, UNSPEC);
    // A stale heartbeat sends even proxied destinations the standard route.
    set_route(&mut bpf, ROUTE_PROXY, 0);
    set_heartbeat(&mut bpf, monotonic_ns() - HEARTBEAT_TIMEOUT_NS - 1);
    assert_eq!(run(&bpf, "edup_egress4", &packet, 0).0, UNSPEC);

    let stats = PerCpuArray::<_, u64>::try_from(bpf.map("CLIENT_STATS").unwrap()).unwrap();
    let count = |i: u32| -> u64 { stats.get(&i, 0).unwrap().iter().sum() };
    assert_eq!(count(client_stat::LOOKUP), 3);
    assert_eq!(count(client_stat::PROXY), 2);
    assert_eq!(count(client_stat::BYPASS), 1);
}

fn insert_prefix(bpf: &mut Ebpf, map: &str, prefix: &str, value: u32) {
    let prefix: Prefix = prefix.parse().unwrap();
    lpm_trie::LpmTrie::<_, [u8; 16], u32>::try_from(bpf.map_mut(map).unwrap())
        .unwrap()
        .insert(
            &{
                let (len, data) = entry(&prefix);
                lpm_trie::Key::new(len.into(), data)
            },
            value,
            0,
        )
        .unwrap();
}
fn mode_mark(mode: u8) -> u32 {
    u32::from(mode) << edup_common::maps::MODE_SHIFT
}

#[test]
#[ignore = "requires root; loads eBPF programs into the kernel"]
fn classifier_marks_client_modes() {
    for v6 in [false, true] {
        let mut bpf = load(v6);
        let (name, client, proxied, bypassed, other) = if v6 {
            (
                "edup_classify6",
                "fd00:1::/64",
                "fd00:1::60",
                "fd00:1::50",
                "fd00:2::1",
            )
        } else {
            (
                "edup_classify4",
                "192.168.1.0/24",
                "192.168.1.60",
                "192.168.1.50",
                "192.168.2.1",
            )
        };
        insert_prefix(&mut bpf, "CLIENTS", client, MODE_BYPASS.into());
        insert_prefix(&mut bpf, "CLIENTS", proxied, MODE_PROXY.into());
        let remote: &[u8] = if v6 { &REMOTE6 } else { &REMOTE };
        let packet = |src: &str| {
            let src = octets(src.parse().unwrap());
            frame(&ip(&src, remote, 17, udp(1, 2, &[0; 8])))
        };
        for (src, mode) in [
            (proxied, MODE_PROXY),
            (bypassed, MODE_BYPASS),
            (other, MODE_RULES),
        ] {
            // Other mark bits stay; an earlier mode byte is replaced.
            for before in [0, 0x1234, mode_mark(MODE_PROXY) | 0x10] {
                let (code, out, mark) = run_marked(&bpf, name, &packet(src), before);
                assert_eq!(code, UNSPEC);
                assert_eq!(out, packet(src));
                assert_eq!(mark, before & 0xff_ffff | mode_mark(mode), "{src}");
            }
        }
        // Another family is left alone.
        let other_family = if v6 {
            frame(&ip(&LOCAL, &REMOTE, 17, udp(1, 2, &[0; 8])))
        } else {
            frame(&ip(&LOCAL6, &REMOTE6, 17, udp(1, 2, &[0; 8])))
        };
        assert_eq!(run_marked(&bpf, name, &other_family, 7).2, 7);
        if v6 {
            continue;
        }
        // With a heartbeat, "rules" clients look up unknown destinations
        // before routing; local networks and known routes need none.
        Array::<_, u64>::try_from(bpf.map_mut("HEARTBEAT").unwrap())
            .unwrap()
            .set(0, monotonic_ns(), 0)
            .unwrap();
        insert_prefix(&mut bpf, "SYSTEM", "192.168.2.0/24", 1);
        let lan = frame(&ip(
            &[192, 168, 2, 1],
            &[192, 168, 2, 9],
            17,
            udp(1, 2, &[0; 8]),
        ));
        assert_eq!(run(&bpf, name, &lan, 0).0, UNSPEC);
        assert_eq!(run(&bpf, name, &packet(other), 0).0, REDIRECT);
        let mut key = [0; 16];
        key[..4].copy_from_slice(&REMOTE);
        let routes = HashMap::<_, [u8; 16], Route>::try_from(bpf.map("ROUTES").unwrap()).unwrap();
        assert_eq!(routes.get(&key, 0).unwrap().0.action, ROUTE_PENDING);
        // Proxied and bypassed clients never look up.
        for src in [proxied, bypassed] {
            let to = frame(&ip(
                &octets(src.parse().unwrap()),
                &[203, 0, 113, 10],
                17,
                udp(1, 2, &[0; 8]),
            ));
            assert_eq!(run(&bpf, name, &to, 0).0, UNSPEC);
        }
        let mut answered = [0; 16];
        answered[..4].copy_from_slice(&[203, 0, 113, 10]);
        assert!(routes.get(&answered, 0).is_err());
    }
}

#[test]
#[ignore = "requires root; loads eBPF programs into the kernel"]
fn egress_applies_client_modes() {
    let mut bpf = load(false);
    let peer = [10, 16, 255, 138];
    insert_prefix(&mut bpf, "SYSTEM", "10.16.255.138/32", 1);
    Array::<_, u64>::try_from(bpf.map_mut("HEARTBEAT").unwrap())
        .unwrap()
        .set(0, monotonic_ns(), 0)
        .unwrap();
    let route = |bpf: &Ebpf, ip: [u8; 4]| {
        let mut key = [0; 16];
        key[..4].copy_from_slice(&ip);
        HashMap::<_, [u8; 16], Route>::try_from(bpf.map("ROUTES").unwrap())
            .unwrap()
            .get(&key, 0)
            .ok()
    };
    let stats = |bpf: &Ebpf, i: u32| -> u64 {
        PerCpuArray::<_, u64>::try_from(bpf.map("CLIENT_STATS").unwrap())
            .unwrap()
            .get(&i, 0)
            .unwrap()
            .iter()
            .sum()
    };
    let egress = |bpf: &Ebpf, packet: &[u8], mark: u32| run(bpf, "edup_egress4", packet, mark).0;
    // Masqueraded traffic of a classified client.
    let packet = frame(&ip(&LOCAL, &REMOTE, 6, syn(2)));
    let other = 0x1234;
    // Bypassed and proxied clients never look up.
    assert_eq!(
        egress(&bpf, &packet, mode_mark(MODE_BYPASS) | other),
        UNSPEC
    );
    assert_eq!(
        egress(&bpf, &packet, mode_mark(MODE_PROXY) | other),
        REDIRECT
    );
    assert!(route(&bpf, REMOTE).is_none());
    assert_eq!(stats(&bpf, client_stat::PROXY), 1);
    // The interface's own networks stay direct even for proxied clients.
    let to_peer = frame(&ip(&LOCAL, &peer, 6, syn(2)));
    assert_eq!(egress(&bpf, &to_peer, mode_mark(MODE_PROXY)), UNSPEC);
    // Without masquerading the tunnel cannot carry a client's packets.
    let unmasqueraded = frame(&ip(&[192, 168, 1, 60], &REMOTE, 6, syn(2)));
    assert_eq!(egress(&bpf, &unmasqueraded, mode_mark(MODE_PROXY)), UNSPEC);
    assert_eq!(stats(&bpf, client_stat::FOREIGN_SOURCE), 1);
    // "rules" clients were looked up by the classifier, before masquerading;
    // the egress hook only applies a known route to them.
    assert_eq!(egress(&bpf, &packet, mode_mark(MODE_RULES)), UNSPEC);
    assert!(route(&bpf, REMOTE).is_none());
    assert_eq!(stats(&bpf, client_stat::LOOKUP), 0);
    // The host's own traffic is looked up here; the re-injected packet may
    // carry any mode byte and is not asked about again.
    assert_eq!(egress(&bpf, &packet, 0), REDIRECT);
    assert_eq!(route(&bpf, REMOTE).unwrap().0.action, ROUTE_PENDING);
    assert_eq!(stats(&bpf, client_stat::LOOKUP), 1);
    let reinjected = mode_mark(MODE_RULES) | CLIENT_MARK;
    assert_eq!(egress(&bpf, &packet, reinjected), UNSPEC);
    assert_eq!(stats(&bpf, client_stat::LOOKUP), 1);
    let route_entry = |action| {
        Route(RouteEntry {
            since_ns: 0,
            action,
            _pad: 0,
        })
    };
    let mut key = [0; 16];
    key[..4].copy_from_slice(&REMOTE);
    HashMap::<_, [u8; 16], Route>::try_from(bpf.map_mut("ROUTES").unwrap())
        .unwrap()
        .insert(key, route_entry(ROUTE_PROXY), 0)
        .unwrap();
    assert_eq!(egress(&bpf, &packet, mode_mark(MODE_RULES)), REDIRECT);
    assert_eq!(stats(&bpf, client_stat::PROXY), 2);
    HashMap::<_, [u8; 16], Route>::try_from(bpf.map_mut("ROUTES").unwrap())
        .unwrap()
        .insert(key, route_entry(ROUTE_PENDING), 0)
        .unwrap();
    // Unclassified traffic uses the host's own mode.
    let mut config = Array::<_, Config>::try_from(bpf.map("CLIENT_CONFIG").unwrap())
        .unwrap()
        .get(&0, 0)
        .unwrap();
    config.0.local_mode = MODE_PROXY;
    Array::<_, Config>::try_from(bpf.map_mut("CLIENT_CONFIG").unwrap())
        .unwrap()
        .set(0, config, 0)
        .unwrap();
    assert_eq!(egress(&bpf, &packet, 0), REDIRECT);
    assert_eq!(stats(&bpf, client_stat::PROXY), 3);
    assert_eq!(stats(&bpf, client_stat::LOOKUP), 1);
    // A stale heartbeat sends proxied clients the standard route.
    Array::<_, u64>::try_from(bpf.map_mut("HEARTBEAT").unwrap())
        .unwrap()
        .set(0, monotonic_ns() - HEARTBEAT_TIMEOUT_NS - 1, 0)
        .unwrap();
    assert_eq!(egress(&bpf, &packet, mode_mark(MODE_PROXY)), UNSPEC);
}

#[test]
#[ignore = "requires root; changes interface features"]
fn udp_gro_is_turned_off_and_restored() {
    struct Pair;
    impl Drop for Pair {
        fn drop(&mut self) {
            let _ = super::ip(&["link", "del", "edupgro0"]);
        }
    }
    let _ = super::ip(&["link", "del", "edupgro0"]);
    super::ip(&[
        "link", "add", "edupgro0", "type", "veth", "peer", "name", "edupgro1",
    ])
    .unwrap();
    let _pair = Pair;
    let vlan = [
        "link",
        "add",
        "link",
        "edupgro0",
        "name",
        "edupgro0.7",
        "type",
        "vlan",
    ];
    super::ip(&[&vlan[..], &["id", "7"]].concat()).unwrap();
    let devices = lower_devices("edupgro0.7");
    assert_eq!(devices, ["edupgro0.7", "edupgro0"]);
    // A VLAN takes only the features its lower device offers VLANs.
    let (names, _) = features("edupgro0").unwrap();
    let all: Vec<u32> = (0..names.len() as u32)
        .filter(|&bit| UDP_GRO.contains(&names[bit as usize].as_str()))
        .collect();
    assert_eq!(all.len(), UDP_GRO.len());
    set_features("edupgro0", &all, true).unwrap();
    let bits: Vec<Vec<u32>> = devices
        .iter()
        .map(|dev| active_features(dev, &UDP_GRO).unwrap())
        .collect();
    assert_eq!(bits[1], all);
    {
        let _gro = UdpGro::disable("edupgro0.7");
        for dev in &devices {
            assert!(active_features(dev, &UDP_GRO).unwrap().is_empty(), "{dev}");
        }
    }
    for (dev, bits) in devices.iter().zip(&bits) {
        assert_eq!(&active_features(dev, &UDP_GRO).unwrap(), bits, "{dev}");
    }
}
