//! Kernel integration tests: no interface attachment or pinned objects.
use aya::{
    Ebpf,
    maps::{Array, HashMap, PerCpuArray},
    programs::{TestRun, TestRunOptions, Xdp},
};
use edup_common::{
    maps::*,
    wire::{self, Key},
};

type Error = Box<dyn std::error::Error>;
const SERVER: [u8; 4] = [192, 0, 2, 1];
const CLIENT: [u8; 4] = [198, 51, 100, 7];
const REMOTE: [u8; 4] = [203, 0, 113, 9];
const INNER: [u8; 4] = [10, 66, 0, 7];
const KEY: Key = Key { k0: 123, k1: 456 };
const ETH: usize = 14;
const MAC: [u8; 14] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0];

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += (pair[0] as u32) << 8 | pair.get(1).copied().unwrap_or(0) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn put16(b: &mut [u8], offset: usize, value: u16) {
    b[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}
fn get16(b: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(b[offset..offset + 2].try_into().unwrap())
}

fn ip(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 20 + payload.len()];
    b[0] = 0x45;
    let len = b.len() as u16;
    put16(&mut b, 2, len);
    b[8] = 64;
    b[9] = proto;
    b[12..16].copy_from_slice(&src);
    b[16..20].copy_from_slice(&dst);
    b[20..].copy_from_slice(payload);
    let sum = checksum(&b[..20]);
    put16(&mut b, 10, sum);
    b
}
fn pseudo(b: &[u8]) -> Vec<u8> {
    let ihl = (b[0] as usize & 15) * 4;
    let mut data = b[12..20].to_vec();
    data.extend([0, b[9]]);
    data.extend(((b.len() - ihl) as u16).to_be_bytes());
    data.extend(&b[ihl..]);
    data
}
fn transport(
    proto: u8,
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    payload: usize,
) -> Vec<u8> {
    let mut l4 = vec![0x5a; if proto == IPPROTO_TCP { 20 } else { 8 } + payload];
    l4[..8].fill(0);
    let check_offset = match proto {
        IPPROTO_TCP => {
            l4[12] = 0x50;
            l4[13] = 0x02;
            16
        }
        IPPROTO_UDP => {
            let len = l4.len() as u16;
            put16(&mut l4, 4, len);
            6
        }
        _ => {
            l4[0] = if src == INNER { 8 } else { 0 };
            put16(&mut l4, 4, sport);
            2
        }
    };
    if proto != IPPROTO_ICMP {
        put16(&mut l4, 0, sport);
        put16(&mut l4, 2, dport);
    }
    put16(&mut l4, check_offset, 0);
    let mut b = ip(src, dst, proto, &l4);
    let c = if proto == IPPROTO_ICMP {
        checksum(&l4)
    } else {
        checksum(&pseudo(&b))
    };
    put16(&mut b, 20 + check_offset, if c == 0 { 65535 } else { c });
    b
}
fn frame(ip: &[u8]) -> Vec<u8> {
    let mut b = MAC.to_vec();
    b.extend(ip);
    b
}
fn tunnel(inner: &[u8], typ: u8, user: u16) -> Vec<u8> {
    let mut data = vec![0; wire::HDR_LEN + inner.len()];
    data[wire::HDR_LEN..].copy_from_slice(inner);
    wire::seal(&KEY, 42, typ, user, &mut data);
    let mut udp = vec![0; 8];
    put16(&mut udp, 0, 40000);
    put16(&mut udp, 2, 7777);
    put16(&mut udp, 4, (8 + data.len()) as u16);
    udp.extend(data);
    frame(&ip(CLIENT, SERVER, IPPROTO_UDP, &udp))
}
fn verify_ip(b: &[u8]) {
    let ihl = (b[0] as usize & 15) * 4;
    assert_eq!(get16(b, 2) as usize, b.len());
    assert_eq!(checksum(&b[..ihl]), 0, "IPv4 checksum");
    if b[9] == IPPROTO_ICMP {
        assert_eq!(checksum(&b[ihl..]), 0, "ICMP checksum");
    } else if b[9] != IPPROTO_UDP || get16(b, ihl + 6) != 0 {
        assert_eq!(checksum(&pseudo(b)), 0, "TCP/UDP checksum");
    }
}
fn run(bpf: &Ebpf, input: &[u8], action: u32) -> Result<Vec<u8>, Error> {
    let p: &Xdp = bpf.program("edup").unwrap().try_into()?;
    let mut out = vec![0; 4096];
    let r = p.test_run(TestRunOptions {
        data_in: Some(input),
        data_out: Some(&mut out),
        ..Default::default()
    })?;
    assert_eq!(r.return_value, action, "unexpected XDP action");
    out.truncate(r.data_size_out as usize);
    if action == 3 {
        let ip_end = ETH + get16(&out, ETH + 2) as usize;
        assert_eq!(
            out.len(),
            ip_end.max(60),
            "XDP_TX Ethernet minimum frame size"
        );
        assert!(
            out[ip_end..].iter().all(|b| *b == 0),
            "padding must be zero"
        );
        out.truncate(ip_end);
        if out[ETH + 9] == IPPROTO_UDP && get16(&out, ETH + 20) == 7777 {
            assert_ne!(
                get16(&out, ETH + 26),
                0,
                "outer UDP checksum required for receive offload"
            );
            verify_ip(&out[ETH..]);
        }
    }
    Ok(out)
}
fn main() -> Result<(), Error> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "target/bpfel-unknown-none/release/edup-ebpf".into());
    let mut bpf = Ebpf::load_file(path)?;
    let p: &mut Xdp = bpf.program_mut("edup").unwrap().try_into()?;
    p.load()?;
    println!("PASS: kernel verifier");
    let cfg = Config {
        key0: KEY.k0,
        key1: KEY.k1,
        server_ip_be: u32::from_ne_bytes(SERVER),
        nat_ip_be: u32::from_ne_bytes(SERVER),
        tun_net: 0x0a420000,
        tun_mask: 0xffff0000,
        port_be: 7777u16.to_be(),
        nat_port_min: 20000,
        nat_port_max: 20100,
        max_frame: 1500,
    };
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, cfg, 0)?;
    Array::<_, User>::try_from(bpf.map_mut("USERS").unwrap())?.set(
        7,
        User {
            enabled: 1,
            ..Default::default()
        },
        0,
    )?;
    if std::env::args().nth(2).as_deref() == Some("--bench") {
        return benchmark(&bpf);
    }
    let keepalive = tunnel(&[], wire::TYPE_KEEPALIVE, 7);
    let mut padded = keepalive.clone();
    padded.resize(60, 0xff);
    let out = run(&bpf, &padded, 3)?;
    assert_eq!(out.len(), keepalive.len());
    verify_ip(&out[ETH..]);
    assert_eq!(&out[42..], &keepalive[42..]);
    assert_eq!(&out[..6], &MAC[6..12]);
    assert_eq!(&out[6..12], &MAC[..6]);
    println!("PASS: KEEPALIVE, Ethernet padding, MAC swap");

    for proto in [IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP] {
        let inner = transport(proto, INNER, REMOTE, 1234, 443, 31);
        let sent = run(&bpf, &tunnel(&inner, wire::TYPE_DATA, 7), 3)?;
        verify_ip(&sent[ETH..]);
        assert_eq!(sent.len(), ETH + inner.len());
        assert_eq!(&sent[26..30], &SERVER);
        assert_eq!(sent[22], 63);
        let public = get16(&sent, ETH + 20 + if proto == IPPROTO_ICMP { 4 } else { 0 });
        assert!((20000..=20100).contains(&public));
        // Different remote destination must reuse the endpoint-independent mapping.
        let other = transport(proto, INNER, [203, 0, 113, 10], 1234, 80, 31);
        let sent2 = run(&bpf, &tunnel(&other, wire::TYPE_DATA, 7), 3)?;
        assert_eq!(
            get16(&sent2, ETH + 20 + if proto == IPPROTO_ICMP { 4 } else { 0 }),
            public
        );
        let reply = transport(
            proto,
            REMOTE,
            SERVER,
            if proto == IPPROTO_ICMP { public } else { 443 },
            public,
            31,
        );
        let received = run(&bpf, &frame(&reply), 3)?;
        verify_ip(&received[ETH..]);
        assert_eq!(&received[30..34], &CLIENT);
        assert_eq!(get16(&received, 36), 40000);
        let mut data = received[42..].to_vec();
        let opened = wire::open(&KEY, &mut data).unwrap();
        assert_eq!(opened.user, 7);
        assert_eq!(opened.typ, wire::TYPE_DATA);
        let inner = &data[8..];
        verify_ip(inner);
        assert_eq!(&inner[16..20], &INNER);
        assert_eq!(inner[8], 63);
        assert_eq!(
            get16(inner, 20 + if proto == IPPROTO_ICMP { 4 } else { 2 }),
            1234
        );
        println!("PASS: protocol {proto} SNAT/DNAT, checksums, TTL, EIM, wire compatibility");
        if proto == IPPROTO_UDP {
            let extended = Config {
                max_frame: (wire::MAX_KS_WORDS * 8 + 32) as u16,
                ..cfg
            };
            Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, extended, 0)?;
            // Every ciphertext tail length, plus both edges of the maximum
            // allowed packet. XDP's output checksum covers encrypted bytes.
            for payload in (0..16).chain([1435, 1436, 1503, 1504]) {
                let reply = transport(proto, REMOTE, SERVER, 443, public, payload);
                let received = run(&bpf, &frame(&reply), 3)?;
                let mut data = received[42..].to_vec();
                wire::open(&KEY, &mut data).unwrap();
                verify_ip(&data[wire::HDR_LEN..]);
            }
            Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, cfg, 0)?;
            println!("PASS: nonzero outer UDP checksums, all XOR tails and maximum wire size");
        }
    }

    let inner = transport(IPPROTO_UDP, INNER, REMOTE, 1234, 443, 10);
    let mut bad = inner.clone();
    bad[12] = 11;
    run(&bpf, &tunnel(&bad, 0, 7), 1)?;
    let mut bad = inner.clone();
    bad[8] = 1;
    run(&bpf, &tunnel(&bad, 0, 7), 1)?;
    let mut bad = inner.clone();
    bad[6] = 0x20;
    run(&bpf, &tunnel(&bad, 0, 7), 1)?;
    run(&bpf, &tunnel(&inner, 0, 8), 1)?;
    run(&bpf, &tunnel(&inner, 0x10, 7), 1)?;
    run(&bpf, &tunnel(&inner, 2, 7), 1)?;
    run(&bpf, &tunnel(&inner, 1, 7), 1)?;
    let mut bad = tunnel(&inner, 0, 7);
    bad[47] ^= 1;
    run(&bpf, &bad, 1)?;
    let mut bad = tunnel(&inner, 0, 7);
    put16(&mut bad, 38, 8);
    run(&bpf, &bad, 1)?;
    let mut bad = inner.clone();
    put16(&mut bad, 24, 8);
    run(&bpf, &tunnel(&bad, 0, 7), 1)?;
    let large = transport(IPPROTO_UDP, INNER, REMOTE, 1234, 443, 1437);
    run(&bpf, &tunnel(&large, 0, 7), 1)?;
    let max = transport(IPPROTO_UDP, INNER, REMOTE, 1234, 443, 1436);
    let out = run(&bpf, &tunnel(&max, 0, 7), 3)?;
    assert_eq!(out.len(), ETH + 1464);
    verify_ip(&out[ETH..]);
    println!("PASS: spoof, TTL, fragments, user/header validation, MTU boundary");

    let host = frame(&transport(IPPROTO_TCP, REMOTE, SERVER, 10000, 22, 0));
    assert_eq!(run(&bpf, &host, 2)?, host);
    let mut arp = vec![0; 60];
    arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    assert_eq!(run(&bpf, &arp, 2)?, arp);
    let unknown = frame(&transport(IPPROTO_UDP, REMOTE, SERVER, 53, 21000, 0));
    assert_eq!(run(&bpf, &unknown, 2)?, unknown);
    println!("PASS: SSH, ARP, unmapped host traffic unchanged");

    // Simulate independent LRU eviction and expiration without waiting minutes.
    let key = NatOutKey {
        inner_ip_be: u32::from_ne_bytes(INNER),
        inner_port_be: 1234u16.to_be(),
        proto: IPPROTO_UDP,
        _pad: 0,
    };
    let out =
        HashMap::<_, NatOutKey, NatOutVal>::try_from(bpf.map("NAT_OUT").unwrap())?.get(&key, 0)?;
    let reverse = NatInKey {
        pub_port_be: out.pub_port_be,
        proto: IPPROTO_UDP,
        _pad: 0,
    };
    HashMap::<_, NatInKey, NatInVal>::try_from(bpf.map_mut("NAT_IN").unwrap())?.remove(&reverse)?;
    run(&bpf, &tunnel(&inner, 0, 7), 3)?;
    let echo_key = NatOutKey {
        proto: IPPROTO_ICMP,
        ..key
    };
    let echo_port = HashMap::<_, NatOutKey, NatOutVal>::try_from(bpf.map("NAT_OUT").unwrap())?
        .get(&echo_key, 0)?
        .pub_port_be;
    let echo_reverse = NatInKey {
        pub_port_be: echo_port,
        proto: IPPROTO_ICMP,
        _pad: 0,
    };
    let mut reverse_map =
        HashMap::<_, NatInKey, NatInVal>::try_from(bpf.map_mut("NAT_IN").unwrap())?;
    let mut val = reverse_map.get(&echo_reverse, 0)?;
    let timeout = nat_timeout_ns(IPPROTO_ICMP, ST_OTHER);
    if val.last_seen_ns <= timeout + 1 {
        // A just-booted WSL kernel cannot represent a sufficiently old timestamp.
        // Keep the kernel alive and wait at most 31 s before injecting expiry.
        println!("Waiting for kernel uptime > 30 seconds to test lazy expiration...");
        std::thread::sleep(
            std::time::Duration::from_nanos(timeout + 1 - val.last_seen_ns)
                + std::time::Duration::from_millis(100),
        );
    }
    val.last_seen_ns = 1;
    reverse_map.insert(echo_reverse, val, 0)?;
    let reply = frame(&transport(
        IPPROTO_ICMP,
        REMOTE,
        SERVER,
        u16::from_be(echo_port),
        0,
        0,
    ));
    assert_eq!(run(&bpf, &reply, 2)?, reply);
    assert!(
        HashMap::<_, NatInKey, NatInVal>::try_from(bpf.map("NAT_IN").unwrap())?
            .get(&echo_reverse, 0)
            .is_err()
    );
    run(
        &bpf,
        &tunnel(&transport(IPPROTO_ICMP, INNER, REMOTE, 1234, 0, 0), 0, 7),
        3,
    )?;
    println!("PASS: lazy expiration removes reverse mapping and recreates the flow");
    println!("PASS: independent NAT_IN eviction recovery");

    // The reverse direction must also require the forward index.
    let public = HashMap::<_, NatOutKey, NatOutVal>::try_from(bpf.map("NAT_OUT").unwrap())?
        .get(&key, 0)?
        .pub_port_be;
    let reply = frame(&transport(
        IPPROTO_UDP,
        REMOTE,
        SERVER,
        443,
        u16::from_be(public),
        0,
    ));
    HashMap::<_, NatOutKey, NatOutVal>::try_from(bpf.map_mut("NAT_OUT").unwrap())?.remove(&key)?;
    assert_eq!(run(&bpf, &reply, 2)?, reply);
    let sent = run(&bpf, &tunnel(&inner, 0, 7), 3)?;
    let public = get16(&sent, ETH + 20);
    let reply_ip = transport(IPPROTO_UDP, REMOTE, SERVER, 443, public, 0);
    let reply = frame(&reply_ip);
    let user = Array::<_, User>::try_from(bpf.map("USERS").unwrap())?.get(&7, 0)?;
    Array::<_, User>::try_from(bpf.map_mut("USERS").unwrap())?.set(
        7,
        User {
            endpoint: 0,
            ..user
        },
        0,
    )?;
    run(&bpf, &reply, 1)?;
    Array::<_, User>::try_from(bpf.map_mut("USERS").unwrap())?.set(
        7,
        User { enabled: 0, ..user },
        0,
    )?;
    run(&bpf, &reply, 1)?;
    Array::<_, User>::try_from(bpf.map_mut("USERS").unwrap())?.set(7, user, 0)?;
    let mut roamed = keepalive.clone();
    roamed[29] = 99;
    put16(&mut roamed, 34, 41000);
    put16(&mut roamed, 24, 0);
    let c = checksum(&roamed[14..34]);
    put16(&mut roamed, 24, c);
    run(&bpf, &roamed, 3)?;
    let mut padded_reply = reply.clone();
    padded_reply.resize(60, 0xa5);
    let received = run(&bpf, &padded_reply, 3)?;
    assert_eq!(received.len(), ETH + 36 + reply_ip.len());
    assert_eq!(&received[30..34], &[198, 51, 100, 99]);
    assert_eq!(get16(&received, 36), 41000);
    let mut data = received[42..].to_vec();
    wire::open(&KEY, &mut data).unwrap();
    verify_ip(&data[8..]);
    let mut bad = tunnel(&inner, 0, 7);
    bad[47] ^= 1;
    run(&bpf, &bad, 1)?;
    let after = Array::<_, User>::try_from(bpf.map("USERS").unwrap())?.get(&7, 0)?;
    assert_eq!(
        after.endpoint,
        User::pack_endpoint(u32::from_ne_bytes([198, 51, 100, 99]), 41000u16.to_be())
    );
    println!(
        "PASS: NAT_OUT eviction, disabled/unknown endpoint, roaming, rejected packet cannot roam, inbound padding"
    );

    let max_reply = transport(IPPROTO_UDP, REMOTE, SERVER, 443, public, 1436);
    let received = run(&bpf, &frame(&max_reply), 3)?;
    assert_eq!(received.len(), ETH + 1500);
    let mut data = received[42..].to_vec();
    wire::open(&KEY, &mut data).unwrap();
    verify_ip(&data[8..]);
    run(
        &bpf,
        &frame(&transport(IPPROTO_UDP, REMOTE, SERVER, 443, public, 1437)),
        1,
    )?;
    // IPv4 options are preserved on inner packets; transport offsets follow IHL.
    let mut options = inner.clone();
    options.splice(20..20, [1, 1, 1, 0]);
    options[0] = 0x46;
    let len = options.len() as u16;
    put16(&mut options, 2, len);
    put16(&mut options, 10, 0);
    let c = checksum(&options[..24]);
    put16(&mut options, 10, c);
    let sent = run(&bpf, &tunnel(&options, 0, 7), 3)?;
    verify_ip(&sent[ETH..]);
    assert_eq!(&sent[34..38], &[1, 1, 1, 0]);
    let mut zero_udp = inner.clone();
    put16(&mut zero_udp, 26, 0);
    let sent = run(&bpf, &tunnel(&zero_udp, 0, 7), 3)?;
    assert_eq!(get16(&sent, ETH + 26), 0);
    let bad_proto = ip(INNER, REMOTE, 47, &[0; 20]);
    run(&bpf, &tunnel(&bad_proto, 0, 7), 1)?;
    let mut bad_tcp = transport(IPPROTO_TCP, INNER, REMOTE, 1234, 443, 0);
    bad_tcp[32] = 0x40;
    run(&bpf, &tunnel(&bad_tcp, 0, 7), 1)?;
    println!(
        "PASS: inbound MTU, inner IPv4 options, absent UDP checksum, unsupported protocol/TCP header"
    );

    // A tiny range forces collisions and exhausts every available port.
    let small = Config {
        nat_port_min: 30000,
        nat_port_max: 30001,
        ..cfg
    };
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, small, 0)?;
    let a = transport(IPPROTO_UDP, INNER, REMOTE, 4001, 443, 0);
    let b = transport(IPPROTO_UDP, INNER, REMOTE, 4002, 443, 0);
    let c = transport(IPPROTO_UDP, INNER, REMOTE, 4003, 443, 0);
    let sent_a = run(&bpf, &tunnel(&a, 0, 7), 3)?;
    let sent_b = run(&bpf, &tunnel(&b, 0, 7), 3)?;
    assert_ne!(get16(&sent_a, ETH + 20), get16(&sent_b, ETH + 20));
    run(&bpf, &tunnel(&c, 0, 7), 1)?;
    assert_eq!(
        get16(&run(&bpf, &tunnel(&a, 0, 7), 3)?, ETH + 20),
        get16(&sent_a, ETH + 20)
    );
    let reserved = Config {
        nat_port_min: 7777,
        nat_port_max: 7777,
        ..cfg
    };
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, reserved, 0)?;
    run(&bpf, &tunnel(&c, 0, 7), 1)?;
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, cfg, 0)?;
    println!("PASS: NAT collision, exhaustion, existing mapping survives, tunnel port reserved");

    // Verify TCP lifetime transitions against map state, not just packet output.
    let mut tcp = transport(IPPROTO_TCP, INNER, REMOTE, 1234, 443, 0);
    for (flags, expected) in [
        (0x10, ST_TCP_EST),
        (0x11, ST_TCP_CLOSING),
        (0x10, ST_TCP_CLOSING),
    ] {
        tcp[33] = flags;
        put16(&mut tcp, 36, 0);
        let c = checksum(&pseudo(&tcp));
        put16(&mut tcp, 36, c);
        let sent = run(&bpf, &tunnel(&tcp, 0, 7), 3)?;
        verify_ip(&sent[ETH..]);
        let reverse = NatInKey {
            pub_port_be: get16(&sent, ETH + 20).to_be(),
            proto: IPPROTO_TCP,
            _pad: 0,
        };
        let value = HashMap::<_, NatInKey, NatInVal>::try_from(bpf.map("NAT_IN").unwrap())?
            .get(&reverse, 0)?;
        assert_eq!(value.state, expected);
    }
    println!("PASS: TCP established/closing state and late ACK");

    let stats = PerCpuArray::<_, u64>::try_from(bpf.map("STATS").unwrap())?;
    for (index, name) in stat::NAMES.iter().enumerate() {
        let sum: u64 = stats.get(&(index as u32), 0)?.iter().sum();
        println!("{name}: {sum}");
        if !matches!(index as u32, stat::DROP_ADJUST) {
            assert!(sum > 0, "untested outcome: {name}");
        }
    }
    println!("All XDP integration checks passed; nothing attached or pinned.");
    Ok(())
}

// Repeat separate syscalls: XDP modifies the input in place, so kernel repeat>1
// can time a different path after the first iteration. No program is attached.
fn benchmark(bpf: &Ebpf) -> Result<(), Error> {
    let program: &Xdp = bpf.program("edup").unwrap().try_into()?;
    for payload in [0, 1360] {
        let mut inner = transport(IPPROTO_TCP, INNER, REMOTE, 1234, 443, payload);
        inner[33] = 0x10; // established ACK; no state transition in the hot path
        put16(&mut inner, 36, 0);
        let sum = checksum(&pseudo(&inner));
        put16(&mut inner, 36, sum);
        let outbound = tunnel(&inner, wire::TYPE_DATA, 7);
        let sent = run(bpf, &outbound, 3)?;
        let public = get16(&sent, ETH + 20);
        let mut reply = transport(IPPROTO_TCP, REMOTE, SERVER, 443, public, payload);
        reply[33] = 0x10;
        put16(&mut reply, 36, 0);
        let sum = checksum(&pseudo(&reply));
        put16(&mut reply, 36, sum);
        let inbound = frame(&reply);
        for (direction, input) in [("outbound", &outbound), ("inbound", &inbound)] {
            let mut out = [0; 2048];
            let mut samples = Vec::new();
            for round in 0..8 {
                let mut total = 0u128;
                for _ in 0..2000 {
                    let result = program.test_run(TestRunOptions {
                        data_in: Some(input),
                        data_out: Some(&mut out),
                        repeat: 1,
                        ..Default::default()
                    })?;
                    assert_eq!(
                        result.return_value, 3,
                        "benchmark must forward every packet"
                    );
                    total += result.duration.as_nanos();
                }
                if round != 0 {
                    samples.push(total as f64 / 2000.0);
                }
            }
            samples.sort_by(f64::total_cmp);
            println!(
                "BENCH {direction} inner_bytes={} median_ns={:.1}",
                inner.len(),
                samples[3]
            );
        }
    }
    Ok(())
}
