//! Kernel integration tests: no interface attachment or pinned objects.
use aya::{
    Ebpf,
    maps::{Array, HashMap, PerCpuArray, ProgramArray},
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
const TEST_ID: i64 = 4829017365182049271;
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
    if ip[0] >> 4 == 6 {
        put16(&mut b, 12, 0x86dd);
    }
    b
}
// Independent encoder allows malformed compact fields to reach XDP validation.
fn test_data(inner: &[u8], typ: u8, id: i64, key: &Key) -> Vec<u8> {
    let v4 = inner.first().is_some_and(|v| v >> 4 == 4);
    let mut body = inner.to_vec();
    if v4 {
        let ihl = (inner[0] & 15) as usize * 4;
        let old = u32::from_ne_bytes(inner[12..16].try_into().unwrap());
        if let Some(off) = match inner[9] {
            6 => Some(ihl + 16),
            17 => Some(ihl + 6),
            _ => None,
        } {
            let c = u16::from_ne_bytes(body[off..off + 2].try_into().unwrap());
            let c = if inner[9] == 17 {
                edup_common::csum::udp_replace4(c, old, 0)
            } else {
                edup_common::csum::replace4(c, old, 0)
            };
            body[off..off + 2].copy_from_slice(&c.to_ne_bytes());
        }
        let mut compact = inner[16..20].to_vec();
        compact.extend(&inner[4..6]);
        compact.extend([
            (inner[6] & 0xe0) | (inner[0] & 15).saturating_sub(5),
            inner[1],
            inner[8],
            inner[9],
        ]);
        compact.extend(&body[20..]);
        body = compact;
    } else if inner.len() >= 40 {
        if let Some(off) = match inner[6] {
            6 => Some(56),
            17 => Some(46),
            58 => Some(42),
            _ => None,
        } {
            let check = get16(inner, off);
            if inner[6] != 17 || check != 0 {
                let mut sum = (!check) as u64;
                for i in (8..24).step_by(2) {
                    sum += (!get16(inner, i)) as u64;
                }
                let c = !edup_common::csum::fold(sum);
                put16(
                    &mut body,
                    off,
                    if inner[6] == 17 && c == 0 { 65535 } else { c },
                );
            }
        }
        let mut compact = inner[24..40].to_vec();
        compact.extend([
            inner[0] & 15,
            inner[1],
            inner[2],
            inner[3],
            inner[6],
            inner[7],
        ]);
        compact.extend(&body[40..]);
        body = compact;
    }
    let mut data = vec![0; wire::HDR_LEN];
    data.extend(body);
    let typ = if typ == wire::TYPE_DATA && !v4 && !inner.is_empty() {
        wire::TYPE_IPV6
    } else {
        typ
    };
    wire::seal(key, typ, id, &mut data);
    data
}
fn open_test<const N: usize>(key: &Key, data: &mut Vec<u8>, local: [u8; N]) -> wire::Opened {
    let opened = wire::open(key, data).unwrap();
    let mut ip = vec![0; data.len() + 20];
    let n = wire::unpack(opened.typ, &data[wire::HDR_LEN..], &mut ip, &local, false).unwrap();
    data.truncate(wire::HDR_LEN);
    data.extend(&ip[..n]);
    opened
}
fn tunnel(inner: &[u8], typ: u8, user: u16) -> Vec<u8> {
    let data = test_data(
        inner,
        typ,
        if user == 7 { TEST_ID } else { user as i64 },
        &KEY,
    );
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
    if r.return_value != action {
        let stats = PerCpuArray::<_, u64>::try_from(bpf.map("STATS").unwrap())?;
        for (i, name) in stat::NAMES.iter().enumerate() {
            let count: u64 = stats.get(&(i as u32), 0)?.iter().sum();
            if count != 0 {
                eprintln!("{name}={count}");
            }
        }
    }
    assert_eq!(r.return_value, action, "unexpected XDP action");
    out.truncate(r.data_size_out as usize);
    if action == 3 {
        let v6 = out[ETH] >> 4 == 6;
        let ip_end = ETH
            + if v6 {
                40 + get16(&out, ETH + 4) as usize
            } else {
                get16(&out, ETH + 2) as usize
            };
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
        if !v6 && out[ETH + 9] == IPPROTO_UDP && get16(&out, ETH + 20) == 7777 {
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
    for (index, name) in ["edup_ipv4", "edup_ipv6"].into_iter().enumerate() {
        let p: &mut Xdp = bpf.program_mut(name).unwrap().try_into()?;
        p.load()?;
        let fd = p.fd()?.try_clone()?;
        ProgramArray::try_from(bpf.map_mut("PROTOCOLS").unwrap())?.set(index as u32, &fd, 0)?;
        println!("PASS: {name} kernel verifier");
    }
    let p: &mut Xdp = bpf.program_mut("edup").unwrap().try_into()?;
    p.load()?;
    println!("PASS: kernel verifier");
    let cfg = Config {
        server_ip_be: u32::from_ne_bytes(SERVER),
        nat_ip_be: u32::from_ne_bytes(SERVER),
        port_be: 7777u16.to_be(),
        nat_port_min: 20000,
        nat_port_max: 20100,
        max_frame: 1500,
        ..Default::default()
    };
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, cfg, 0)?;
    Array::<_, User>::try_from(bpf.map_mut("USERS").unwrap())?.set(
        7,
        User {
            id: TEST_ID,
            key0: KEY.k0,
            key1: KEY.k1,
            enabled: 1,
            ..Default::default()
        },
        0,
    )?;
    HashMap::<_, i64, u16>::try_from(bpf.map_mut("USER_IDS").unwrap())?.insert(TEST_ID, 7, 0)?;
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
        let opened = open_test(&KEY, &mut data, INNER);
        assert_eq!(opened.user, TEST_ID);
        assert_eq!(opened.typ, wire::TYPE_DATA);
        let inner = &data[wire::HDR_LEN..];
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
                max_frame: (wire::MAX_KS_WORDS * 8 + 36) as u16,
                ..cfg
            };
            Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, extended, 0)?;
            // Every ciphertext tail length, plus both edges of the maximum
            // allowed packet. XDP's output checksum covers encrypted bytes.
            for payload in (0..16).chain([1444, 1445, 1516, 1517]) {
                let reply = transport(proto, REMOTE, SERVER, 443, public, payload);
                let received = run(&bpf, &frame(&reply), 3)?;
                let mut data = received[42..].to_vec();
                open_test(&KEY, &mut data, INNER);
                verify_ip(&data[wire::HDR_LEN..]);
            }
            Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, cfg, 0)?;
            println!("PASS: nonzero outer UDP checksums, all XOR tails and maximum wire size");
        }
    }

    let inner = transport(IPPROTO_UDP, INNER, REMOTE, 1234, 443, 10);

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
    bad[50] ^= 0x80;
    run(&bpf, &bad, 1)?;
    let mut bad = tunnel(&inner, 0, 7);
    put16(&mut bad, 38, 8);
    run(&bpf, &bad, 1)?;
    let mut bad = inner.clone();
    put16(&mut bad, 24, 8);
    run(&bpf, &tunnel(&bad, 0, 7), 1)?;
    let large = transport(IPPROTO_UDP, INNER, REMOTE, 1234, 443, 1446);
    run(&bpf, &tunnel(&large, 0, 7), 1)?;
    let max = transport(IPPROTO_UDP, INNER, REMOTE, 1234, 443, 1445);
    let out = run(&bpf, &tunnel(&max, 0, 7), 3)?;
    assert_eq!(out.len(), ETH + 1473);
    verify_ip(&out[ETH..]);
    println!("PASS: TTL, fragments, user/header validation, MTU boundary");

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
        user: 7,
        _pad: [0; 2],
        inner_port_be: 1234u16.to_be(),
        proto: IPPROTO_UDP,
        v6: 0,
    };
    let out =
        HashMap::<_, NatOutKey, NatOutVal>::try_from(bpf.map("NAT_OUT").unwrap())?.get(&key, 0)?;
    let reverse = NatInKey {
        pub_port_be: out.pub_port_be,
        proto: IPPROTO_UDP,
        v6: 0,
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
        v6: 0,
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
    HashMap::<_, u16, Endpoint>::try_from(bpf.map_mut("ENDPOINTS").unwrap())?.remove(&7)?;
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
    assert_eq!(received.len(), ETH + wire::OVERHEAD_V4 + reply_ip.len());
    assert_eq!(&received[30..34], &[198, 51, 100, 99]);
    assert_eq!(get16(&received, 36), 41000);
    let mut data = received[42..].to_vec();
    open_test(&KEY, &mut data, INNER);
    verify_ip(&data[wire::HDR_LEN..]);
    let mut bad = tunnel(&inner, 0, 7);
    bad[50] ^= 0x80;
    run(&bpf, &bad, 1)?;
    let after = Array::<_, User>::try_from(bpf.map("USERS").unwrap())?.get(&7, 0)?;
    assert_eq!(
        after.endpoint,
        User::pack_endpoint(u32::from_ne_bytes([198, 51, 100, 99]), 41000u16.to_be())
    );
    println!(
        "PASS: NAT_OUT eviction, disabled/unknown endpoint, roaming, rejected packet cannot roam, inbound padding"
    );

    let max_reply = transport(IPPROTO_UDP, REMOTE, SERVER, 443, public, 1445);
    let received = run(&bpf, &frame(&max_reply), 3)?;
    assert_eq!(received.len(), ETH + 1500);
    let mut data = received[42..].to_vec();
    open_test(&KEY, &mut data, INNER);
    verify_ip(&data[wire::HDR_LEN..]);
    run(
        &bpf,
        &frame(&transport(IPPROTO_UDP, REMOTE, SERVER, 443, public, 1446)),
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
    for options_len in [0, 4, 40] {
        let prepare = |mut ip: Vec<u8>| {
            ip.splice(20..20, vec![1; options_len]);
            ip[0] = 0x45 + options_len as u8 / 4;
            ip[1] = 0xab;
            put16(&mut ip, 4, 0xdead);
            put16(&mut ip, 6, 0x4000);
            let len = ip.len();
            put16(&mut ip, 2, len as u16);
            put16(&mut ip, 10, 0);
            let c = checksum(&ip[..20 + options_len]);
            put16(&mut ip, 10, c);
            ip
        };
        let outbound = prepare(inner.clone());
        let mut encoded = vec![0; wire::HDR_LEN + outbound.len()];
        encoded[wire::HDR_LEN..].copy_from_slice(&outbound);
        let n = wire::seal_data(&KEY, TEST_ID, &mut encoded, true).unwrap();
        encoded.truncate(n);
        assert_eq!(
            encoded,
            test_data(&outbound, wire::TYPE_DATA, TEST_ID, &KEY)
        );
        let sent = run(&bpf, &tunnel(&outbound, 0, 7), 3)?;
        verify_ip(&sent[ETH..]);
        assert_eq!(sent[ETH + 1], 0xab);
        assert_eq!(get16(&sent, ETH + 4), 0xdead);
        assert_eq!(get16(&sent, ETH + 6), 0x4000);
        let public = get16(&sent, ETH + 20 + options_len);
        let reply = prepare(transport(IPPROTO_UDP, REMOTE, SERVER, 443, public, 10));
        let returned = run(&bpf, &frame(&reply), 3)?;
        let mut body = returned[42..].to_vec();
        open_test(&KEY, &mut body, INNER);
        let ip = &body[wire::HDR_LEN..];
        verify_ip(ip);
        assert_eq!(ip[0], 0x45 + options_len as u8 / 4);
        assert_eq!(ip[1], 0xab);
        assert_eq!(get16(ip, 4), 0xdead);
        assert_eq!(get16(ip, 6), 0x4000);
        assert_eq!(&ip[20..20 + options_len], &vec![1; options_len]);
    }
    for flags in [0x80, 0x20, 0x10, 11, 15] {
        let mut bad = tunnel(&inner, 0, 7);
        let body = &mut bad[42..];
        wire::open(&KEY, body).unwrap();
        body[wire::HDR_LEN + 6] = flags;
        wire::seal(&KEY, wire::TYPE_DATA, TEST_ID, body);
        run(&bpf, &bad, 1)?;
    }
    println!(
        "PASS: client codec, DSCP/ECN, DF, identification, all IPv4 option sizes and malformed flags"
    );
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
            v6: 0,
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
        if !matches!(index as u32, stat::DROP_ADJUST | stat::DROP_SPOOF) {
            assert!(sum > 0, "untested outcome: {name}");
        }
    }
    check_ipv6(&mut bpf, cfg)?;
    check_multiple_users(&mut bpf, cfg)?;
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

fn addr6(s: &str) -> [u8; 16] {
    s.parse::<std::net::Ipv6Addr>().unwrap().octets()
}
fn pseudo6(ip: &[u8]) -> Vec<u8> {
    let mut p = ip[8..40].to_vec();
    p.extend(((ip.len() - 40) as u32).to_be_bytes());
    p.extend([0, 0, 0, ip[6]]);
    p.extend(&ip[40..]);
    p
}
fn ip6(src: [u8; 16], dst: [u8; 16], proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut p = vec![0; 40];
    p[0] = 0x60;
    put16(&mut p, 4, l4.len() as u16);
    p[6] = proto;
    p[7] = 64;
    p[8..24].copy_from_slice(&src);
    p[24..40].copy_from_slice(&dst);
    p.extend(l4);
    p
}
#[allow(clippy::too_many_arguments)]
fn transport6(
    proto: u8,
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    payload: usize,
    reply: bool,
) -> Vec<u8> {
    let mut l4 = vec![0x5a; if proto == IPPROTO_TCP { 20 } else { 8 } + payload];
    l4[..8].fill(0);
    let check_offset = match proto {
        IPPROTO_TCP => {
            l4[12] = 0x50;
            l4[13] = 2;
            16
        }
        IPPROTO_UDP => {
            let len = l4.len() as u16;
            put16(&mut l4, 4, len);
            6
        }
        _ => {
            l4[0] = if reply { 129 } else { 128 };
            put16(&mut l4, 4, sport);
            2
        }
    };
    if proto != IPPROTO_ICMPV6 {
        put16(&mut l4, 0, sport);
        put16(&mut l4, 2, dport);
    }
    put16(&mut l4, check_offset, 0);
    let mut p = ip6(src, dst, proto, &l4);
    let sum = checksum(&pseudo6(&p));
    put16(
        &mut p,
        40 + check_offset,
        if sum == 0 { 0xffff } else { sum },
    );
    p
}
fn tunnel6(inner: &[u8], typ: u8, user: u16) -> Vec<u8> {
    let data = test_data(
        inner,
        typ,
        if user == 7 { TEST_ID } else { user as i64 },
        &KEY,
    );
    let mut udp = vec![0; 8];
    put16(&mut udp, 0, 40000);
    put16(&mut udp, 2, 7777);
    put16(&mut udp, 4, (8 + data.len()) as u16);
    udp.extend(data);
    let mut ip = ip6(
        addr6("2001:db8:1::7"),
        addr6("2001:db8::1"),
        IPPROTO_UDP,
        &udp,
    );
    let sum = checksum(&pseudo6(&ip));
    put16(&mut ip, 46, if sum == 0 { 0xffff } else { sum });
    frame(&ip)
}
fn check_ipv6(bpf: &mut Ebpf, cfg: Config) -> Result<(), Error> {
    let server = addr6("2001:db8::1");
    let inner6 = addr6("fd66::7");
    let remote = addr6("2001:db8:2::9");
    let cfg = Config {
        server_ip6: server,
        nat_ip6: server,
        gateway_mac: [2, 1, 2, 3, 4, 5],
        gateway6_mac: [2, 6, 7, 8, 9, 10],
        ..cfg
    };
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, cfg, 0)?;
    for outer6 in [false, true] {
        let wrap = if outer6 { tunnel6 } else { tunnel };
        let keep = run(bpf, &wrap(&[], wire::TYPE_KEEPALIVE, 7), 3)?;
        let hlen = if outer6 { 40 } else { 20 };
        if outer6 {
            assert_eq!(
                checksum(&pseudo6(&keep[ETH..])),
                0,
                "IPv6 KEEPALIVE checksum"
            );
            assert_eq!(&keep[ETH + 24..ETH + 40], &addr6("2001:db8:1::7"));
        }
        let v6 = outer6;
        for proto in [
            IPPROTO_TCP,
            IPPROTO_UDP,
            if v6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP },
        ] {
            for payload in [0, 1, 7, 1200] {
                let mut inner = if v6 {
                    transport6(proto, inner6, remote, 4321, 443, payload, false)
                } else {
                    transport(proto, INNER, REMOTE, 4321, 443, payload)
                };
                if v6 {
                    inner[..4].copy_from_slice(&0x6ab54321u32.to_be_bytes());
                    let mut encoded = vec![0; wire::HDR_LEN + inner.len()];
                    encoded[wire::HDR_LEN..].copy_from_slice(&inner);
                    let n = wire::seal_data(&KEY, TEST_ID, &mut encoded, true).unwrap();
                    encoded.truncate(n);
                    assert_eq!(encoded, test_data(&inner, wire::TYPE_DATA, TEST_ID, &KEY));
                }
                let sent = run(bpf, &wrap(&inner, wire::TYPE_DATA, 7), 3)?;
                if v6 {
                    assert_eq!(&sent[ETH..ETH + 4], &inner[..4]);
                }
                assert_eq!(
                    &sent[..6],
                    if v6 {
                        &cfg.gateway6_mac
                    } else {
                        &cfg.gateway_mac
                    }
                );
                let ihl = if v6 { 40 } else { 20 };
                let port_offset = if proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6 {
                    4
                } else {
                    0
                };
                let public = get16(&sent, ETH + ihl + port_offset);
                let mut reply = if v6 {
                    assert_eq!(&sent[ETH + 8..ETH + 24], &server);
                    assert_eq!(sent[ETH + 7], 63);
                    assert_eq!(
                        checksum(&pseudo6(&sent[ETH..])),
                        0,
                        "NAT66 outbound checksum"
                    );
                    transport6(
                        proto,
                        remote,
                        server,
                        if proto == IPPROTO_ICMPV6 { public } else { 443 },
                        public,
                        payload,
                        true,
                    )
                } else {
                    verify_ip(&sent[ETH..]);
                    transport(
                        proto,
                        REMOTE,
                        SERVER,
                        if proto == IPPROTO_ICMP { public } else { 443 },
                        public,
                        payload,
                    )
                };
                if v6 {
                    reply[..4].copy_from_slice(&0x6fefedcbu32.to_be_bytes());
                }
                let received = run(bpf, &frame(&reply), 3)?;
                assert_eq!(received[ETH] >> 4, if outer6 { 6 } else { 4 });
                if outer6 {
                    assert_eq!(
                        checksum(&pseudo6(&received[ETH..])),
                        0,
                        "outer IPv6 checksum"
                    );
                }
                let mut data = received[ETH + hlen + 8..].to_vec();
                let opened = if v6 {
                    open_test(&KEY, &mut data, inner6)
                } else {
                    open_test(&KEY, &mut data, INNER)
                };
                assert_eq!(opened.user, TEST_ID);
                let ip = &data[wire::HDR_LEN..];
                if v6 {
                    assert_eq!(&ip[24..40], &inner6);
                    assert_eq!(&ip[..4], &reply[..4]);
                    assert_eq!(ip[7], 63);
                    assert_eq!(checksum(&pseudo6(ip)), 0, "NAT66 inbound checksum");
                } else {
                    verify_ip(ip);
                }
                assert_eq!(get16(ip, ihl + if port_offset == 4 { 4 } else { 2 }), 4321);
            }
        }
    }
    let valid = transport6(IPPROTO_UDP, inner6, remote, 4321, 443, 0, false);
    for (offset, value) in [(6, 44), (6, 0), (6, 1), (7, 1)] {
        let mut bad = valid.clone();
        bad[offset] = value;
        run(bpf, &tunnel6(&bad, wire::TYPE_DATA, 7), 1)?;
    }
    let mut zero = valid.clone();
    put16(&mut zero, 46, 0);
    run(bpf, &tunnel6(&zero, wire::TYPE_DATA, 7), 1)?;
    let mut zero = tunnel6(&valid, wire::TYPE_DATA, 7);
    put16(&mut zero, ETH + 46, 0);
    run(bpf, &zero, 1)?;
    let ndp = frame(&ip6(
        addr6("fe80::1"),
        addr6("ff02::1"),
        IPPROTO_ICMPV6,
        &[134; 16],
    ));
    assert_eq!(run(bpf, &ndp, 2)?, ndp, "NDP belongs to host stack");
    let host = frame(&transport6(IPPROTO_TCP, remote, server, 5555, 22, 0, false));
    assert_eq!(
        run(bpf, &host, 2)?,
        host,
        "unmapped IPv6 host traffic passes"
    );
    let too_big = transport6(IPPROTO_UDP, inner6, remote, 4321, 443, 1414, false);
    run(bpf, &tunnel6(&too_big, wire::TYPE_DATA, 7), 1)?;
    // Exercise every XOR tail and the exact default/maximum IPv6 wire sizes.
    let extended = Config {
        max_frame: 1592,
        ..cfg
    };
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, extended, 0)?;
    for payload in (0..16).chain([1412, 1413, 1504, 1505]) {
        let inner = transport6(IPPROTO_UDP, inner6, remote, 4321, 443, payload, false);
        let sent = run(bpf, &tunnel6(&inner, wire::TYPE_DATA, 7), 3)?;
        assert_eq!(checksum(&pseudo6(&sent[ETH..])), 0);
        let public = get16(&sent, ETH + 40);
        let reply = transport6(IPPROTO_UDP, remote, server, 443, public, payload, true);
        let received = run(bpf, &frame(&reply), 3)?;
        assert_eq!(received.len(), ETH + inner.len() + wire::OVERHEAD_V6);
        assert_eq!(checksum(&pseudo6(&received[ETH..])), 0);
        let mut body = received[ETH + 48..].to_vec();
        open_test(&KEY, &mut body, inner6);
        assert_eq!(checksum(&pseudo6(&body[wire::HDR_LEN..])), 0);
    }
    let too_big = transport6(IPPROTO_UDP, inner6, remote, 4321, 443, 1506, false);
    run(bpf, &tunnel6(&too_big, wire::TYPE_DATA, 7), 1)?;
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, cfg, 0)?;
    // Reserved bits and truncated compact metadata never update the endpoint.
    let mut bad = tunnel6(&valid, wire::TYPE_DATA, 7);
    let body = &mut bad[ETH + 48..];
    wire::open(&KEY, body).unwrap();
    body[wire::HDR_LEN + 16] |= 0x10;
    wire::seal(&KEY, wire::TYPE_IPV6, TEST_ID, body);
    run(bpf, &bad, 1)?;
    run(bpf, &tunnel6(&[], wire::TYPE_IPV6, 7), 1)?;
    println!("PASS: compact IPv6 client codec, flow label/traffic class, XOR tails and MTU bounds");
    let disabled = Config {
        nat_ip6: [0; 16],
        ..cfg
    };
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, disabled, 0)?;
    run(bpf, &tunnel6(&valid, wire::TYPE_DATA, 7), 1)?;
    run(bpf, &tunnel(&valid, wire::TYPE_DATA, 7), 1)?;
    run(
        bpf,
        &tunnel6(
            &transport(IPPROTO_UDP, INNER, REMOTE, 4321, 443, 0),
            wire::TYPE_DATA,
            7,
        ),
        1,
    )?;
    println!(
        "PASS: separate IPv4/IPv6 paths and cross-family rejection, NAT66 TCP/UDP/ICMPv6, checksums, MAC routes, roaming, malformed IPv6, MTU and NDP passthrough"
    );
    Ok(())
}

// Overlapping local addresses and ports must remain independent across users.
fn check_multiple_users(bpf: &mut Ebpf, mut cfg: Config) -> Result<(), Error> {
    cfg.server_ip6 = addr6("2001:db8::1");
    cfg.nat_ip6 = cfg.server_ip6;
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, cfg, 0)?;
    let second_id = TEST_ID ^ i64::MIN;
    let second_key = Key { k0: 789, k1: 987 };
    HashMap::<_, i64, u16>::try_from(bpf.map_mut("USER_IDS").unwrap())?.insert(second_id, 42, 0)?;
    Array::<_, User>::try_from(bpf.map_mut("USERS").unwrap())?.set(
        42,
        User {
            id: second_id,
            key0: second_key.k0,
            key1: second_key.k1,
            enabled: 1,
            ..Default::default()
        },
        0,
    )?;
    for v6 in [false, true] {
        let hlen = if v6 { 40 } else { 20 };
        let wrap = if v6 { tunnel6 } else { tunnel };
        for proto in [
            IPPROTO_TCP,
            IPPROTO_UDP,
            if v6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP },
        ] {
            let echo = proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6;
            let mut flows = Vec::new();
            // Both users can use identical local addresses and ports.
            {
                let address4 = [172, 19, 8, 23];
                let address6 = addr6("fd77:1::1234");
                for (id, slot, key) in [(TEST_ID, 7u16, KEY), (second_id, 42, second_key)] {
                    let inner = if v6 {
                        transport6(
                            proto,
                            address6,
                            addr6("2001:db8:2::9"),
                            5555,
                            443,
                            17,
                            false,
                        )
                    } else {
                        let mut ip = transport(proto, address4, REMOTE, 5555, 443, 17);
                        if echo {
                            ip[20] = 8;
                            put16(&mut ip, 22, 0);
                            let sum = checksum(&ip[20..]);
                            put16(&mut ip, 22, sum);
                        }
                        ip
                    };
                    let mut packet = wrap(&inner, wire::TYPE_DATA, 7);
                    let body = &mut packet[ETH + hlen + 8..];
                    body.copy_from_slice(&test_data(&inner, wire::TYPE_DATA, id, &key));
                    put16(&mut packet, ETH + hlen, 40000 + slot);
                    // Keep the test's outer UDP checksum valid after replacing its body.
                    put16(&mut packet, ETH + hlen + 6, 0);
                    let sum = checksum(&if v6 {
                        pseudo6(&packet[ETH..])
                    } else {
                        pseudo(&packet[ETH..])
                    });
                    put16(
                        &mut packet,
                        ETH + hlen + 6,
                        if sum == 0 { 65535 } else { sum },
                    );
                    let sent = run(bpf, &packet, 3)?;
                    let port = get16(&sent, ETH + hlen + if echo { 4 } else { 0 });
                    if v6 {
                        assert_eq!(checksum(&pseudo6(&sent[ETH..])), 0);
                    } else {
                        verify_ip(&sent[ETH..]);
                    }
                    flows.push((id, slot, key, address4, address6, packet, port));
                }
            }
            // Check all mappings AFTER the colliding tuples have been inserted.
            for (i, (id, slot, key, address4, address6, packet, port)) in flows.iter().enumerate() {
                assert!(
                    flows[..i].iter().all(|f| f.6 != *port),
                    "NAT mappings must not overlap"
                );
                let sent = run(bpf, packet, 3)?;
                assert_eq!(
                    get16(&sent, ETH + hlen + if echo { 4 } else { 0 }),
                    *port,
                    "another user/address must not replace this mapping"
                );
                let reply = if v6 {
                    transport6(
                        proto,
                        addr6("2001:db8:2::9"),
                        cfg.server_ip6,
                        if echo { *port } else { 443 },
                        *port,
                        17,
                        true,
                    )
                } else {
                    transport(
                        proto,
                        REMOTE,
                        SERVER,
                        if echo { *port } else { 443 },
                        *port,
                        17,
                    )
                };
                let returned = run(bpf, &frame(&reply), 3)?;
                assert_eq!(get16(&returned, ETH + hlen + 2), 40000 + slot);
                if v6 {
                    assert_eq!(checksum(&pseudo6(&returned[ETH..])), 0);
                }
                let mut body = returned[ETH + hlen + 8..].to_vec();
                let opened = if v6 {
                    open_test(key, &mut body, *address6)
                } else {
                    open_test(key, &mut body, *address4)
                };
                assert_eq!(opened.user, *id);
                let inner = &body[wire::HDR_LEN..];
                if v6 {
                    assert_eq!(&inner[24..40], address6);
                    assert_eq!(checksum(&pseudo6(inner)), 0);
                } else {
                    assert_eq!(&inner[16..20], address4);
                    verify_ip(inner);
                }
                assert_eq!(get16(inner, hlen + if echo { 4 } else { 2 }), 5555);
            }
        }
        let before = Array::<_, User>::try_from(bpf.map("USERS").unwrap())?.get(&42, 0)?;
        let mut wrong = wrap(&[], wire::TYPE_KEEPALIVE, 7);
        wrong[ETH + hlen + 8..ETH + hlen + 16].copy_from_slice(&second_id.to_be_bytes());
        run(bpf, &wrong, 1)?;
        let after = Array::<_, User>::try_from(bpf.map("USERS").unwrap())?.get(&42, 0)?;
        assert_eq!(after.last_seen_ns, before.last_seen_ns);
        let counter = || -> Result<u64, Error> {
            Ok(PerCpuArray::<_, u64>::try_from(bpf.map("STATS").unwrap())?
                .get(&stat::DROP_UNKNOWN_USER, 0)?
                .iter()
                .sum())
        };
        let before_unknown = counter()?;
        wrong[ETH + hlen + 8..ETH + hlen + 16].copy_from_slice(&i64::MAX.to_be_bytes());
        wrong[ETH + hlen + 16..].fill(0);
        run(bpf, &wrong, 1)?;
        assert_eq!(counter()?, before_unknown + 1);
    }
    println!(
        "PASS: omitted local addresses, overlapping client ports, independent TCP/UDP/ICMP NAT and reply addresses, per-user keys and unknown-ID early drop"
    );
    Ok(())
}
