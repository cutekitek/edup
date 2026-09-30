//! Kernel integration tests: no interface attachment or pinned objects.
use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, HashMap, PerCpuArray, ProgramArray},
    programs::{TestRun, TestRunOptions, Xdp},
};
use edup_common::{
    aead::{self, Cipher},
    crypto::Key,
    maps::*,
    wire::{self, Header},
};

type Error = Box<dyn std::error::Error>;
const SERVER: [u8; 4] = [192, 0, 2, 1];
const CLIENT: [u8; 4] = [198, 51, 100, 7];
const REMOTE: [u8; 4] = [203, 0, 113, 9];
const INNER: [u8; 4] = [10, 66, 0, 7];
const TEST_ID: i64 = 4829017365182049271;
const KEY: Key = [123, 456, 789, 1011, 1213, 1415, 1617, 1819];
const ETH: usize = 14;
const MAC: [u8; 14] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0];
const TX: u32 = 3;
static NONCES: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0x80);
const DROP: u32 = 1;
const PASS: u32 = 2;

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
// Independent compact encoder: lets malformed compact fields reach XDP
// validation, and cross-checks the userspace codec.
fn compact(inner: &[u8]) -> Vec<u8> {
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
    body
}

/// A tunnel client: long-term key, outer addressing and the session from
/// its last handshake.
struct Client {
    id: i64,
    key: Key,
    v6: bool,
    addr4: [u8; 4],
    addr6: [u8; 16],
    port: u16,
    session: Key,
    phase: u8,
    counter: u64,
}

impl Client {
    fn new(id: i64, key: Key, v6: bool) -> Self {
        Self {
            id,
            key,
            v6,
            addr4: CLIENT,
            addr6: addr6("2001:db8:1::7"),
            port: 40000,
            // No session until `handshake`: this key is unknown to XDP.
            session: [0xdead; 8],
            phase: 0,
            counter: 1,
        }
    }
    fn hlen(&self) -> usize {
        if self.v6 { 40 } else { 20 }
    }
    /// Outer Ethernet/IP/UDP around a wire payload.
    fn frame(&self, payload: &[u8]) -> Vec<u8> {
        let mut udp = vec![0; 8];
        put16(&mut udp, 0, self.port);
        put16(&mut udp, 2, 7777);
        put16(&mut udp, 4, (8 + payload.len()) as u16);
        udp.extend(payload);
        if self.v6 {
            let mut ip = ip6(self.addr6, addr6("2001:db8::1"), IPPROTO_UDP, &udp);
            let sum = checksum(&pseudo6(&ip));
            put16(&mut ip, 46, if sum == 0 { 0xffff } else { sum });
            frame(&ip)
        } else {
            // IPv4 UDP checksums are optional; the tunnel's are zero here.
            frame(&ip(self.addr4, SERVER, IPPROTO_UDP, &udp))
        }
    }
    /// Seal an arbitrary body with the next counter.
    fn seal(&mut self, typ: u8, body: &[u8]) -> Vec<u8> {
        let header = Header {
            user: self.id,
            typ,
            phase: self.phase,
            counter: self.counter,
        };
        self.counter += 1;
        let mut pkt = header.encode().to_vec();
        pkt.extend([0; wire::TAG_LEN]);
        pkt.extend(body);
        Cipher::new(&self.session).seal(wire::TO_SERVER, &mut pkt);
        pkt
    }
    fn data(&mut self, inner: &[u8], typ: u8) -> Vec<u8> {
        let typ = if typ == wire::TYPE_DATA && inner.first().is_some_and(|v| v >> 4 == 6) {
            wire::TYPE_IPV6
        } else {
            typ
        };
        self.seal(typ, &compact(inner))
    }
    fn tunnel(&mut self, inner: &[u8], typ: u8) -> Vec<u8> {
        let data = self.data(inner, typ);
        self.frame(&data)
    }
    fn keepalive(&mut self) -> Vec<u8> {
        let data = self.seal(wire::TYPE_KEEPALIVE, &[]);
        self.frame(&data)
    }
    fn init(&self, nonce: [u8; 16]) -> (Vec<u8>, Key) {
        let (pkt, k1) = aead::init(&self.key, self.id, &nonce);
        (self.frame(&pkt), k1)
    }
    /// INIT → RESPONSE, then a KEEPALIVE that confirms the new session.
    fn handshake(&mut self, bpf: &Ebpf) -> Result<(), Error> {
        let nonce = [NONCES.fetch_add(1, std::sync::atomic::Ordering::Relaxed); 16];
        let (init, k1) = self.init(nonce);
        let out = run(bpf, &init, TX)?;
        let hlen = self.hlen();
        assert_eq!(&out[..6], &MAC[6..12], "RESPONSE goes back to the sender");
        assert_eq!(get16(&out, ETH + hlen + 2), self.port);
        if self.v6 {
            assert_eq!(&out[ETH + 24..ETH + 40], &self.addr6);
            assert_eq!(checksum(&pseudo6(&out[ETH..])), 0);
        } else {
            assert_eq!(&out[ETH + 16..ETH + 20], &self.addr4);
        }
        let (session, phase) =
            aead::open_response(&k1, &out[ETH + hlen + 8..]).expect("RESPONSE authenticates");
        self.session = session;
        self.phase = phase;
        self.counter = 1;
        let reply = run(bpf, &self.keepalive(), TX)?;
        let mut body = reply[ETH + hlen + 8..].to_vec();
        let header = Cipher::new(&self.session)
            .open(wire::TO_CLIENT, &mut body)
            .expect("KEEPALIVE reply authenticates");
        assert_eq!(header.typ, wire::TYPE_KEEPALIVE);
        assert_eq!(header.phase, phase);
        assert!(header.counter >= 1, "counter 0 sealed the RESPONSE");
        Ok(())
    }
    /// Verify, decrypt and expand a server-to-client packet in place.
    fn open<const N: usize>(&self, data: &mut Vec<u8>, local: [u8; N]) -> Header {
        let header = Cipher::new(&self.session)
            .open(wire::TO_CLIENT, data)
            .expect("reply authenticates");
        let mut ip = vec![0; data.len() + 20];
        let n = wire::unpack(header.typ, &data[wire::HDR_LEN..], &mut ip, &local, false).unwrap();
        data.truncate(wire::HDR_LEN);
        data.extend(&ip[..n]);
        header
    }
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
fn counter(bpf: &Ebpf, index: u32) -> Result<u64, Error> {
    Ok(PerCpuArray::<_, u64>::try_from(bpf.map("STATS").unwrap())?
        .get(&index, 0)?
        .iter()
        .sum())
}
/// Run a frame and require a drop for `reason`.
fn dropped(bpf: &Ebpf, input: &[u8], reason: u32) -> Result<(), Error> {
    let before = counter(bpf, reason)?;
    run(bpf, input, DROP)?;
    assert_eq!(
        counter(bpf, reason)?,
        before + 1,
        "expected drop reason {}",
        stat::NAMES[reason as usize]
    );
    Ok(())
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
        for (i, name) in stat::NAMES.iter().enumerate() {
            let count = counter(bpf, i as u32)?;
            if count != 0 {
                eprintln!("{name}={count}");
            }
        }
    }
    assert_eq!(r.return_value, action, "unexpected XDP action");
    out.truncate(r.data_size_out as usize);
    if action == TX {
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
    let mut bpf = EbpfLoader::new()
        .map_max_entries("SESSIONS", 128)
        .load(&std::fs::read(path)?)?;
    for (index, name) in program::NAMES.into_iter().enumerate() {
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
        salt: 0x5a17_5a17_5a17_5a17,
        ..Default::default()
    };
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, cfg, 0)?;
    Array::<_, User>::try_from(bpf.map_mut("USERS").unwrap())?.set(
        7,
        User {
            id: TEST_ID,
            key: KEY,
            enabled: 1,
            ..Default::default()
        },
        0,
    )?;
    HashMap::<_, i64, u16>::try_from(bpf.map_mut("USER_IDS").unwrap())?.insert(TEST_ID, 7, 0)?;
    if std::env::args().nth(2).as_deref() == Some("--bench") {
        return benchmark(&bpf);
    }
    let mut client = Client::new(TEST_ID, KEY, false);
    check_handshake(&bpf, &mut client)?;

    let mut keepalive = client.keepalive();
    let trailer = keepalive.len();
    keepalive.resize(trailer + 6, 0xff);
    let out = run(&bpf, &keepalive, TX)?;
    assert_eq!(out.len(), trailer);
    verify_ip(&out[ETH..]);
    assert_eq!(&out[..6], &MAC[6..12]);
    assert_eq!(&out[6..12], &MAC[..6]);
    let mut body = out[42..].to_vec();
    let reply = Cipher::new(&client.session)
        .open(wire::TO_CLIENT, &mut body)
        .unwrap();
    assert_eq!(reply.typ, wire::TYPE_KEEPALIVE);
    println!("PASS: KEEPALIVE reply is freshly sealed, Ethernet trailer, MAC swap");

    for proto in [IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP] {
        let inner = transport(proto, INNER, REMOTE, 1234, 443, 31);
        let sent = run(&bpf, &client.tunnel(&inner, wire::TYPE_DATA), TX)?;
        verify_ip(&sent[ETH..]);
        assert_eq!(sent.len(), ETH + inner.len());
        assert_eq!(&sent[26..30], &SERVER);
        assert_eq!(sent[22], 63);
        let public = get16(&sent, ETH + 20 + if proto == IPPROTO_ICMP { 4 } else { 0 });
        assert!((20000..=20100).contains(&public));
        // Different remote destination must reuse the endpoint-independent mapping.
        let other = transport(proto, INNER, [203, 0, 113, 10], 1234, 80, 31);
        let sent2 = run(&bpf, &client.tunnel(&other, wire::TYPE_DATA), TX)?;
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
        let received = run(&bpf, &frame(&reply), TX)?;
        verify_ip(&received[ETH..]);
        assert_eq!(&received[30..34], &CLIENT);
        assert_eq!(get16(&received, 36), 40000);
        let mut data = received[42..].to_vec();
        let opened = client.open(&mut data, INNER);
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
                max_frame: (wire::MAX_BODY + wire::IPV4_SAVING + wire::OVERHEAD_V4) as u16,
                ..cfg
            };
            Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, extended, 0)?;
            // Every ciphertext tail length, both edges of the default MTU and
            // of the largest ciphertext. The outer checksum covers ciphertext.
            let default = 1500 - wire::OVERHEAD_V4 - 28;
            let max = wire::MAX_BODY + wire::IPV4_SAVING - 28;
            for payload in (0..80).chain([default - 1, default, max - 1, max]) {
                let reply = transport(proto, REMOTE, SERVER, 443, public, payload);
                let received = run(&bpf, &frame(&reply), TX)?;
                let mut data = received[42..].to_vec();
                client.open(&mut data, INNER);
                verify_ip(&data[wire::HDR_LEN..]);
                let sent = run(
                    &bpf,
                    &client.tunnel(
                        &transport(proto, INNER, REMOTE, 1234, 443, payload),
                        wire::TYPE_DATA,
                    ),
                    TX,
                )?;
                verify_ip(&sent[ETH..]);
            }
            let reply = transport(proto, REMOTE, SERVER, 443, public, max + 1);
            dropped(&bpf, &frame(&reply), stat::DROP_TOO_BIG)?;
            Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, cfg, 0)?;
            println!(
                "PASS: nonzero outer UDP checksums, every ChaCha20/Poly1305 tail and maximum wire size"
            );
        }
    }

    let inner = transport(IPPROTO_UDP, INNER, REMOTE, 1234, 443, 10);
    check_authentication(&bpf, &mut client, &inner)?;

    let mut bad = inner.clone();
    bad[8] = 1;
    dropped(&bpf, &client.tunnel(&bad, 0), stat::DROP_TTL)?;
    let mut bad = inner.clone();
    bad[6] = 0x20;
    dropped(&bpf, &client.tunnel(&bad, 0), stat::DROP_BAD_INNER)?;
    let mut stranger = Client::new(8, KEY, false);
    dropped(&bpf, &stranger.tunnel(&inner, 0), stat::DROP_UNKNOWN_USER)?;
    dropped(&bpf, &client.tunnel(&inner, 0x10), stat::DROP_BAD_HDR)?;
    dropped(
        &bpf,
        &client.tunnel(&inner, wire::TYPE_IPV6),
        stat::DROP_BAD_HDR,
    )?;
    dropped(
        &bpf,
        &client.tunnel(&inner, wire::TYPE_KEEPALIVE),
        stat::DROP_BAD_HDR,
    )?;
    let mut bad = client.tunnel(&inner, 0);
    put16(&mut bad, 38, 8);
    dropped(&bpf, &bad, stat::DROP_BAD_HDR)?;
    let mut bad = inner.clone();
    put16(&mut bad, 24, 8);
    dropped(&bpf, &client.tunnel(&bad, 0), stat::DROP_BAD_INNER)?;
    let largest = 1500 - wire::OVERHEAD_V4 - 28;
    let large = transport(IPPROTO_UDP, INNER, REMOTE, 1234, 443, largest + 1);
    dropped(&bpf, &client.tunnel(&large, 0), stat::DROP_TOO_BIG)?;
    let max = transport(IPPROTO_UDP, INNER, REMOTE, 1234, 443, largest);
    let out = run(&bpf, &client.tunnel(&max, 0), TX)?;
    assert_eq!(out.len(), ETH + 1500 - wire::OVERHEAD_V4);
    verify_ip(&out[ETH..]);
    println!("PASS: TTL, fragments, user/header validation, MTU boundary");

    let host = frame(&transport(IPPROTO_TCP, REMOTE, SERVER, 10000, 22, 0));
    assert_eq!(run(&bpf, &host, PASS)?, host);
    let mut arp = vec![0; 60];
    arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    assert_eq!(run(&bpf, &arp, PASS)?, arp);
    let unknown = frame(&transport(IPPROTO_UDP, REMOTE, SERVER, 53, 21000, 0));
    assert_eq!(run(&bpf, &unknown, PASS)?, unknown);
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
    run(&bpf, &client.tunnel(&inner, 0), TX)?;
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
    assert_eq!(run(&bpf, &reply, PASS)?, reply);
    assert!(
        HashMap::<_, NatInKey, NatInVal>::try_from(bpf.map("NAT_IN").unwrap())?
            .get(&echo_reverse, 0)
            .is_err()
    );
    run(
        &bpf,
        &client.tunnel(&transport(IPPROTO_ICMP, INNER, REMOTE, 1234, 0, 0), 0),
        TX,
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
    assert_eq!(run(&bpf, &reply, PASS)?, reply);
    let sent = run(&bpf, &client.tunnel(&inner, 0), TX)?;
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
    dropped(&bpf, &reply, stat::DROP_NO_ENDPOINT)?;
    Array::<_, User>::try_from(bpf.map_mut("USERS").unwrap())?.set(
        7,
        User { enabled: 0, ..user },
        0,
    )?;
    dropped(&bpf, &reply, stat::DROP_UNKNOWN_USER)?;
    Array::<_, User>::try_from(bpf.map_mut("USERS").unwrap())?.set(7, user, 0)?;
    // A client that moves learns its new address with a fresh, sealed packet.
    let captured = client.keepalive();
    client.addr4 = [198, 51, 100, 99];
    client.port = 41000;
    run(&bpf, &client.keepalive(), TX)?;
    let mut padded_reply = reply.clone();
    padded_reply.resize(60, 0xa5);
    let received = run(&bpf, &padded_reply, TX)?;
    assert_eq!(received.len(), ETH + wire::OVERHEAD_V4 + reply_ip.len());
    assert_eq!(&received[30..34], &[198, 51, 100, 99]);
    assert_eq!(get16(&received, 36), 41000);
    let mut data = received[42..].to_vec();
    client.open(&mut data, INNER);
    verify_ip(&data[wire::HDR_LEN..]);
    // Neither a forged nor a replayed packet can redirect return traffic.
    let mut forged = client.tunnel(&inner, 0);
    forged[29] = 66;
    forged[60] ^= 0x80;
    let c = {
        put16(&mut forged, 24, 0);
        checksum(&forged[14..34])
    };
    put16(&mut forged, 24, c);
    dropped(&bpf, &forged, stat::DROP_AUTH)?;
    let mut replayed = captured;
    replayed[29] = 66;
    put16(&mut replayed, 24, 0);
    let c = checksum(&replayed[14..34]);
    put16(&mut replayed, 24, c);
    // Never delivered before, so accepted once; but it is older than the
    // newest packet, so the reply goes to the learned endpoint.
    let answer = run(&bpf, &replayed, TX)?;
    assert_eq!(&answer[30..34], &[198, 51, 100, 99]);
    assert_eq!(get16(&answer, 36), 41000);
    dropped(&bpf, &replayed, stat::DROP_REPLAY)?;
    let after = Array::<_, User>::try_from(bpf.map("USERS").unwrap())?.get(&7, 0)?;
    assert_eq!(
        after.endpoint,
        User::pack_endpoint(u32::from_ne_bytes([198, 51, 100, 99]), 41000u16.to_be())
    );
    println!(
        "PASS: NAT_OUT eviction, disabled/unknown endpoint, roaming, forged and replayed packets cannot redirect, inbound padding"
    );

    let max_reply = transport(IPPROTO_UDP, REMOTE, SERVER, 443, public, largest);
    let received = run(&bpf, &frame(&max_reply), TX)?;
    assert_eq!(received.len(), ETH + 1500);
    let mut data = received[42..].to_vec();
    client.open(&mut data, INNER);
    verify_ip(&data[wire::HDR_LEN..]);
    dropped(
        &bpf,
        &frame(&transport(
            IPPROTO_UDP,
            REMOTE,
            SERVER,
            443,
            public,
            largest + 1,
        )),
        stat::DROP_TOO_BIG,
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
    let sent = run(&bpf, &client.tunnel(&options, 0), TX)?;
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
        let (typ, n) = wire::compact(&mut encoded, true).unwrap();
        assert_eq!(typ, wire::TYPE_DATA);
        assert_eq!(encoded[wire::HDR_LEN..n], compact(&outbound));
        let sent = run(&bpf, &client.tunnel(&outbound, 0), TX)?;
        verify_ip(&sent[ETH..]);
        assert_eq!(sent[ETH + 1], 0xab);
        assert_eq!(get16(&sent, ETH + 4), 0xdead);
        assert_eq!(get16(&sent, ETH + 6), 0x4000);
        let public = get16(&sent, ETH + 20 + options_len);
        let reply = prepare(transport(IPPROTO_UDP, REMOTE, SERVER, 443, public, 10));
        let returned = run(&bpf, &frame(&reply), TX)?;
        let mut body = returned[42..].to_vec();
        client.open(&mut body, INNER);
        let ip = &body[wire::HDR_LEN..];
        verify_ip(ip);
        assert_eq!(ip[0], 0x45 + options_len as u8 / 4);
        assert_eq!(ip[1], 0xab);
        assert_eq!(get16(ip, 4), 0xdead);
        assert_eq!(get16(ip, 6), 0x4000);
        assert_eq!(&ip[20..20 + options_len], &vec![1; options_len]);
    }
    for flags in [0x80, 0x20, 0x10, 11, 15] {
        let mut body = compact(&inner);
        body[6] = flags;
        let data = client.seal(wire::TYPE_DATA, &body);
        dropped(&bpf, &client.frame(&data), stat::DROP_BAD_INNER)?;
    }
    println!(
        "PASS: client codec, DSCP/ECN, DF, identification, all IPv4 option sizes and malformed flags"
    );
    let mut zero_udp = inner.clone();
    put16(&mut zero_udp, 26, 0);
    let sent = run(&bpf, &client.tunnel(&zero_udp, 0), TX)?;
    assert_eq!(get16(&sent, ETH + 26), 0);
    let bad_proto = ip(INNER, REMOTE, 47, &[0; 20]);
    dropped(&bpf, &client.tunnel(&bad_proto, 0), stat::DROP_PROTO)?;
    let mut bad_tcp = transport(IPPROTO_TCP, INNER, REMOTE, 1234, 443, 0);
    bad_tcp[32] = 0x40;
    dropped(&bpf, &client.tunnel(&bad_tcp, 0), stat::DROP_BAD_INNER)?;
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
    let sent_a = run(&bpf, &client.tunnel(&a, 0), TX)?;
    let sent_b = run(&bpf, &client.tunnel(&b, 0), TX)?;
    assert_ne!(get16(&sent_a, ETH + 20), get16(&sent_b, ETH + 20));
    dropped(&bpf, &client.tunnel(&c, 0), stat::DROP_NAT_FULL)?;
    assert_eq!(
        get16(&run(&bpf, &client.tunnel(&a, 0), TX)?, ETH + 20),
        get16(&sent_a, ETH + 20)
    );
    let reserved = Config {
        nat_port_min: 7777,
        nat_port_max: 7777,
        ..cfg
    };
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, reserved, 0)?;
    dropped(&bpf, &client.tunnel(&c, 0), stat::DROP_NAT_FULL)?;
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
        let sent = run(&bpf, &client.tunnel(&tcp, 0), TX)?;
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

    check_ipv6(&mut bpf, cfg)?;
    check_multiple_users(&mut bpf, cfg)?;
    for (index, name) in stat::NAMES.iter().enumerate() {
        let sum = counter(&bpf, index as u32)?;
        println!("{name}: {sum}");
        if !matches!(index as u32, stat::DROP_ADJUST | stat::DROP_SPOOF) {
            assert!(sum > 0, "untested outcome: {name}");
        }
    }
    println!("All XDP integration checks passed; nothing attached or pinned.");
    Ok(())
}

/// Sessions: nothing before a handshake, forged/replayed INIT, confirmation
/// by the first packet, and rekeying.
fn check_handshake(bpf: &Ebpf, client: &mut Client) -> Result<(), Error> {
    dropped(bpf, &client.keepalive(), stat::DROP_NO_SESSION)?;
    let (init, k1) = client.init([1; 16]);
    let mut forged = init.clone();
    forged[ETH + 20 + 8 + wire::HDR_LEN] ^= 1;
    dropped(bpf, &forged, stat::DROP_AUTH)?;
    let wrong = Client::new(TEST_ID, [7; 8], false);
    dropped(bpf, &wrong.init([1; 16]).0, stat::DROP_AUTH)?;
    let mut truncated = init.clone();
    truncated.truncate(truncated.len() - 1);
    let len = truncated.len();
    put16(&mut truncated, ETH + 2, (len - ETH) as u16);
    put16(&mut truncated, ETH + 24, (len - ETH - 20) as u16);
    put16(&mut truncated, ETH + 10, 0);
    let c = checksum(&truncated[ETH..ETH + 20]);
    put16(&mut truncated, ETH + 10, c);
    dropped(bpf, &truncated, stat::DROP_BAD_HDR)?;
    let first = run(bpf, &init, TX)?;
    let (key, phase) = aead::open_response(&k1, &first[42..]).unwrap();
    assert_eq!(phase, 1, "a handshake fills the inactive slot");
    // A replayed INIT gets a different server nonce: a fresh pending session.
    let again = run(bpf, &init, TX)?;
    let (replayed_key, _) = aead::open_response(&k1, &again[42..]).unwrap();
    assert_ne!(replayed_key, key);
    // The superseded response's key was never confirmed and is not accepted.
    client.session = key;
    client.phase = phase;
    dropped(bpf, &client.keepalive(), stat::DROP_AUTH)?;
    client.handshake(bpf)?;
    let active = client.session;
    let data = client.tunnel(&transport(IPPROTO_UDP, INNER, REMOTE, 1234, 443, 1), 0);
    run(bpf, &data, TX)?;
    // Replaying INIT again cannot displace the confirmed session.
    run(bpf, &init, TX)?;
    run(bpf, &client.keepalive(), TX)?;
    // Rekey: the new session replaces the old one once confirmed.
    let old = (client.session, client.phase, client.counter);
    client.handshake(bpf)?;
    assert_ne!(client.phase, old.1);
    assert_ne!(client.session, active);
    let current = (client.session, client.phase, client.counter);
    (client.session, client.phase, client.counter) = old;
    dropped(bpf, &client.keepalive(), stat::DROP_NO_SESSION)?;
    (client.session, client.phase, client.counter) = current;
    run(bpf, &client.keepalive(), TX)?;
    println!(
        "PASS: handshake, forged/wrong-key/truncated INIT, replayed INIT, confirmation, rekey retires the old session"
    );
    Ok(())
}

/// Integrity and replay protection on the data path.
fn check_authentication(bpf: &Ebpf, client: &mut Client, inner: &[u8]) -> Result<(), Error> {
    let sealed = client.tunnel(inner, 0);
    for byte in [42, 49, 52, 57, 58, 73, 74, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[byte] ^= 0x01;
        // The user ID (42..50) selects the key: a changed ID is unknown.
        let reason = if byte < 50 {
            stat::DROP_UNKNOWN_USER
        } else if byte == 51 {
            stat::DROP_BAD_HDR
        } else {
            stat::DROP_AUTH
        };
        dropped(bpf, &bad, reason)?;
    }
    let mut bad = sealed.clone();
    bad[51] ^= 0x02;
    dropped(bpf, &bad, stat::DROP_BAD_HDR)?;
    let before = Array::<_, User>::try_from(bpf.map("USERS").unwrap())?.get(&7, 0)?;
    run(bpf, &sealed, TX)?;
    dropped(bpf, &sealed, stat::DROP_REPLAY)?;
    // Out-of-order delivery inside the window is fine; each counter once.
    let earlier = client.tunnel(inner, 0);
    let later = client.tunnel(inner, 0);
    run(bpf, &later, TX)?;
    run(bpf, &earlier, TX)?;
    dropped(bpf, &earlier, stat::DROP_REPLAY)?;
    // A packet held back until the window moved past it is refused even
    // though it was never delivered.
    let stale = client.tunnel(inner, 0);
    for _ in 0..(WINDOW_SLOTS + 1) * 16 {
        run(bpf, &client.keepalive(), TX)?;
    }
    dropped(bpf, &stale, stat::DROP_REPLAY)?;
    let after = Array::<_, User>::try_from(bpf.map("USERS").unwrap())?.get(&7, 0)?;
    assert_eq!(after.endpoint, before.endpoint);
    println!(
        "PASS: every header, tag and ciphertext modification is rejected; replays and stale counters are dropped"
    );
    Ok(())
}

// Repeat separate syscalls: XDP modifies the input in place, so kernel repeat>1
// can time a different path after the first iteration. No program is attached.
fn benchmark(bpf: &Ebpf) -> Result<(), Error> {
    let program: &Xdp = bpf.program("edup").unwrap().try_into()?;
    let mut client = Client::new(TEST_ID, KEY, false);
    client.handshake(bpf)?;
    for payload in [0, 1360] {
        let mut inner = transport(IPPROTO_TCP, INNER, REMOTE, 1234, 443, payload);
        inner[33] = 0x10; // established ACK; no state transition in the hot path
        put16(&mut inner, 36, 0);
        let sum = checksum(&pseudo(&inner));
        put16(&mut inner, 36, sum);
        let sent = run(bpf, &client.tunnel(&inner, 0), TX)?;
        let public = get16(&sent, ETH + 20);
        let mut reply = transport(IPPROTO_TCP, REMOTE, SERVER, 443, public, payload);
        reply[33] = 0x10;
        put16(&mut reply, 36, 0);
        let sum = checksum(&pseudo(&reply));
        put16(&mut reply, 36, sum);
        let inbound = frame(&reply);
        for direction in ["outbound", "inbound"] {
            let mut out = [0; 2048];
            let mut samples = Vec::new();
            for round in 0..8 {
                // Every outbound packet needs a fresh counter; seal them
                // before timing starts. Only the kernel's duration counts.
                let inputs: Vec<_> = (0..2000)
                    .map(|_| {
                        if direction == "outbound" {
                            client.tunnel(&inner, 0)
                        } else {
                            inbound.clone()
                        }
                    })
                    .collect();
                let mut total = 0u128;
                for input in &inputs {
                    let result = program.test_run(TestRunOptions {
                        data_in: Some(input),
                        data_out: Some(&mut out),
                        repeat: 1,
                        ..Default::default()
                    })?;
                    assert_eq!(
                        result.return_value, TX,
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
        let mut client = Client::new(TEST_ID, KEY, outer6);
        client.handshake(bpf)?;
        let keep = run(bpf, &client.keepalive(), TX)?;
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
                    let (typ, n) = wire::compact(&mut encoded, true).unwrap();
                    assert_eq!(typ, wire::TYPE_IPV6);
                    assert_eq!(encoded[wire::HDR_LEN..n], compact(&inner));
                }
                let sent = run(bpf, &client.tunnel(&inner, wire::TYPE_DATA), TX)?;
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
                let received = run(bpf, &frame(&reply), TX)?;
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
                    client.open(&mut data, inner6)
                } else {
                    client.open(&mut data, INNER)
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
    let mut client = Client::new(TEST_ID, KEY, true);
    client.handshake(bpf)?;
    let valid = transport6(IPPROTO_UDP, inner6, remote, 4321, 443, 0, false);
    for (offset, value, reason) in [
        (6, 44, stat::DROP_PROTO),
        (6, 0, stat::DROP_PROTO),
        (6, 1, stat::DROP_PROTO),
        (7, 1, stat::DROP_TTL),
    ] {
        let mut bad = valid.clone();
        bad[offset] = value;
        dropped(bpf, &client.tunnel(&bad, wire::TYPE_DATA), reason)?;
    }
    let mut zero = valid.clone();
    put16(&mut zero, 46, 0);
    dropped(
        bpf,
        &client.tunnel(&zero, wire::TYPE_DATA),
        stat::DROP_BAD_INNER,
    )?;
    let mut zero = client.tunnel(&valid, wire::TYPE_DATA);
    put16(&mut zero, ETH + 46, 0);
    dropped(bpf, &zero, stat::DROP_BAD_HDR)?;
    let ndp = frame(&ip6(
        addr6("fe80::1"),
        addr6("ff02::1"),
        IPPROTO_ICMPV6,
        &[134; 16],
    ));
    assert_eq!(run(bpf, &ndp, PASS)?, ndp, "NDP belongs to host stack");
    let host = frame(&transport6(IPPROTO_TCP, remote, server, 5555, 22, 0, false));
    assert_eq!(
        run(bpf, &host, PASS)?,
        host,
        "unmapped IPv6 host traffic passes"
    );
    let largest = 1500 - wire::OVERHEAD_V6 - 48;
    let too_big = transport6(IPPROTO_UDP, inner6, remote, 4321, 443, largest + 1, false);
    dropped(
        bpf,
        &client.tunnel(&too_big, wire::TYPE_DATA),
        stat::DROP_TOO_BIG,
    )?;
    // Exercise every cipher tail and the exact default/maximum IPv6 wire sizes.
    let extended = Config {
        max_frame: (wire::MAX_BODY + wire::IPV6_SAVING + wire::OVERHEAD_V6) as u16,
        ..cfg
    };
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, extended, 0)?;
    let max = wire::MAX_BODY + wire::IPV6_SAVING - 48;
    for payload in (0..80).chain([largest - 1, largest, max - 1, max]) {
        let inner = transport6(IPPROTO_UDP, inner6, remote, 4321, 443, payload, false);
        let sent = run(bpf, &client.tunnel(&inner, wire::TYPE_DATA), TX)?;
        assert_eq!(checksum(&pseudo6(&sent[ETH..])), 0);
        let public = get16(&sent, ETH + 40);
        let reply = transport6(IPPROTO_UDP, remote, server, 443, public, payload, true);
        let received = run(bpf, &frame(&reply), TX)?;
        assert_eq!(received.len(), ETH + inner.len() + wire::OVERHEAD_V6);
        assert_eq!(checksum(&pseudo6(&received[ETH..])), 0);
        let mut body = received[ETH + 48..].to_vec();
        client.open(&mut body, inner6);
        assert_eq!(checksum(&pseudo6(&body[wire::HDR_LEN..])), 0);
    }
    let too_big = transport6(IPPROTO_UDP, inner6, remote, 4321, 443, max + 1, false);
    dropped(
        bpf,
        &client.tunnel(&too_big, wire::TYPE_DATA),
        stat::DROP_TOO_BIG,
    )?;
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, cfg, 0)?;
    // Reserved bits and truncated compact metadata never update the endpoint.
    let mut body = compact(&valid);
    body[16] |= 0x10;
    let data = client.seal(wire::TYPE_IPV6, &body);
    dropped(bpf, &client.frame(&data), stat::DROP_BAD_INNER)?;
    let data = client.seal(wire::TYPE_IPV6, &[]);
    dropped(bpf, &client.frame(&data), stat::DROP_BAD_INNER)?;
    println!(
        "PASS: compact IPv6 client codec, flow label/traffic class, cipher tails and MTU bounds"
    );
    let disabled = Config {
        nat_ip6: [0; 16],
        ..cfg
    };
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, disabled, 0)?;
    dropped(
        bpf,
        &client.tunnel(&valid, wire::TYPE_DATA),
        stat::DROP_PROTO,
    )?;
    let mut client4 = Client::new(TEST_ID, KEY, false);
    client4.handshake(bpf)?;
    dropped(
        bpf,
        &client4.tunnel(&valid, wire::TYPE_DATA),
        stat::DROP_BAD_HDR,
    )?;
    let mut client6 = Client::new(TEST_ID, KEY, true);
    client6.handshake(bpf)?;
    dropped(
        bpf,
        &client6.tunnel(
            &transport(IPPROTO_UDP, INNER, REMOTE, 4321, 443, 0),
            wire::TYPE_DATA,
        ),
        stat::DROP_BAD_HDR,
    )?;
    println!(
        "PASS: separate IPv4/IPv6 paths and cross-family rejection, NAT66 TCP/UDP/ICMPv6, checksums, MAC routes, malformed IPv6, MTU and NDP passthrough"
    );
    Ok(())
}

// Overlapping local addresses and ports must remain independent across users.
fn check_multiple_users(bpf: &mut Ebpf, mut cfg: Config) -> Result<(), Error> {
    cfg.server_ip6 = addr6("2001:db8::1");
    cfg.nat_ip6 = cfg.server_ip6;
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").unwrap())?.set(0, cfg, 0)?;
    let second_id = TEST_ID ^ i64::MIN;
    let second_key: Key = [789, 987, 1, 2, 3, 4, 5, 6];
    HashMap::<_, i64, u16>::try_from(bpf.map_mut("USER_IDS").unwrap())?.insert(second_id, 42, 0)?;
    Array::<_, User>::try_from(bpf.map_mut("USERS").unwrap())?.set(
        42,
        User {
            id: second_id,
            key: second_key,
            enabled: 1,
            ..Default::default()
        },
        0,
    )?;
    for v6 in [false, true] {
        let hlen = if v6 { 40 } else { 20 };
        let mut clients = [
            (7u16, Client::new(TEST_ID, KEY, v6)),
            (42, Client::new(second_id, second_key, v6)),
        ];
        for (slot, client) in &mut clients {
            client.port = 40000 + *slot;
            client.handshake(bpf)?;
        }
        for proto in [
            IPPROTO_TCP,
            IPPROTO_UDP,
            if v6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP },
        ] {
            let echo = proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6;
            let mut flows = Vec::new();
            // Both users can use identical local addresses and ports.
            let address4 = [172, 19, 8, 23];
            let address6 = addr6("fd77:1::1234");
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
            for (_, client) in &mut clients {
                let sent = run(bpf, &client.tunnel(&inner, wire::TYPE_DATA), TX)?;
                let port = get16(&sent, ETH + hlen + if echo { 4 } else { 0 });
                if v6 {
                    assert_eq!(checksum(&pseudo6(&sent[ETH..])), 0);
                } else {
                    verify_ip(&sent[ETH..]);
                }
                flows.push(port);
            }
            // Check all mappings AFTER the colliding tuples have been inserted.
            for (i, (slot, client)) in clients.iter_mut().enumerate() {
                let port = flows[i];
                assert!(
                    flows[..i].iter().all(|f| *f != port),
                    "NAT mappings must not overlap"
                );
                let sent = run(bpf, &client.tunnel(&inner, wire::TYPE_DATA), TX)?;
                assert_eq!(
                    get16(&sent, ETH + hlen + if echo { 4 } else { 0 }),
                    port,
                    "another user/address must not replace this mapping"
                );
                let reply = if v6 {
                    transport6(
                        proto,
                        addr6("2001:db8:2::9"),
                        cfg.server_ip6,
                        if echo { port } else { 443 },
                        port,
                        17,
                        true,
                    )
                } else {
                    transport(
                        proto,
                        REMOTE,
                        SERVER,
                        if echo { port } else { 443 },
                        port,
                        17,
                    )
                };
                let returned = run(bpf, &frame(&reply), TX)?;
                assert_eq!(get16(&returned, ETH + hlen + 2), 40000 + *slot);
                if v6 {
                    assert_eq!(checksum(&pseudo6(&returned[ETH..])), 0);
                }
                let mut body = returned[ETH + hlen + 8..].to_vec();
                let opened = if v6 {
                    client.open(&mut body, address6)
                } else {
                    client.open(&mut body, address4)
                };
                assert_eq!(opened.user, client.id);
                let inner = &body[wire::HDR_LEN..];
                if v6 {
                    assert_eq!(&inner[24..40], &address6);
                    assert_eq!(checksum(&pseudo6(inner)), 0);
                } else {
                    assert_eq!(&inner[16..20], &address4);
                    verify_ip(inner);
                }
                assert_eq!(get16(inner, hlen + if echo { 4 } else { 2 }), 5555);
            }
        }
        // One user's session key cannot speak for another user.
        let before = Array::<_, User>::try_from(bpf.map("USERS").unwrap())?.get(&42, 0)?;
        let (first, second) = clients.split_at_mut(1);
        let impostor = &mut first[0].1;
        impostor.id = second_id;
        impostor.phase = second[0].1.phase;
        dropped(bpf, &impostor.keepalive(), stat::DROP_AUTH)?;
        impostor.id = TEST_ID;
        let after = Array::<_, User>::try_from(bpf.map("USERS").unwrap())?.get(&42, 0)?;
        assert_eq!(after.last_seen_ns, before.last_seen_ns);
        let mut unknown = Client::new(i64::MAX, KEY, v6);
        dropped(bpf, &unknown.keepalive(), stat::DROP_UNKNOWN_USER)?;
    }
    println!(
        "PASS: omitted local addresses, overlapping client ports, independent TCP/UDP/ICMP NAT and reply addresses, per-user keys and unknown-ID early drop"
    );
    Ok(())
}
