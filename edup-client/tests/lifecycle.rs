#![cfg(target_os = "linux")]

use edup_common::{key::derive_key, wire};
use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, TcpListener, TcpStream, UdpSocket},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

fn checked(program: &str, args: &[&str]) -> String {
    let out = Command::new(program).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
fn ip(args: &[&str]) -> String {
    checked("ip", args)
}
fn wait_for(mut condition: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < until, "timed out waiting for test process");
        thread::sleep(Duration::from_millis(50));
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn stop(client: &mut Process) {
    assert_eq!(
        unsafe { libc::kill(client.0.id() as i32, libc::SIGTERM) },
        0
    );
    let mut status = None;
    wait_for(|| {
        status = client.0.try_wait().unwrap();
        status.is_some()
    });
    assert!(status.unwrap().success());
}
fn client(dir: &Path) -> Process {
    let log = fs::File::create(dir.join("client.log")).unwrap();
    Process(
        Command::new(env!("CARGO_BIN_EXE_edup-client"))
            .args(["--config", dir.join("client.json").to_str().unwrap(), "run"])
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    )
}
fn started(dir: &Path, client: &mut Process) {
    wait_for(|| {
        let log = fs::read_to_string(dir.join("client.log")).unwrap();
        assert!(
            client.0.try_wait().unwrap().is_none(),
            "client exited: {log}"
        );
        log.contains("client ready")
    });
}
fn assert_clean() {
    let links = ip(&["-j", "link", "show"]);
    assert!(!links.contains("edup0"), "{links}");
    assert!(ip(&["-4", "route", "show", "exact", "0.0.0.0/1"]).is_empty());
    assert!(ip(&["-4", "route", "show", "exact", "128.0.0.0/1"]).is_empty());
    assert!(ip(&["-4", "route", "show", "default"]).contains("via 192.0.2.1 dev edup-test0"));
    for family in ["-4", "-6"] {
        let routes = ip(&[family, "route", "show"]);
        assert!(!routes.contains("metric 42760"), "{routes}");
    }
}

#[test]
#[ignore = "requires root, iproute2, ping, unshare and /dev/net/tun; isolated namespaces"]
fn isolated_client() {
    isolated(false);
}

#[test]
#[ignore = "requires root, iproute2, ping, unshare and /dev/net/tun; isolated namespaces"]
fn isolated_ipv6_client() {
    isolated(true);
}

fn isolated(ipv6: bool) {
    if std::env::var_os("EDUP_CLIENT_NS").is_none() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "run as root");
        let status = Command::new("unshare")
            .args(["--mount", "--net"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                if ipv6 {
                    "isolated_ipv6_client"
                } else {
                    "isolated_client"
                },
                "--nocapture",
            ])
            .env("EDUP_CLIENT_NS", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    checked("mount", &["--make-rprivate", "/"]);
    checked("mount", &["-t", "sysfs", "sysfs", "/sys"]);
    let dir = std::env::temp_dir().join(format!("edup-client-test-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let mut config = include_str!("../../config/client.example.json")
        .replace("\"keepalive_secs\": 15", "\"keepalive_secs\": 1");
    if ipv6 {
        config = config
            .replace("\"192.0.2.1:7777\"", "\"[2001:db8:1::1]:7777\"")
            .replace("\"mtu\": 1473", "\"mtu\": 1461")
            .replace(
                "\"tunnel_ip\": \"10.66.0.7\",",
                "\"tunnel_ip\": \"10.66.0.7\", \"tunnel_ip6\": \"fd66::7\",",
            );
    }
    fs::write(dir.join("client.json"), &config).unwrap();
    ip(&["link", "set", "lo", "up"]);
    ip(&[
        "link",
        "add",
        "edup-test0",
        "type",
        "veth",
        "peer",
        "name",
        "edup-peer0",
    ]);
    let _peer = Process(
        Command::new("unshare")
            .arg("--net")
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "echo_peer", "--nocapture"])
            .env("EDUP_PEER_DIR", &dir)
            .env("EDUP_PEER_IPV6", if ipv6 { "1" } else { "0" })
            .spawn()
            .unwrap(),
    );
    wait_for(|| dir.join("peer-pid").exists());
    let pid = fs::read_to_string(dir.join("peer-pid")).unwrap();
    ip(&["link", "set", "edup-peer0", "netns", &pid]);
    ip(&["addr", "add", "192.0.2.2/24", "dev", "edup-test0"]);
    ip(&["link", "set", "edup-test0", "up"]);
    ip(&["route", "add", "default", "via", "192.0.2.1"]);
    if ipv6 {
        ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:1::2/64",
            "dev",
            "edup-test0",
            "nodad",
        ]);
        ip(&["-6", "route", "add", "default", "via", "2001:db8:1::1"]);
    }
    wait_for(|| dir.join("peer-ready").exists());

    let mut first = client(&dir);
    started(&dir, &mut first);
    let duplicate = Command::new(env!("CARGO_BIN_EXE_edup-client"))
        .args(["--config", dir.join("client.json").to_str().unwrap(), "run"])
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already exists"));
    let destination = if ipv6 { "2001:db8:2::9" } else { "203.0.113.9" };
    assert!(ip(&["route", "get", destination]).contains("dev edup0"));
    assert!(ip(&["route", "get", "192.0.2.1"]).contains("dev edup-test0"));
    // The example bypasses private IPv4 ranges through the physical gateway.
    for private in ["10.1.2.3", "172.16.0.1", "192.168.7.7"] {
        let route = ip(&["route", "get", private]);
        assert!(route.contains("via 192.0.2.1 dev edup-test0"), "{route}");
    }
    checked("ping", &["-n", "-c", "2", "-W", "3", destination]);
    let udp = UdpSocket::bind(if ipv6 { "[fd66::7]:0" } else { "10.66.0.7:0" }).unwrap();
    udp.connect(if ipv6 {
        "[2001:db8:2::9]:9000"
    } else {
        "203.0.113.9:9000"
    })
    .unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let payload = vec![0x5au8; if ipv6 { 1392 } else { 1400 }];
    udp.send(&payload).unwrap();
    let mut reply = [0u8; 1500];
    let len = udp.recv(&mut reply).unwrap();
    assert_eq!(&reply[..len], &payload);
    // One real UDP GSO packet from the application crosses TUN segmentation,
    // independent wire sealing, outer UDP segmentation, GRO and TUN injection.
    let mut burst = vec![0x6b; 32 * 1000];
    for (i, p) in burst.chunks_mut(1000).enumerate() {
        p[1] = i as u8;
    }
    segment_size(&udp, 1000);
    assert_eq!(udp.send(&burst).unwrap(), burst.len());
    segment_size(&udp, 0);
    for p in burst.chunks(1000) {
        let len = udp.recv(&mut reply).unwrap();
        assert_eq!(&reply[..len], p);
    }
    wait_for(|| {
        fs::read_to_string(dir.join("keepalives"))
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0)
            >= 2
    });
    stop(&mut first);
    assert_clean();
    assert!(ip(&["route", "show", "exact", "192.0.2.1/32"]).is_empty());
    let log = fs::read_to_string(dir.join("client.log")).unwrap();
    assert!(log.contains("tx=35 rx=35"), "{log}");
    assert!(log.contains("TUN offload: tcp=true, udp=true"), "{log}");
    assert!(!log.contains("udp_coalesced_receives=0"), "{log}");
    assert!(!log.contains("udp_segmented_sends=0"), "{log}");
    assert!(!log.contains("tun_segmented_reads=0"), "{log}");
    assert!(!log.contains("tun_coalesced_writes=0"), "{log}");
    let dropped: u64 = log
        .split_whitespace()
        .find_map(|s| s.strip_prefix("dropped="))
        .unwrap()
        .parse()
        .unwrap();
    assert!(dropped >= 2, "malformed replies were not dropped: {log}");

    // The second tunnel route conflicts in the kernel after the first one was
    // added; the client must remove exactly the routes it created.
    let family = if ipv6 { "-6" } else { "-4" };
    let (added, taken) = if ipv6 {
        ("2001:db8:5::/48", "2001:db8:7::/48")
    } else {
        ("198.51.100.0/24", "198.51.102.0/24")
    };
    ip(&[
        family,
        "route",
        "add",
        taken,
        "dev",
        "edup-test0",
        "metric",
        "42760",
    ]);
    fs::write(
        dir.join("client.json"),
        config
            .replace("\"default_route\": \"proxy\"", "\"default_route\": \"bypass\"")
            .replace(
                "{ \"ip\": [\"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\"], \"to\": \"bypass\" }",
                &format!("{{ \"ip\": [\"{added}\", \"{taken}\"], \"to\": \"proxy\" }}"),
            ),
    )
    .unwrap();
    let mut partial = client(&dir);
    let mut status = None;
    wait_for(|| {
        status = partial.0.try_wait().unwrap();
        status.is_some()
    });
    assert!(!status.unwrap().success());
    let log = fs::read_to_string(dir.join("client.log")).unwrap();
    assert!(log.contains(&format!("route {taken} ifindex")), "{log}");
    assert!(log.contains("already exists"), "{log}");
    assert!(ip(&[family, "route", "show", "exact", added]).is_empty());
    assert!(ip(&[family, "route", "show", "exact", taken]).contains("edup-test0"));
    ip(&[
        family,
        "route",
        "del",
        taken,
        "dev",
        "edup-test0",
        "metric",
        "42760",
    ]);
    fs::write(dir.join("client.json"), &config).unwrap();
    assert_clean();
    assert!(ip(&["route", "show", "exact", "192.0.2.1/32"]).is_empty());

    dns_rules(&dir, &config, ipv6);

    // An identical bypass route, e.g. left by a crashed client, keeps its owner.
    if !ipv6 {
        ip(&[
            "route",
            "add",
            "10.0.0.0/8",
            "via",
            "192.0.2.1",
            "dev",
            "edup-test0",
            "metric",
            "42760",
            "proto",
            "static",
        ]);
    }

    // A pre-existing server exception belongs to its owner and must survive.
    ip(&[
        "route",
        "add",
        "192.0.2.1/32",
        "dev",
        "edup-test0",
        "metric",
        "123",
    ]);
    // The same binary must still operate with all offloads explicitly disabled.
    let path = dir.join("client.json");
    fs::write(
        &path,
        fs::read_to_string(&path)
            .unwrap()
            .replace("\"offload\": true", "\"offload\": false"),
    )
    .unwrap();
    let mut second = client(&dir);
    started(&dir, &mut second);
    checked("ping", &["-n", "-c", "1", "-W", "3", destination]);
    if ipv6 {
        assert!(ip(&["-6", "route", "get", "2001:db8:2::9"]).contains("dev edup0"));
        assert!(ip(&["-6", "route", "get", "2001:db8:1::1"]).contains("dev edup-test0"));
        checked("ping", &["-6", "-n", "-c", "2", "-W", "3", "2001:db8:2::9"]);
        let udp6 = UdpSocket::bind("[fd66::7]:0").unwrap();
        udp6.connect("[2001:db8:2::9]:9000").unwrap();
        udp6.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let payload = [0x59; 1413]; // 1461-byte IPv6 packet, 1500-byte outer packet
        udp6.send(&payload).unwrap();
        let mut data = [0; 1500];
        let n = udp6.recv(&mut data).unwrap();
        assert_eq!(&data[..n], &payload);
    }
    stop(&mut second);
    if ipv6 {
        for prefix in ["::/1", "8000::/1", "2001:db8:1::1/128"] {
            assert!(ip(&["-6", "route", "show", "exact", prefix]).is_empty());
        }
    } else {
        assert!(ip(&["route", "show", "exact", "10.0.0.0/8"]).contains("metric 42760"));
        ip(&["route", "del", "10.0.0.0/8", "metric", "42760"]);
    }
    assert_clean();
    assert!(ip(&["route", "show", "exact", "192.0.2.1/32"]).contains("metric 123"));

    // Conflicting VPN routes fail after TUN creation without replacing routes.
    let conflict_prefix = if ipv6 { "::/1" } else { "0.0.0.0/1" };
    let gateway = if ipv6 { "2001:db8:1::1" } else { "192.0.2.1" };
    ip(&["route", "add", conflict_prefix, "via", gateway]);
    let mut conflict = client(&dir);
    let mut status = None;
    wait_for(|| {
        status = conflict.0.try_wait().unwrap();
        status.is_some()
    });
    assert!(!status.unwrap().success());
    assert!(!ip(&["-j", "link", "show"]).contains("edup0"));
    assert!(
        ip(&[
            if ipv6 { "-6" } else { "-4" },
            "route",
            "show",
            "exact",
            conflict_prefix
        ])
        .contains(gateway)
    );
    assert!(ip(&["route", "show", "exact", "128.0.0.0/1"]).is_empty());
    assert!(
        fs::read_to_string(dir.join("client.log"))
            .unwrap()
            .contains("already exists")
    );
    fs::write(dir.join("stop"), "").unwrap();
    drop(_peer);
    println!(
        "TUN/UDP echo, packet filtering, KEEPALIVE, route ownership and SIGTERM cleanup passed"
    );
    // Leave only bounded logs on failure; successful runs remove their own files.
    fs::remove_dir_all(&dir).unwrap();
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|p| ((p[0] as u32) << 8) | u32::from(*p.get(1).unwrap_or(&0)))
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

fn segment_size(socket: &UdpSocket, size: libc::c_int) {
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_UDP,
                libc::UDP_SEGMENT,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as _,
            )
        },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
}

fn l4_checksum(ip: &[u8]) -> u16 {
    let ihl = usize::from(ip[0] & 15) * 4;
    let mut pseudo = ip[12..20].to_vec();
    pseudo.extend([0, ip[9]]);
    pseudo.extend(((ip.len() - ihl) as u16).to_be_bytes());
    pseudo.extend(&ip[ihl..]);
    checksum(&pseudo)
}

#[test]
#[ignore = "helper for isolated_client"]
fn echo_peer() {
    let Some(dir) = std::env::var_os("EDUP_PEER_DIR").map(PathBuf::from) else {
        return;
    };
    fs::write(dir.join("peer-pid"), std::process::id().to_string()).unwrap();
    wait_for(|| {
        Command::new("ip")
            .args(["link", "show", "edup-peer0"])
            .output()
            .unwrap()
            .status
            .success()
    });
    ip(&["addr", "add", "192.0.2.1/24", "dev", "edup-peer0"]);
    ip(&["link", "set", "edup-peer0", "up"]);
    let ipv6 = std::env::var("EDUP_PEER_IPV6").as_deref() == Ok("1");
    if ipv6 {
        ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:1::1/64",
            "dev",
            "edup-peer0",
            "nodad",
        ]);
    }
    // Addresses the peer answers itself, without the tunnel.
    ip(&["link", "set", "lo", "up"]);
    for address in std::env::var("EDUP_PEER_ADDRESSES")
        .unwrap_or_default()
        .split_whitespace()
    {
        let dev = if address.ends_with("/24") || address.ends_with("/64") {
            "edup-peer0"
        } else {
            "lo"
        };
        if address.contains(':') {
            ip(&["addr", "add", address, "dev", dev, "nodad"]);
        } else {
            ip(&["addr", "add", address, "dev", dev]);
        }
    }
    // A GRE link: a client interface without a link-layer header.
    let gre = std::env::var("EDUP_PEER_GRE").as_deref() == Ok("1");
    if gre {
        ip(&[
            "link",
            "add",
            "edup-gre0",
            "type",
            "gre",
            "local",
            "192.0.2.1",
            "remote",
            "192.0.2.2",
        ]);
        ip(&[
            "addr",
            "add",
            "198.18.0.1",
            "peer",
            "198.18.0.2",
            "dev",
            "edup-gre0",
        ]);
        ip(&["link", "set", "edup-gre0", "up"]);
    }
    let socket = UdpSocket::bind(if ipv6 {
        "[2001:db8:1::1]:7777"
    } else if gre {
        "198.18.0.1:7777"
    } else {
        "192.0.2.1:7777"
    })
    .unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    fs::write(dir.join("peer-ready"), "").unwrap();
    let key = derive_key("replace-this-password");
    let mut buf = [0u8; 2048];
    let mut keepalives = 0;
    let mut injected = false;
    let mut burst_reply = Vec::new();
    let mut tunnelled = std::collections::BTreeSet::new();
    while !dir.join("stop").exists() {
        let (len, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => panic!("{e}"),
        };
        let opened = wire::open(&key, &mut buf[..len]).unwrap();
        assert_eq!(opened.user, 4829017365182049271);
        let mut packet = [0u8; 2048];
        let ip_len = if opened.typ == wire::TYPE_KEEPALIVE {
            0
        } else {
            wire::unpack(
                opened.typ,
                &buf[wire::HDR_LEN..len],
                &mut packet,
                if ipv6 { &[0; 16][..] } else { &[0; 4][..] },
                true,
            )
            .unwrap()
        };
        let burst = ip_len == if ipv6 { 40 } else { 20 } + 8 + 1000
            && packet[if ipv6 { 48 } else { 28 }] == 0x6b;
        if opened.typ == wire::TYPE_KEEPALIVE {
            keepalives += 1;
            fs::write(dir.join("keepalives"), keepalives.to_string()).unwrap();
            if !injected {
                socket.send_to(&[0; 3], from).unwrap();
                let mut wrong = [0; wire::HDR_LEN];
                wire::seal(&key, wire::TYPE_KEEPALIVE, 42, &mut wrong);
                socket.send_to(&wrong, from).unwrap();
                injected = true;
            }
        } else {
            let ip = &mut packet[..ip_len];
            let destination = if ip[0] >> 4 == 6 {
                IpAddr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap())
            } else {
                IpAddr::from(<[u8; 4]>::try_from(&ip[16..20]).unwrap())
            };
            if tunnelled.insert(destination) {
                let list: String = tunnelled.iter().map(|a| format!("{a}\n")).collect();
                fs::write(dir.join("tunnelled"), list).unwrap();
            }
            if ip[0] >> 4 == 6 {
                assert_eq!(l4_checksum6(ip), 0, "IPv6 TUN checksum");
                for i in 0..16 {
                    ip.swap(8 + i, 24 + i);
                }
                let check_offset = match ip[6] {
                    58 => {
                        assert_eq!(ip[40], 128);
                        ip[40] = 129;
                        42
                    }
                    17 => {
                        ip.swap(40, 42);
                        ip.swap(41, 43);
                        46
                    }
                    p => panic!("unexpected IPv6 protocol {p}"),
                };
                ip[check_offset..check_offset + 2].fill(0);
                let sum = l4_checksum6(ip);
                ip[check_offset..check_offset + 2]
                    .copy_from_slice(&if sum == 0 { 0xffff } else { sum }.to_be_bytes());
            } else {
                let ihl = usize::from(ip[0] & 15) * 4;
                assert_eq!(
                    checksum(&ip[..ihl]),
                    0,
                    "TUN segmentation must complete IPv4 checksum"
                );
                if ip[9] == 17 && ip[ihl + 6..ihl + 8] != [0, 0] {
                    assert_eq!(
                        l4_checksum(ip),
                        0,
                        "TUN segmentation must complete UDP checksum"
                    );
                }
                for i in 0..4 {
                    ip.swap(12 + i, 16 + i);
                }
                match ip[9] {
                    1 => {
                        assert_eq!(ip[ihl], 8);
                        ip[ihl] = 0;
                        ip[ihl + 2..ihl + 4].fill(0);
                        let sum = checksum(&ip[ihl..]);
                        ip[ihl + 2..ihl + 4].copy_from_slice(&sum.to_be_bytes());
                    }
                    17 => {
                        ip.swap(ihl, ihl + 2);
                        ip.swap(ihl + 1, ihl + 3);
                        ip[ihl + 6..ihl + 8].fill(0);
                        // Valid nonzero checksums allow the client's TUN GRO path
                        // to combine the burst before delivery to the application.
                        let sum = l4_checksum(ip);
                        ip[ihl + 6..ihl + 8]
                            .copy_from_slice(&if sum == 0 { u16::MAX } else { sum }.to_be_bytes());
                    }
                    p => panic!("unexpected protocol {p}"),
                }
                ip[10..12].fill(0);
                let sum = checksum(&ip[..ihl]);
                ip[10..12].copy_from_slice(&sum.to_be_bytes());
            }
        }
        let len = if opened.typ == wire::TYPE_KEEPALIVE {
            wire::seal(&key, opened.typ, 4829017365182049271, &mut buf[..len]);
            len
        } else {
            buf[wire::HDR_LEN..wire::HDR_LEN + ip_len].copy_from_slice(&packet[..ip_len]);
            wire::seal_data(
                &key,
                4829017365182049271,
                &mut buf[..wire::HDR_LEN + ip_len],
                false,
            )
            .unwrap()
        };
        // Generic XDP sees GSO packets from a veth peer unsegmented; a
        // server's XDP_TX sends separate datagrams.
        if burst && std::env::var("EDUP_PEER_GSO").as_deref() != Ok("0") {
            burst_reply.extend_from_slice(&buf[..len]);
            if burst_reply.len() == 32 * len {
                segment_size(&socket, len as libc::c_int);
                socket.send_to(&burst_reply, from).unwrap();
                segment_size(&socket, 0);
                burst_reply.clear();
            }
        } else {
            socket.send_to(&buf[..len], from).unwrap();
        }
    }
}

/// Domain rules: the client's DNS forwarder adds host routes for answers of
/// matched names before replying. The upstream is a fake resolver on loopback.
fn dns_rules(dir: &Path, config: &str, ipv6: bool) {
    let (proxied, bypassed, range, gateway, local) = if ipv6 {
        (
            "2001:db8:5::7",
            "2001:db8:6::80",
            "2001:db8:5::/48",
            "2001:db8:1::1",
            "[fd66::7]:53",
        )
    } else {
        (
            "198.51.100.7",
            "203.0.113.80",
            "198.51.100.0/24",
            "192.0.2.1",
            "10.66.0.7:53",
        )
    };
    let family = if ipv6 { "-6" } else { "-4" };
    let host = |ip: &str| format!("{ip}/{}", if ipv6 { 128 } else { 32 });
    let names = [
        ("proxy.test", proxied.parse::<IpAddr>().unwrap()),
        ("a.bypass.test", bypassed.parse().unwrap()),
    ];
    let upstream_stop = Arc::new(AtomicBool::new(false));
    let upstream = UdpSocket::bind("127.0.0.1:5353").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let tcp_upstream = TcpListener::bind("127.0.0.1:5353").unwrap();
    tcp_upstream.set_nonblocking(true).unwrap();
    let quit = upstream_stop.clone();
    let server = thread::spawn(move || {
        let mut buf = [0; 512];
        while !quit.load(Ordering::Relaxed) {
            if let Ok((len, from)) = upstream.recv_from(&mut buf) {
                upstream
                    .send_to(&dns_answer(&buf[..len], &names), from)
                    .unwrap();
            }
            if let Ok((mut stream, _)) = tcp_upstream.accept() {
                stream.set_nonblocking(false).unwrap();
                let mut len = [0; 2];
                stream.read_exact(&mut len).unwrap();
                let mut query = vec![0; u16::from_be_bytes(len) as usize];
                stream.read_exact(&mut query).unwrap();
                let reply = dns_answer(&query, &names);
                stream
                    .write_all(&(reply.len() as u16).to_be_bytes())
                    .unwrap();
                stream.write_all(&reply).unwrap();
            }
        }
    });
    fs::write(
        dir.join("client.json"),
        config
            .replace(
                "{ \"ip\": [\"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\"], \"to\": \"bypass\" }",
                &format!(
                    "{{ \"domain\": \"proxy.test\", \"to\": \"proxy\" }}, {{ \"ip\": \"{range}\", \"to\": \"bypass\" }}, {{ \"domain_suffix\": \".bypass.test\", \"to\": \"bypass\" }}"
                ),
            )
            .replace(
                "\"offload\": true,",
                "\"offload\": true, \"dns\": { \"servers\": \"127.0.0.1:5353\", \"set_system\": false },",
            ),
    )
    .unwrap();
    let mut client = client(dir);
    started(dir, &mut client);
    let log = fs::read_to_string(dir.join("client.log")).unwrap();
    assert!(log.contains(&format!("DNS={local}")), "{log}");
    let kind = if ipv6 { 28 } else { 1 };
    let udp = UdpSocket::bind(if ipv6 { "[::]:0" } else { "0.0.0.0:0" }).unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reply = [0; 512];
    // proxy.test is caught by the domain rule ahead of the bypassed range.
    udp.send_to(&dns_query(7, "Proxy.Test", kind), local)
        .unwrap();
    let len = udp.recv(&mut reply).unwrap();
    let address = proxied.parse::<IpAddr>().unwrap();
    assert!(reply[..len].ends_with(&ip_octets(address)));
    assert!(ip(&[family, "route", "show", "exact", &host(proxied)]).contains("dev edup0"));
    // TCP queries take the same path.
    let mut tcp = TcpStream::connect(local).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let query = dns_query(8, "a.bypass.test", kind);
    tcp.write_all(&(query.len() as u16).to_be_bytes()).unwrap();
    tcp.write_all(&query).unwrap();
    let mut len = [0; 2];
    tcp.read_exact(&mut len).unwrap();
    let mut answer = vec![0; u16::from_be_bytes(len) as usize];
    tcp.read_exact(&mut answer).unwrap();
    assert_eq!(&answer[..2], &[0, 8]);
    let route = ip(&[family, "route", "show", "exact", &host(bypassed)]);
    assert!(
        route.contains(&format!("via {gateway} dev edup-test0")),
        "{route}"
    );
    // Unmatched names pass through without routes.
    udp.send_to(&dns_query(9, "other.test", kind), local)
        .unwrap();
    let len = udp.recv(&mut reply).unwrap();
    assert_eq!((reply[1], reply[3] & 15, len > 12), (9, 3, true));
    stop(&mut client);
    for address in [proxied, bypassed] {
        assert!(ip(&[family, "route", "show", "exact", &host(address)]).is_empty());
    }
    let log = fs::read_to_string(dir.join("client.log")).unwrap();
    assert!(
        log.contains("dns_queries=3 dns_failures=0 dns_routes=2"),
        "{log}"
    );
    upstream_stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
    fs::write(dir.join("client.json"), config).unwrap();
    assert_clean();
}

fn ip_octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn dns_query(id: u16, name: &str, kind: u16) -> Vec<u8> {
    let mut m = id.to_be_bytes().to_vec();
    m.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend(label.bytes());
    }
    m.push(0);
    m.extend(kind.to_be_bytes());
    m.extend([0, 1]);
    m
}

/// Answers a single-question query from `names`, or NXDOMAIN.
fn dns_answer(query: &[u8], names: &[(&str, IpAddr)]) -> Vec<u8> {
    let mut pos = 12;
    let mut name = Vec::new();
    while query[pos] != 0 {
        let len = query[pos] as usize;
        name.push(String::from_utf8_lossy(&query[pos + 1..pos + 1 + len]).to_lowercase());
        pos += 1 + len;
    }
    let end = pos + 5;
    let mut reply = query[..end].to_vec();
    reply[2] |= 0x80;
    reply[3] = 0x80;
    reply[10..12].fill(0);
    match names.iter().find(|(n, _)| *n == name.join(".")) {
        Some((_, ip)) => {
            let data = ip_octets(*ip);
            reply[7] = 1;
            reply.extend([0xc0, 12]);
            reply.extend(&query[end - 4..end - 2]);
            reply.extend([0, 1, 0, 0, 0, 60, 0, data.len() as u8]);
            reply.extend(data);
        }
        None => reply[3] |= 3,
    }
    reply
}

fn l4_checksum6(ip: &[u8]) -> u16 {
    let mut pseudo = ip[8..40].to_vec();
    pseudo.extend(((ip.len() - 40) as u32).to_be_bytes());
    pseudo.extend([0, 0, 0, ip[6]]);
    pseudo.extend(&ip[40..]);
    checksum(&pseudo)
}

#[cfg(feature = "xdp")]
#[test]
#[ignore = "requires root, iproute2, ping, unshare, /dev/net/tun and eBPF; isolated namespaces"]
fn isolated_xdp_client() {
    isolated_xdp(false);
}

#[cfg(feature = "xdp")]
#[test]
#[ignore = "requires root, iproute2, ping, unshare, /dev/net/tun and eBPF; isolated namespaces"]
fn isolated_xdp_ipv6_client() {
    isolated_xdp(true);
}

/// XDP mode: eBPF on edup-test0 tunnels proxied destinations, userspace
/// answers route lookups, and a stalled client leaves the standard route.
#[cfg(feature = "xdp")]
fn isolated_xdp(ipv6: bool) {
    let test = if ipv6 {
        "isolated_xdp_ipv6_client"
    } else {
        "isolated_xdp_client"
    };
    if std::env::var_os("EDUP_CLIENT_NS").is_none() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "run as root");
        let status = Command::new("unshare")
            .args(["--mount", "--net"])
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", test, "--nocapture"])
            .env("EDUP_CLIENT_NS", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    checked("mount", &["--make-rprivate", "/"]);
    checked("mount", &["-t", "sysfs", "sysfs", "/sys"]);
    let dir = std::env::temp_dir().join(format!("edup-xdp-test-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let mut config = include_str!("../../config/client.example.json")
        .replace("\"keepalive_secs\": 15", "\"keepalive_secs\": 1")
        .replacen('{', "{\"mode\": \"xdp\",", 1);
    if ipv6 {
        // Generic XDP here; the IPv4 run attaches natively to the veth.
        config = config
            .replace("\"192.0.2.1:7777\"", "\"[2001:db8:1::1]:7777\"")
            .replace("\"mtu\": 1473", "\"mtu\": 1461")
            .replacen('{', "{\"xdp_mode\": \"skb\",", 1);
    }
    fs::write(dir.join("client.json"), &config).unwrap();
    ip(&["link", "set", "lo", "up"]);
    ip(&[
        "link",
        "add",
        "edup-test0",
        "type",
        "veth",
        "peer",
        "name",
        "edup-peer0",
    ]);
    // The peer answers these itself: a second on-link address, a bypassed
    // rule range and a destination for the stalled client.
    let peer_addresses = if ipv6 {
        "2001:db8:1::3/64 2001:db8:2::77/128"
    } else {
        "192.0.2.3/24 10.1.2.3/32 203.0.113.77/32"
    };
    let _peer = Process(
        Command::new("unshare")
            .arg("--net")
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "echo_peer", "--nocapture"])
            .env("EDUP_PEER_DIR", &dir)
            .env("EDUP_PEER_IPV6", if ipv6 { "1" } else { "0" })
            .env("EDUP_PEER_ADDRESSES", peer_addresses)
            .env("EDUP_PEER_GSO", if ipv6 { "0" } else { "1" })
            .spawn()
            .unwrap(),
    );
    wait_for(|| dir.join("peer-pid").exists());
    let pid = fs::read_to_string(dir.join("peer-pid")).unwrap();
    ip(&["link", "set", "edup-peer0", "netns", &pid]);
    ip(&["addr", "add", "192.0.2.2/24", "dev", "edup-test0"]);
    ip(&["link", "set", "edup-test0", "up"]);
    ip(&["route", "add", "default", "via", "192.0.2.1"]);
    if ipv6 {
        ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:1::2/64",
            "dev",
            "edup-test0",
            "nodad",
        ]);
        ip(&["-6", "route", "add", "default", "via", "2001:db8:1::1"]);
    }
    wait_for(|| dir.join("peer-ready").exists());
    let tunnelled = |address: &str| {
        fs::read_to_string(dir.join("tunnelled"))
            .unwrap_or_default()
            .lines()
            .any(|l| l == address)
    };
    let ping = |address: &str| checked("ping", &["-n", "-c", "2", "-W", "3", address]);
    let (proxied, stalled, bypassed): (&str, &str, &[&str]) = if ipv6 {
        ("2001:db8:2::9", "2001:db8:2::77", &["2001:db8:1::3"])
    } else {
        ("203.0.113.9", "203.0.113.77", &["10.1.2.3", "192.0.2.3"])
    };

    let mut first = client(&dir);
    started(&dir, &mut first);
    let log = fs::read_to_string(dir.join("client.log")).unwrap();
    let mode = if ipv6 { "skb" } else { "driver" };
    assert!(log.contains(&format!("({mode} XDP on edup-test0")), "{log}");
    // No routes: the datapath decides per destination.
    assert!(ip(&["route", "get", proxied]).contains("dev edup-test0"));
    ping(proxied);
    assert!(tunnelled(proxied));
    let udp = UdpSocket::bind(if ipv6 { "[::]:0" } else { "0.0.0.0:0" }).unwrap();
    udp.connect((proxied, 9000)).unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    // The largest inner packet fills a 1500-byte outer packet.
    let payload = vec![0x5au8; if ipv6 { 1413 } else { 1445 }];
    udp.send(&payload).unwrap();
    let mut reply = [0u8; 1500];
    let len = udp.recv(&mut reply).unwrap();
    assert_eq!(&reply[..len], &payload);
    // A UDP GSO packet is segmented by the kernel before encapsulation.
    let mut burst = vec![0x6b; 32 * 1000];
    for (i, p) in burst.chunks_mut(1000).enumerate() {
        p[1] = i as u8;
    }
    segment_size(&udp, 1000);
    assert_eq!(udp.send(&burst).unwrap(), burst.len());
    segment_size(&udp, 0);
    for p in burst.chunks(1000) {
        let len = udp.recv(&mut reply).unwrap();
        assert_eq!(&reply[..len], p);
    }
    // Bypass rules and on-link routes keep the standard route.
    for address in bypassed {
        ping(address);
        assert!(!tunnelled(address), "{address} was tunnelled");
    }

    // A stalled client stops answering lookups; new destinations then take
    // the standard route instead of waiting for it.
    assert_eq!(unsafe { libc::kill(first.0.id() as i32, libc::SIGSTOP) }, 0);
    thread::sleep(Duration::from_millis(2500));
    ping(stalled);
    assert!(!tunnelled(stalled));
    assert_eq!(unsafe { libc::kill(first.0.id() as i32, libc::SIGCONT) }, 0);
    wait_for(|| {
        Command::new("ping")
            .args(["-n", "-c", "1", "-W", "1", stalled])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
            && tunnelled(stalled)
    });
    stop(&mut first);
    let log = fs::read_to_string(dir.join("client.log")).unwrap();
    for counter in [
        "xdp_lookup",
        "xdp_proxy",
        "xdp_tx_tunnel",
        "xdp_rx_tunnel",
        "xdp_fallback",
    ] {
        let value: u64 = log
            .split_whitespace()
            .find_map(|s| s.strip_prefix(&format!("{counter}=")))
            .unwrap_or_else(|| panic!("{counter} missing: {log}"))
            .parse()
            .unwrap();
        assert_ne!(value, 0, "{counter}: {log}");
    }
    assert_clean_xdp();

    if !ipv6 {
        xdp_dns_rules(&dir, &config);
    }

    // SIGKILL leaves the veth pair behind; the next client replaces it.
    let mut crashed = client(&dir);
    started(&dir, &mut crashed);
    ping(proxied);
    crashed.0.kill().unwrap();
    crashed.0.wait().unwrap();
    assert!(Path::new("/sys/class/net/edup0s").exists());
    // The datapath went away with its client's links.
    ping(stalled);
    let mut second = client(&dir);
    started(&dir, &mut second);
    let log = fs::read_to_string(dir.join("client.log")).unwrap();
    assert!(log.contains("removing veth pair"), "{log}");
    ping(proxied);
    stop(&mut second);
    assert_clean_xdp();

    fs::write(dir.join("stop"), "").unwrap();
    drop(_peer);
    println!("XDP tunnel, route lookups, bypass, fallback, crash recovery and cleanup passed");
    fs::remove_dir_all(&dir).unwrap();
}

#[cfg(feature = "xdp")]
#[test]
#[ignore = "requires root, iproute2, nft, ping, unshare, /dev/net/tun and eBPF; isolated namespaces"]
fn isolated_xdp_router() {
    const TEST: &str = "isolated_xdp_router";
    if std::env::var_os("EDUP_CLIENT_NS").is_none() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "run as root");
        let status = Command::new("unshare")
            .args(["--mount", "--net"])
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", TEST, "--nocapture"])
            .env("EDUP_CLIENT_NS", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    checked("mount", &["--make-rprivate", "/"]);
    checked("mount", &["-t", "sysfs", "sysfs", "/sys"]);
    checked("mount", &["-t", "tmpfs", "tmpfs", "/run"]);
    let dir = std::env::temp_dir().join(format!("edup-router-test-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    // A router: LAN clients behind masquerading, and a WAN interface without
    // a link-layer header (GRE here, PPPoE in practice).
    let rules = r#"[
      { "from": "192.168.77.2", "to": "proxy" },
      { "from": "192.168.77.3", "to": "bypass" },
      { "from": "192.168.77.0/24", "to": "rules" },
      { "ip": "10.0.0.0/8", "to": "bypass" }
    ]"#;
    let config = |rules: &str| {
        format!(
            r#"{{"mode": "xdp", "server": "198.18.0.1:7777", "user": 4829017365182049271,
            "password": "replace-this-password", "tunnel_ip": "10.66.0.7", "mtu": 1400,
            "keepalive_secs": 1, "routing": {{"default_route": "proxy", "routes": {rules}}}}}"#
        )
    };
    fs::write(dir.join("client.json"), config(rules)).unwrap();
    ip(&["link", "set", "lo", "up"]);
    ip(&[
        "link",
        "add",
        "edup-test0",
        "type",
        "veth",
        "peer",
        "name",
        "edup-peer0",
    ]);
    let peer_addresses = "10.1.2.3/32 10.1.2.4/32 10.1.2.5/32 203.0.113.78/32";
    let _peer = Process(
        Command::new("unshare")
            .arg("--net")
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "echo_peer", "--nocapture"])
            .env("EDUP_PEER_DIR", &dir)
            .env("EDUP_PEER_IPV6", "0")
            .env("EDUP_PEER_ADDRESSES", peer_addresses)
            .env("EDUP_PEER_GSO", "0")
            .env("EDUP_PEER_GRE", "1")
            .spawn()
            .unwrap(),
    );
    wait_for(|| dir.join("peer-pid").exists());
    let pid = fs::read_to_string(dir.join("peer-pid")).unwrap();
    ip(&["link", "set", "edup-peer0", "netns", &pid]);
    ip(&["addr", "add", "192.0.2.2/24", "dev", "edup-test0"]);
    ip(&["link", "set", "edup-test0", "up"]);
    ip(&[
        "link",
        "add",
        "edup-wan0",
        "type",
        "gre",
        "local",
        "192.0.2.2",
        "remote",
        "192.0.2.1",
    ]);
    ip(&[
        "addr",
        "add",
        "198.18.0.2",
        "peer",
        "198.18.0.1",
        "dev",
        "edup-wan0",
    ]);
    ip(&["link", "set", "edup-wan0", "up"]);
    ip(&["route", "add", "default", "dev", "edup-wan0"]);
    // The LAN host owns one address per client mode.
    ip(&["netns", "add", "edup-lanhost"]);
    ip(&[
        "link",
        "add",
        "edup-lan0",
        "type",
        "veth",
        "peer",
        "name",
        "edup-lan1",
        "netns",
        "edup-lanhost",
    ]);
    ip(&["addr", "add", "192.168.77.1/24", "dev", "edup-lan0"]);
    ip(&["link", "set", "edup-lan0", "up"]);
    let lan = |args: &[&str]| {
        let mut all = vec!["netns", "exec", "edup-lanhost"];
        all.extend(args);
        checked("ip", &all)
    };
    lan(&["ip", "link", "set", "lo", "up"]);
    for address in ["192.168.77.2/24", "192.168.77.3/24", "192.168.77.4/24"] {
        lan(&["ip", "addr", "add", address, "dev", "edup-lan1"]);
    }
    lan(&["ip", "link", "set", "edup-lan1", "up"]);
    lan(&["ip", "route", "add", "default", "via", "192.168.77.1"]);
    fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
    checked(
        "nft",
        &[
            "add table ip nat; add chain ip nat post { type nat hook postrouting priority srcnat; }; add rule ip nat post oifname edup-wan0 masquerade",
        ],
    );
    wait_for(|| dir.join("peer-ready").exists());
    let tunnelled = |address: &str| {
        fs::read_to_string(dir.join("tunnelled"))
            .unwrap_or_default()
            .lines()
            .any(|l| l == address)
    };
    let ping = |address: &str| checked("ping", &["-n", "-c", "2", "-W", "3", address]);
    let lan_ping = |source: &str, address: &str| {
        lan(&["ping", "-n", "-c", "2", "-W", "3", "-I", source, address])
    };

    let mut router = client(&dir);
    started(&dir, &mut router);
    let log = fs::read_to_string(dir.join("client.log")).unwrap();
    assert!(log.contains("(TC on edup-wan0"), "{log}");
    assert!(log.contains("clients: 2 prefixes on edup-lan0"), "{log}");
    // The router's own traffic follows the destination rules.
    ping("203.0.113.9");
    assert!(tunnelled("203.0.113.9"));
    ping("10.1.2.3");
    assert!(!tunnelled("10.1.2.3"));
    // A proxied client: everything through the tunnel, rules or not.
    lan_ping("192.168.77.2", "10.1.2.4");
    assert!(tunnelled("10.1.2.4"));
    // A bypassed client never uses the tunnel.
    lan_ping("192.168.77.3", "203.0.113.78");
    assert!(!tunnelled("203.0.113.78"));
    // A "rules" client: looked up before masquerading.
    lan_ping("192.168.77.4", "10.1.2.5");
    assert!(!tunnelled("10.1.2.5"));
    lan_ping("192.168.77.4", "203.0.113.80");
    assert!(tunnelled("203.0.113.80"));
    // UDP of a "rules" client: the first datagram is re-injected unchanged.
    let echo = lan(&[
        "bash",
        "-c",
        "exec 3<>/dev/udp/203.0.113.81/9000; printf routed >&3; timeout 3 head -c 6 <&3",
    ]);
    assert_eq!(echo, "routed");
    assert!(tunnelled("203.0.113.81"));

    // SIGHUP applies a changed client table without a restart.
    fs::write(
        dir.join("client.json"),
        config(&rules.replace(
            r#"{ "from": "192.168.77.3", "to": "bypass" }"#,
            r#"{ "from": "192.168.77.3", "to": "proxy" }"#,
        )),
    )
    .unwrap();
    assert_eq!(unsafe { libc::kill(router.0.id() as i32, libc::SIGHUP) }, 0);
    wait_for(|| {
        fs::read_to_string(dir.join("client.log"))
            .unwrap()
            .contains("edup client reloaded")
    });
    lan_ping("192.168.77.3", "203.0.113.79");
    assert!(tunnelled("203.0.113.79"));
    lan_ping("192.168.77.2", "10.1.2.3");
    stop(&mut router);
    let log = fs::read_to_string(dir.join("client.log")).unwrap();
    assert!(!log.contains("restart edup-client"), "{log}");
    assert!(!log.contains("reload failed"), "{log}");
    for name in ["edup0", "edup0s", "edup0e"] {
        assert!(!Path::new("/sys/class/net").join(name).exists(), "{name}");
    }
    // Without the client, every client takes the standard route again.
    lan_ping("192.168.77.2", "203.0.113.78");

    fs::write(dir.join("stop"), "").unwrap();
    drop(_peer);
    println!("router clients, live reload and a link without Ethernet headers passed");
    fs::remove_dir_all(&dir).unwrap();
}

#[cfg(feature = "xdp")]
fn assert_clean_xdp() {
    for name in ["edup0", "edup0s", "edup0e"] {
        assert!(!Path::new("/sys/class/net").join(name).exists(), "{name}");
    }
    let link = ip(&["-d", "link", "show", "edup-test0"]);
    assert!(!link.contains("xdp"), "{link}");
    assert!(ip(&["-4", "route", "show", "default"]).contains("via 192.0.2.1 dev edup-test0"));
}

/// A domain rule overrides the address rules through the route cache.
#[cfg(feature = "xdp")]
fn xdp_dns_rules(dir: &Path, config: &str) {
    let names = [("proxy.test", "198.51.100.7".parse::<IpAddr>().unwrap())];
    let upstream = UdpSocket::bind("127.0.0.1:5353").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let quit = Arc::new(AtomicBool::new(false));
    let server = {
        let quit = quit.clone();
        thread::spawn(move || {
            let mut buf = [0; 512];
            while !quit.load(Ordering::Relaxed) {
                if let Ok((len, from)) = upstream.recv_from(&mut buf) {
                    upstream
                        .send_to(&dns_answer(&buf[..len], &names), from)
                        .unwrap();
                }
            }
        })
    };
    fs::write(
        dir.join("client.json"),
        config
            .replace(
                "{ \"ip\": [\"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\"], \"to\": \"bypass\" }",
                "{ \"domain\": \"proxy.test\", \"to\": \"proxy\" }, { \"ip\": \"198.51.100.0/24\", \"to\": \"bypass\" }",
            )
            .replace(
                "\"offload\": true,",
                "\"offload\": true, \"dns\": { \"servers\": \"127.0.0.1:5353\", \"set_system\": false },",
            ),
    )
    .unwrap();
    let mut client = client(dir);
    started(dir, &mut client);
    let udp = UdpSocket::bind("0.0.0.0:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    udp.send_to(&dns_query(7, "proxy.test", 1), "10.66.0.7:53")
        .unwrap();
    let mut reply = [0; 512];
    let len = udp.recv(&mut reply).unwrap();
    assert!(reply[..len].ends_with(&[198, 51, 100, 7]));
    let tunnelled = |address: &str| {
        fs::read_to_string(dir.join("tunnelled"))
            .unwrap_or_default()
            .lines()
            .any(|l| l == address)
    };
    // The answer's address is tunnelled; its bypassed neighbour is not.
    udp.send_to(b"named", "198.51.100.7:9000").unwrap();
    let len = udp.recv(&mut reply).unwrap();
    assert_eq!(&reply[..len], b"named");
    assert!(tunnelled("198.51.100.7"));
    udp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    udp.send_to(b"unnamed", "198.51.100.8:9000").unwrap();
    assert!(udp.recv(&mut reply).is_err());
    assert!(!tunnelled("198.51.100.8"));
    stop(&mut client);
    let log = fs::read_to_string(dir.join("client.log")).unwrap();
    assert!(
        log.contains("dns_queries=1 dns_failures=0 dns_routes=1"),
        "{log}"
    );
    quit.store(true, Ordering::Relaxed);
    server.join().unwrap();
    fs::write(dir.join("client.json"), config).unwrap();
    assert_clean_xdp();
}
