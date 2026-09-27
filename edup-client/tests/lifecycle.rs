#![cfg(target_os = "linux")]

use edup_common::{key::derive_key, wire};
use std::{
    fs,
    net::UdpSocket,
    os::fd::AsRawFd,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
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
    client_with_path(dir, None)
}
fn client_with_path(dir: &Path, path: Option<&str>) -> Process {
    let log = fs::File::create(dir.join("client.log")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_edup-client"));
    if let Some(path) = path {
        cmd.env("PATH", path);
    }
    Process(
        cmd.args(["--config", dir.join("client.toml").to_str().unwrap(), "run"])
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
    fs::write(
        dir.join("client.toml"),
        include_str!("../../config/client.example.toml")
            .replace("keepalive_secs = 15", "keepalive_secs = 1"),
    )
    .unwrap();
    if ipv6 {
        let path = dir.join("client.toml");
        let config = fs::read_to_string(&path)
            .unwrap()
            .replace("\"192.0.2.1:7777\"", "\"[2001:db8:1::1]:7777\"")
            .replace("mtu = 1464", "mtu = 1444");
        fs::write(path, format!("{config}\ntunnel_net6 = \"fd66::/112\"\n")).unwrap();
    }
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
        .args(["--config", dir.join("client.toml").to_str().unwrap(), "run"])
        .output()
        .unwrap();
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already exists"));
    let destination = if ipv6 { "2001:db8:2::9" } else { "203.0.113.9" };
    assert!(ip(&["route", "get", destination]).contains("dev edup0"));
    assert!(ip(&["route", "get", "192.0.2.1"]).contains("dev edup-test0"));
    checked("ping", &["-n", "-c", "2", "-W", "3", destination]);
    let udp = UdpSocket::bind(if ipv6 { "[fd66::7]:0" } else { "10.66.0.7:0" }).unwrap();
    udp.connect(if ipv6 {
        "[2001:db8:2::9]:9000"
    } else {
        "203.0.113.9:9000"
    })
    .unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let payload = vec![0x5au8; if ipv6 { 1396 } else { 1400 }];
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

    // Fail the third route addition after the first two actually reach the kernel.
    // Only this child sees the ip wrapper; cleanup calls use the real ip binary.
    fs::write(dir.join("ip"), "#!/bin/sh\nif [ \"$1 $2 $3 $4\" = \"-4 route add 128.0.0.0/1\" ]; then\n  echo injected-route-failure >&2\n  exit 1\nfi\nexec /usr/bin/ip \"$@\"\n".replace("-4 route add 128.0.0.0/1", if ipv6 { "-6 route add 8000::/1" } else { "-4 route add 128.0.0.0/1" })).unwrap();
    fs::set_permissions(dir.join("ip"), fs::Permissions::from_mode(0o755)).unwrap();
    let mut partial = client_with_path(&dir, Some(&format!("{}:/usr/bin:/bin", dir.display())));
    let mut status = None;
    wait_for(|| {
        status = partial.0.try_wait().unwrap();
        status.is_some()
    });
    assert!(!status.unwrap().success());
    assert!(
        fs::read_to_string(dir.join("client.log"))
            .unwrap()
            .contains("injected-route-failure")
    );
    assert_clean();
    assert!(ip(&["route", "show", "exact", "192.0.2.1/32"]).is_empty());

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
    let path = dir.join("client.toml");
    fs::write(
        &path,
        fs::read_to_string(&path)
            .unwrap()
            .replace("offload = true", "offload = false"),
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
        let payload = [0x59; 1396]; // 1444-byte IPv6 packet, 1500-byte outer packet
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
    let socket = UdpSocket::bind(if ipv6 {
        "[2001:db8:1::1]:7777"
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
    let mut nonce = 10;
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
        assert_eq!(opened.user, 7);
        let burst = opened.typ == wire::TYPE_DATA
            && len == wire::HDR_LEN + if ipv6 { 40 } else { 20 } + 8 + 1000
            && buf[wire::HDR_LEN + if ipv6 { 48 } else { 28 }] == 0x6b;
        if opened.typ == wire::TYPE_KEEPALIVE {
            keepalives += 1;
            fs::write(dir.join("keepalives"), keepalives.to_string()).unwrap();
            if !injected {
                socket.send_to(&[0; 3], from).unwrap();
                let mut wrong = [0; wire::HDR_LEN];
                wire::seal(&key, 9, wire::TYPE_KEEPALIVE, 42, &mut wrong);
                socket.send_to(&wrong, from).unwrap();
                injected = true;
            }
        } else {
            let ip = &mut buf[wire::HDR_LEN..len];
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
        nonce += 1;
        wire::seal(&key, nonce, opened.typ, 7, &mut buf[..len]);
        if burst {
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

fn l4_checksum6(ip: &[u8]) -> u16 {
    let mut pseudo = ip[8..40].to_vec();
    pseudo.extend(((ip.len() - 40) as u32).to_be_bytes());
    pseudo.extend([0, 0, 0, ip[6]]);
    pseudo.extend(&ip[40..]);
    checksum(&pseudo)
}
