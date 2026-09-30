#![cfg(target_os = "linux")]

use aya::{
    maps::{Array, HashMap, Map, MapData},
    programs::{
        TestRun, TestRunOptions, Xdp,
        links::{FdLink, PinnedLink},
    },
};
use aya_obj::programs::XdpAttachType;
use edup_common::{
    aead::{self, Cipher},
    key::derive_key,
    maps::{Config, NatInKey, NatInVal, NatOutKey, NatOutVal, User},
    wire::{self, Header},
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const PIN: &str = "/sys/fs/bpf/edup-test";
fn exec(program: &str, args: &[&str]) -> Output {
    Command::new(program).args(args).output().unwrap()
}
fn checked(program: &str, args: &[&str]) -> String {
    let out = exec(program, args);
    assert!(
        out.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
fn server(config: &Path, command: &str, success: bool) -> String {
    let out = exec(
        env!("CARGO_BIN_EXE_edup-server"),
        &[
            "--config",
            config.to_str().unwrap(),
            "--pin-path",
            PIN,
            command,
        ],
    );
    assert_eq!(
        out.status.success(),
        success,
        "{command}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
fn generation() -> PathBuf {
    let link = FdLink::from(PinnedLink::from_pin(Path::new(PIN).join("link")).unwrap());
    let id = link.info().unwrap().program_id();
    fs::read_dir(PIN)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&format!("gen_{id}_"))
        })
        .unwrap()
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|p| ((p[0] as u32) << 8) | p.get(1).copied().unwrap_or(0) as u32)
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
const ID: i64 = 4829017365182049271;

/// Ethernet frame of a UDP datagram from the test client to the server.
fn frame(cfg: &Config, v6: bool, payload: &[u8]) -> Vec<u8> {
    let mut udp = vec![0; 8];
    udp[..2].copy_from_slice(&40000u16.to_be_bytes());
    udp[2..4].copy_from_slice(&cfg.port_be.to_ne_bytes());
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend(payload);
    let mut data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    if v6 {
        data.extend([0x86, 0xdd, 0x60, 0, 0, 0]);
        data.extend((udp.len() as u16).to_be_bytes());
        data.extend([17, 64]);
        data.extend(
            "2001:db8:1::7"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        data.extend(cfg.server_ip6);
        let mut pseudo = data[22..54].to_vec();
        pseudo.extend((udp.len() as u32).to_be_bytes());
        pseudo.extend([0, 0, 0, 17]);
        pseudo.extend(&udp);
        let sum = checksum(&pseudo);
        udp[6..8].copy_from_slice(&if sum == 0 { 0xffff } else { sum }.to_be_bytes());
    } else {
        data.extend([8, 0, 0x45, 0]);
        data.extend(((20 + udp.len()) as u16).to_be_bytes());
        data.extend([0, 0, 0, 0, 64, 17, 0, 0, 198, 51, 100, 7]);
        data.extend(cfg.server_ip_be.to_ne_bytes());
        let c = checksum(&data[14..34]);
        data[24..26].copy_from_slice(&c.to_be_bytes());
    }
    data.extend(udp);
    data
}

fn run(prog: &Xdp, input: &[u8]) -> (u32, Vec<u8>) {
    let mut output = vec![0; 256];
    let result = prog
        .test_run(TestRunOptions {
            data_in: Some(input),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .unwrap();
    output.truncate(result.data_size_out as usize);
    (result.return_value, output)
}

/// Handshake, then a KEEPALIVE that confirms the session, through the
/// pinned dispatcher and its tail-called programs.
fn keepalive(gen_path: &Path, v6: bool) {
    let cfg = Array::<_, Config>::try_from(Map::Array(
        MapData::from_pin(gen_path.join("CONFIG")).unwrap(),
    ))
    .unwrap()
    .get(&0, 0)
    .unwrap();
    let slot = HashMap::<_, i64, u16>::try_from(Map::HashMap(
        MapData::from_pin(gen_path.join("USER_IDS")).unwrap(),
    ))
    .unwrap()
    .get(&ID, 0)
    .unwrap();
    let user = Array::<_, User>::try_from(Map::Array(
        MapData::from_pin(gen_path.join("USERS")).unwrap(),
    ))
    .unwrap()
    .get(&(slot as u32), 0)
    .unwrap();
    let prog = Xdp::from_pin(gen_path.join("program"), XdpAttachType::Interface).unwrap();
    let body = 14 + if v6 { 40 } else { 20 } + 8;
    let (init, k1) = aead::init(&user.key, ID, &[v6 as u8; 16]);
    let (action, output) = run(&prog, &frame(&cfg, v6, &init));
    assert_eq!(action, 3, "RESPONSE");
    let (key, phase) = aead::open_response(&k1, &output[body..]).expect("RESPONSE");
    let mut packet = Header {
        user: ID,
        typ: wire::TYPE_KEEPALIVE,
        phase,
        counter: 1,
    }
    .encode()
    .to_vec();
    packet.extend([0; wire::TAG_LEN]);
    Cipher::new(&key).seal(wire::TO_SERVER, &mut packet);
    let input = frame(&cfg, v6, &packet);
    let (action, mut output) = run(&prog, &input);
    assert_eq!(action, 3, "KEEPALIVE reply");
    assert_eq!(output.len(), input.len());
    if v6 {
        assert_eq!(&output[22..38], &cfg.server_ip6);
    }
    let header = Cipher::new(&key)
        .open(wire::TO_CLIENT, &mut output[body..])
        .expect("reply authenticates");
    assert_eq!(header.typ, wire::TYPE_KEEPALIVE);
    // The same packet again is a replay.
    assert_eq!(run(&prog, &input).0, 1);
}

// The outer process creates disposable mount and network namespaces. Even a
// failed assertion cannot leave links, mounts or interfaces in the host netns.
#[test]
#[ignore = "root + unshare + iproute2 + mount; run scripts/check-server.sh"]
fn isolated_lifecycle() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run this ignored test as root"
    );
    if std::env::var_os("EDUP_TEST_NAMESPACE").is_none() {
        let status = Command::new("unshare")
            .args(["--mount", "--net"])
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "isolated_lifecycle", "--nocapture"])
            .env("EDUP_TEST_NAMESPACE", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    checked("mount", &["--make-rprivate", "/"]);
    checked("mount", &["-t", "sysfs", "sysfs", "/sys"]);
    checked(
        "mount",
        &["-t", "bpf", "-o", "mode=700", "bpf", "/sys/fs/bpf"],
    );
    checked(
        "ip",
        &[
            "link",
            "add",
            "edup-test0",
            "type",
            "veth",
            "peer",
            "name",
            "edup-test1",
        ],
    );
    checked("ip", &["link", "set", "edup-test0", "up"]);
    checked("ip", &["link", "set", "edup-test1", "up"]);

    let temp = std::env::temp_dir().join(format!("edup-test-{}", std::process::id()));
    fs::create_dir(&temp).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(temp.clone());
    let config = temp.join("server.toml");
    let original = format!(
        "server_ip6 = \"2001:db8::1\"\nnat_ip6 = \"2001:db8::1\"\n{}",
        include_str!("../../config/server.example.toml").replace("eth0", "edup-test0")
    );
    fs::write(&config, &original).unwrap();
    server(&config, "check", true);
    server(&config, "up", true);
    let first = generation();
    let link_state = checked("ip", &["-details", "link", "show", "dev", "edup-test0"]);
    assert!(link_state.contains("prog/xdp"), "{link_state}");
    assert!(!link_state.contains("xdpgeneric"), "{link_state}");
    let ids = HashMap::<_, i64, u16>::try_from(Map::HashMap(
        MapData::from_pin(first.join("USER_IDS")).unwrap(),
    ))
    .unwrap();
    assert_eq!(ids.get(&4829017365182049271, 0).unwrap(), 1);
    assert_eq!(ids.get(&-738215604982170351, 0).unwrap(), 2);
    drop(ids);
    keepalive(&first, false);
    assert!(server(&temp.join("missing"), "users", true).contains("198.51.100.7:40000"));
    keepalive(&first, true);
    assert!(server(&temp.join("missing"), "users", true).contains("[2001:db8:1::7]:40000"));
    assert!(server(&temp.join("missing"), "stats", true).contains("keepalive 2"));
    // Repeated up and a second instance may not replace an existing attachment.
    server(&config, "up", false);
    let second = "/sys/fs/bpf/edup-other";
    let out = exec(
        env!("CARGO_BIN_EXE_edup-server"),
        &[
            "--config",
            config.to_str().unwrap(),
            "--pin-path",
            second,
            "up",
        ],
    );
    assert!(!out.status.success());
    assert!(!Path::new(second).exists());
    assert_eq!(generation(), first);

    // Reject config/environment changes before touching active state.
    for bad in [
        original.replace("port = 7777", "port = 20000"),
        original.replace("max_frame = 1500", "max_frame = 1568"),
        original.replace("xdp_mode = \"driver\"", "xdp_mode = \"skb\""),
        original.replace("29999", "40000"),
    ] {
        fs::write(&config, bad).unwrap();
        server(&config, "reload", false);
        assert_eq!(generation(), first);
        assert!(server(&config, "stats", true).contains("keepalive 2"));
    }
    fs::write(&config, &original).unwrap();
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 20001)).unwrap();
    server(&config, "reload", false);
    drop(socket);
    assert_eq!(generation(), first);

    // Seed NAT so a reload checks actual removal, not just different map IDs.
    let forward = NatOutKey {
        user: 1,
        _pad: [0; 2],
        inner_port_be: 1234u16.to_be(),
        proto: 17,
        v6: 0,
    };
    HashMap::<_, NatOutKey, NatOutVal>::try_from(Map::LruHashMap(
        MapData::from_pin(first.join("NAT_OUT")).unwrap(),
    ))
    .unwrap()
    .insert(
        forward,
        NatOutVal {
            pub_port_be: 20000u16.to_be(),
            _pad: 0,
        },
        0,
    )
    .unwrap();
    HashMap::<_, NatInKey, NatInVal>::try_from(Map::LruHashMap(
        MapData::from_pin(first.join("NAT_IN")).unwrap(),
    ))
    .unwrap()
    .insert(
        NatInKey {
            pub_port_be: 20000u16.to_be(),
            proto: 17,
            v6: 0,
        },
        NatInVal {
            user: 1,
            ..Default::default()
        },
        0,
    )
    .unwrap();
    // Reverse the actual user records, retaining each user's password.
    let records: Vec<_> = original.split("[[users]]").collect();
    let revised = format!(
        "{}[[users]]{}[[users]]{}",
        records[0], records[2], records[1]
    )
    .replace("-738215604982170351", "-1234567890123456789")
    .replace("replace-this-password", "new-password")
    .replace("20000", "21000");
    fs::write(&config, revised).unwrap();
    server(&config, "reload", true);
    let active = generation();
    assert_ne!(active, first);
    assert!(!first.exists());
    assert_eq!(
        fs::read_dir(PIN).unwrap().count(),
        2,
        "only link + active generation"
    );
    let users = server(&temp.join("missing"), "users", true);
    assert!(users.contains("4829017365182049271\t2\t-\t-"));
    assert!(users.contains("-1234567890123456789\t1\t"));
    assert!(!users.contains("-738215604982170351\t"));
    assert!(server(&config, "stats", true).contains("keepalive 0"));
    let map = HashMap::<_, NatOutKey, NatOutVal>::try_from(Map::LruHashMap(
        MapData::from_pin(active.join("NAT_OUT")).unwrap(),
    ))
    .unwrap();
    assert_eq!(map.iter().count(), 0);
    drop(map);
    let raw = Array::<_, Config>::try_from(Map::Array(
        MapData::from_pin(active.join("CONFIG")).unwrap(),
    ))
    .unwrap()
    .get(&0, 0)
    .unwrap();
    assert_eq!(raw.nat_port_min, 21000);
    let users_map =
        Array::<_, User>::try_from(Map::Array(MapData::from_pin(active.join("USERS")).unwrap()))
            .unwrap();
    assert_eq!(users_map.get(&42, 0).unwrap().enabled, 0);
    assert_eq!(
        users_map.get(&2, 0).unwrap().key,
        derive_key("new-password")
    );
    drop(users_map);
    keepalive(&active, true);
    assert!(server(&config, "stats", true).contains("keepalive 1"));

    server(&temp.join("missing"), "down", true);
    assert!(!Path::new(PIN).exists());
    server(&temp.join("missing"), "down", true);
    let link_state = checked("ip", &["-details", "link", "show", "dev", "edup-test0"]);
    assert!(!link_state.contains("prog/xdp"), "{link_state}");
    // Explicit generic mode works too and leaves no attachment after down.
    fs::write(
        &config,
        original.replace("xdp_mode = \"driver\"", "xdp_mode = \"skb\""),
    )
    .unwrap();
    server(&config, "up", true);
    keepalive(&generation(), false);
    keepalive(&generation(), true);
    server(&config, "down", true);
    println!(
        "PASS: native/generic attach, pin lifetime, packet/maps, reload/reset, failure preservation, exclusive attach, down/idempotence"
    );
}
