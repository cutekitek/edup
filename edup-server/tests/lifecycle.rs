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
    key::derive_key,
    maps::{Config, NatInKey, NatInVal, NatOutKey, NatOutVal, User},
    wire,
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
fn keepalive(gen_path: &Path) {
    let prog = Xdp::from_pin(gen_path.join("program"), XdpAttachType::Interface).unwrap();
    let mut data = [0u8; 50];
    data[..14].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0]);
    data[14] = 0x45;
    data[16..18].copy_from_slice(&36u16.to_be_bytes());
    data[22] = 64;
    data[23] = 17;
    data[26..30].copy_from_slice(&[198, 51, 100, 7]);
    data[30..34].copy_from_slice(&[192, 0, 2, 1]);
    let c = checksum(&data[14..34]);
    data[24..26].copy_from_slice(&c.to_be_bytes());
    data[34..36].copy_from_slice(&40000u16.to_be_bytes());
    data[36..38].copy_from_slice(&7777u16.to_be_bytes());
    data[38..40].copy_from_slice(&16u16.to_be_bytes());
    wire::seal(
        &derive_key("replace-this-password"),
        42,
        wire::TYPE_KEEPALIVE,
        7,
        &mut data[42..],
    );
    let mut output = [0; 128];
    let result = prog
        .test_run(TestRunOptions {
            data_in: Some(&data),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(result.return_value, 3);
    assert_eq!(result.data_size_out, 60);
}

fn keepalive6(gen_path: &Path) {
    let cfg = Array::<_, Config>::try_from(Map::Array(
        MapData::from_pin(gen_path.join("CONFIG")).unwrap(),
    ))
    .unwrap()
    .get(&0, 0)
    .unwrap();
    let prog = Xdp::from_pin(gen_path.join("program"), XdpAttachType::Interface).unwrap();
    let mut data = [0u8; 70];
    data[..14].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd]);
    let ip = &mut data[14..];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&16u16.to_be_bytes());
    ip[6] = 17;
    ip[7] = 64;
    ip[8..24].copy_from_slice(
        &"2001:db8:1::7"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    ip[24..40].copy_from_slice(&cfg.server_ip6);
    ip[40..42].copy_from_slice(&40000u16.to_be_bytes());
    ip[42..44].copy_from_slice(&cfg.port_be.to_ne_bytes());
    ip[44..46].copy_from_slice(&16u16.to_be_bytes());
    wire::seal(
        &wire::Key {
            k0: cfg.key0,
            k1: cfg.key1,
        },
        42,
        wire::TYPE_KEEPALIVE,
        7,
        &mut ip[48..],
    );
    let mut pseudo = ip[8..40].to_vec();
    pseudo.extend([0, 0, 0, 16, 0, 0, 0, 17]);
    pseudo.extend(&ip[40..]);
    let sum = checksum(&pseudo);
    ip[46..48].copy_from_slice(&if sum == 0 { 0xffff } else { sum }.to_be_bytes());
    let mut output = [0; 128];
    let result = prog
        .test_run(TestRunOptions {
            data_in: Some(&data),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(result.return_value, 3);
    assert_eq!(result.data_size_out, 70);
    assert_eq!(&output[22..38], &cfg.server_ip6);
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
        "{}\nserver_ip6 = \"2001:db8::1\"\nnat_ip6 = \"2001:db8::1\"\ntunnel_net6 = \"fd66::/112\"\n",
        include_str!("../../config/server.example.toml").replace("eth0", "edup-test0")
    );
    fs::write(&config, &original).unwrap();
    server(&config, "check", true);
    server(&config, "up", true);
    let first = generation();
    let link_state = checked("ip", &["-details", "link", "show", "dev", "edup-test0"]);
    assert!(link_state.contains("prog/xdp"), "{link_state}");
    assert!(!link_state.contains("xdpgeneric"), "{link_state}");
    keepalive(&first);
    assert!(server(&temp.join("missing"), "users", true).contains("198.51.100.7:40000"));
    keepalive6(&first);
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
        inner_ip_be: u32::from_ne_bytes([10, 66, 0, 7]),
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
            inner_ip_be: forward.inner_ip_be,
            user: 7,
            ..Default::default()
        },
        0,
    )
    .unwrap();
    let revised = original
        .replace("10.66.0.0", "10.67.0.0")
        .replace("users = [7, 42]", "users = [7, 99]")
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
    assert!(users.contains("7\t10.67.0.7\t-\t-"));
    assert!(users.contains("99\t10.67.0.99"));
    assert!(!users.contains("42\t"));
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
    assert_eq!(raw.key0, derive_key("new-password").k0);
    let users_map =
        Array::<_, User>::try_from(Map::Array(MapData::from_pin(active.join("USERS")).unwrap()))
            .unwrap();
    assert_eq!(users_map.get(&42, 0).unwrap().enabled, 0);
    drop(users_map);
    keepalive6(&active);
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
    keepalive(&generation());
    keepalive6(&generation());
    server(&config, "down", true);
    println!(
        "PASS: native/generic attach, pin lifetime, packet/maps, reload/reset, failure preservation, exclusive attach, down/idempotence"
    );
}
