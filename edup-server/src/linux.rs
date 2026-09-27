use crate::{
    Cli, Command,
    config::{Mode, Settings},
    sys,
};
use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    maps::{Array, Map, MapData, PerCpuArray},
    programs::{
        Xdp,
        links::{FdLink, LinkType, PinnedLink},
    },
};
use edup_common::maps::{Config, MAX_USERS, User, stat};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io,
    net::Ipv4Addr,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

const MAPS: [&str; 5] = ["CONFIG", "USERS", "NAT_OUT", "NAT_IN", "STATS"];
const OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/edup-ebpf"));

pub fn run(cli: Cli) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "run as root to manage/read pinned BPF objects"
    );
    // All loader instances serialize mutations and snapshots. Never unlink the
    // lock file: a replacement inode would let two processes enter at once.
    let _lock = lock()?;
    validate_path(&cli.pin_path)?;
    match cli.command {
        Command::Up | Command::Reload => {
            let cfg = Settings::load(&cli.config)?;
            let ifindex = environment(&cfg)?;
            ensure!(
                sys::bpffs(cli.pin_path.parent().context("pin path needs a parent")?)?,
                "pin parent is not bpffs; mount it first (mount -t bpf bpf /sys/fs/bpf)"
            );
            if matches!(cli.command, Command::Up) {
                up(&cli.pin_path, &cfg, ifindex)
            } else {
                reload(&cli.pin_path, &cfg, ifindex)
            }
        }
        Command::Down => down(&cli.pin_path),
        Command::Stats => stats(&cli.pin_path),
        Command::Users => users(&cli.pin_path),
        Command::Check => unreachable!(),
    }
}

fn lock() -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run/edup-loader.lock")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "unsafe loader lock file"
    );
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(file)
}

fn validate_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.file_name().is_some(),
        "pin path must be an absolute instance directory"
    );
    let mut current = PathBuf::new();
    for part in path.components() {
        ensure!(
            matches!(part, Component::RootDir | Component::Normal(_)),
            "pin path must not contain . or .."
        );
        current.push(part.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) => ensure!(
                meta.is_dir()
                    && !meta.file_type().is_symlink()
                    && meta.uid() == 0
                    && meta.mode() & 0o022 == 0,
                "unsafe pin directory {}",
                current.display()
            ),
            Err(e) if e.kind() == io::ErrorKind::NotFound && current == path => {}
            Err(e) => return Err(e).with_context(|| format!("inspect {}", current.display())),
        }
    }
    Ok(())
}

fn environment(cfg: &Settings) -> Result<u32> {
    let name = CString::new(cfg.interface.as_str())?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    ensure!(index != 0, "interface {} does not exist", cfg.interface);
    let base = Path::new("/sys/class/net").join(&cfg.interface);
    let kind: u32 = fs::read_to_string(base.join("type"))?.trim().parse()?;
    ensure!(kind == 1, "interface must use Ethernet framing");
    let mtu: u16 = fs::read_to_string(base.join("mtu"))?.trim().parse()?;
    ensure!(
        cfg.max_frame <= mtu,
        "max_frame {} exceeds interface MTU {mtu}",
        cfg.max_frame
    );
    cfg.check_local_ports(&fs::read_to_string(
        "/proc/sys/net/ipv4/ip_local_port_range",
    )?)?;
    // Check explicit host bindings too; an ephemeral-range check cannot detect
    // daemons listening on statically configured NAT ports.
    for table in ["tcp", "tcp6", "udp", "udp6"] {
        let text = fs::read_to_string(format!("/proc/net/{table}"))?;
        for line in text.lines().skip(1) {
            let local = line
                .split_whitespace()
                .nth(1)
                .context("invalid /proc/net socket table")?;
            let port = u16::from_str_radix(
                local.rsplit_once(':').context("invalid socket endpoint")?.1,
                16,
            )?;
            ensure!(
                !(cfg.nat_port_min..=cfg.nat_port_max).contains(&port) && port != cfg.port,
                "host {table} socket occupies reserved port {port}"
            );
        }
    }
    Ok(index)
}

#[derive(Debug)]
struct Generation {
    path: PathBuf,
    program: u32,
    ifindex: u32,
    mode: Mode,
}

impl Generation {
    fn parse(path: PathBuf) -> Option<Self> {
        let parts: Vec<_> = path.file_name()?.to_str()?.split('_').collect();
        if parts.len() != 4 || parts[0] != "gen" {
            return None;
        }
        let program = parts[1].parse().ok()?;
        let ifindex = parts[2].parse().ok()?;
        let mode = match parts[3] {
            "driver" => Mode::Driver,
            "skb" => Mode::Skb,
            _ => return None,
        };
        if program == 0 || ifindex == 0 {
            return None;
        }
        Some(Self {
            path,
            program,
            ifindex,
            mode,
        })
    }
}

fn generations(root: &Path) -> Result<Vec<Generation>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_name() == "link" && entry.file_type()?.is_file() {
            continue;
        }
        let generation = Generation::parse(entry.path())
            .context("unrecognized entry in pin directory; refusing automatic removal")?;
        ensure!(entry.file_type()?.is_dir(), "generation is not a directory");
        // Check before any removal, so down doesn't erase arbitrary files.
        for file in fs::read_dir(&generation.path)? {
            let file = file?;
            let name = file.file_name();
            ensure!(
                file.file_type()?.is_file()
                    && (name == "program" || MAPS.iter().any(|m| name == *m)),
                "unrecognized entry in generation directory"
            );
        }
        result.push(generation);
    }
    Ok(result)
}

fn live(root: &Path) -> Result<(Generation, FdLink)> {
    ensure!(
        root.exists() && sys::bpffs(root)?,
        "instance is not running in bpffs"
    );
    let link = FdLink::from(
        PinnedLink::from_pin(root.join("link")).context("open pinned XDP link; run up first")?,
    );
    let info = link.info()?;
    ensure!(info.link_type()? == LinkType::Xdp, "pinned link is not XDP");
    let matches: Vec<_> = generations(root)?
        .into_iter()
        .filter(|g| g.program == info.program_id())
        .collect();
    ensure!(
        matches.len() == 1,
        "active link has no unique pinned generation; use down/up to recover"
    );
    Ok((matches.into_iter().next().unwrap(), link))
}

fn load(cfg: &Settings) -> Result<Ebpf> {
    let mut bpf = Ebpf::load(OBJECT).context("load embedded eBPF object")?;
    Array::<_, Config>::try_from(bpf.map_mut("CONFIG").context("missing CONFIG")?)?.set(
        0,
        cfg.map_config()?,
        0,
    )?;
    let mut users = Array::<_, User>::try_from(bpf.map_mut("USERS").context("missing USERS")?)?;
    for &id in &cfg.users {
        users.set(
            id as u32,
            User {
                enabled: 1,
                ..Default::default()
            },
            0,
        )?;
    }
    let prog: &mut Xdp = bpf
        .program_mut("edup")
        .context("missing edup program")?
        .try_into()?;
    prog.load().context("kernel rejected XDP program")?;
    Ok(bpf)
}

// A failed preparation only removes this newly created generation. The active
// pinned link is the commit point and remains the single source of truth.
struct Staging {
    path: PathBuf,
    committed: bool,
}
impl Drop for Staging {
    fn drop(&mut self) {
        if !self.committed
            && let Err(err) = remove_generation(&self.path)
        {
            eprintln!(
                "failed to clean staged generation {}: {err:#}",
                self.path.display()
            );
        }
    }
}

fn prepare(root: &Path, bpf: &mut Ebpf, ifindex: u32, mode: Mode) -> Result<Staging> {
    let prog: &mut Xdp = bpf.program_mut("edup").unwrap().try_into()?;
    let id = prog.info()?.id();
    let path = root.join(format!("gen_{id}_{ifindex}_{}", mode.name()));
    fs::DirBuilder::new().mode(0o700).create(&path)?;
    let stage = Staging {
        path,
        committed: false,
    };
    prog.pin(stage.path.join("program"))?;
    for name in MAPS {
        bpf.map(name)
            .with_context(|| format!("missing {name}"))?
            .pin(stage.path.join(name))?;
    }
    Ok(stage)
}

fn up(root: &Path, cfg: &Settings, ifindex: u32) -> Result<()> {
    // create_dir (not create_dir_all) claims the instance without clobbering pins.
    fs::DirBuilder::new().mode(0o700).create(root).context("instance directory already exists or cannot be created; use reload, or down to remove stale pins")?;
    let result = (|| {
        let mut bpf = load(cfg)?;
        let mut stage = prepare(root, &mut bpf, ifindex, cfg.xdp_mode)?;
        let prog: &Xdp = bpf.program("edup").unwrap().try_into()?;
        let fd = sys::attach(prog.fd()?, ifindex, cfg.xdp_mode.flags())?;
        sys::pin(&fd, &root.join("link"))?;
        stage.committed = true;
        println!(
            "edup up: {} ({}), {} users; pinned at {}",
            cfg.interface,
            cfg.xdp_mode.name(),
            cfg.users.len(),
            root.display()
        );
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir(root);
    }
    result
}

fn reload(root: &Path, cfg: &Settings, ifindex: u32) -> Result<()> {
    let (old, link) = live(root)?;
    ensure!(
        old.ifindex == ifindex && old.mode == cfg.xdp_mode,
        "changing interface or XDP mode requires down/up"
    );
    let mut bpf = load(cfg)?;
    let mut stage = prepare(root, &mut bpf, ifindex, cfg.xdp_mode)?;
    let prog: &mut Xdp = bpf.program_mut("edup").unwrap().try_into()?;
    prog.attach_to_link(link.try_into()?)
        .context("atomic XDP link update failed; previous generation remains active")?;
    // No fallible operations between link update and marking the generation live.
    stage.committed = true;
    match generations(root) {
        Ok(old_generations) => {
            for generation in old_generations {
                if generation.path != stage.path
                    && let Err(error) = remove_generation(&generation.path)
                {
                    eprintln!("reload succeeded; stale generation cleanup failed: {error:#}");
                }
            }
        }
        Err(error) => {
            eprintln!("reload succeeded; could not enumerate stale generations: {error:#}")
        }
    }
    println!("edup reloaded atomically; NAT, endpoints and counters reset");
    Ok(())
}

fn remove_generation(path: &Path) -> Result<()> {
    for name in MAPS.into_iter().chain(["program"]) {
        match fs::remove_file(path.join(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    fs::remove_dir(path)?;
    Ok(())
}

fn down(root: &Path) -> Result<()> {
    if !root.exists() {
        println!("edup already down");
        return Ok(());
    }
    ensure!(sys::bpffs(root)?, "refusing cleanup outside bpffs");
    let old = generations(root)?;
    if root.join("link").exists() {
        drop(PinnedLink::from_pin(root.join("link"))?.unpin()?);
    }
    for generation in old {
        remove_generation(&generation.path)?;
    }
    fs::remove_dir(root)?;
    println!("edup down; link and maps unpinned");
    Ok(())
}

fn pinned_array<T: aya::Pod>(path: &Path) -> Result<Array<MapData, T>> {
    let data = MapData::from_pin(path)?;
    ensure!(
        data.info()?.map_type()? == aya::maps::MapType::Array,
        "unexpected pinned map type"
    );
    Ok(Array::try_from(Map::Array(data))?)
}

fn stats(root: &Path) -> Result<()> {
    let (active, _link) = live(root)?;
    let data = MapData::from_pin(active.path.join("STATS"))?;
    ensure!(
        data.info()?.map_type()? == aya::maps::MapType::PerCpuArray,
        "unexpected STATS map type"
    );
    let counters = PerCpuArray::<_, u64>::try_from(Map::PerCpuArray(data))?;
    ensure!(counters.len() == stat::COUNT, "incompatible STATS ABI");
    for (index, name) in stat::NAMES.iter().enumerate() {
        let sum: u128 = counters
            .get(&(index as u32), 0)?
            .iter()
            .map(|&v| v as u128)
            .sum();
        println!("{name} {sum}");
    }
    Ok(())
}

fn users(root: &Path) -> Result<()> {
    let (active, _link) = live(root)?;
    let config = pinned_array::<Config>(&active.path.join("CONFIG"))?.get(&0, 0)?;
    let users = pinned_array::<User>(&active.path.join("USERS"))?;
    ensure!(users.len() == MAX_USERS, "incompatible USERS ABI");
    let now = sys::monotonic_ns()?;
    println!("ID\tTUNNEL_IP\tENDPOINT\tLAST_SEEN_SECONDS_AGO");
    for id in 0..MAX_USERS {
        let user = users.get(&id, 0)?;
        if user.enabled == 0 {
            continue;
        }
        let ip = Ipv4Addr::from(config.tun_net + id);
        if user.endpoint == 0 {
            println!("{id}\t{ip}\t-\t-");
        } else {
            let endpoint = Ipv4Addr::from(User::endpoint_ip_be(user.endpoint).to_ne_bytes());
            let port = u16::from_be(User::endpoint_port_be(user.endpoint));
            println!(
                "{id}\t{ip}\t{endpoint}:{port}\t{}",
                now.saturating_sub(user.last_seen_ns) / 1_000_000_000
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generation_names_are_strict() {
        let generation = Generation::parse("/pins/gen_12_3_driver".into()).unwrap();
        assert_eq!(generation.program, 12);
        assert_eq!(generation.ifindex, 3);
        for name in [
            "gen_0_3_driver",
            "gen_12_0_driver",
            "gen_12_3_driver_extra",
            "other",
            "gen_12_3_auto",
        ] {
            assert!(Generation::parse(name.into()).is_none());
        }
    }
}
