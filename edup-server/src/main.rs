mod config;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod sys;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "One-shot edup XDP loader (Linux)")]
struct Cli {
    #[arg(short, long, global = true, default_value = "/etc/edup/server.toml")]
    config: PathBuf,
    #[arg(long, global = true, default_value = "/sys/fs/bpf/edup")]
    pin_path: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate the TOML without requiring root or touching the network.
    Check,
    /// Load, configure, attach and pin; exit with no daemon left running.
    Up,
    /// Unpin and detach this instance. Safe to repeat.
    Down,
    /// Atomically replace the program/maps. Resets NAT, endpoints and statistics.
    Reload,
    /// Print summed per-CPU counters from the running instance.
    Stats,
    /// Print enabled users and their learned endpoints.
    Users,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if matches!(cli.command, Command::Check) {
        let cfg = config::Settings::load(&cli.config)?;
        println!(
            "Configuration valid: interface={}, mode={}, users={}, tunnel MTU={}",
            cfg.interface,
            cfg.xdp_mode.name(),
            cfg.users.len(),
            cfg.max_frame as usize - edup_common::wire::OVERHEAD_V4
        );
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        linux::run(cli)
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!(
            "edup-server requires Linux; use `check` to validate a configuration on this platform"
        )
    }
}
