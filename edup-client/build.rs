fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../edup-common/src");
    println!("cargo:rerun-if-changed=../edup-common/Cargo.toml");
    println!("cargo:rerun-if-changed=../Cargo.toml");
    println!("cargo:rerun-if-changed=../Cargo.lock");
    println!("cargo:rerun-if-changed=../.cargo/config.toml");
    // XDP mode embeds its eBPF object; the default build needs no BPF toolchain.
    #[cfg(feature = "xdp")]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        aya_build::build_ebpf(
            [aya_build::Package {
                name: "edup-ebpf-client",
                root_dir: "../edup-ebpf-client",
                no_default_features: true,
                ..Default::default()
            }],
            aya_build::Toolchain::Custom("nightly-2026-09-26"),
        )?;
    }
    Ok(())
}
