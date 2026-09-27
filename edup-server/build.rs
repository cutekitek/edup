fn main() -> aya_build::Result<()> {
    println!("cargo:rerun-if-changed=../edup-common/src");
    println!("cargo:rerun-if-changed=../edup-common/Cargo.toml");
    println!("cargo:rerun-if-changed=../Cargo.toml");
    println!("cargo:rerun-if-changed=../Cargo.lock");
    println!("cargo:rerun-if-changed=../.cargo/config.toml");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        aya_build::build_ebpf(
            [aya_build::Package {
                name: "edup-ebpf",
                root_dir: "../edup-ebpf",
                no_default_features: true,
                ..Default::default()
            }],
            aya_build::Toolchain::Custom("nightly-2026-09-26"),
        )?;
    }
    Ok(())
}
