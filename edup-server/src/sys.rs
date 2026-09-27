//! Small Linux UAPI wrappers for strict BPF-link-only attachment.
//! Aya's Xdp::attach can fall back to a legacy netlink attachment, which cannot
//! be pinned and may replace an existing program. The loader must never do that.
use anyhow::{Context, Result};
use std::{
    ffi::CString,
    io,
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
};

fn bpf<T>(command: u32, attr: &T) -> io::Result<libc::c_long> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command,
            attr as *const T,
            std::mem::size_of::<T>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub fn attach(prog: impl AsFd, ifindex: u32, flags: u32) -> Result<OwnedFd> {
    // linux/bpf.h: BPF_LINK_CREATE=28, attach_type BPF_XDP=37.
    #[repr(C)]
    struct Attr {
        prog_fd: u32,
        target_ifindex: u32,
        attach_type: u32,
        flags: u32,
    }
    let attr = Attr {
        prog_fd: prog.as_fd().as_raw_fd() as u32,
        target_ifindex: ifindex,
        attach_type: 37,
        flags,
    };
    let fd = bpf(28, &attr).context("BPF_LINK_CREATE failed: require a free XDP slot and kernel/driver support for a pinnable link (no fallback or replacement)")?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

pub fn pin(fd: &OwnedFd, path: &Path) -> Result<()> {
    #[repr(C)]
    struct Attr {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
    }
    let path = CString::new(path.as_os_str().as_bytes())?;
    let attr = Attr {
        pathname: path.as_ptr() as u64,
        bpf_fd: fd.as_raw_fd() as u32,
        file_flags: 0,
    };
    bpf(6, &attr).context("pin XDP link")?;
    Ok(())
}

pub fn bpffs(path: &Path) -> Result<bool> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { stat.assume_init() }.f_type == 0xcafe4a11)
}

pub fn monotonic_ns() -> Result<u64> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let time = unsafe { time.assume_init() };
    Ok(time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
}
