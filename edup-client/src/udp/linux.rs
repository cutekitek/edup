use super::{control::Control, invalid};
use std::{io, mem, net::UdpSocket, os::fd::AsRawFd, ptr};

pub struct State {
    rx: bool,
}
impl State {
    pub fn rx_enabled(&self) -> bool {
        self.rx
    }
}

pub fn unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EINVAL | libc::ENOPROTOOPT | libc::EOPNOTSUPP | libc::EIO | libc::EMSGSIZE)
    )
}
pub fn configure(socket: &UdpSocket, enabled: bool) -> io::Result<(State, bool)> {
    if !enabled {
        return Ok((State { rx: false }, false));
    }
    let mut value: libc::c_int = 0;
    let mut len = mem::size_of_val(&value) as libc::socklen_t;
    // Probe support without changing the per-socket segmentation size; KEEPALIVE
    // is sent concurrently and must never inherit another thread's segment size.
    let tx = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_UDP,
            libc::UDP_SEGMENT,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        )
    } == 0;
    value = 1;
    let rx = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_UDP,
            libc::UDP_GRO,
            (&value as *const libc::c_int).cast(),
            mem::size_of_val(&value) as _,
        )
    } == 0;
    if !rx {
        let e = io::Error::last_os_error();
        if !unsupported(&e) {
            return Err(e);
        }
        eprintln!("UDP GRO unavailable: {e}");
    }
    Ok((State { rx }, tx))
}
pub fn send_segmented(socket: &UdpSocket, data: &[u8], segment: u16) -> io::Result<usize> {
    let mut control = Control::new();
    let len = control.encode(libc::IPPROTO_UDP, libc::UDP_SEGMENT, &segment.to_ne_bytes());
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = len;
    // SAFETY: all msg pointers refer to live buffers for this synchronous call.
    let n = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, 0) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}
pub fn recv(
    socket: &UdpSocket,
    _state: &State,
    buf: &mut [u8],
) -> io::Result<(usize, Option<usize>)> {
    let mut control = Control::new();
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = ptr::null_mut();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.capacity();
    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(invalid("truncated UDP payload or control data"));
    }
    Ok((
        n as usize,
        control.segment(msg.msg_controllen, libc::IPPROTO_UDP, libc::UDP_GRO)?,
    ))
}
