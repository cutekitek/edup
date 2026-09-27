use super::{RECEIVE_CAPACITY, control::Control, invalid};
use std::{io, mem, net::UdpSocket, os::windows::io::AsRawSocket, ptr};
use windows_sys::Win32::Networking::WinSock::*;

pub struct State {
    recv: LPFN_WSARECVMSG,
    rx: bool,
}
impl State {
    pub fn rx_enabled(&self) -> bool {
        self.rx
    }
}
fn error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}
pub fn unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(WSAEINVAL | WSAENOPROTOOPT | WSAEOPNOTSUPP | WSAEMSGSIZE)
    )
}
pub fn configure(socket: &UdpSocket, enabled: bool) -> io::Result<(State, bool)> {
    let raw = socket.as_raw_socket() as SOCKET;
    let mut recv: LPFN_WSARECVMSG = None;
    let mut bytes = 0;
    // Retrieve the extension for this socket provider. URO is enabled only if
    // we can read ancillary data, otherwise boundaries would be lost.
    let rc = unsafe {
        WSAIoctl(
            raw,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            (&WSAID_WSARECVMSG as *const windows_sys::core::GUID).cast(),
            mem::size_of_val(&WSAID_WSARECVMSG) as _,
            (&mut recv as *mut LPFN_WSARECVMSG).cast(),
            mem::size_of_val(&recv) as _,
            &mut bytes,
            ptr::null_mut(),
            None,
        )
    };
    if rc != 0 {
        recv = None;
    }
    if !enabled {
        return Ok((State { recv, rx: false }, false));
    }
    let mut value: u32 = 0;
    let mut len = mem::size_of_val(&value) as i32;
    let tx = unsafe {
        getsockopt(
            raw,
            IPPROTO_UDP,
            UDP_SEND_MSG_SIZE,
            (&mut value as *mut u32).cast(),
            &mut len,
        )
    } == 0;
    value = RECEIVE_CAPACITY as u32;
    let rx = recv.is_some()
        && unsafe {
            setsockopt(
                raw,
                IPPROTO_UDP,
                UDP_RECV_MAX_COALESCED_SIZE,
                (&value as *const u32).cast(),
                mem::size_of_val(&value) as _,
            )
        } == 0;
    if recv.is_some() && !rx {
        let e = error();
        if !unsupported(&e) {
            return Err(e);
        }
        eprintln!("UDP URO unavailable: {e}");
    }
    Ok((State { recv, rx }, tx))
}
pub fn send_segmented(socket: &UdpSocket, data: &[u8], segment: u16) -> io::Result<usize> {
    let mut control = Control::new();
    let len = control.encode(
        IPPROTO_UDP,
        UDP_SEND_MSG_SIZE,
        &u32::from(segment).to_ne_bytes(),
    );
    let mut buffer = WSABUF {
        len: data.len() as u32,
        buf: data.as_ptr().cast_mut(),
    };
    let msg = WSAMSG {
        lpBuffers: &mut buffer,
        dwBufferCount: 1,
        Control: WSABUF {
            len: len as u32,
            buf: control.as_mut_ptr(),
        },
        ..Default::default()
    };
    let mut sent = 0;
    // Per-message cmsg avoids races with ordinary KEEPALIVE sends.
    let rc = unsafe {
        WSASendMsg(
            socket.as_raw_socket() as SOCKET,
            &msg,
            0,
            &mut sent,
            ptr::null_mut(),
            None,
        )
    };
    if rc != 0 {
        Err(error())
    } else {
        Ok(sent as usize)
    }
}
pub fn recv(
    socket: &UdpSocket,
    state: &State,
    buf: &mut [u8],
) -> io::Result<(usize, Option<usize>)> {
    let Some(recv) = state.recv else {
        return socket.recv(buf).map(|n| (n, None)).map_err(|e| {
            if e.raw_os_error() == Some(WSAEMSGSIZE) {
                invalid("truncated UDP payload")
            } else {
                e
            }
        });
    };
    let mut control = Control::new();
    let mut buffer = WSABUF {
        len: buf.len() as u32,
        buf: buf.as_mut_ptr(),
    };
    let mut msg = WSAMSG {
        lpBuffers: &mut buffer,
        dwBufferCount: 1,
        Control: WSABUF {
            len: control.capacity() as u32,
            buf: control.as_mut_ptr(),
        },
        ..Default::default()
    };
    let mut received = 0;
    let rc = unsafe {
        recv(
            socket.as_raw_socket() as SOCKET,
            &mut msg,
            &mut received,
            ptr::null_mut(),
            None,
        )
    };
    if rc != 0 {
        let e = error();
        return Err(if e.raw_os_error() == Some(WSAEMSGSIZE) {
            invalid("truncated UDP message")
        } else {
            e
        });
    }
    if msg.dwFlags & (MSG_TRUNC | MSG_CTRUNC) != 0 {
        return Err(invalid("truncated UDP payload or control data"));
    }
    Ok((
        received as usize,
        control.segment(
            msg.Control.len as usize,
            IPPROTO_UDP,
            UDP_COALESCED_INFO as i32,
        )?,
    ))
}
