//! DNS forwarder for domain rules. Addresses in answers for matched names get
//! host routes before the answer reaches the application, so its first
//! connection already takes the rule's route.
use crate::{config::Action, routes::Routes, routing::Rules};
use anyhow::{Context, Result, bail};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    thread::{self, Scope},
    time::{Duration, Instant},
};

const UDP_WORKERS: usize = 8;
const POLL: Duration = Duration::from_millis(200);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const TCP_IDLE: Duration = Duration::from_secs(10);

pub struct Listener {
    udp: UdpSocket,
    tcp: TcpListener,
}
impl Listener {
    /// Binds port 53 on the tunnel address. Windows may need a moment before
    /// a new adapter address becomes usable.
    pub fn bind(address: IpAddr) -> Result<Self> {
        let at = SocketAddr::new(address, 53);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match UdpSocket::bind(at).and_then(|udp| Ok((udp, TcpListener::bind(at)?))) {
                Ok((udp, tcp)) => {
                    udp.set_read_timeout(Some(POLL))?;
                    tcp.set_nonblocking(true)?;
                    return Ok(Self { udp, tcp });
                }
                Err(e)
                    if e.kind() == io::ErrorKind::AddrNotAvailable && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(e).with_context(|| format!("bind DNS forwarder on {at}")),
            }
        }
    }
}

/// Where answers send their addresses: system host routes in TUN mode, the
/// eBPF route cache in XDP mode.
pub trait HostRoutes: Sync {
    fn host(&self, ip: IpAddr, action: Action) -> Result<()>;
}
impl HostRoutes for Mutex<Routes> {
    fn host(&self, ip: IpAddr, action: Action) -> Result<()> {
        self.lock()
            .unwrap_or_else(|e| e.into_inner())
            .host(ip, action)
    }
}

pub struct Forwarder<'a> {
    rules: &'a Rules,
    routes: &'a dyn HostRoutes,
    upstreams: Vec<SocketAddr>,
    pub queries: AtomicU64,
    pub failures: AtomicU64,
}
impl<'a> Forwarder<'a> {
    pub fn new(rules: &'a Rules, routes: &'a dyn HostRoutes, upstreams: Vec<SocketAddr>) -> Self {
        Self {
            rules,
            routes,
            upstreams,
            queries: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        }
    }

    pub fn spawn<'scope, 'env>(
        &'env self,
        scope: &'scope Scope<'scope, 'env>,
        listener: &'env Listener,
        stop: &'env AtomicBool,
    ) {
        for _ in 0..UDP_WORKERS {
            scope.spawn(move || self.udp(&listener.udp, stop));
        }
        scope.spawn(move || self.tcp(scope, &listener.tcp, stop));
    }

    fn udp(&self, socket: &UdpSocket, stop: &AtomicBool) {
        let mut buf = vec![0; 65535];
        while !stop.load(Relaxed) {
            // Timeouts, and on Windows resets reported for earlier replies.
            let Ok((len, from)) = socket.recv_from(&mut buf) else {
                continue;
            };
            if let Some(reply) = self.answer(&buf[..len], false) {
                let _ = socket.send_to(&reply, from);
            }
        }
    }

    fn tcp<'scope, 'env>(
        &'env self,
        scope: &'scope Scope<'scope, 'env>,
        listener: &'env TcpListener,
        stop: &'env AtomicBool,
    ) {
        while !stop.load(Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    scope.spawn(move || {
                        let _ = self.connection(stream, stop);
                    });
                }
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    fn connection(&self, mut stream: TcpStream, stop: &AtomicBool) -> io::Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(POLL))?;
        loop {
            let mut len = [0; 2];
            if !read_full(&mut stream, &mut len, stop)? {
                return Ok(());
            }
            let mut query = vec![0; u16::from_be_bytes(len).into()];
            if !read_full(&mut stream, &mut query, stop)? {
                return Ok(());
            }
            let Some(reply) = self.answer(&query, true) else {
                return Ok(());
            };
            stream.write_all(&framed(&reply))?;
        }
    }

    /// Forwards one query; None drops a malformed one.
    fn answer(&self, query: &[u8], tcp: bool) -> Option<Vec<u8>> {
        let question = question(query)?;
        self.queries.fetch_add(1, Relaxed);
        let response = self.upstreams.iter().find_map(|&upstream| {
            let response = if tcp {
                exchange_tcp(upstream, query)
            } else {
                exchange_udp(upstream, query)
            };
            response.ok().filter(|r| is_response(r, question.id))
        });
        let Some(response) = response else {
            self.failures.fetch_add(1, Relaxed);
            return Some(servfail(query, &question));
        };
        for ip in addresses(&response).unwrap_or_default() {
            if let Some(action) = self.rules.host_action(&question.name, ip)
                && let Err(error) = self.routes.host(ip, action)
            {
                eprintln!("DNS route for {} ({ip}): {error:#}", question.name);
            }
        }
        Some(response)
    }
}

/// Fills `buf`; Ok(false) at a clean end of stream, idle timeout or shutdown.
fn read_full(stream: &mut TcpStream, buf: &mut [u8], stop: &AtomicBool) -> io::Result<bool> {
    let mut filled = 0;
    let idle = Instant::now() + TCP_IDLE;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if stop.load(Relaxed) || Instant::now() > idle {
                    return Ok(false);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn framed(message: &[u8]) -> Vec<u8> {
    let mut out = (message.len() as u16).to_be_bytes().to_vec();
    out.extend(message);
    out
}

fn exchange_udp(upstream: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let local: IpAddr = if upstream.is_ipv6() {
        Ipv6Addr::UNSPECIFIED.into()
    } else {
        Ipv4Addr::UNSPECIFIED.into()
    };
    let socket = UdpSocket::bind((local, 0))?;
    socket.connect(upstream)?;
    socket.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    socket.send(query)?;
    let mut buf = vec![0; 65535];
    let deadline = Instant::now() + UPSTREAM_TIMEOUT;
    while Instant::now() < deadline {
        let len = socket.recv(&mut buf)?;
        // Ignore stray datagrams with another ID.
        if buf[..len].get(..2) == query.get(..2) {
            buf.truncate(len);
            return Ok(buf);
        }
    }
    bail!("DNS timeout")
}

fn exchange_tcp(upstream: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&upstream, UPSTREAM_TIMEOUT)?;
    stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    stream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
    stream.write_all(&framed(query))?;
    let mut len = [0; 2];
    stream.read_exact(&mut len)?;
    let mut response = vec![0; u16::from_be_bytes(len).into()];
    stream.read_exact(&mut response)?;
    Ok(response)
}

fn u16_at(m: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(m.get(i..i + 2)?.try_into().ok()?))
}

/// A possibly compressed name, normalized, and the offset after it.
fn name(m: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let (mut out, mut end, mut jumps) = (String::new(), None, 0);
    loop {
        let len = *m.get(pos)? as usize;
        match len {
            0 => return Some((out, end.unwrap_or(pos + 1))),
            _ if len & 0xc0 == 0xc0 => {
                end.get_or_insert(pos + 2);
                jumps += 1;
                if jumps > 32 {
                    return None;
                }
                pos = (u16_at(m, pos)? & 0x3fff) as usize;
            }
            _ if len < 64 => {
                let label = m.get(pos + 1..pos + 1 + len)?;
                if !out.is_empty() {
                    out.push('.');
                }
                out.extend(label.iter().map(|b| b.to_ascii_lowercase() as char));
                if out.len() > 255 {
                    return None;
                }
                pos += 1 + len;
            }
            _ => return None,
        }
    }
}

struct Question {
    id: u16,
    name: String,
    end: usize,
}
fn question(m: &[u8]) -> Option<Question> {
    // A standard query (QR=0, opcode 0) with one question.
    if m.len() < 12 || m[2] & 0xf8 != 0 || u16_at(m, 4)? != 1 {
        return None;
    }
    let (name, pos) = name(m, 12)?;
    (m.len() >= pos + 4).then(|| Question {
        id: u16_at(m, 0).unwrap(),
        name,
        end: pos + 4,
    })
}
fn is_response(m: &[u8], id: u16) -> bool {
    m.len() >= 12 && u16_at(m, 0) == Some(id) && m[2] & 0x80 != 0
}
/// A and AAAA records in the answer section, including after CNAMEs.
fn addresses(m: &[u8]) -> Option<Vec<IpAddr>> {
    let mut pos = 12;
    for _ in 0..u16_at(m, 4)? {
        pos = name(m, pos)?.1 + 4;
    }
    let mut out = Vec::new();
    for _ in 0..u16_at(m, 6)? {
        pos = name(m, pos)?.1;
        let (kind, class) = (u16_at(m, pos)?, u16_at(m, pos + 2)?);
        let len = u16_at(m, pos + 8)? as usize;
        let data = m.get(pos + 10..pos + 10 + len)?;
        match (kind, class, len) {
            (1, 1, 4) => out.push(IpAddr::from(<[u8; 4]>::try_from(data).unwrap())),
            (28, 1, 16) => out.push(IpAddr::from(<[u8; 16]>::try_from(data).unwrap())),
            _ => {}
        }
        pos += 10 + len;
    }
    Some(out)
}
fn servfail(query: &[u8], q: &Question) -> Vec<u8> {
    let mut reply = query[..q.end].to_vec();
    reply[2] = 0x80 | (query[2] & 0x79);
    reply[3] = 0x82;
    reply[6..12].fill(0);
    reply
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn query(id: u16, name: &str, kind: u16) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend(label.bytes());
        }
        m.extend([0]);
        m.extend(kind.to_be_bytes());
        m.extend([0, 1]);
        // EDNS OPT record.
        m.extend([0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        m
    }
    /// Answer with a CNAME to a compressed name, then the addresses.
    pub fn response(query: &[u8], addresses: &[IpAddr]) -> Vec<u8> {
        let q = question(query).unwrap();
        let mut m = query[..q.end].to_vec();
        m[2] |= 0x80;
        m[3] = 0x80;
        m[6..8].copy_from_slice(&(1 + addresses.len() as u16).to_be_bytes());
        m[10..12].fill(0);
        let cname = m.len();
        m.extend([
            0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, b'c', b'd', b'n', 0xc0, 12,
        ]);
        for ip in addresses {
            let (kind, data) = match ip {
                IpAddr::V4(ip) => (1u16, ip.octets().to_vec()),
                IpAddr::V6(ip) => (28, ip.octets().to_vec()),
            };
            m.extend([0xc0, (cname + 12) as u8]);
            m.extend(kind.to_be_bytes());
            m.extend([0, 1, 0, 0, 0, 60]);
            m.extend((data.len() as u16).to_be_bytes());
            m.extend(data);
        }
        m
    }

    #[test]
    fn parses_questions_and_answers() {
        let q = query(0x1234, "WWW.Example.RU", 1);
        let parsed = question(&q).unwrap();
        assert_eq!(
            (parsed.id, parsed.name.as_str()),
            (0x1234, "www.example.ru")
        );
        let ips: Vec<IpAddr> = vec![
            "203.0.113.5".parse().unwrap(),
            "2001:db8::5".parse().unwrap(),
        ];
        let r = response(&q, &ips);
        assert!(is_response(&r, 0x1234) && !is_response(&r, 1) && !is_response(&q, 0x1234));
        assert_eq!(addresses(&r).unwrap(), ips);
        assert!(question(&r).is_none(), "responses are not queries");
        let fail = servfail(&q, &parsed);
        assert_eq!((fail[2], fail[3]), (0x81, 0x82));
        assert_eq!(fail.len(), parsed.end);
        assert!(addresses(&fail).unwrap().is_empty());
    }

    #[test]
    fn malformed_names_are_rejected() {
        let mut q = query(1, "a.b", 1);
        assert!(question(&q[..14]).is_none());
        // A compression loop.
        q.truncate(12);
        q.extend([0xc0, 12, 0, 1, 0, 1]);
        assert!(question(&q).is_none());
        let long = vec!["a".repeat(63); 5].join(".");
        assert!(question(&query(1, &long, 1)).is_none());
        let mut bad = response(&query(1, "a.b", 1), &["192.0.2.9".parse().unwrap()]);
        bad.truncate(bad.len() - 2);
        assert!(addresses(&bad).is_none());
    }
}
