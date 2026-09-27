//! Socket offloads preserve the wire protocol: every segment is a complete,
//! independently sealed edup datagram. Only the final segment may be shorter.
use std::{
    io,
    net::UdpSocket,
    sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
};

mod control;
#[cfg(target_os = "linux")]
#[path = "udp/linux.rs"]
mod platform;
#[cfg(target_os = "windows")]
#[path = "udp/windows.rs"]
mod platform;

// Conservative common denominator: Linux supports at least 64 UDP segments,
// and an IPv4 UDP super-packet must fit in 65535 - 20 - 8 bytes.
pub const MAX_SEGMENTS: usize = 64;
pub const MAX_PAYLOAD: usize = 65507;
pub const RECEIVE_CAPACITY: usize = 65536;

pub struct Transport {
    socket: UdpSocket,
    state: platform::State,
    tx: AtomicBool,
    pub segmented_sends: AtomicU64,
    pub coalesced_receives: AtomicU64,
    pub fallbacks: AtomicU64,
}

impl Transport {
    pub fn new(socket: UdpSocket, enabled: bool) -> io::Result<Self> {
        let (state, tx) = platform::configure(&socket, enabled)?;
        eprintln!("UDP offload: tx={}, rx={}", tx, state.rx_enabled());
        Ok(Self {
            socket,
            state,
            tx: AtomicBool::new(tx),
            segmented_sends: AtomicU64::new(0),
            coalesced_receives: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
        })
    }

    pub fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.socket.send(data)
    }

    /// Returns a segment stride, after checking payload/control truncation.
    /// No metadata means exactly one datagram, even if its bytes look like edup.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, usize)> {
        let (len, stride) = platform::recv(&self.socket, &self.state, buf)?;
        let stride = receive_stride(len, stride)?;
        if len > stride {
            self.coalesced_receives.fetch_add(1, Relaxed);
        }
        Ok((len, stride))
    }

    pub fn send_batch(&self, batch: &Batch, stop: &AtomicBool) -> io::Result<(u64, u64)> {
        self.send_batch_with(batch, |data, segment| {
            if stop.load(Relaxed) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            match segment {
                Some(size) => platform::send_segmented(&self.socket, data, size),
                None => self.socket.send(data),
            }
        })
    }

    fn send_batch_with(
        &self,
        batch: &Batch,
        mut send: impl FnMut(&[u8], Option<u16>) -> io::Result<usize>,
    ) -> io::Result<(u64, u64)> {
        if batch.count == 0 {
            return Ok((0, 0));
        }
        if batch.count > 1 && self.tx.load(Relaxed) {
            match send(&batch.bytes, Some(batch.stride as u16)) {
                Ok(n) if n == batch.bytes.len() => {
                    self.segmented_sends.fetch_add(1, Relaxed);
                    return Ok((batch.count as u64, 0));
                }
                Ok(_) => return Err(io::Error::other("partial segmented UDP send")),
                Err(e) if platform::unsupported(&e) => {
                    // An atomic failed UDP send submitted no datagrams. Retry each
                    // original segment once; never resend a successful aggregate.
                    if self.tx.swap(false, Relaxed) {
                        self.fallbacks.fetch_add(1, Relaxed);
                        eprintln!("UDP segmentation disabled on this path: {e}");
                    }
                }
                Err(e) if crate::temporary(&e) => return Ok((0, batch.count as u64)),
                Err(e) => return Err(e),
            }
        }
        let (mut sent, mut dropped) = (0, 0);
        for data in batch.bytes.chunks(batch.stride) {
            match send(data, None) {
                Ok(n) if n == data.len() => sent += 1,
                Ok(_) => return Err(io::Error::other("partial UDP datagram")),
                Err(e) if crate::temporary(&e) => dropped += 1,
                Err(e) => return Err(e),
            }
        }
        Ok((sent, dropped))
    }
}

/// Accumulates only adjacent equal-size datagrams and an optional short tail.
/// A caller flushes immediately when the source queue is empty.
pub struct Batch {
    bytes: Vec<u8>,
    stride: usize,
    count: usize,
}
impl Batch {
    pub fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(MAX_PAYLOAD),
            stride: 0,
            count: 0,
        }
    }
    pub fn push(&mut self, data: &[u8]) -> bool {
        if data.is_empty()
            || data.len() > MAX_PAYLOAD
            || self.count == MAX_SEGMENTS
            || self.bytes.len() + data.len() > MAX_PAYLOAD
            || (self.count != 0
                && (data.len() > self.stride || !self.bytes.len().is_multiple_of(self.stride)))
        {
            return false;
        }
        if self.count == 0 {
            self.stride = data.len();
        }
        self.bytes.extend_from_slice(data);
        self.count += 1;
        true
    }
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.count = 0;
        self.stride = 0;
    }
}

fn receive_stride(len: usize, stride: Option<usize>) -> io::Result<usize> {
    match stride {
        Some(n) if n == 0 || n > len || n > MAX_PAYLOAD => Err(invalid("invalid UDP segment size")),
        Some(n) => Ok(n),
        None => Ok(len.max(1)), // zero-length datagram must reach the wire validator
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests;
