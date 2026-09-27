//! Reusable packet buffers. Linux's virtio headers stay entirely inside tun-rs;
//! the protocol only sees fully segmented IP packets with completed checksums.
#[cfg(target_os = "windows")]
use crate::receive_tun;
use crate::udp;
use edup_common::wire;
use std::io;
#[cfg(target_os = "linux")]
use std::time::Duration;
use tun_rs::{InterruptEvent, SyncDevice};

pub const BATCH_SIZE: usize = 128;
pub struct Reader {
    pub packets: Vec<Vec<u8>>,
    pub sizes: Vec<usize>,
    #[cfg(target_os = "linux")]
    original: Vec<u8>,
}
impl Reader {
    pub fn new() -> Self {
        Self {
            // Large enough even for an invalid oversized, non-GSO TUN packet.
            // Validation later drops it without truncating it into a valid packet.
            packets: (0..BATCH_SIZE)
                .map(|i| {
                    vec![
                        0;
                        if i == 0 {
                            udp::RECEIVE_CAPACITY + wire::HDR_LEN
                        } else {
                            2048
                        }
                    ]
                })
                .collect(),
            sizes: vec![0; BATCH_SIZE],
            #[cfg(target_os = "linux")]
            original: vec![0; udp::RECEIVE_CAPACITY + tun_rs::VIRTIO_NET_HDR_LEN],
        }
    }
    pub fn recv(
        &mut self,
        tun: &SyncDevice,
        event: &InterruptEvent,
        wait: bool,
    ) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            let read = |this: &mut Self| {
                tun.recv_multiple(
                    &mut this.original,
                    &mut this.packets,
                    &mut this.sizes,
                    wire::HDR_LEN,
                )
                .map_err(|e| {
                    // tun-rs reports malformed/unsupported virtio packets and
                    // GSO batches exceeding its bounded output as input errors.
                    // The read consumed that packet; drop it, keep the tunnel up.
                    if e.raw_os_error().is_none()
                        && matches!(e.kind(), io::ErrorKind::InvalidInput | io::ErrorKind::Other)
                    {
                        io::Error::new(io::ErrorKind::InvalidData, e)
                    } else {
                        e
                    }
                })
            };
            match read(self) {
                Err(e) if wait && e.kind() == io::ErrorKind::WouldBlock => {
                    tun.wait_readable_intr_timeout(event, Some(Duration::from_millis(200)))?;
                    read(self)
                }
                r => r,
            }
        }
        #[cfg(target_os = "windows")]
        {
            let buf = &mut self.packets[0][wire::HDR_LEN..];
            self.sizes[0] = if wait {
                receive_tun(tun, buf, event)?
            } else {
                tun.try_recv(buf)?
            };
            Ok(1)
        }
    }
}

pub struct Writer {
    #[cfg(target_os = "linux")]
    gro: tun_rs::GROTable,
    packets: Vec<Vec<u8>>,
    count: usize,
    pub coalesced_writes: u64,
}
impl Writer {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            gro: tun_rs::GROTable::default(),
            // tun-rs only coalesces into existing capacity (no reallocations).
            packets: (0..BATCH_SIZE)
                .map(|_| {
                    Vec::with_capacity(if cfg!(target_os = "linux") {
                        udp::RECEIVE_CAPACITY + 16
                    } else {
                        2048
                    })
                })
                .collect(),
            count: 0,
            coalesced_writes: 0,
        }
    }
    pub fn push(&mut self, packet: &[u8]) {
        assert!(self.count < BATCH_SIZE);
        let p = &mut self.packets[self.count];
        p.clear();
        #[cfg(target_os = "linux")]
        p.resize(tun_rs::VIRTIO_NET_HDR_LEN, 0);
        p.extend_from_slice(packet);
        self.count += 1;
    }
    pub fn full(&self) -> bool {
        self.count == BATCH_SIZE
    }
    pub fn flush(&mut self, tun: &SyncDevice, event: &InterruptEvent) -> io::Result<(u64, u64)> {
        let count = std::mem::take(&mut self.count);
        if count == 0 {
            return Ok((0, 0));
        }
        #[cfg(target_os = "linux")]
        {
            let original_bytes: usize = self.packets[..count].iter().map(Vec::len).sum();
            match tun.send_multiple_intr(
                &mut self.gro,
                &mut self.packets[..count],
                tun_rs::VIRTIO_NET_HDR_LEN,
                event,
            ) {
                Ok(bytes) => {
                    if tun.tcp_gso() && bytes < original_bytes {
                        self.coalesced_writes += 1;
                    }
                    Ok((count as u64, 0))
                }
                // tun-rs can have written part of a batch before an error. Do not
                // retry it: that would duplicate packets already delivered.
                Err(e) if crate::temporary(&e) => Ok((0, count as u64)),
                Err(e) => Err(e),
            }
        }
        #[cfg(target_os = "windows")]
        {
            let (mut sent, mut dropped) = (0, 0);
            for p in &self.packets[..count] {
                match tun.send_intr(p, event) {
                    Ok(n) if n == p.len() => sent += 1,
                    Ok(_) => return Err(io::Error::other("partial TUN packet")),
                    Err(e) if crate::temporary(&e) => dropped += 1,
                    Err(e) => return Err(e),
                }
            }
            Ok((sent, dropped))
        }
    }
}
