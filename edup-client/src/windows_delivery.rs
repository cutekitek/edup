//! Bounded delivery into Wintun's ring; no staging copy or sleeping retries.
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};

// A few immediate retries can catch space released by the stack on another CPU.
// A persistently full ring drops this packet rather than stalling UDP reception.
const SEND_ATTEMPTS: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    Sent,
    Congested,
    Dropped,
    Stopped,
}

pub fn deliver(
    packet: &[u8],
    stop: &AtomicBool,
    mut send: impl FnMut(&[u8]) -> io::Result<usize>,
) -> io::Result<Delivery> {
    for _ in 0..SEND_ATTEMPTS {
        if stop.load(Relaxed) {
            return Ok(Delivery::Stopped);
        }
        match send(packet) {
            Ok(n) if n == packet.len() => return Ok(Delivery::Sent),
            Ok(_) => return Err(io::Error::other("partial Wintun packet")),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::hint::spin_loop(),
            Err(_) if stop.load(Relaxed) => return Ok(Delivery::Stopped),
            Err(e) if crate::temporary(&e) => return Ok(Delivery::Dropped),
            Err(e) => return Err(e),
        }
    }
    Ok(Delivery::Congested)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_ring_is_bounded_and_next_packet_can_progress() {
        let stop = AtomicBool::new(false);
        let mut calls = 0;
        assert_eq!(
            deliver(&[1, 2], &stop, |_| {
                calls += 1;
                Err(io::ErrorKind::WouldBlock.into())
            })
            .unwrap(),
            Delivery::Congested
        );
        assert_eq!(calls, SEND_ATTEMPTS);
        assert_eq!(
            deliver(&[3], &stop, |p| Ok(p.len())).unwrap(),
            Delivery::Sent
        );
    }

    #[test]
    fn transient_full_ring_retries_same_borrow_without_duplicate_delivery() {
        let stop = AtomicBool::new(false);
        let packet = [1, 2, 3];
        let mut calls = 0;
        assert_eq!(
            deliver(&packet, &stop, |p| {
                assert_eq!(p.as_ptr(), packet.as_ptr());
                calls += 1;
                if calls == 1 {
                    Err(io::ErrorKind::WouldBlock.into())
                } else {
                    Ok(p.len())
                }
            })
            .unwrap(),
            Delivery::Sent
        );
        assert_eq!(calls, 2);
    }

    #[test]
    fn shutdown_stops_before_send_and_during_congestion() {
        let stop = AtomicBool::new(true);
        assert_eq!(
            deliver(&[1], &stop, |_| panic!("sent after shutdown")).unwrap(),
            Delivery::Stopped
        );
        stop.store(false, Relaxed);
        let mut calls = 0;
        assert_eq!(
            deliver(&[1], &stop, |_| {
                calls += 1;
                stop.store(true, Relaxed);
                Err(io::ErrorKind::WouldBlock.into())
            })
            .unwrap(),
            Delivery::Stopped
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn partial_and_fatal_writes_are_not_retried() {
        let stop = AtomicBool::new(false);
        for result in [Ok(0), Err(io::ErrorKind::BrokenPipe.into())] {
            let mut result = Some(result);
            assert!(
                deliver(&[1], &stop, |_| result
                    .take()
                    .expect("retried failed write"))
                .is_err()
            );
        }
        assert_eq!(
            deliver(&[1], &stop, |_| Err(io::ErrorKind::Interrupted.into())).unwrap(),
            Delivery::Dropped
        );
    }
}
