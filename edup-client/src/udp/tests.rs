use super::*;
use edup_common::{key::derive_key, wire};
use std::time::Duration;

fn pair(offload: bool) -> (Transport, Transport) {
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    a.connect(b.local_addr().unwrap()).unwrap();
    b.connect(a.local_addr().unwrap()).unwrap();
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    (
        Transport::new(a, offload).unwrap(),
        Transport::new(b, offload).unwrap(),
    )
}
fn sealed(nonce: u32, len: usize) -> Vec<u8> {
    let mut p = vec![nonce as u8; len];
    wire::seal(&derive_key("test"), nonce, wire::TYPE_DATA, 7, &mut p);
    p
}

#[test]
fn batch_preserves_boundaries_order_and_limits() {
    let mut b = Batch::new();
    assert!(!b.push(&[]));
    for _ in 0..MAX_SEGMENTS {
        assert!(b.push(&[1; 40]));
    }
    assert!(!b.push(&[1; 40]));
    b.clear();
    assert!(b.push(&[1; 1400]));
    assert!(!b.push(&[2; 1401]));
    assert!(b.push(&[3; 1200]));
    assert!(!b.push(&[4; 1200])); // no second short segment
    assert_eq!(
        b.bytes
            .chunks(b.stride)
            .map(<[u8]>::len)
            .collect::<Vec<_>>(),
        [1400, 1200]
    );
    b.clear();
    assert!(b.push(&vec![1; MAX_PAYLOAD]));
    assert!(!b.push(&[2]));
    assert_eq!(receive_stride(0, None).unwrap(), 1);
    assert!(receive_stride(100, Some(0)).is_err());
    assert!(receive_stride(100, Some(101)).is_err());
    assert_eq!(receive_stride(2001, Some(1000)).unwrap(), 1000);
}

#[test]
fn socket_offloads_preserve_independent_wire_packets() {
    for enabled in [false, true] {
        let (sender, receiver) = pair(enabled);
        let packets = [sealed(1, 1400), sealed(2, 1400), sealed(3, 73)];
        let mut batch = Batch::new();
        for p in &packets {
            assert!(batch.push(p));
        }
        assert_eq!(
            sender.send_batch(&batch, &AtomicBool::new(false)).unwrap(),
            (3, 0)
        );
        // An ordinary send after a segmented send must not inherit its size.
        let extra = sealed(4, 1464);
        sender.send(&extra).unwrap();
        let expected: Vec<_> = packets.iter().chain(std::iter::once(&extra)).collect();
        let mut seen = 0;
        let mut buf = vec![0; RECEIVE_CAPACITY];
        while seen < expected.len() {
            let (n, stride) = receiver.recv(&mut buf).unwrap();
            for segment in buf[..n].chunks_mut(stride) {
                assert_eq!(segment, expected[seen].as_slice());
                let opened = wire::open(&derive_key("test"), segment).unwrap();
                assert_eq!(opened.user, 7);
                assert!(
                    segment[wire::HDR_LEN..]
                        .iter()
                        .all(|b| *b == (seen + 1) as u8)
                );
                seen += 1;
            }
        }
        eprintln!(
            "offload={enabled}: segmented_sends={}, coalesced_receives={}",
            sender.segmented_sends.load(Relaxed),
            receiver.coalesced_receives.load(Relaxed)
        );
        #[cfg(target_os = "linux")]
        if enabled {
            assert_eq!(sender.segmented_sends.load(Relaxed), 1);
            assert!(receiver.coalesced_receives.load(Relaxed) > 0);
        }
    }
}

#[test]
fn ordinary_peer_receives_segments_and_short_tail() {
    let (sender, receiver) = pair(true);
    let mut batch = Batch::new();
    let packets = [sealed(1, 1200), sealed(2, 1200), sealed(3, 8)];
    for p in &packets {
        assert!(batch.push(p));
    }
    // Use a separate socket with offload disabled, like the existing peer.
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    sender.socket.connect(peer.local_addr().unwrap()).unwrap();
    sender.send_batch(&batch, &AtomicBool::new(false)).unwrap();
    let mut buf = [0; 2048];
    for p in &packets {
        let n = peer.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], p);
    }
    drop(receiver);
}

#[test]
fn unsupported_send_retries_originals_once_and_latches_fallback() {
    let (sender, _) = pair(false);
    sender.tx.store(true, Relaxed);
    let mut b = Batch::new();
    b.push(&[1; 100]);
    b.push(&[2; 33]);
    let mut calls = Vec::new();
    let result = sender
        .send_batch_with(&b, |data, segment| {
            calls.push((data.to_vec(), segment));
            if segment.is_some() {
                #[cfg(target_os = "linux")]
                return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
                #[cfg(target_os = "windows")]
                return Err(io::Error::from_raw_os_error(10045));
            }
            Ok(data.len())
        })
        .unwrap();
    assert_eq!(result, (2, 0));
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[1], (vec![1; 100], None));
    assert_eq!(calls[2], (vec![2; 33], None));
    assert!(!sender.tx.load(Relaxed));
    assert_eq!(sender.fallbacks.load(Relaxed), 1);
    let r = sender
        .send_batch_with(&b, |_, segment| {
            assert!(segment.is_none());
            Err(io::ErrorKind::WouldBlock.into())
        })
        .unwrap();
    assert_eq!(r, (0, 2));
}

#[test]
fn transient_and_partial_sends_never_duplicate_packets() {
    let (sender, _) = pair(false);
    sender.tx.store(true, Relaxed);
    let mut b = Batch::new();
    b.push(&[1; 100]);
    b.push(&[2; 100]);
    let mut calls = 0;
    assert_eq!(
        sender
            .send_batch_with(&b, |_, _| {
                calls += 1;
                Err(io::ErrorKind::WouldBlock.into())
            })
            .unwrap(),
        (0, 2)
    );
    assert_eq!(calls, 1);
    assert!(sender.tx.load(Relaxed));
    calls = 0;
    assert!(
        sender
            .send_batch_with(&b, |_, _| {
                calls += 1;
                Ok(100)
            })
            .is_err()
    );
    assert_eq!(calls, 1);
}

#[test]
fn truncated_datagrams_are_rejected() {
    let (sender, receiver) = pair(true);
    sender.send(&[1; 100]).unwrap();
    assert_eq!(
        receiver.recv(&mut [0; 10]).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}
