//! CPU-only wire benchmark; run in release mode, without changing networking.
//! Measures the client's per-packet cryptography: seal and a successful open.
use edup_common::{
    aead::Cipher,
    wire::{self, Header},
};
use std::{hint::black_box, time::Instant};

fn measure(mut f: impl FnMut()) -> f64 {
    let iterations = 1_000_000;
    let mut samples = Vec::new();
    for _ in 0..7 {
        let start = Instant::now();
        for _ in 0..iterations {
            f();
        }
        samples.push(start.elapsed().as_nanos() as f64 / iterations as f64);
    }
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

fn main() {
    let cipher = Cipher::new(black_box(&[7; 8]));
    // Includes short control/ACK packets and a typical full-size tunnel packet.
    for len in [0, 31, 1400] {
        let mut sealed = vec![0x5a; wire::HDR_LEN + len];
        sealed[..wire::AAD_LEN].copy_from_slice(
            &Header {
                user: 1,
                typ: wire::TYPE_DATA,
                phase: 0,
                counter: 1,
            }
            .encode(),
        );
        let mut buf = sealed.clone();
        let seal = measure(|| cipher.seal(wire::TO_SERVER, black_box(&mut buf)));
        cipher.seal(wire::TO_SERVER, &mut sealed);
        // Restore the ciphertext each time so that every open succeeds.
        let open = measure(|| {
            buf.copy_from_slice(&sealed);
            assert!(cipher.open(wire::TO_SERVER, black_box(&mut buf)).is_some());
        });
        for (name, ns) in [("seal", seal), ("open", open)] {
            println!(
                "{name} bytes={len} median_ns={ns:.2} Gbit/s={:.2}",
                len as f64 * 8.0 / ns
            );
        }
    }
}
