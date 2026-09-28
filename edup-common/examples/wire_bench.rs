//! CPU-only wire benchmark; run in release mode, without changing networking.
use edup_common::wire::{Key, xor_region};
use std::{hint::black_box, time::Instant};

fn main() {
    let key = black_box(Key { k0: 123, k1: 456 });
    // Includes short control/ACK packets and a typical full-size tunnel packet.
    for len in [1, 31, 1391] {
        let mut buf = vec![0x5a; len];
        let iterations = 1_000_000;
        let mut samples = Vec::new();
        for _ in 0..7 {
            let start = Instant::now();
            for _ in 0..iterations {
                xor_region(black_box(&key), black_box(&mut buf));
            }
            black_box(&buf);
            samples.push(start.elapsed().as_nanos() as f64 / iterations as f64);
        }
        samples.sort_by(f64::total_cmp);
        let ns = samples[samples.len() / 2];
        println!(
            "bytes={len} median_ns={ns:.2} Gbit/s={:.2}",
            len as f64 * 8.0 / ns
        );
    }
}
