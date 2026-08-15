// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Benchmark IPS zero-copy UDP/TCP ingress throughput at a 1 Gbps target rate.
//!
//! Run with:
//! ```text
//! cargo bench -p netstack3-ips --features benchmark --bench ips_receive_throughput
//! ```
//!
//! Attack-sized datagrams/segments (small payloads) are in the `netstack3/ips/attack_throughput`
//! and `netstack3/ips/tcp_attack_throughput` groups. Compare measured throughput to
//! [`netstack3_ips::benchmarks::TARGET_BPS`].

use criterion::{Criterion, criterion_group, criterion_main};

fn bench_ips_receive(c: &mut Criterion) {
    netstack3_ips::benchmarks::add_benches(c);
}

criterion_group!(benches, bench_ips_receive);
criterion_main!(benches);
