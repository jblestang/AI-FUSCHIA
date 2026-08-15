// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Benchmark UDP receive throughput at a 1 Gbps target rate across packet sizes.
//!
//! Run with:
//! ```text
//! cargo bench -p netstack3-udp --features benchmark --bench udp_receive_throughput
//! ```

use criterion::{Criterion, criterion_group, criterion_main};

fn bench_udp_receive(c: &mut Criterion) {
    netstack3_udp::benchmarks::add_benches(c);
}

criterion_group!(benches, bench_udp_receive);
criterion_main!(benches);
