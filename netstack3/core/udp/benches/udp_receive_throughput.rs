// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! UDP receive throughput benchmarks (subset of the netstack3 aggregate suite).
//!
//! Prefer the unified harness when running multiple crates:
//! ```text
//! cargo bench -p netstack3-core --features benchmark --bench netstack3
//! ```
//!
//! UDP-only:
//! ```text
//! cargo bench -p netstack3-udp --features benchmark --bench udp_receive_throughput
//! ```

use criterion::{Criterion, criterion_group, criterion_main};

fn bench_udp_receive(c: &mut Criterion) {
    let mut group = c.benchmark_group("netstack3/udp/receive_throughput");
    netstack3_base::benchmarks::configure_group(&mut group);
    netstack3_udp::benchmarks::add_benches(&mut group);
    group.finish();
}

criterion_group!(benches, bench_udp_receive);
criterion_main!(benches);
