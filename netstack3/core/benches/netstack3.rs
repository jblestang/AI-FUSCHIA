// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Run all netstack3 Criterion benchmarks.
//!
//! ```text
//! cargo bench -p netstack3-core --bench netstack3
//! ```

mod base_token_bucket;
mod common;

use criterion::{Criterion, criterion_group, criterion_main};

fn add_base_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("netstack3/base");
    common::configure_group(&mut group);
    base_token_bucket::add_benches(&mut group);
    group.finish();
}

fn add_udp_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("netstack3/udp/receive_throughput");
    common::configure_group(&mut group);
    netstack3_udp::bench_support::add_benches(&mut group);
    group.finish();
}

fn bench_netstack3(c: &mut Criterion) {
    add_base_benches(c);
    add_udp_benches(c);
}

criterion_group!(benches, bench_netstack3);
criterion_main!(benches);
