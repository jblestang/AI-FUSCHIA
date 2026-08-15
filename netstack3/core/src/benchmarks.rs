// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Aggregate Criterion benchmarks for netstack3.
//!
//! Each protocol registers into a named [`criterion::BenchmarkGroup`] via its
//! own `add_benches` function. Group timing settings live in
//! [`netstack3_base::benchmarks::configure_group`].

use criterion::Criterion;

/// Registers base-crate micro-benchmarks (token bucket, etc.).
pub fn add_base_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("netstack3/base");
    netstack3_base::benchmarks::configure_group(&mut group);
    netstack3_base::benchmarks::add_benches(&mut group);
    group.finish();
}

/// Registers UDP receive throughput benchmarks.
pub fn add_udp_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("netstack3/udp/receive_throughput");
    netstack3_base::benchmarks::configure_group(&mut group);
    netstack3_udp::benchmarks::add_benches(&mut group);
    group.finish();
}

/// Registers all netstack3 Criterion benchmarks.
pub fn add_benches(c: &mut Criterion) {
    add_base_benches(c);
    add_udp_benches(c);
}
