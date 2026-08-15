// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Run all netstack3 Criterion benchmarks.
//!
//! ```text
//! cargo bench -p netstack3-core --features benchmark --bench netstack3
//! ```

use criterion::{Criterion, criterion_group, criterion_main};

fn bench_netstack3(c: &mut Criterion) {
    netstack3_core::benchmarks::add_benches(c);
}

criterion_group!(benches, bench_netstack3);
criterion_main!(benches);
