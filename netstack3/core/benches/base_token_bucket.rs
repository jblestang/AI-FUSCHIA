// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Token bucket Criterion benchmarks.

use core::time::Duration;

use criterion::{BenchmarkGroup, Bencher, measurement::WallTime};
use netstack3_base::TokenBucket;
use netstack3_base::testutil::FakeInstantCtx;

const SECOND: Duration = Duration::from_secs(1);

fn bench_try_take(b: &mut Bencher, enforced_rate: u64, try_rate: u32) {
    let sleep = SECOND / try_rate;
    let mut ctx = FakeInstantCtx::default();
    let mut bucket = TokenBucket::new(enforced_rate);
    b.iter(|| {
        ctx.sleep(sleep);
        let _: bool = core::hint::black_box(bucket.try_take(core::hint::black_box(&ctx)));
    });
}

/// Registers token bucket micro-benchmarks.
pub fn add_benches(group: &mut BenchmarkGroup<'_, WallTime>) {
    let _ = group.bench_function("TokenBucket/TryTake/Slow", |b| bench_try_take(b, 64, 1));
    let _ = group.bench_function("TokenBucket/TryTake/HalfRate", |b| bench_try_take(b, 64, 32));
    let _ = group.bench_function("TokenBucket/TryTake/EqualRate", |b| bench_try_take(b, 64, 64));
    let _ = group.bench_function("TokenBucket/TryTake/AlmostEqualRate", |b| bench_try_take(b, 64, 65));
    let _ = group.bench_function("TokenBucket/TryTake/DoubleRate", |b| bench_try_take(b, 64, 64 * 2));
}
