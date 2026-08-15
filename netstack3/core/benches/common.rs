// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Shared Criterion settings for netstack3 throughput benchmarks.

use core::time::Duration;

use criterion::{BenchmarkGroup, measurement::WallTime};

/// Shared Criterion settings for netstack3 throughput benchmarks.
pub fn configure_group(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(3));
    group.sample_size(50);
}
