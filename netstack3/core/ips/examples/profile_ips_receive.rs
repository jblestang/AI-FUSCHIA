// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Standalone IPS ingress hot loop for CPU profiling (perf / samply).
//!
//! ```text
//! cargo run -p netstack3-ips --features benchmark --example profile_ips_receive --release
//! PAYLOAD=64 cargo run -p netstack3-ips --features benchmark --example profile_ips_receive --release
//! samply record --save-only -o /tmp/ips.json -- target/release/examples/profile_ips_receive
//! ```

use std::env;

use netstack3_ips::benchmarks::{self, TARGET_BPS};

/// How many [`benchmarks::BATCH_DURATION`] @ 1 Gbps batches to execute (~10 s simulated traffic).
const BATCHES: u64 = 10;

fn main() {
    let payload_len: usize = env::var("PAYLOAD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);

    let wire_bytes = benchmarks::ethernet_ipv4_udp_wire_bytes(payload_len);
    let packet_count = benchmarks::packets_for_rate(wire_bytes, benchmarks::BATCH_DURATION);
    let pps = benchmarks::packets_per_second_for_1gbps(wire_bytes);

    let batch_ms = benchmarks::BATCH_DURATION.as_millis();
    eprintln!(
        "profile_ips_receive: payload={payload_len}B wire={wire_bytes}B packets/batch={packet_count} \
         batch_ms={batch_ms} batches={BATCHES} target={TARGET_BPS}bps required_pps={pps:.0}"
    );

    benchmarks::profile_hot_loop(payload_len, Some(BATCHES));
}
