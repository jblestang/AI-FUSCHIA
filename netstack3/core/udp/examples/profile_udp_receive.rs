// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Standalone UDP receive hot loop for CPU profiling (perf / samply).
//!
//! ```text
//! cargo run -p netstack3-udp --features benches --example profile_udp_receive --release
//! PAYLOAD=64 cargo run -p netstack3-udp --features benches --example profile_udp_receive --release
//! ```

use std::env;

/// How many [`netstack3_udp::bench_support::BATCH_DURATION`] @ 1 Gbps batches (~10 s simulated traffic).
const BATCHES: u64 = 10;

fn main() {
    let payload_len: usize = env::var("PAYLOAD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);

    let wire_bytes = netstack3_udp::bench_support::ipv4_udp_wire_bytes(payload_len);
    let packet_count =
        netstack3_udp::bench_support::packets_for_rate(wire_bytes, netstack3_udp::bench_support::BATCH_DURATION);

    let batch_ms = netstack3_udp::bench_support::BATCH_DURATION.as_millis();
    eprintln!(
        "profile_udp_receive: payload={payload_len}B wire={wire_bytes}B packets/batch={packet_count} batch_ms={batch_ms} batches={BATCHES} target={}bps",
        netstack3_udp::bench_support::TARGET_BPS
    );

    netstack3_udp::bench_support::profile_hot_loop(payload_len, Some(BATCHES));
}
