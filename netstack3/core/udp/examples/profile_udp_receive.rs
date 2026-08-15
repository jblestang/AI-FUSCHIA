// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Standalone UDP receive hot loop for CPU profiling (perf / samply).
//!
//! ```text
//! cargo run -p netstack3-udp --features benchmark --example profile_udp_receive --release
//! PAYLOAD=64 cargo run -p netstack3-udp --features benchmark --example profile_udp_receive --release
//! samply record --save-only -o /tmp/udp.json -- target/release/examples/profile_udp_receive
//! ```

use std::env;

use netstack3_udp::benchmarks::{self, TARGET_BPS};

/// How many 10 ms @ 1 Gbps batches to execute (~10 s of hot path at 512 B payload).
const BATCHES: u64 = 8000;

fn main() {
    let payload_len: usize = env::var("PAYLOAD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);

    let wire_bytes = benchmarks::ipv4_udp_wire_bytes(payload_len);
    let packet_count = benchmarks::packets_for_rate(wire_bytes, benchmarks::BATCH_DURATION);

    eprintln!(
        "profile_udp_receive: payload={payload_len}B wire={wire_bytes}B packets/batch={packet_count} batches={BATCHES} target={TARGET_BPS}bps"
    );

    benchmarks::profile_hot_loop(payload_len, Some(BATCHES));
}
