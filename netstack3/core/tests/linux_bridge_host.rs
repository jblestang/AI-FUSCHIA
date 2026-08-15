//! Linux L2 bridge host for netstack3 with UDP receive example.
//!
//! Run (requires root/CAP_NET_ADMIN for TAP):
//! ```text
//! cargo test -p netstack3-core --test linux_bridge_host --features testutils -- --nocapture tap0
//! cargo test -p netstack3-core --test linux_bridge_host --features testutils -- --nocapture --self-test
//! ```

#![recursion_limit = "256"]

mod linux_bridge;

use core::num::NonZeroU16;
use std::time::Duration;

use linux_bridge::host::BridgeHost;
use linux_bridge::udp::{self, DEFAULT_UDP_PORT};
use net_types::ip::Ipv4;
use netstack3_base::testutil::TestIpExt;

fn print_usage(prog: &str) {
    eprintln!("Usage:");
    eprintln!("  {prog} --self-test");
    eprintln!("  {prog} <tap-interface> [udp-port] [idle-timeout-ms]");
    eprintln!();
    eprintln!("Bridge setup example:");
    eprintln!("  ip link add name br0 type bridge");
    eprintln!("  ip tuntap add dev tap0 mode tap");
    eprintln!("  ip link set tap0 master br0");
    eprintln!("  ip link set tap0 address 00:01:02:03:04:05 up");
    eprintln!("  ip link set br0 up");
    eprintln!();
    eprintln!("Send UDP to the stack (from a host on the bridge):");
    eprintln!("  echo -n hello | nc -u {} {DEFAULT_UDP_PORT}", Ipv4::TEST_ADDRS.local_ip);
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--self-test") {
        if udp::self_test().is_err() {
            std::process::exit(1);
        }
        return;
    }

    // Skip flags injected by `cargo test` (e.g. `--nocapture`).
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();

    let tap_name = positional.first().cloned().unwrap_or_else(|| {
        print_usage(&std::env::args().next().unwrap_or_else(|| "linux_bridge_host".into()));
        std::process::exit(1);
    });

    let udp_port: NonZeroU16 = positional
        .get(1)
        .and_then(|s| s.parse().ok())
        .and_then(NonZeroU16::new)
        .unwrap_or(DEFAULT_UDP_PORT);

    let idle_ms: u64 = positional
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    log::info!(
        "starting netstack3 on TAP {tap_name}, UDP port {udp_port} (idle poll {idle_ms}ms)"
    );

    let mut host = BridgeHost::new(&tap_name).unwrap_or_else(|e| {
        log::error!("failed to attach to TAP {tap_name}: {e}");
        std::process::exit(1);
    });

    log::info!(
        "stack ready: {} on {}, neighbor {}",
        Ipv4::TEST_ADDRS.local_ip,
        Ipv4::TEST_ADDRS.local_mac,
        Ipv4::TEST_ADDRS.remote_ip,
    );

    if let Err(e) = host.run_udp_listener(udp_port, Duration::from_millis(idle_ms)) {
        log::error!("host loop exited: {e}");
        std::process::exit(1);
    }
}
