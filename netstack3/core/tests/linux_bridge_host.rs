//! Linux L2 bridge host for netstack3.
//!
//! Run (requires root/CAP_NET_ADMIN for TAP):
//! ```text
//! cargo test -p netstack3-core --test linux_bridge_host --features testutils -- --nocapture tap0
//! ```

#![recursion_limit = "256"]

mod linux_bridge;

use std::time::Duration;

use linux_bridge::host::BridgeHost;
use net_types::ip::Ipv4;
use netstack3_base::testutil::TestIpExt;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let tap_name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!(
            "Usage: {} <tap-interface> [idle-timeout-ms]",
            std::env::args().next().unwrap()
        );
        eprintln!();
        eprintln!("Bridge setup example:");
        eprintln!("  ip link add name br0 type bridge");
        eprintln!("  ip tuntap add dev tap0 mode tap");
        eprintln!("  ip link set tap0 master br0");
        eprintln!("  ip link set tap0 address 00:01:02:03:04:05 up");
        eprintln!("  ip link set br0 up");
        std::process::exit(1);
    });

    let idle_ms: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    log::info!("starting netstack3 on TAP {tap_name} (idle poll {idle_ms}ms)");

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

    if let Err(e) = host.run(Duration::from_millis(idle_ms)) {
        log::error!("host loop exited: {e}");
        std::process::exit(1);
    }
}
