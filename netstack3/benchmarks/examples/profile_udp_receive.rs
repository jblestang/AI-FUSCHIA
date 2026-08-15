use std::env;

const BATCHES: u64 = 10;

fn main() {
    let payload_len: usize = env::var("PAYLOAD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);

    let wire_bytes = netstack3_udp::bench_support::ipv4_udp_wire_bytes(payload_len);
    let packet_count = netstack3_udp::bench_support::packets_for_rate(
        wire_bytes,
        netstack3_udp::bench_support::BATCH_DURATION,
    );

    let batch_ms = netstack3_udp::bench_support::BATCH_DURATION.as_millis();
    eprintln!(
        "profile_udp_receive: payload={payload_len}B wire={wire_bytes}B packets/batch={packet_count} batch_ms={batch_ms} batches={BATCHES} target={}bps",
        netstack3_udp::bench_support::TARGET_BPS
    );

    netstack3_udp::bench_support::profile_hot_loop(payload_len, Some(BATCHES));
}
