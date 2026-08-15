// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! IPS zero-copy UDP ingress throughput benchmarks targeting 1 Gbps.
//!
//! Small payload sizes mirror volumetric UDP attack traffic (high packet rate,
//! minimal bytes per datagram). Each iteration exercises
//! [`crate::process_ethernet_frame`] end-to-end through a no-op L7 handler.

use core::num::NonZeroU16;

use criterion::{BenchmarkGroup, Criterion, Throughput, black_box, measurement::WallTime};
use internet_checksum::Checksum;
use net_types::ethernet::Mac;
use net_types::ip::Ipv4Addr;
use netstack3_base::testutil::FakeDeviceId;
use netstack3_base::NetworkSerializationContext;
use packet::{Buf, NestableSerializer as _, Serializer};
use packet_formats::ethernet::{EtherType, ETHERNET_HDR_LEN_NO_TAG, EthernetFrameBuilder};
use packet_formats::ip::{IpProto, Ipv4Proto};
use packet_formats::ipv4::Ipv4PacketBuilder;
use packet_formats::udp::UdpPacketBuilder;

use crate::context::{IpsReceiveBindingsContext, IpsReceiveError};
use crate::receive::process_ethernet_frame;
use crate::state::IpsState;
use crate::view::ReceivedUdpDatagramView;

/// Target sustained receive rate (1 Gbps).
pub const TARGET_GBPS: f64 = 1.0;

/// Target receive rate in bits per second.
pub const TARGET_BPS: u64 = 1_000_000_000;

/// Simulated traffic duration per batch benchmark iteration.
pub const BATCH_DURATION: core::time::Duration = core::time::Duration::from_millis(1000);

const LOCAL_PORT: NonZeroU16 = NonZeroU16::new(100).unwrap();
const REMOTE_PORT: NonZeroU16 = NonZeroU16::new(200).unwrap();
const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);

/// Small UDP payload sizes typical of attack traffic (bytes).
pub const ATTACK_PAYLOAD_SIZES: &[usize] = &[0, 32, 64, 128, 256, 512];

/// Broader payload sweep for comparison with the socket receive path.
pub const PAYLOAD_SIZES: &[usize] = &[0, 32, 64, 128, 256, 512, 1024, 1472];

/// Ethernet wire size for an IPv4/UDP datagram with `payload_len` bytes.
pub fn ethernet_ipv4_udp_wire_bytes(payload_len: usize) -> usize {
    ETHERNET_HDR_LEN_NO_TAG
        + packet_formats::ipv4::HDR_PREFIX_LEN
        + packet_formats::udp::HEADER_BYTES
        + payload_len
}

/// Packet rate (packets/s) required to sustain `TARGET_BPS` at `wire_bytes` per packet.
pub fn packets_per_second_for_1gbps(wire_bytes: usize) -> f64 {
    let bits_per_packet = (wire_bytes as f64) * 8.0;
    (TARGET_BPS as f64) / bits_per_packet
}

/// Number of packets representing `duration` of traffic at `TARGET_BPS`.
pub fn packets_for_rate(wire_bytes: usize, duration: core::time::Duration) -> u64 {
    let batch_bits = TARGET_BPS.saturating_mul(duration.as_millis() as u64) / 1000;
    let batch_bytes = batch_bits / 8;
    (batch_bytes / wire_bytes as u64).max(1)
}

/// Total on-wire bytes for `packet_count` frames of `wire_bytes` each.
pub fn total_wire_bytes(wire_bytes: usize, packet_count: u64) -> u64 {
    wire_bytes as u64 * packet_count
}

struct PreparedFrame {
    template: Vec<u8>,
}

fn build_ethernet_ipv4_udp_frame(payload_len: usize) -> PreparedFrame {
    let payload = vec![0u8; payload_len];
    let udp = UdpPacketBuilder::new(REMOTE_IP, LOCAL_IP, Some(REMOTE_PORT), LOCAL_PORT);
    let ip = Ipv4PacketBuilder::new(REMOTE_IP, LOCAL_IP, 64, Ipv4Proto::Proto(IpProto::Udp));
    let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
    let buffer = Buf::new(payload, ..)
        .wrap_in(udp)
        .wrap_in(ip)
        .wrap_in(eth)
        .serialize_vec_outer(&mut NetworkSerializationContext::default())
        .expect("serialize IPS benchmark frame")
        .into_inner()
        .into_inner();
    PreparedFrame { template: buffer }
}

#[derive(Default)]
struct NoopIpsBindings {
    datagrams: u64,
}

impl IpsReceiveBindingsContext<FakeDeviceId> for NoopIpsBindings {
    fn receive_udp_datagram(
        &mut self,
        _device_id: &FakeDeviceId,
        _view: ReceivedUdpDatagramView,
    ) -> Result<(), IpsReceiveError> {
        self.datagrams += 1;
        Ok(())
    }
}

/// How [`OverwriteIpsBindings`] rewrites the UDP payload after ingress.
#[derive(Clone, Copy, Debug)]
pub enum OverwriteMode {
    /// Same-length patch via [`UdpOverwriter::overwrite_payload_in_place`].
    InPlace,
    /// Shrink to half the original payload via [`UdpOverwriter::overwrite_payload`].
    ShrinkHalf,
}

struct OverwriteIpsBindings {
    datagrams: u64,
    mode: OverwriteMode,
    replacement: Vec<u8>,
}

impl OverwriteIpsBindings {
    fn new(payload_len: usize, mode: OverwriteMode) -> Self {
        let replacement_len = match mode {
            OverwriteMode::InPlace => payload_len,
            OverwriteMode::ShrinkHalf => payload_len / 2,
        };
        Self {
            datagrams: 0,
            mode,
            replacement: vec![0xBB; replacement_len],
        }
    }
}

impl IpsReceiveBindingsContext<FakeDeviceId> for OverwriteIpsBindings {
    fn receive_udp_datagram(
        &mut self,
        _device_id: &FakeDeviceId,
        mut view: ReceivedUdpDatagramView,
    ) -> Result<(), IpsReceiveError> {
        match self.mode {
            OverwriteMode::InPlace => {
                view.udp_overwriter()
                    .overwrite_payload_in_place(&self.replacement)
                    .expect("in-place overwrite");
            }
            OverwriteMode::ShrinkHalf => {
                view.udp_overwriter()
                    .overwrite_payload(&self.replacement)
                    .expect("shrink overwrite");
            }
        }
        self.datagrams += 1;
        Ok(())
    }
}

struct BenchmarkCtx {
    state: IpsState,
    bindings: NoopIpsBindings,
    device_id: FakeDeviceId,
}

fn setup_benchmark_ctx() -> BenchmarkCtx {
    BenchmarkCtx {
        state: IpsState::new(),
        bindings: NoopIpsBindings::default(),
        device_id: FakeDeviceId,
    }
}

fn receive_ips_frame(ctx: &mut BenchmarkCtx, template: &[u8]) {
    let frame = Buf::new(template.to_vec(), ..);
    let result = process_ethernet_frame(
        &ctx.state,
        &mut ctx.bindings,
        &ctx.device_id,
        frame,
    );
    assert!(result.is_ok(), "IPS ingress must consume valid UDP/IPv4 Ethernet frames");
}

struct OverwriteBenchmarkCtx {
    state: IpsState,
    bindings: OverwriteIpsBindings,
    device_id: FakeDeviceId,
}

fn setup_overwrite_benchmark_ctx(payload_len: usize, mode: OverwriteMode) -> OverwriteBenchmarkCtx {
    OverwriteBenchmarkCtx {
        state: IpsState::new(),
        bindings: OverwriteIpsBindings::new(payload_len, mode),
        device_id: FakeDeviceId,
    }
}

fn receive_ips_frame_with_overwrite(ctx: &mut OverwriteBenchmarkCtx, template: &[u8]) {
    let frame = Buf::new(template.to_vec(), ..);
    let result = process_ethernet_frame(
        &ctx.state,
        &mut ctx.bindings,
        &ctx.device_id,
        frame,
    );
    assert!(result.is_ok(), "IPS ingress with overwrite must succeed");
}

fn register_payload_benches(group: &mut BenchmarkGroup<'_, WallTime>, payload_sizes: &[usize]) {
    for &payload_len in payload_sizes {
        let frame = build_ethernet_ipv4_udp_frame(payload_len);
        let wire_bytes = frame.template.len();
        let packet_count = packets_for_rate(wire_bytes, BATCH_DURATION);
        let batch_bytes = total_wire_bytes(wire_bytes, packet_count);
        let pps = packets_per_second_for_1gbps(wire_bytes);

        let batch_ms = BATCH_DURATION.as_millis();
        let base = format!(
            "ipv4/ips/recv/{payload_len}B-payload/{packet_count}pkts/{batch_ms}ms/{TARGET_GBPS:.2}Gbps/{pps:.0}pps-required"
        );

        group.throughput(Throughput::Bytes(batch_bytes));
        group.bench_function(format!("{base}/bytes"), |bencher| {
            let mut ctx = setup_benchmark_ctx();

            bencher.iter(|| {
                for _ in 0..packet_count {
                    receive_ips_frame(&mut ctx, &frame.template);
                }
            });
        });

        group.throughput(Throughput::Elements(1));
        group.bench_function(format!("{base}/per-packet"), |bencher| {
            let mut ctx = setup_benchmark_ctx();

            bencher.iter(|| {
                receive_ips_frame(&mut ctx, &frame.template);
            });
        });

        group.throughput(Throughput::Bytes(1));
    }
}

/// Registers IPS ingress throughput benchmarks at [`TARGET_GBPS`] Gbps for all [`PAYLOAD_SIZES`].
pub fn add_ips_receive_benches(group: &mut BenchmarkGroup<'_, WallTime>) {
    register_payload_benches(group, PAYLOAD_SIZES);
}

/// Registers IPS ingress benchmarks focused on small attack-sized datagrams.
pub fn add_ips_attack_benches(group: &mut BenchmarkGroup<'_, WallTime>) {
    register_payload_benches(group, ATTACK_PAYLOAD_SIZES);
}

fn register_overwrite_benches(
    group: &mut BenchmarkGroup<'_, WallTime>,
    payload_sizes: &[usize],
    mode: OverwriteMode,
) {
    let mode_label = match mode {
        OverwriteMode::InPlace => "in-place",
        OverwriteMode::ShrinkHalf => "shrink-half",
    };

    for &payload_len in payload_sizes {
        if matches!(mode, OverwriteMode::ShrinkHalf) && payload_len < 2 {
            continue;
        }

        let frame = build_ethernet_ipv4_udp_frame(payload_len);
        let wire_bytes = frame.template.len();
        let pps = packets_per_second_for_1gbps(wire_bytes);
        let replacement_len = match mode {
            OverwriteMode::InPlace => payload_len,
            OverwriteMode::ShrinkHalf => payload_len / 2,
        };

        let base = format!(
            "ipv4/ips/recv+overwrite/{mode_label}/{payload_len}B->{replacement_len}B/{TARGET_GBPS:.2}Gbps/{pps:.0}pps-required"
        );

        group.throughput(Throughput::Elements(1));
        group.bench_function(format!("{base}/per-packet"), |bencher| {
            let mut ctx = setup_overwrite_benchmark_ctx(payload_len, mode);

            bencher.iter(|| {
                receive_ips_frame_with_overwrite(&mut ctx, &frame.template);
            });
        });
    }
}

/// Registers end-to-end receive + [`UdpOverwriter`] benchmarks.
pub fn add_ips_overwrite_benches(group: &mut BenchmarkGroup<'_, WallTime>) {
    register_overwrite_benches(group, ATTACK_PAYLOAD_SIZES, OverwriteMode::InPlace);
    register_overwrite_benches(group, ATTACK_PAYLOAD_SIZES, OverwriteMode::ShrinkHalf);
}

fn deliver_udp_view(template: &[u8]) -> ReceivedUdpDatagramView {
    struct Capture {
        view: Option<ReceivedUdpDatagramView>,
    }

    impl IpsReceiveBindingsContext<FakeDeviceId> for Capture {
        fn receive_udp_datagram(
            &mut self,
            _device_id: &FakeDeviceId,
            view: ReceivedUdpDatagramView,
        ) -> Result<(), IpsReceiveError> {
            self.view = Some(view);
            Ok(())
        }
    }

    let state = IpsState::new();
    let mut capture = Capture { view: None };
    process_ethernet_frame(
        &state,
        &mut capture,
        &FakeDeviceId,
        Buf::new(template.to_vec(), ..),
    )
    .expect("deliver view");
    capture.view.expect("view delivered")
}

fn bench_udp_ipv4_checksums(payload_len: usize) {
    let src = LOCAL_IP;
    let dst = REMOTE_IP;
    let mut udp_segment = vec![0u8; packet_formats::udp::HEADER_BYTES + payload_len];
    let udp_len = udp_segment.len();
    udp_segment[4..6].copy_from_slice(&u16::try_from(udp_len).unwrap_or(u16::MAX).to_be_bytes());

    let mut udp_checksum = Checksum::new();
    udp_checksum.add_bytes(&src.ipv4_bytes());
    udp_checksum.add_bytes(&dst.ipv4_bytes());
    udp_checksum.add_bytes(&[0, IpProto::Udp.into()]);
    udp_checksum.add_bytes(&udp_segment.len().to_be_bytes()[..2]);
    udp_checksum.add_bytes(&udp_segment);
    let udp = udp_checksum.checksum();

    let mut ip_checksum = Checksum::new();
    ip_checksum.add_bytes(&[0u8; packet_formats::ipv4::HDR_PREFIX_LEN]);
    let ip = ip_checksum.checksum();

    black_box((udp, ip));
}

/// Isolated checksum and overwrite-only benchmarks for cost breakdown.
pub fn add_ips_overwrite_breakdown_benches(group: &mut BenchmarkGroup<'_, WallTime>) {
    for &payload_len in &[32, 64] {
        group.bench_function(format!("checksum/udp+ipv4/{payload_len}B-payload"), |bencher| {
            bencher.iter(|| bench_udp_ipv4_checksums(payload_len));
        });
    }

    for &payload_len in &[64] {
        let frame = build_ethernet_ipv4_udp_frame(payload_len);
        group.bench_function(format!("deliver-only/{payload_len}B-payload"), |bencher| {
            bencher.iter(|| deliver_udp_view(&frame.template));
        });
    }

    for &(payload_len, mode) in &[(64, OverwriteMode::InPlace), (64, OverwriteMode::ShrinkHalf)] {
        let frame = build_ethernet_ipv4_udp_frame(payload_len);
        let replacement_len = match mode {
            OverwriteMode::InPlace => payload_len,
            OverwriteMode::ShrinkHalf => payload_len / 2,
        };
        let replacement = vec![0xBB; replacement_len];
        let label = match mode {
            OverwriteMode::InPlace => "in-place",
            OverwriteMode::ShrinkHalf => "shrink-half",
        };

        group.bench_function(
            format!("overwrite-only/{label}/{payload_len}B->{replacement_len}B"),
            |bencher| {
                bencher.iter(|| {
                    let mut view = deliver_udp_view(&frame.template);
                    match mode {
                        OverwriteMode::InPlace => view
                            .udp_overwriter()
                            .overwrite_payload_in_place(&replacement)
                            .expect("in-place"),
                        OverwriteMode::ShrinkHalf => view
                            .udp_overwriter()
                            .overwrite_payload(&replacement)
                            .expect("shrink"),
                    }
                });
            },
        );
    }
}

/// Hot loop for CPU profiling (perf / samply).
pub fn profile_hot_loop(payload_len: usize, batches: Option<u64>) {
    let wire_bytes = ethernet_ipv4_udp_wire_bytes(payload_len);
    let packet_count = packets_for_rate(wire_bytes, BATCH_DURATION);
    let frame = build_ethernet_ipv4_udp_frame(payload_len);
    let mut ctx = setup_benchmark_ctx();

    let mut batch = 0u64;
    loop {
        if batches.is_some_and(|limit| batch >= limit) {
            break;
        }
        batch += 1;
        for _ in 0..packet_count {
            receive_ips_frame(&mut ctx, &frame.template);
        }
    }
}

/// Registers all IPS ingress throughput benchmarks.
pub fn add_benches(c: &mut Criterion) {
    let mut attack = c.benchmark_group("netstack3/ips/attack_throughput");
    attack.warm_up_time(core::time::Duration::from_millis(500));
    attack.measurement_time(core::time::Duration::from_secs(3));
    attack.sample_size(50);
    add_ips_attack_benches(&mut attack);
    attack.finish();

    let mut group = c.benchmark_group("netstack3/ips/receive_throughput");
    group.warm_up_time(core::time::Duration::from_millis(500));
    group.measurement_time(core::time::Duration::from_secs(3));
    group.sample_size(50);
    add_ips_receive_benches(&mut group);
    group.finish();

    let mut overwrite = c.benchmark_group("netstack3/ips/overwrite_throughput");
    overwrite.warm_up_time(core::time::Duration::from_millis(500));
    overwrite.measurement_time(core::time::Duration::from_secs(3));
    overwrite.sample_size(50);
    add_ips_overwrite_benches(&mut overwrite);
    overwrite.finish();

    let mut breakdown = c.benchmark_group("netstack3/ips/overwrite_breakdown");
    breakdown.warm_up_time(core::time::Duration::from_millis(500));
    breakdown.measurement_time(core::time::Duration::from_secs(3));
    breakdown.sample_size(50);
    add_ips_overwrite_breakdown_benches(&mut breakdown);
    breakdown.finish();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_64b_requires_over_1m_pps_for_1gbps() {
        let wire = ethernet_ipv4_udp_wire_bytes(64);
        let pps = packets_per_second_for_1gbps(wire);
        assert!(pps > 1_000_000.0, "64B attack traffic exceeds 1 Mpps at 1 Gbps: {pps}");
    }

    #[test]
    fn frame_sizes_match_on_wire_layout() {
        for &payload_len in ATTACK_PAYLOAD_SIZES {
            let frame = build_ethernet_ipv4_udp_frame(payload_len);
            assert!(
                frame.template.len() >= ethernet_ipv4_udp_wire_bytes(payload_len),
                "payload {payload_len}: frame {} < minimum {}",
                frame.template.len(),
                ethernet_ipv4_udp_wire_bytes(payload_len),
            );
        }
    }

    #[test]
    fn smoke_ips_receive_zero_payload() {
        let frame = build_ethernet_ipv4_udp_frame(0);
        let mut ctx = setup_benchmark_ctx();
        receive_ips_frame(&mut ctx, &frame.template);
        assert_eq!(ctx.bindings.datagrams, 1);
    }

    #[test]
    fn packets_for_rate_matches_wire_volume() {
        let wire = ethernet_ipv4_udp_wire_bytes(128);
        let count = packets_for_rate(wire, BATCH_DURATION);
        let total = total_wire_bytes(wire, count);
        // Integer division in `packets_for_rate` may be slightly below the exact bit budget.
        assert!(total <= TARGET_BPS / 8);
        assert!(total + wire as u64 > TARGET_BPS / 8);
    }

    #[test]
    fn smoke_ips_receive_with_in_place_overwrite() {
        let payload_len = 64;
        let frame = build_ethernet_ipv4_udp_frame(payload_len);
        let mut ctx = setup_overwrite_benchmark_ctx(payload_len, OverwriteMode::InPlace);
        receive_ips_frame_with_overwrite(&mut ctx, &frame.template);
        assert_eq!(ctx.bindings.datagrams, 1);
    }

    #[test]
    fn smoke_ips_receive_with_shrink_overwrite() {
        let payload_len = 64;
        let frame = build_ethernet_ipv4_udp_frame(payload_len);
        let mut ctx = setup_overwrite_benchmark_ctx(payload_len, OverwriteMode::ShrinkHalf);
        receive_ips_frame_with_overwrite(&mut ctx, &frame.template);
        assert_eq!(ctx.bindings.datagrams, 1);
    }

    #[test]
    fn smoke_ips_receive_batch() {
        let payload_len = 64;
        let wire_bytes = ethernet_ipv4_udp_wire_bytes(payload_len);
        let packet_count =
            packets_for_rate(wire_bytes, core::time::Duration::from_millis(1)).min(32);
        let frame = build_ethernet_ipv4_udp_frame(payload_len);
        let mut ctx = setup_benchmark_ctx();
        for _ in 0..packet_count {
            receive_ips_frame(&mut ctx, &frame.template);
        }
        assert_eq!(ctx.bindings.datagrams, packet_count);
    }
}
