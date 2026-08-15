// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! UDP receive throughput benchmark support.

use alloc::format;
use core::num::NonZeroU16;

use net_types::Witness as _;
use net_types::ip::{Ipv4, Ipv4Addr};
use net_types::{SpecifiedAddr, ZonedAddr};
use netstack3_base::testutil::FakeDeviceId;
use netstack3_base::NetworkSerializationContext;
use netstack3_ip::testutil::FakeIpHeaderInfo;
use netstack3_ip::{IpTransportContext, LocalDeliveryPacketInfo};
use packet::{Buf, NestablePacketBuilder as _, Serializer};
use packet_formats::udp::UdpPacketBuilder;

use crate::internal::base::testutils::{
    BaseTestIpExt as _, FakeUdpBindingsCtx, UdpFakeDeviceCoreCtx, UdpFakeDeviceCtx, local_ip,
    remote_ip,
};
use crate::{
    DualStackUdpSocketId, UdpApi, UdpIpTransportContext, UdpPacketMeta, UdpRemotePort,
};

struct BenchmarkCtx {
    ctx: UdpFakeDeviceCtx,
    early_demux_socket: DualStackUdpSocketId<
        Ipv4,
        netstack3_base::testutil::FakeWeakDeviceId<FakeDeviceId>,
        FakeUdpBindingsCtx<FakeDeviceId>,
    >,
}

fn setup_connected_benchmark_ctx(packet: &PreparedPacket) -> BenchmarkCtx {
    let mut ctx = UdpFakeDeviceCtx::with_core_ctx(UdpFakeDeviceCoreCtx::new_fake_device::<Ipv4>());
    let mut api = UdpApi::<Ipv4, _>::new(ctx.as_mut());
    let socket = api.create();
    api.listen(&socket, Some(ZonedAddr::Unzoned(local_ip::<Ipv4>())), Some(LOCAL_PORT))
        .expect("listen failed");
    api.connect(
        &socket,
        Some(ZonedAddr::Unzoned(remote_ip::<Ipv4>())),
        UdpRemotePort::from(REMOTE_PORT),
    )
    .expect("connect failed");

    let UdpPacketMeta { src_ip, dst_ip, .. } = packet.meta;
    let early_demux_socket =
        <UdpIpTransportContext as IpTransportContext<Ipv4, _, _>>::early_demux(
            ctx.as_mut().core_ctx,
            &FakeDeviceId,
            src_ip,
            dst_ip,
            packet.buffer.as_ref(),
        )
        .expect("early_demux must resolve connected socket for benchmark traffic");

    BenchmarkCtx { ctx, early_demux_socket }
}

/// Target receive rate for the benchmark (1 Gbps).
pub const TARGET_GBPS: f64 = 1.0;

/// Target receive rate in bits per second.
pub const TARGET_BPS: u64 = 1_000_000_000;

/// Duration of traffic simulated per benchmark iteration (1 second @ [`TARGET_BPS`]).
pub const BATCH_DURATION: core::time::Duration = core::time::Duration::from_millis(1000);

const LOCAL_PORT: NonZeroU16 = NonZeroU16::new(100).unwrap();
const REMOTE_PORT: NonZeroU16 = NonZeroU16::new(200).unwrap();

/// UDP payload sizes exercised by the benchmark (bytes).
pub const PAYLOAD_SIZES: &[usize] = &[64, 128, 256, 512, 1024, 1472, 4096, 8192, 9000];

/// IPv4 wire size for a UDP datagram with the given payload (header + UDP + payload).
pub fn ipv4_udp_wire_bytes(payload_len: usize) -> usize {
    packet_formats::ipv4::HDR_PREFIX_LEN + packet_formats::udp::HEADER_BYTES + payload_len
}

/// Number of packets representing `duration` seconds of traffic at [`TARGET_BPS`].
pub fn packets_for_rate(wire_bytes: usize, duration: core::time::Duration) -> u64 {
    let batch_bits = TARGET_BPS.saturating_mul(duration.as_millis() as u64) / 1000;
    let batch_bytes = batch_bits / 8;
    (batch_bytes / wire_bytes as u64).max(1)
}

/// Total bytes transferred when sending `packet_count` packets of `wire_bytes` each.
pub fn total_wire_bytes(wire_bytes: usize, packet_count: u64) -> u64 {
    wire_bytes as u64 * packet_count
}

struct PreparedPacket {
    buffer: alloc::vec::Vec<u8>,
    meta: UdpPacketMeta<Ipv4>,
}

fn build_ipv4_udp_packet(payload_len: usize) -> PreparedPacket {
    let local_ip: Ipv4Addr = local_ip::<Ipv4>().get();
    let remote_ip: Ipv4Addr = remote_ip::<Ipv4>().get();
    let payload = alloc::vec![0u8; payload_len];
    let meta = UdpPacketMeta::<Ipv4> {
        src_ip: remote_ip,
        src_port: Some(REMOTE_PORT),
        dst_ip: local_ip,
        dst_port: LOCAL_PORT,
        dscp_and_ecn: Default::default(),
    };
    let udp = UdpPacketBuilder::new(remote_ip, local_ip, Some(REMOTE_PORT), LOCAL_PORT);
    let buffer = udp
        .wrap_body(Buf::new(payload, ..))
        .serialize_vec_outer(&mut NetworkSerializationContext::default())
        .expect("serialize benchmark packet")
        .into_inner()
        .into_inner();
    PreparedPacket { buffer, meta }
}

fn receive_ipv4_udp_packet(
    core_ctx: &mut UdpFakeDeviceCoreCtx,
    bindings_ctx: &mut FakeUdpBindingsCtx<FakeDeviceId>,
    packet: &mut PreparedPacket,
    early_demux_socket: Option<
        &DualStackUdpSocketId<
            Ipv4,
            netstack3_base::testutil::FakeWeakDeviceId<FakeDeviceId>,
            FakeUdpBindingsCtx<FakeDeviceId>,
        >,
    >,
) {
    let PreparedPacket { buffer, meta } = packet;
    let UdpPacketMeta { src_ip, dst_ip, dst_port, dscp_and_ecn, .. } = meta;

    let result = <UdpIpTransportContext as IpTransportContext<Ipv4, _, _>>::receive_ip_packet(
        core_ctx,
        bindings_ctx,
        &FakeDeviceId,
        Ipv4::into_recv_src_addr(*src_ip),
        SpecifiedAddr::new(*dst_ip).unwrap(),
        Buf::new(&mut buffer[..], ..),
        &mut LocalDeliveryPacketInfo {
            header_info: FakeIpHeaderInfo { dscp_and_ecn: *dscp_and_ecn, ..Default::default() },
            ..Default::default()
        },
        early_demux_socket.cloned(),
    );
    assert!(result.is_ok(), "receive_ip_packet failed for dst_port={dst_port}");
}

/// Registers UDP receive throughput benchmarks for IPv4 at [`TARGET_GBPS`] Gbps.
pub fn add_benches(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    for &payload_len in PAYLOAD_SIZES {
        let wire_bytes = ipv4_udp_wire_bytes(payload_len);
        let packet_count = packets_for_rate(wire_bytes, BATCH_DURATION);
        let batch_bytes = total_wire_bytes(wire_bytes, packet_count);

        let batch_ms = BATCH_DURATION.as_millis();
        let base = format!(
            "ipv4/recv/{payload_len}B-payload/{packet_count}pkts/{batch_ms}ms/{TARGET_GBPS:.2}Gbps-target"
        );

        group.throughput(criterion::Throughput::Bytes(batch_bytes));
        group.bench_function(format!("{base}/bytes"), |bencher| {
            let mut packet = build_ipv4_udp_packet(payload_len);
            let BenchmarkCtx { mut ctx, early_demux_socket } = setup_connected_benchmark_ctx(&packet);

            bencher.iter(|| {
                let ctx_pair = ctx.as_mut();
                for _ in 0..packet_count {
                    receive_ipv4_udp_packet(
                        ctx_pair.core_ctx,
                        ctx_pair.bindings_ctx,
                        &mut packet,
                        Some(&early_demux_socket),
                    );
                }
            });
        });

        group.throughput(criterion::Throughput::Elements(1));
        group.bench_function(format!("{base}/per-packet"), |bencher| {
            let mut packet = build_ipv4_udp_packet(payload_len);
            let BenchmarkCtx { mut ctx, early_demux_socket } = setup_connected_benchmark_ctx(&packet);

            bencher.iter(|| {
                let ctx_pair = ctx.as_mut();
                receive_ipv4_udp_packet(
                    ctx_pair.core_ctx,
                    ctx_pair.bindings_ctx,
                    &mut packet,
                    Some(&early_demux_socket),
                );
            });
        });

        group.throughput(criterion::Throughput::Bytes(1));
    }
}

/// Runs the UDP receive hot loop for CPU profiling (perf / samply).
pub fn profile_hot_loop(payload_len: usize, batches: Option<u64>) {
    let wire_bytes = ipv4_udp_wire_bytes(payload_len);
    let packet_count = packets_for_rate(wire_bytes, BATCH_DURATION);

    let mut packet = build_ipv4_udp_packet(payload_len);
    let BenchmarkCtx { mut ctx, early_demux_socket } = setup_connected_benchmark_ctx(&packet);

    let mut batch = 0u64;
    loop {
        if batches.is_some_and(|limit| batch >= limit) {
            break;
        }
        batch += 1;
        let ctx_pair = ctx.as_mut();
        for _ in 0..packet_count {
            receive_ipv4_udp_packet(
                ctx_pair.core_ctx,
                ctx_pair.bindings_ctx,
                &mut packet,
                Some(&early_demux_socket),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_for_rate_scales_with_packet_size() {
        let small = packets_for_rate(ipv4_udp_wire_bytes(64), BATCH_DURATION);
        let large = packets_for_rate(ipv4_udp_wire_bytes(9000), BATCH_DURATION);
        assert!(small > large);
        assert_eq!(
            total_wire_bytes(ipv4_udp_wire_bytes(64), small),
            total_wire_bytes(ipv4_udp_wire_bytes(9000), large),
        );
    }
}
