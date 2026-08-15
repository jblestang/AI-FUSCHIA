// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Example IPS agent: detect forced IP segmentation when the path MTU is sufficient.
//!
//! Builds a small UDP datagram that would fit in a single 1500-byte Ethernet frame,
//! deliberately splits it into two IP fragments, feeds them through the IPS ingress
//! path, and flags the unnecessary fragmentation at Layer 7.
//!
//! ```text
//! cargo run -p netstack3-ips --features testutils --example detect_forced_segmentation
//! ```

use net_types::ethernet::Mac;
use net_types::ip::Ipv4Addr;
use netstack3_base::testutil::FakeDeviceId;
use netstack3_base::NetworkSerializationContext;
use netstack3_ips::analysis::{
    ETHERNET_IPV4_MTU, ForcedIpSegmentation, detect_forced_ip_segmentation,
};
use netstack3_ips::{
    IpsReceiveBindingsContext, IpsReceiveError, IpsState, ReceivedTcpSegmentView,
    ReceivedUdpDatagramView, ReassemblyOutcome, process_ethernet_frame,
};
use packet::{Buf, NestableSerializer as _, Serializer};
use packet_formats::ethernet::{EtherType, EthernetFrameBuilder};
use packet_formats::ip::{FragmentOffset, IpProto, Ipv4Proto};
use packet_formats::ipv4::Ipv4PacketBuilder;

const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);
const FRAGMENT_ID: u16 = 0x00_7e;
const FRAGMENT_BODY_LEN: usize = 104;
/// Small UDP payload — entire datagram fits well under standard Ethernet MTU.
const UDP_PAYLOAD_LEN: usize = 200;

/// Example Layer 7 IPS agent with configurable path MTU policy.
struct ForcedSegmentationAgent {
    path_mtu: usize,
    last_view: Option<ReceivedUdpDatagramView>,
    forced_segmentation: Option<ForcedIpSegmentation>,
}

impl ForcedSegmentationAgent {
    fn new(path_mtu: usize) -> Self {
        Self { path_mtu, last_view: None, forced_segmentation: None }
    }
}

impl IpsReceiveBindingsContext<FakeDeviceId> for ForcedSegmentationAgent {
    fn receive_udp_datagram(
        &mut self,
        _device_id: &FakeDeviceId,
        view: ReceivedUdpDatagramView,
    ) -> Result<(), IpsReceiveError> {
        self.forced_segmentation = detect_forced_ip_segmentation(&view, self.path_mtu);
        self.last_view = Some(view);
        Ok(())
    }

    fn receive_tcp_segment(
        &mut self,
        _device_id: &FakeDeviceId,
        _view: ReceivedTcpSegmentView,
    ) -> Result<(), IpsReceiveError> {
        Ok(())
    }
        fn receive_icmp_message(
            &mut self,
            _device_id: &FakeDeviceId,
            _view: netstack3_ips::ReceivedIcmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_igmp_message(
            &mut self,
            _device_id: &FakeDeviceId,
            _view: netstack3_ips::ReceivedIgmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }}

fn build_ipv4_udp_fragment(
    fragment_offset: FragmentOffset,
    more_fragments: bool,
    body: Vec<u8>,
) -> Buf<Vec<u8>> {
    let mut ip = Ipv4PacketBuilder::new(REMOTE_IP, LOCAL_IP, 64, Ipv4Proto::Proto(IpProto::Udp));
    ip.id(FRAGMENT_ID);
    ip.mf_flag(more_fragments);
    ip.fragment_offset(fragment_offset);
    let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
    let bytes = Buf::new(body, ..)
        .wrap_in(ip)
        .wrap_in(eth)
        .serialize_vec_outer(&mut NetworkSerializationContext::default())
        .expect("serialize fragment")
        .into_inner()
        .into_inner();
    Buf::new(bytes, ..)
}

fn main() {
    // First fragment: UDP header + start of payload (well under MTU on its own).
    let mut first_body = vec![
        0x00, 0xc8, 0x00, 0x64, 0x00, 0xd0, 0x00, 0x00, // UDP header, length = 208
    ];
    first_body.resize(FRAGMENT_BODY_LEN, 0xAA);

    // Second fragment: remainder of the small payload.
    let second_len = UDP_PAYLOAD_LEN + 8 - FRAGMENT_BODY_LEN;
    let second_body = vec![0xBB; second_len];

    let frag0 = build_ipv4_udp_fragment(FragmentOffset::ZERO, true, first_body);
    let frag1 = build_ipv4_udp_fragment(
        FragmentOffset::new(13).expect("aligned offset"),
        false,
        second_body,
    );

    let state = IpsState::new();
    let mut agent = ForcedSegmentationAgent::new(ETHERNET_IPV4_MTU);
    let device_id = FakeDeviceId;

    for frame in [frag0, frag1] {
        process_ethernet_frame(&state, &mut agent, &device_id, frame)
            .expect("IPS ingress accepts artificially fragmented UDP");
    }

    let view = agent.last_view.as_ref().expect("L7 delivery after reassembly");
    assert_eq!(
        view.ip_fragment_metadata().reassembly_outcome,
        ReassemblyOutcome::Complete,
        "non-overlapping fragments should reassemble"
    );
    assert_eq!(view.ip_fragments().len(), 2, "attacker sent two fragments");

    let hit = agent
        .forced_segmentation
        .or_else(|| detect_forced_ip_segmentation(view, ETHERNET_IPV4_MTU))
        .expect("forced segmentation must be detected for small split datagram");

    println!("Forced IP segmentation agent alert:");
    println!("  path MTU: {} bytes", hit.path_mtu);
    println!("  reassembled IPv4 datagram: {} bytes (fits in one frame)", hit.ip_datagram_bytes);
    println!("  fragment count: {}", hit.fragment_count);
    println!("  identification: 0x{:04x}", hit.identification);
    println!(
        "  headroom: {} bytes unused below MTU",
        hit.path_mtu.saturating_sub(hit.ip_datagram_bytes),
    );
    println!("Policy: alert or drop — datagram did not require IP fragmentation on this path.");
}
