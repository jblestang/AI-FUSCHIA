// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Example: detect RFC 5722 overlapping IP fragments at Layer 7.
//!
//! Builds two UDP fragments of the same datagram whose byte ranges overlap,
//! feeds them through the IPS ingress path, and inspects the delivered view for
//! overlap metadata via [`netstack3_ips::analysis::detect_rfc5722_overlap`].
//!
//! ```text
//! cargo run -p netstack3-ips --features testutils --example detect_ip_overlap
//! ```

use net_types::ethernet::Mac;
use net_types::ip::Ipv4Addr;
use netstack3_base::testutil::FakeDeviceId;
use netstack3_base::NetworkSerializationContext;
use netstack3_ips::analysis::{Rfc5722Overlap, detect_rfc5722_overlap};
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
const FRAGMENT_ID: u16 = 0x00_05;
const FRAGMENT_BODY_LEN: usize = 104;

/// Example L7 handler that records overlap detection results.
struct ExampleIpsHandler {
    last_view: Option<ReceivedUdpDatagramView>,
    overlap: Option<Rfc5722Overlap>,
}

impl IpsReceiveBindingsContext<FakeDeviceId> for ExampleIpsHandler {
    fn receive_udp_datagram(
        &mut self,
        _device_id: &FakeDeviceId,
        view: ReceivedUdpDatagramView,
    ) -> Result<(), IpsReceiveError> {
        self.overlap = detect_rfc5722_overlap(&view);
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
    // First fragment: offset 12 (96 bytes into IP payload), 104-byte body.
    let first_body = vec![0xAA; FRAGMENT_BODY_LEN];
    // Second fragment: offset 6 (48 bytes) — overlaps the tail of the first.
    let second_body = vec![0xBB; FRAGMENT_BODY_LEN];

    let frag0 = build_ipv4_udp_fragment(
        FragmentOffset::new(12).expect("aligned offset"),
        true,
        first_body,
    );
    let frag1 = build_ipv4_udp_fragment(
        FragmentOffset::new(6).expect("aligned offset"),
        true,
        second_body,
    );

    let state = IpsState::new();
    let mut handler = ExampleIpsHandler { last_view: None, overlap: None };
    let device_id = FakeDeviceId;

    for frame in [frag0, frag1] {
        process_ethernet_frame(&state, &mut handler, &device_id, frame)
            .expect("IPS ingress accepts overlapping UDP fragments for L7 inspection");
    }

    let view = handler.last_view.as_ref().expect("L7 delivery after overlap abort");
    assert_eq!(
        view.ip_fragment_metadata().reassembly_outcome,
        ReassemblyOutcome::AbortedRfc5722Overlap,
        "RFC 5722 overlap must abort reassembly"
    );
    assert!(
        view.payload_slices().is_empty(),
        "aborted reassembly delivers empty payload to L7"
    );
    assert_eq!(view.ip_fragments().len(), 2, "both fragment frames retained for inspection");

    let overlap = handler
        .overlap
        .or_else(|| detect_rfc5722_overlap(view))
        .expect("overlapping fragments must be detected");

    println!("Detected RFC 5722 IP fragment overlap:");
    println!("  identification: 0x{:04x}", overlap.identification);
    println!(
        "  overlapping fragment index: {} (offset {}, {} bytes into IP payload)",
        overlap.conflicting_fragment_index,
        overlap.fragment_offset,
        overlap.fragment_offset as u32 * 8,
    );
    if overlap.conflicting_fragment_index > 0 {
        println!(
            "  prior fragment index: {} (offset {})",
            overlap.conflicting_fragment_index - 1,
            view.ip_fragments()[overlap.conflicting_fragment_index - 1].fragment_offset,
        );
    }
    println!(
        "  fragment events: {:?}",
        view.ip_fragment_metadata().events,
    );
    println!("Policy: abort reassembly, deliver metadata + zero-copy frames, empty payload.");
}
