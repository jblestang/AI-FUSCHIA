// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Example: detect IPv4 TOS (DSCP+ECN) modification between IP fragments at Layer 7.
//!
//! Builds two non-overlapping UDP fragments of the same datagram where the second
//! fragment carries a different TOS byte, feeds them through the IPS ingress path,
//! and runs [`netstack3_ips::analysis::detect_tos_mismatch`] on the delivered view.
//!
//! ```text
//! cargo run -p netstack3-ips --features testutils --example detect_tos_mismatch
//! ```

use net_types::ethernet::Mac;
use net_types::ip::Ipv4Addr;
use netstack3_base::testutil::FakeDeviceId;
use netstack3_base::NetworkSerializationContext;
use netstack3_ips::analysis::{detect_tos_mismatch, TosMismatch};
use netstack3_ips::{
    IpsReceiveBindingsContext, IpsReceiveError, IpsState, ReceivedTcpSegmentView,
    ReceivedUdpDatagramView, ReassemblyOutcome, process_ethernet_frame,
};
use packet::{Buf, NestableSerializer as _, Serializer};
use packet_formats::ethernet::{EtherType, EthernetFrameBuilder};
use packet_formats::ip::{DscpAndEcn, FragmentOffset, IpProto, Ipv4Proto};
use packet_formats::ipv4::Ipv4PacketBuilder;

const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);
const FRAGMENT_ID: u16 = 0x00_2a;
const FRAGMENT_BODY_LEN: usize = 104;

/// Example L7 handler that records the last datagram and any detected TOS mismatch.
struct ExampleIpsHandler {
    last_view: Option<ReceivedUdpDatagramView>,
    tos_mismatch: Option<TosMismatch>,
}

impl IpsReceiveBindingsContext<FakeDeviceId> for ExampleIpsHandler {
    fn receive_udp_datagram(
        &mut self,
        _device_id: &FakeDeviceId,
        view: ReceivedUdpDatagramView,
    ) -> Result<(), IpsReceiveError> {
        self.tos_mismatch = detect_tos_mismatch(&view);
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
    dscp_and_ecn: DscpAndEcn,
    body: Vec<u8>,
) -> Buf<Vec<u8>> {
    let mut ip = Ipv4PacketBuilder::new(REMOTE_IP, LOCAL_IP, 64, Ipv4Proto::Proto(IpProto::Udp));
    ip.id(FRAGMENT_ID);
    ip.dscp_and_ecn(dscp_and_ecn);
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
    // First fragment: TOS = 0 (best effort). Contains UDP header + payload prefix.
    let mut first_body = vec![
        0x00, 0xc8, 0x00, 0x64, 0x00, 0x08, 0x00, 0x00, // UDP header
    ];
    first_body.resize(FRAGMENT_BODY_LEN, 0xAA);

    // Second fragment: TOS = EF (DSCP 46). Payload continuation only.
    let second_body = vec![0xBB; FRAGMENT_BODY_LEN];

    let frag0 = build_ipv4_udp_fragment(
        FragmentOffset::ZERO,
        true,
        DscpAndEcn::default(),
        first_body,
    );
    let frag1 = build_ipv4_udp_fragment(
        FragmentOffset::new(13).expect("aligned offset"),
        false,
        DscpAndEcn::new(0x2e, 0), // EF — raw TOS byte 0xB8
        second_body,
    );

    let state = IpsState::new();
    let mut handler = ExampleIpsHandler { last_view: None, tos_mismatch: None };
    let device_id = FakeDeviceId;

    for frame in [frag0, frag1] {
        process_ethernet_frame(&state, &mut handler, &device_id, frame)
            .expect("IPS ingress accepts valid UDP fragments");
    }

    let view = handler.last_view.as_ref().expect("L7 delivery after reassembly");
    assert_eq!(
        view.ip_fragment_metadata().reassembly_outcome,
        ReassemblyOutcome::Complete,
        "non-overlapping fragments should reassemble"
    );
    assert_eq!(view.ip_fragments().len(), 2, "both fragment frames retained");

    let mismatch = handler
        .tos_mismatch
        .or_else(|| detect_tos_mismatch(view))
        .expect("TOS mismatch between fragments must be detected");

    println!("Detected TOS evasion between fragments:");
    println!("  identification: 0x{:04x}", mismatch.identification);
    println!(
        "  fragment indices: {} (TOS {:?}) vs {} (TOS {:?})",
        mismatch.first_fragment_index,
        mismatch.expected,
        mismatch.conflicting_fragment_index,
        mismatch.observed,
    );
    println!(
        "  raw TOS bytes: 0x{:02x} -> 0x{:02x}",
        mismatch.expected.raw(),
        mismatch.observed.raw(),
    );
    println!("Policy: drop or alert even when reassembly succeeded (RFC 791 violation).");
}
