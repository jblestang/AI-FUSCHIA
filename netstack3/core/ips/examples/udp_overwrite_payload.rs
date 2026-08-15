// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Example: overwrite UDP payload after L7 deep inspection with [`UdpOverwriter`].
//!
//! Receives a UDP datagram, scans the payload, replaces malicious bytes in place,
//! and refreshes UDP/IPv4 lengths and checksums on the backing frame buffer.
//!
//! ```text
//! cargo run -p netstack3-ips --features testutils --example udp_overwrite_payload
//! ```

use core::num::NonZeroU16;

use net_types::ethernet::Mac;
use net_types::ip::Ipv4Addr;
use netstack3_base::testutil::FakeDeviceId;
use netstack3_base::NetworkSerializationContext;
use netstack3_ips::{
    IpsReceiveBindingsContext, IpsReceiveError, IpsState, ReceivedUdpDatagramView,
    process_ethernet_frame,
};
use packet::{Buf, NestableSerializer as _, ParsablePacket, Serializer};
use packet_formats::ethernet::{EtherType, ETHERNET_HDR_LEN_NO_TAG, EthernetFrameBuilder};
use packet_formats::ip::{IpProto, Ipv4Proto};
use packet_formats::ipv4::Ipv4Packet;
use packet_formats::udp::UdpPacketBuilder;

const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);
const LOCAL_PORT: NonZeroU16 = NonZeroU16::new(100).unwrap();
const REMOTE_PORT: NonZeroU16 = NonZeroU16::new(200).unwrap();
/// Simulated attack marker byte in the original payload.
const ATTACK_MARKER: u8 = 0xEE;

/// Example IPS agent: inspect payload, then overwrite with a sanitized version.
struct SanitizingAgent {
    view: Option<ReceivedUdpDatagramView>,
}

impl IpsReceiveBindingsContext<FakeDeviceId> for SanitizingAgent {
    fn receive_udp_datagram(
        &mut self,
        _device: &FakeDeviceId,
        mut view: ReceivedUdpDatagramView,
    ) -> Result<(), IpsReceiveError> {
        let inspected: Vec<u8> = view.payload_slices().iter().flat_map(|s| s.iter().copied()).collect();
        println!(
            "Inspected {} payload bytes (prefix {:02x?})",
            inspected.len(),
            &inspected[..inspected.len().min(8)]
        );

        // Sanitize: drop attack markers (simulated deep analysis outcome).
        let sanitized: Vec<u8> = inspected.into_iter().filter(|b| *b != ATTACK_MARKER).collect();
        assert_eq!(sanitized.len(), 0, "all bytes were attack markers in this demo");

        view.udp_overwriter()
            .overwrite_payload(&sanitized)
            .expect("overwrite payload with updated checksums");

        self.view = Some(view);
        Ok(())
    }
}

fn main() {
    let attack_payload = vec![ATTACK_MARKER; 64];

    let udp = UdpPacketBuilder::new(REMOTE_IP, LOCAL_IP, Some(REMOTE_PORT), LOCAL_PORT);
    let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
        REMOTE_IP,
        LOCAL_IP,
        64,
        Ipv4Proto::Proto(IpProto::Udp),
    );
    let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
    let frame = Buf::new(attack_payload, ..)
        .wrap_in(udp)
        .wrap_in(ip)
        .wrap_in(eth)
        .serialize_vec_outer(&mut NetworkSerializationContext::default())
        .expect("serialize frame")
        .into_inner()
        .into_inner();

    let state = IpsState::new();
    let mut agent = SanitizingAgent { view: None };
    process_ethernet_frame(&state, &mut agent, &FakeDeviceId, Buf::new(frame, ..))
        .expect("IPS ingress");

    let view = agent.view.as_ref().expect("sanitized view");
    let payload_len: usize = view.payload_slices().iter().map(|s| s.len()).sum();
    println!("After overwrite: {payload_len} payload bytes");
    assert_eq!(payload_len, 0);

    let udp_len = view.udp_header().expect("udp header").length;
    assert_eq!(usize::from(udp_len), payload_len + 8);

    let frame = view.eth_frames().next().expect("frame");
    let mut ip_bytes = &frame[ETHERNET_HDR_LEN_NO_TAG..];
    assert!(Ipv4Packet::parse(&mut ip_bytes, ()).is_ok(), "IPv4 checksum valid after overwrite");

    println!("UDP length field: {udp_len}; IPv4 and UDP checksums updated in place.");
}
