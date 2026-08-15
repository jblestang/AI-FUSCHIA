// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Example: reassemble interleaved fragmented UDP datagrams from multiple sources.
//!
//! The fragment cache keys each assembly by `(src_ip, dst_ip, identification, UDP)`.
//! Interleaved first fragments from three sources are tracked in parallel until
//! each datagram completes.
//!
//! ```text
//! cargo run -p netstack3-ips --features testutils --example multi_source_fragments
//! ```

use core::num::NonZeroU16;

use net_types::ethernet::Mac;
use net_types::ip::Ipv4Addr;
use netstack3_base::testutil::FakeDeviceId;
use netstack3_base::NetworkSerializationContext;
use netstack3_ips::{
    IpsReceiveBindingsContext, IpsReceiveError, IpsState, ReceivedTcpSegmentView,
    ReassemblyOutcome, process_ethernet_frame,
};
use packet::{Buf, NestableSerializer as _, Serializer};
use packet_formats::ethernet::{EtherType, EthernetFrameBuilder};
use packet_formats::ip::{FragmentOffset, IpProto, Ipv4Proto};

const DST: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
const LOCAL_PORT: NonZeroU16 = NonZeroU16::new(100).unwrap();
const REMOTE_PORT: NonZeroU16 = NonZeroU16::new(200).unwrap();
const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
const FRAGMENT_BODY_LEN: usize = 104;
const PAYLOAD_LEN: usize = 200;

struct Capture {
    delivered: usize,
}

impl IpsReceiveBindingsContext<FakeDeviceId> for Capture {
    fn receive_udp_datagram(
        &mut self,
        _device: &FakeDeviceId,
        view: netstack3_ips::ReceivedUdpDatagramView,
    ) -> Result<(), IpsReceiveError> {
        assert_eq!(
            view.ip_fragment_metadata().reassembly_outcome,
            ReassemblyOutcome::Complete
        );
        assert_eq!(view.payload_slices().iter().map(|s| s.len()).sum::<usize>(), PAYLOAD_LEN);
        self.delivered += 1;
        Ok(())
    }

    fn receive_tcp_segment(
        &mut self,
        _device: &FakeDeviceId,
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
}

fn main() {
    let state = IpsState::new();
    let mut handler = Capture { delivered: 0 };
    let udp_total = 8 + PAYLOAD_LEN;

    let streams = [(2_u8, 0x1001_u16), (3, 0x1002), (4, 0x1003)];

    for &(src_host, frag_id) in &streams {
        let src = Ipv4Addr::new([192, 0, 2, src_host]);
        let mut first_body = vec![
            (REMOTE_PORT.get() >> 8) as u8,
            (REMOTE_PORT.get() & 0xff) as u8,
            (LOCAL_PORT.get() >> 8) as u8,
            (LOCAL_PORT.get() & 0xff) as u8,
            (udp_total >> 8) as u8,
            (udp_total & 0xff) as u8,
            0,
            0,
        ];
        first_body.resize(FRAGMENT_BODY_LEN, src_host);

        let frag0 = build_fragment(src, FragmentOffset::ZERO, true, first_body, frag_id);
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frag0).expect("frag 0");
    }

    let second_len = udp_total - FRAGMENT_BODY_LEN;
    for &(src_host, frag_id) in &streams {
        let src = Ipv4Addr::new([192, 0, 2, src_host]);
        let frag1 = build_fragment(
            src,
            FragmentOffset::new(13).unwrap(),
            false,
            vec![src_host; second_len],
            frag_id,
        );
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frag1).expect("frag 1");
    }

    println!("Delivered {} reassembled datagrams", handler.delivered);
    assert_eq!(handler.delivered, 3);
}

fn build_fragment(
    src: Ipv4Addr,
    fragment_offset: FragmentOffset,
    more_fragments: bool,
    body: Vec<u8>,
    fragment_id: u16,
) -> Buf<Vec<u8>> {
    let mut ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
        src,
        DST,
        64,
        Ipv4Proto::Proto(IpProto::Udp),
    );
    ip.id(fragment_id);
    ip.mf_flag(more_fragments);
    ip.fragment_offset(fragment_offset);
    let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
    let bytes = Buf::new(body, ..)
        .wrap_in(ip)
        .wrap_in(eth)
        .serialize_vec_outer(&mut NetworkSerializationContext::default())
        .expect("serialize")
        .into_inner()
        .into_inner();
    Buf::new(bytes, ..)
}
