// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Example: zero-copy iteration over reassembled UDP payload slices at Layer 7.
//!
//! Sends a fragmented UDP datagram through the IPS ingress path, then walks the
//! delivered [`ReceivedUdpDatagramView::payload_slices`] iovec-style without
//! copying bytes out of the driver-owned frame buffers.
//!
//! ```text
//! cargo run -p netstack3-ips --features testutils --example iterate_payload
//! ```

use net_types::ethernet::Mac;
use net_types::ip::Ipv4Addr;
use netstack3_base::testutil::FakeDeviceId;
use netstack3_base::NetworkSerializationContext;
use netstack3_ips::{
    IpsReceiveBindingsContext, IpsReceiveError, IpsState, ReceivedTcpSegmentView,
    ReceivedUdpDatagramView, ReassemblyOutcome, process_ethernet_frame,
};
use packet::{Buf, NestableSerializer as _, Serializer};
use packet_formats::ethernet::{EtherType, EthernetFrameBuilder};
use packet_formats::ip::{FragmentOffset, IpProto, Ipv4Proto};
use packet_formats::ipv4::Ipv4PacketBuilder;
use packet_formats::udp::HEADER_BYTES;

const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);
const FRAGMENT_ID: u16 = 0x00_31;
const FRAGMENT_BODY_LEN: usize = 104;
const UDP_PAYLOAD_LEN: usize = 200;

/// Summary produced by iterating payload slices in reassembly order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PayloadScan {
    slice_count: usize,
    total_bytes: usize,
    xor_checksum: u8,
}

/// Walks every payload byte via [`ReceivedUdpDatagramView::payload_slices`].
///
/// Each slice is a borrow into the original Ethernet frame buffer; iteration
/// stays within slice bounds — no manual offset arithmetic across fragments.
fn scan_payload_slices(view: &ReceivedUdpDatagramView) -> PayloadScan {
    let slices = view.payload_slices();
    let mut xor_checksum = 0u8;
    let mut total_bytes = 0usize;

    for (slice_index, chunk) in slices.iter().enumerate() {
        println!(
            "  slice {slice_index}: {} bytes @ frame buffer (first=0x{:02x}, last=0x{:02x})",
            chunk.len(),
            chunk.first().copied().unwrap_or(0),
            chunk.last().copied().unwrap_or(0),
        );

        for (offset, &byte) in chunk.iter().enumerate() {
            // In-bounds access: `offset` is always `< chunk.len()`.
            xor_checksum ^= byte;
            total_bytes += 1;

            if offset == 0 || offset + 1 == chunk.len() {
                println!("    byte[{offset}] = 0x{byte:02x}");
            }
        }
    }

    PayloadScan {
        slice_count: slices.len(),
        total_bytes,
        xor_checksum,
    }
}

/// Alternative path using [`ReceivedUdpDatagramView::payload`] + [`FragmentedByteSlice`].
fn scan_payload_fragmented(view: &ReceivedUdpDatagramView) -> PayloadScan {
    let part_count = view.payload_slices().len();
    let mut scratch = vec![&[] as &[u8]; part_count.max(1)];
    let fragmented = view.payload(&mut scratch);
    let mut xor_checksum = 0u8;

    for byte in fragmented.iter() {
        xor_checksum ^= byte;
    }

    PayloadScan {
        slice_count: part_count,
        total_bytes: fragmented.len(),
        xor_checksum,
    }
}

struct PayloadIterationAgent {
    last_view: Option<ReceivedUdpDatagramView>,
    scan: Option<PayloadScan>,
}

impl IpsReceiveBindingsContext<FakeDeviceId> for PayloadIterationAgent {
    fn receive_udp_datagram(
        &mut self,
        _device_id: &FakeDeviceId,
        view: ReceivedUdpDatagramView,
    ) -> Result<(), IpsReceiveError> {
        println!("Iterating payload slices (zero-copy):");
        self.scan = Some(scan_payload_slices(&view));
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
}

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
    let udp_total_len = UDP_PAYLOAD_LEN + HEADER_BYTES;

    let mut first_body = vec![
        0x00, 0xc8, 0x00, 0x64,
        (udp_total_len >> 8) as u8,
        (udp_total_len & 0xff) as u8,
        0x00, 0x00,
    ];
    first_body.resize(FRAGMENT_BODY_LEN, 0xAA);

    let second_len = udp_total_len - FRAGMENT_BODY_LEN;
    let second_body = vec![0xBB; second_len];

    let frag0 = build_ipv4_udp_fragment(FragmentOffset::ZERO, true, first_body);
    let frag1 = build_ipv4_udp_fragment(
        FragmentOffset::new(13).expect("aligned offset"),
        false,
        second_body,
    );

    let state = IpsState::new();
    let mut agent = PayloadIterationAgent { last_view: None, scan: None };
    let device_id = FakeDeviceId;

    for frame in [frag0, frag1] {
        process_ethernet_frame(&state, &mut agent, &device_id, frame)
            .expect("IPS ingress delivers reassembled UDP to L7");
    }

    let view = agent.last_view.as_ref().expect("L7 delivery");
    assert_eq!(
        view.ip_fragment_metadata().reassembly_outcome,
        ReassemblyOutcome::Complete,
    );
    assert_eq!(view.ip_fragments().len(), 2);

    let scan = agent.scan.as_ref().expect("agent scanned payload");
    assert_eq!(scan.slice_count, 2, "expect one payload slice per fragment body");
    assert_eq!(scan.total_bytes, UDP_PAYLOAD_LEN);

    let via_fragmented = scan_payload_fragmented(view);
    assert_eq!(
        scan, &via_fragmented,
        "slice iteration and FragmentedByteSlice must agree"
    );

    let udp_len = usize::from(view.udp_header().expect("udp header").length);
    assert_eq!(
        scan.total_bytes,
        udp_len - HEADER_BYTES,
        "iterated payload length matches UDP header"
    );

    println!();
    println!("Payload iteration summary:");
    println!("  slices: {}", scan.slice_count);
    println!("  total payload bytes: {}", scan.total_bytes);
    println!("  XOR over all bytes: 0x{:02x}", scan.xor_checksum);
    println!("No payload copy — slices borrow driver RX frame memory.");
}
