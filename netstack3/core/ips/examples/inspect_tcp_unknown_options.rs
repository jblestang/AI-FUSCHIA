// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Example: Layer 7 inspection of TCP options for unknown kinds.
//!
//! Builds TCP segments through the IPS ingress path, walks the zero-copy
//! [`ReceivedTcpSegmentView`] header bytes, and flags options that are not in
//! the demo allowlist (MSS, window scale, SACK, timestamps, NOP/EOL).
//!
//! ```text
//! cargo run -p netstack3-ips --features testutils --example inspect_tcp_unknown_options
//! ```

use core::num::NonZeroU16;

use net_types::ethernet::Mac;
use net_types::ip::{IpAddress, Ipv4Addr};
use netstack3_base::testutil::FakeDeviceId;
use netstack3_base::NetworkSerializationContext;
use netstack3_ips::{
    IpsReceiveBindingsContext, IpsReceiveError, IpsState, ReceivedTcpSegmentView,
    ReceivedUdpDatagramView, TcpHeaderView, process_ethernet_frame,
};
use packet::{
    Buf, BufferViewMut, FragmentedBytesMut, NestablePacketBuilder, NestableSerializer as _,
    PacketBuilder, PacketConstraints, SerializeTarget, Serializer,
};
use packet_formats::ethernet::{EtherType, EthernetFrameBuilder};
use packet_formats::ip::{IpProto, Ipv4Proto};
use packet_formats::tcp::{TcpEnvelope, TcpSegmentBuilder, TcpSerializationContext, HDR_PREFIX_LEN};

const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);
const LOCAL_PORT: NonZeroU16 = NonZeroU16::new(100).unwrap();
const REMOTE_PORT: NonZeroU16 = NonZeroU16::new(200).unwrap();

const TCP_OPTION_EOL: u8 = 0;
const TCP_OPTION_NOP: u8 = 1;
const TCP_OPTION_MSS: u8 = 2;
const TCP_OPTION_WINDOW_SCALE: u8 = 3;
const TCP_OPTION_SACK_PERMITTED: u8 = 4;
const TCP_OPTION_SACK: u8 = 5;
const TCP_OPTION_TIMESTAMP: u8 = 8;

/// Unknown / experimental option kind injected in the second demo segment.
const DEMO_UNKNOWN_OPTION_KIND: u8 = 254;

/// Raw option bytes (kind 254, length 4, payload 0xDEAD) for the suspicious segment.
const DEMO_UNKNOWN_OPTION: [u8; 4] = [DEMO_UNKNOWN_OPTION_KIND, 4, 0xDE, 0xAD];

/// One non-allowlisted TCP option observed on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnknownTcpOption {
    /// Option kind byte (RFC 793 options layout).
    pub kind: u8,
    /// Total option length including kind and length octets (0 for EOL/NOP).
    pub length: u8,
    /// Start offset of this option within the Ethernet frame.
    pub frame_offset: usize,
}

/// Demo L7 agent: inspect TCP options, record findings, forward the view unchanged.
struct TcpOptionsInspector {
    segments: Vec<ReceivedTcpSegmentView>,
    findings: Vec<Vec<UnknownTcpOption>>,
}

impl IpsReceiveBindingsContext<FakeDeviceId> for TcpOptionsInspector {
    fn receive_udp_datagram(
        &mut self,
        _device: &FakeDeviceId,
        _view: ReceivedUdpDatagramView,
    ) -> Result<(), IpsReceiveError> {
        Ok(())
    }

    fn receive_tcp_segment(
        &mut self,
        _device: &FakeDeviceId,
        view: ReceivedTcpSegmentView,
    ) -> Result<(), IpsReceiveError> {
        let unknown = inspect_unknown_tcp_options(&view);
        if unknown.is_empty() {
            println!(
                "TCP segment seq {}: no unknown options",
                view.tcp_header().map(|h| h.seq_num).unwrap_or(0)
            );
        } else {
            println!(
                "TCP segment seq {}: {} unknown option(s): {:?}",
                view.tcp_header().map(|h| h.seq_num).unwrap_or(0),
                unknown.len(),
                unknown
            );
        }
        self.findings.push(unknown);
        self.segments.push(view);
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
        
        fn receive_pim_message(
            &mut self,
            _device_id: &FakeDeviceId,
            _view: netstack3_ips::ReceivedPimMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_ipsec_message(
            &mut self,
            _device_id: &FakeDeviceId,
            _view: netstack3_ips::ReceivedIpsecMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }
    }

fn is_known_option_kind(kind: u8) -> bool {
    matches!(
        kind,
        TCP_OPTION_EOL
            | TCP_OPTION_NOP
            | TCP_OPTION_MSS
            | TCP_OPTION_WINDOW_SCALE
            | TCP_OPTION_SACK_PERMITTED
            | TCP_OPTION_SACK
            | TCP_OPTION_TIMESTAMP
    )
}

/// Walks TCP options in the backing frame and returns kinds outside the allowlist.
fn inspect_unknown_tcp_options(view: &ReceivedTcpSegmentView) -> Vec<UnknownTcpOption> {
    let Some(tcp_hdr) = view.tcp_header() else {
        return Vec::new();
    };
    let frame_index = tcp_hdr.eth_frame_index;
    let Some(frame) = view.eth_frames().nth(frame_index) else {
        return Vec::new();
    };
    scan_unknown_tcp_options(frame, tcp_hdr)
}

fn scan_unknown_tcp_options(frame: &[u8], tcp_hdr: &TcpHeaderView) -> Vec<UnknownTcpOption> {
    let tcp_start = tcp_hdr.header_range.start;
    let data_offset = tcp_hdr.header_range.len();
    if data_offset <= 20 {
        return Vec::new();
    }

    let mut unknown = Vec::new();
    let opts_start = tcp_start + 20;
    let opts_end = tcp_start + data_offset;
    if opts_end > frame.len() {
        return unknown;
    }

    let mut i = opts_start;
    while i < opts_end {
        let kind = frame[i];
        if kind == TCP_OPTION_EOL {
            break;
        }
        if kind == TCP_OPTION_NOP {
            i += 1;
            continue;
        }
        if i + 1 >= opts_end {
            break;
        }
        let len = frame[i + 1];
        if len < 2 || usize::from(len) > opts_end - i {
            unknown.push(UnknownTcpOption { kind, length: len, frame_offset: i });
            break;
        }
        if !is_known_option_kind(kind) {
            unknown.push(UnknownTcpOption { kind, length: len, frame_offset: i });
        }
        i += usize::from(len);
    }
    unknown
}

/// Builder for TCP segments with arbitrary raw option bytes (used for unknown kinds).
#[derive(Debug)]
struct TcpSegmentBuilderWithRawOptions<A: IpAddress, O> {
    prefix_builder: TcpSegmentBuilder<A>,
    options: O,
}

impl<A: IpAddress, O: AsRef<[u8]>> NestablePacketBuilder
    for TcpSegmentBuilderWithRawOptions<A, O>
{
    fn constraints(&self) -> PacketConstraints {
        let opt_len = self.options.as_ref().len();
        let header_len = HDR_PREFIX_LEN + opt_len;
        PacketConstraints::new(header_len, 0, 0, (1 << 16) - 1 - header_len)
    }
}

impl<A: IpAddress, O: AsRef<[u8]>> PacketBuilder<NetworkSerializationContext>
    for TcpSegmentBuilderWithRawOptions<A, O>
{
    fn context_state(
        &self,
    ) -> <NetworkSerializationContext as packet::SerializationContext>::ContextState {
        NetworkSerializationContext::envelope_to_state(TcpEnvelope)
    }

    fn serialize(
        &self,
        context: &mut NetworkSerializationContext,
        target: &mut SerializeTarget<'_>,
        body: FragmentedBytesMut<'_, '_>,
    ) {
        let mut header = &mut &mut target.header[..];
        header.write_obj_back(self.options.as_ref()).expect("TCP options fit in header");
        self.prefix_builder.serialize(context, target, body);
    }
}

fn build_tcp_segment(payload: &[u8], seq: u32) -> Buf<Vec<u8>> {
    let tcp = TcpSegmentBuilder::new(
        REMOTE_IP,
        LOCAL_IP,
        REMOTE_PORT,
        LOCAL_PORT,
        seq,
        None,
        65535,
    );
    let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
        REMOTE_IP,
        LOCAL_IP,
        64,
        Ipv4Proto::Proto(IpProto::Tcp),
    );
    let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
    let frame = Buf::new(payload.to_vec(), ..)
        .wrap_in(tcp)
        .wrap_in(ip)
        .wrap_in(eth)
        .serialize_vec_outer(&mut NetworkSerializationContext::default())
        .expect("serialize baseline TCP segment")
        .into_inner()
        .into_inner();
    Buf::new(frame, ..)
}

fn build_tcp_segment_with_raw_options(payload: &[u8], seq: u32, options: [u8; 4]) -> Buf<Vec<u8>> {
    let prefix_builder = TcpSegmentBuilder::new(
        REMOTE_IP,
        LOCAL_IP,
        REMOTE_PORT,
        LOCAL_PORT,
        seq,
        None,
        65535,
    );
    let tcp = TcpSegmentBuilderWithRawOptions { prefix_builder, options };
    let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
        REMOTE_IP,
        LOCAL_IP,
        64,
        Ipv4Proto::Proto(IpProto::Tcp),
    );
    let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
    let frame = Buf::new(payload.to_vec(), ..)
        .wrap_in(tcp)
        .wrap_in(ip)
        .wrap_in(eth)
        .serialize_vec_outer(&mut NetworkSerializationContext::default())
        .expect("serialize TCP segment with raw options")
        .into_inner()
        .into_inner();
    Buf::new(frame, ..)
}

fn deliver(state: &IpsState, handler: &mut TcpOptionsInspector, frame: Buf<Vec<u8>>) {
    process_ethernet_frame(state, handler, &FakeDeviceId, frame).expect("IPS ingress");
}

fn main() {
    let state = IpsState::new();
    let mut handler = TcpOptionsInspector { segments: Vec::new(), findings: Vec::new() };

    // Baseline: standard 20-byte TCP header, no options.
    deliver(&state, &mut handler, build_tcp_segment(&[0xCC; 32], 1000));

    // Evasion attempt: experimental option kind 254 before payload.
    deliver(
        &state,
        &mut handler,
        build_tcp_segment_with_raw_options(&[0xDD; 32], 2000, DEMO_UNKNOWN_OPTION),
    );

    assert_eq!(handler.segments.len(), 2);
    assert!(handler.findings[0].is_empty(), "baseline segment has no options");
    assert_eq!(handler.findings[1].len(), 1, "unknown option must be detected");
    assert_eq!(handler.findings[1][0].kind, DEMO_UNKNOWN_OPTION_KIND);

    let view = &handler.segments[1];
    let tcp_hdr = view.tcp_header().expect("tcp header");
    let rescanned = inspect_unknown_tcp_options(view);
    assert_eq!(rescanned, handler.findings[1]);

    println!();
    println!("Policy: alert or drop segments carrying non-allowlisted TCP options.");
    println!(
        "Rescanned unknown option at frame offset {} (kind {}, len {}).",
        rescanned[0].frame_offset, rescanned[0].kind, rescanned[0].length
    );
    println!(
        "Header data offset: {} bytes (seq {}).",
        tcp_hdr.data_offset_bytes, tcp_hdr.seq_num
    );
}
