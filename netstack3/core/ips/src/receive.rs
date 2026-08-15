// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! IPS Ethernet ingress: zero-copy path from driver to Layer 7.

use alloc::vec::Vec;
use core::ops::Range;

use log::trace;
use net_types::ip::{Ip, IpAddr, Ipv4, Ipv6};
use netstack3_base::StrongDeviceIdentifier;
use packet::{Buf, Buffer as _, GrowBuffer as _, ParsablePacket};
use packet_formats::ethernet::{EtherType, EthernetFrame, EthernetFrameLengthCheck};
use packet_formats::ip::{IpProto, Ipv4Proto, Ipv6Proto};
use packet_formats::ipv4::{Ipv4Header, Ipv4Packet};
use packet_formats::ipv6::{Ipv6Header, Ipv6Packet};

use crate::context::{IpsReceiveBindingsContext, IpsReceiveError};
use crate::fragment::{add_fragment, ipv4_key, store_fragment};
use crate::state::{
    assembly_metadata, ip_addr_v4, ip_addr_v6, AssemblyProgress, DatagramAssembly, IpsState,
};
use crate::view::{
    IpFragmentInfo, IpFragmentMetadata, IpsecProtocol, ReceivedIcmpMessageView,
    ReceivedIgmpMessageView, ReceivedIpsecMessageView, ReceivedPimMessageView,
    ReceivedTcpSegmentView, ReceivedUdpDatagramView, ReassemblyOutcome, TcpHeaderView,
    UdpHeaderView, parse_ah_header, parse_esp_header, parse_icmp_header, parse_igmp_header,
    parse_pim_header, parse_tcp_header, parse_udp_header,
};

const IP_PROTO_ESP: u8 = 50;
const IP_PROTO_AH: u8 = 51;
const IP_PROTO_PIM: u8 = 103;

enum Ipv4IngressL4 {
    Udp,
    Tcp,
    Icmp,
    Igmp,
    Pim,
    Esp,
    Ah,
}

fn ipv4_ingress_l4(proto: Ipv4Proto) -> Option<Ipv4IngressL4> {
    match proto {
        Ipv4Proto::Proto(IpProto::Udp) => Some(Ipv4IngressL4::Udp),
        Ipv4Proto::Proto(IpProto::Tcp) => Some(Ipv4IngressL4::Tcp),
        Ipv4Proto::Icmp => Some(Ipv4IngressL4::Icmp),
        Ipv4Proto::Igmp => Some(Ipv4IngressL4::Igmp),
        Ipv4Proto::Other(IP_PROTO_PIM) => Some(Ipv4IngressL4::Pim),
        Ipv4Proto::Other(IP_PROTO_ESP) => Some(Ipv4IngressL4::Esp),
        Ipv4Proto::Other(IP_PROTO_AH) => Some(Ipv4IngressL4::Ah),
        _ => None,
    }
}

fn deliver_pim_to_l7<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    view: ReceivedPimMessageView,
) where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    if bindings_ctx.receive_pim_message(device_id, view) == Err(IpsReceiveError::QueueFull) {
        state.record_l7_queue_full();
    }
}

fn deliver_ipsec_to_l7<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    view: ReceivedIpsecMessageView,
) where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    if bindings_ctx.receive_ipsec_message(device_id, view) == Err(IpsReceiveError::QueueFull) {
        state.record_l7_queue_full();
    }
}

fn deliver_igmp_to_l7<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    view: ReceivedIgmpMessageView,
) where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    if bindings_ctx.receive_igmp_message(device_id, view) == Err(IpsReceiveError::QueueFull) {
        state.record_l7_queue_full();
    }
}

fn deliver_icmp_to_l7<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    view: ReceivedIcmpMessageView,
) where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    if bindings_ctx.receive_icmp_message(device_id, view) == Err(IpsReceiveError::QueueFull) {
        state.record_l7_queue_full();
    }
}

fn deliver_udp_to_l7<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    view: ReceivedUdpDatagramView,
) where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    if bindings_ctx.receive_udp_datagram(device_id, view) == Err(IpsReceiveError::QueueFull) {
        state.record_l7_queue_full();
    }
}

fn deliver_tcp_to_l7<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    view: ReceivedTcpSegmentView,
) where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    if bindings_ctx.receive_tcp_segment(device_id, view) == Err(IpsReceiveError::QueueFull) {
        state.record_l7_queue_full();
    }
}

/// EtherTypes consumed at ingress without IP/L7 parsing (normal SPAN noise).
pub fn ingress_accepts_without_l7(ethertype: EtherType) -> bool {
    matches!(ethertype, EtherType::Arp)
}

/// Processes one owned Ethernet frame on the IPS ingress path.
pub fn process_ethernet_frame<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    mut frame: Buf<Vec<u8>>,
) -> Result<(), Buf<Vec<u8>>>
where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let (eth, _whole) =
        match frame.parse_with_view::<_, EthernetFrame<_>>(EthernetFrameLengthCheck::NoCheck) {
            Ok(v) => v,
            Err(_) => return Err(frame),
        };

    let ethertype = eth.ethertype();
    let ip_offset = _whole.len() - frame.as_ref().len();
    frame.grow_front(ip_offset);

    match ethertype {
        Some(EtherType::Ipv4) => process_ipv4(state, bindings_ctx, device_id, frame, ip_offset),
        Some(EtherType::Ipv6) => process_ipv6(state, bindings_ctx, device_id, frame, ip_offset),
        Some(et) if ingress_accepts_without_l7(et) => Ok(()),
        _ => Err(frame),
    }
}

fn process_ipv4<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    frame: Buf<Vec<u8>>,
    ip_offset: usize,
) -> Result<(), Buf<Vec<u8>>>
where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let mut ip_bytes = &frame.as_ref()[ip_offset..];
    let (src, dst, id, offset, mf, ip_packet_end, body_start, l4) = {
        let packet = match Ipv4Packet::parse(&mut ip_bytes, ()) {
            Ok(p) => p,
            Err(_) => return Err(frame),
        };

        let l4 = match ipv4_ingress_l4(packet.proto()) {
            Some(l4) => l4,
            None => return Err(frame),
        };

        let meta = ParsablePacket::parse_metadata(&packet);
        let ip_packet_end = ip_offset + meta.header_len() + meta.body_len();
        let body_start = ip_offset + meta.header_len();
        (
            packet.src_ip(),
            packet.dst_ip(),
            u32::from(packet.id()),
            packet.fragment_offset().into_raw(),
            packet.mf_flag(),
            ip_packet_end,
            body_start,
            l4,
        )
    };

    let fragmented = mf || offset != 0;

    if !fragmented {
        return match l4 {
            Ipv4IngressL4::Udp => deliver_unfragmented_udp_v4(
                state,
                bindings_ctx,
                device_id,
                frame,
                ip_offset,
                src,
                dst,
                id,
                body_start,
            ),
            Ipv4IngressL4::Tcp => deliver_unfragmented_tcp_v4(
                state,
                bindings_ctx,
                device_id,
                frame,
                ip_offset,
                src,
                dst,
                id,
                body_start,
            ),
            Ipv4IngressL4::Icmp => deliver_unfragmented_icmp_v4(
                state,
                bindings_ctx,
                device_id,
                frame,
                ip_offset,
                src,
                dst,
                id,
                body_start,
            ),
            Ipv4IngressL4::Igmp => deliver_unfragmented_igmp_v4(
                state,
                bindings_ctx,
                device_id,
                frame,
                ip_offset,
                src,
                dst,
                id,
                body_start,
            ),
            Ipv4IngressL4::Pim => deliver_unfragmented_pim_v4(
                state,
                bindings_ctx,
                device_id,
                frame,
                ip_offset,
                src,
                dst,
                id,
                body_start,
            ),
            Ipv4IngressL4::Esp => deliver_unfragmented_ipsec_v4(
                state,
                bindings_ctx,
                device_id,
                frame,
                ip_offset,
                src,
                dst,
                id,
                body_start,
                IpsecProtocol::Esp,
            ),
            Ipv4IngressL4::Ah => deliver_unfragmented_ipsec_v4(
                state,
                bindings_ctx,
                device_id,
                frame,
                ip_offset,
                src,
                dst,
                id,
                body_start,
                IpsecProtocol::Ah,
            ),
        };
    }

    let proto = match l4 {
        Ipv4IngressL4::Udp => IpProto::Udp,
        Ipv4IngressL4::Tcp => IpProto::Tcp,
        Ipv4IngressL4::Icmp
        | Ipv4IngressL4::Igmp
        | Ipv4IngressL4::Pim
        | Ipv4IngressL4::Esp
        | Ipv4IngressL4::Ah => return Err(frame),
    };

    let stored = store_fragment(
        frame,
        ip_offset..ip_packet_end,
        id,
        offset,
        mf,
        body_start..ip_packet_end,
    );

    let key = ipv4_key(src, dst, id, proto);
    match add_fragment(&state.ipv4, key, stored) {
        AssemblyProgress::NeedMore => Ok(()),
        AssemblyProgress::Ready(assembly) => {
            deliver_assembly_v4(state, bindings_ctx, device_id, assembly, ReassemblyOutcome::Complete, proto);
            Ok(())
        }
        AssemblyProgress::Aborted(assembly) => {
            deliver_assembly_v4(
                state,
                bindings_ctx,
                device_id,
                assembly,
                ReassemblyOutcome::AbortedRfc5722Overlap,
                proto,
            );
            Ok(())
        }
    }
}

fn process_ipv6<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    frame: Buf<Vec<u8>>,
    ip_offset: usize,
) -> Result<(), Buf<Vec<u8>>>
where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let is_fragment = ipv6_fragment_info(frame.as_ref(), ip_offset).3;
    let mut ip_bytes = &frame.as_ref()[ip_offset..];
    let (src, dst, body_start, v6_proto) = {
        let packet = match Ipv6Packet::parse(&mut ip_bytes, ()) {
            Ok(p) => p,
            Err(_) => return Err(frame),
        };

        let v6_proto = packet.proto();
        let is_l4 = matches!(
            v6_proto,
            Ipv6Proto::Proto(IpProto::Udp | IpProto::Tcp) | Ipv6Proto::Icmpv6
        ) || is_fragment;

        if !is_l4 {
            return Err(frame);
        }

        let src = packet.src_ip();
        let dst = packet.dst_ip();
        let body_start = ip_offset + ParsablePacket::parse_metadata(&packet).header_len();
        (src, dst, body_start, v6_proto)
    };

    if is_fragment {
        return Err(frame);
    }

    match v6_proto {
        Ipv6Proto::Proto(IpProto::Udp) => {
            deliver_unfragmented_udp_v6(bindings_ctx, device_id, frame, ip_offset, src, dst, body_start)
        }
        Ipv6Proto::Icmpv6 => deliver_unfragmented_icmp_v6(
            state,
            bindings_ctx,
            device_id,
            frame,
            ip_offset,
            src,
            dst,
            body_start,
        ),
        _ => Err(frame),
    }
}

fn ipv6_fragment_info(_frame: &[u8], _ip_offset: usize) -> (u16, bool, u32, bool) {
    // TODO(https://fxbug.dev/000000): IPv6 fragment metadata for IPS ingress.
    (0, false, 0, false)
}

fn deliver_unfragmented_udp_v4<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    frame: Buf<Vec<u8>>,
    ip_offset: usize,
    src: net_types::ip::Ipv4Addr,
    dst: net_types::ip::Ipv4Addr,
    identification: u32,
    body_start: usize,
) -> Result<(), Buf<Vec<u8>>>
where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let frame_len = frame.as_ref().len();
    let udp_hdr = match parse_udp_header(frame.as_ref(), 0, body_start) {
        Some(hdr) => hdr,
        None => return Err(frame),
    };
    let payload_start = udp_hdr.header_range.end;
    if frame_len < payload_start {
        return Err(frame);
    }
    let view = ReceivedUdpDatagramView::new(
        alloc::vec![frame],
        alloc::vec![IpFragmentInfo {
            eth_frame_index: 0,
            ip_packet_range: ip_offset..frame_len,
            identification,
            fragment_offset: 0,
            more_fragments: false,
            ip_body_range: body_start..frame_len,
        }],
        IpFragmentMetadata {
            reassembly_outcome: ReassemblyOutcome::NotApplicable,
            ..Default::default()
        },
        Some(udp_hdr),
        alloc::vec![(0, payload_start..frame_len)],
        IpAddr::V4(src),
        IpAddr::V4(dst),
    );

    deliver_udp_to_l7(state, bindings_ctx, device_id, view);
    Ok(())
}

fn deliver_unfragmented_tcp_v4<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    frame: Buf<Vec<u8>>,
    ip_offset: usize,
    src: net_types::ip::Ipv4Addr,
    dst: net_types::ip::Ipv4Addr,
    identification: u32,
    body_start: usize,
) -> Result<(), Buf<Vec<u8>>>
where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let frame_len = frame.as_ref().len();
    let tcp_hdr = match parse_tcp_header(frame.as_ref(), 0, body_start) {
        Some(hdr) => hdr,
        None => return Err(frame),
    };
    let payload_start = tcp_hdr.header_range.end;
    let payload_parts = if payload_start < frame_len {
        alloc::vec![(0, payload_start..frame_len)]
    } else {
        alloc::vec![]
    };
    let view = ReceivedTcpSegmentView::new(
        alloc::vec![frame],
        alloc::vec![IpFragmentInfo {
            eth_frame_index: 0,
            ip_packet_range: ip_offset..frame_len,
            identification,
            fragment_offset: 0,
            more_fragments: false,
            ip_body_range: body_start..frame_len,
        }],
        IpFragmentMetadata {
            reassembly_outcome: ReassemblyOutcome::NotApplicable,
            ..Default::default()
        },
        Some(tcp_hdr),
        payload_parts,
        IpAddr::V4(src),
        IpAddr::V4(dst),
    );

    deliver_tcp_to_l7(state, bindings_ctx, device_id, view);
    Ok(())
}

fn deliver_unfragmented_icmp_v4<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    frame: Buf<Vec<u8>>,
    ip_offset: usize,
    src: net_types::ip::Ipv4Addr,
    dst: net_types::ip::Ipv4Addr,
    identification: u32,
    body_start: usize,
) -> Result<(), Buf<Vec<u8>>>
where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let frame_len = frame.as_ref().len();
    let icmp_hdr = match parse_icmp_header(frame.as_ref(), 0, body_start) {
        Some(hdr) => hdr,
        None => return Err(frame),
    };
    let payload_start = icmp_hdr.header_range.end;
    let payload_parts = if payload_start < frame_len {
        alloc::vec![(0, payload_start..frame_len)]
    } else {
        alloc::vec![]
    };
    let view = ReceivedIcmpMessageView::new(
        alloc::vec![frame],
        alloc::vec![IpFragmentInfo {
            eth_frame_index: 0,
            ip_packet_range: ip_offset..frame_len,
            identification,
            fragment_offset: 0,
            more_fragments: false,
            ip_body_range: body_start..frame_len,
        }],
        IpFragmentMetadata {
            reassembly_outcome: ReassemblyOutcome::NotApplicable,
            ..Default::default()
        },
        Some(icmp_hdr),
        payload_parts,
        IpAddr::V4(src),
        IpAddr::V4(dst),
    );

    deliver_icmp_to_l7(state, bindings_ctx, device_id, view);
    Ok(())
}

fn deliver_unfragmented_igmp_v4<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    frame: Buf<Vec<u8>>,
    ip_offset: usize,
    src: net_types::ip::Ipv4Addr,
    dst: net_types::ip::Ipv4Addr,
    identification: u32,
    body_start: usize,
) -> Result<(), Buf<Vec<u8>>>
where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let frame_len = frame.as_ref().len();
    let igmp_hdr = match parse_igmp_header(frame.as_ref(), 0, body_start) {
        Some(hdr) => hdr,
        None => return Err(frame),
    };
    let payload_start = igmp_hdr.header_range.end;
    let payload_parts = if payload_start < frame_len {
        alloc::vec![(0, payload_start..frame_len)]
    } else {
        alloc::vec![]
    };
    let view = ReceivedIgmpMessageView::new(
        alloc::vec![frame],
        alloc::vec![IpFragmentInfo {
            eth_frame_index: 0,
            ip_packet_range: ip_offset..frame_len,
            identification,
            fragment_offset: 0,
            more_fragments: false,
            ip_body_range: body_start..frame_len,
        }],
        IpFragmentMetadata {
            reassembly_outcome: ReassemblyOutcome::NotApplicable,
            ..Default::default()
        },
        Some(igmp_hdr),
        payload_parts,
        IpAddr::V4(src),
        IpAddr::V4(dst),
    );

    deliver_igmp_to_l7(state, bindings_ctx, device_id, view);
    Ok(())
}

fn deliver_unfragmented_pim_v4<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    frame: Buf<Vec<u8>>,
    ip_offset: usize,
    src: net_types::ip::Ipv4Addr,
    dst: net_types::ip::Ipv4Addr,
    identification: u32,
    body_start: usize,
) -> Result<(), Buf<Vec<u8>>>
where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let frame_len = frame.as_ref().len();
    let pim_hdr = match parse_pim_header(frame.as_ref(), 0, body_start) {
        Some(hdr) => hdr,
        None => return Err(frame),
    };
    let payload_start = pim_hdr.header_range.end;
    let payload_parts = if payload_start < frame_len {
        alloc::vec![(0, payload_start..frame_len)]
    } else {
        alloc::vec![]
    };
    let view = ReceivedPimMessageView::new(
        alloc::vec![frame],
        alloc::vec![IpFragmentInfo {
            eth_frame_index: 0,
            ip_packet_range: ip_offset..frame_len,
            identification,
            fragment_offset: 0,
            more_fragments: false,
            ip_body_range: body_start..frame_len,
        }],
        IpFragmentMetadata {
            reassembly_outcome: ReassemblyOutcome::NotApplicable,
            ..Default::default()
        },
        Some(pim_hdr),
        payload_parts,
        IpAddr::V4(src),
        IpAddr::V4(dst),
    );

    deliver_pim_to_l7(state, bindings_ctx, device_id, view);
    Ok(())
}

fn deliver_unfragmented_ipsec_v4<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    frame: Buf<Vec<u8>>,
    ip_offset: usize,
    src: net_types::ip::Ipv4Addr,
    dst: net_types::ip::Ipv4Addr,
    identification: u32,
    body_start: usize,
    protocol: IpsecProtocol,
) -> Result<(), Buf<Vec<u8>>>
where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let frame_len = frame.as_ref().len();
    let ipsec_hdr = match protocol {
        IpsecProtocol::Esp => parse_esp_header(frame.as_ref(), 0, body_start),
        IpsecProtocol::Ah => parse_ah_header(frame.as_ref(), 0, body_start),
    };
    let ipsec_hdr = match ipsec_hdr {
        Some(hdr) => hdr,
        None => return Err(frame),
    };
    let payload_start = ipsec_hdr.header_range.end;
    let payload_parts = if payload_start < frame_len {
        alloc::vec![(0, payload_start..frame_len)]
    } else {
        alloc::vec![]
    };
    let view = ReceivedIpsecMessageView::new(
        alloc::vec![frame],
        alloc::vec![IpFragmentInfo {
            eth_frame_index: 0,
            ip_packet_range: ip_offset..frame_len,
            identification,
            fragment_offset: 0,
            more_fragments: false,
            ip_body_range: body_start..frame_len,
        }],
        IpFragmentMetadata {
            reassembly_outcome: ReassemblyOutcome::NotApplicable,
            ..Default::default()
        },
        Some(ipsec_hdr),
        payload_parts,
        IpAddr::V4(src),
        IpAddr::V4(dst),
    );

    deliver_ipsec_to_l7(state, bindings_ctx, device_id, view);
    Ok(())
}

fn deliver_unfragmented_udp_v6<D, BC>(
    bindings_ctx: &mut BC,
    device_id: &D,
    frame: Buf<Vec<u8>>,
    ip_offset: usize,
    src: net_types::ip::Ipv6Addr,
    dst: net_types::ip::Ipv6Addr,
    body_start: usize,
) -> Result<(), Buf<Vec<u8>>>
where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let frame_len = frame.as_ref().len();
    let udp_hdr = match parse_udp_header(frame.as_ref(), 0, body_start) {
        Some(hdr) => hdr,
        None => return Err(frame),
    };
    let payload_start = udp_hdr.header_range.end;
    let view = ReceivedUdpDatagramView::new(
        alloc::vec![frame],
        alloc::vec![IpFragmentInfo {
            eth_frame_index: 0,
            ip_packet_range: ip_offset..frame_len,
            identification: 0,
            fragment_offset: 0,
            more_fragments: false,
            ip_body_range: body_start..frame_len,
        }],
        IpFragmentMetadata {
            reassembly_outcome: ReassemblyOutcome::NotApplicable,
            ..Default::default()
        },
        Some(udp_hdr),
        alloc::vec![(0, payload_start..frame_len)],
        IpAddr::V6(src),
        IpAddr::V6(dst),
    );

    let _ = bindings_ctx.receive_udp_datagram(device_id, view);
    Ok(())
}

fn deliver_unfragmented_icmp_v6<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    frame: Buf<Vec<u8>>,
    ip_offset: usize,
    src: net_types::ip::Ipv6Addr,
    dst: net_types::ip::Ipv6Addr,
    body_start: usize,
) -> Result<(), Buf<Vec<u8>>>
where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let frame_len = frame.as_ref().len();
    let icmp_hdr = match parse_icmp_header(frame.as_ref(), 0, body_start) {
        Some(hdr) => hdr,
        None => return Err(frame),
    };
    let payload_start = icmp_hdr.header_range.end;
    let payload_parts = if payload_start < frame_len {
        alloc::vec![(0, payload_start..frame_len)]
    } else {
        alloc::vec![]
    };
    let view = ReceivedIcmpMessageView::new(
        alloc::vec![frame],
        alloc::vec![IpFragmentInfo {
            eth_frame_index: 0,
            ip_packet_range: ip_offset..frame_len,
            identification: 0,
            fragment_offset: 0,
            more_fragments: false,
            ip_body_range: body_start..frame_len,
        }],
        IpFragmentMetadata {
            reassembly_outcome: ReassemblyOutcome::NotApplicable,
            ..Default::default()
        },
        Some(icmp_hdr),
        payload_parts,
        IpAddr::V6(src),
        IpAddr::V6(dst),
    );

    deliver_icmp_to_l7(state, bindings_ctx, device_id, view);
    Ok(())
}

fn deliver_assembly_v4<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    assembly: DatagramAssembly<Ipv4>,
    outcome: ReassemblyOutcome,
    proto: IpProto,
) where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let (src, dst) = ip_addr_v4(assembly.src_ip, assembly.dst_ip);
    deliver_assembly_impl(state, bindings_ctx, device_id, assembly, outcome, src, dst, proto);
}

fn deliver_assembly_v6<D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    assembly: DatagramAssembly<Ipv6>,
    outcome: ReassemblyOutcome,
) where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let (src, dst) = ip_addr_v6(assembly.src_ip, assembly.dst_ip);
    deliver_assembly_impl(state, bindings_ctx, device_id, assembly, outcome, src, dst, IpProto::Udp);
}

fn deliver_assembly_impl<I, D, BC>(
    state: &IpsState,
    bindings_ctx: &mut BC,
    device_id: &D,
    assembly: DatagramAssembly<I>,
    outcome: ReassemblyOutcome,
    src: IpAddr,
    dst: IpAddr,
    proto: IpProto,
) where
    I: Ip,
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let metadata = assembly_metadata(&assembly, outcome);

    let mut eth_frames = Vec::with_capacity(assembly.fragments.len());
    let mut fragment_infos = Vec::with_capacity(assembly.fragments.len());
    for (i, f) in assembly.fragments.into_iter().enumerate() {
        fragment_infos.push(IpFragmentInfo {
            eth_frame_index: i,
            ip_packet_range: f.ip_packet_range,
            identification: f.identification,
            fragment_offset: f.fragment_offset,
            more_fragments: f.more_fragments,
            ip_body_range: f.ip_body_range,
        });
        eth_frames.push(f.eth_frame);
    }

    match proto {
        IpProto::Udp => {
            let (udp_header, payload_parts) = if outcome == ReassemblyOutcome::Complete {
                build_udp_views(&eth_frames, &fragment_infos)
            } else {
                (None, Vec::new())
            };
            let view = ReceivedUdpDatagramView::new(
                eth_frames,
                fragment_infos,
                metadata,
                udp_header,
                payload_parts,
                src,
                dst,
            );
            trace!("ips: delivering UDP datagram to L7, outcome={:?}", outcome);
            deliver_udp_to_l7(state, bindings_ctx, device_id, view);
        }
        IpProto::Tcp => {
            let (tcp_header, payload_parts) = if outcome == ReassemblyOutcome::Complete {
                build_tcp_views(&eth_frames, &fragment_infos)
            } else {
                (None, Vec::new())
            };
            let view = ReceivedTcpSegmentView::new(
                eth_frames,
                fragment_infos,
                metadata,
                tcp_header,
                payload_parts,
                src,
                dst,
            );
            trace!("ips: delivering TCP segment to L7, outcome={:?}", outcome);
            deliver_tcp_to_l7(state, bindings_ctx, device_id, view);
        }
        _ => {}
    }
}

fn build_udp_views(
    eth_frames: &[Buf<Vec<u8>>],
    fragments: &[IpFragmentInfo],
) -> (Option<UdpHeaderView>, Vec<(usize, Range<usize>)>) {
    let mut sorted: Vec<(u16, usize)> =
        fragments.iter().enumerate().map(|(i, f)| (f.fragment_offset, i)).collect();
    sorted.sort_by_key(|(offset, _)| *offset);

    let mut udp_header = None;
    let mut payload_parts = Vec::new();

    for (offset, idx) in sorted {
        let info = &fragments[idx];
        let body = &info.ip_body_range;

        if offset == 0 {
            if body.len() >= packet_formats::udp::HEADER_BYTES {
                if let Some(hdr) =
                    parse_udp_header(
                        eth_frames[info.eth_frame_index].as_ref(),
                        info.eth_frame_index,
                        body.start,
                    )
                {
                    let payload_start = hdr.header_range.end;
                    udp_header = Some(hdr);
                    if payload_start < body.end {
                        payload_parts.push((info.eth_frame_index, payload_start..body.end));
                    }
                }
            }
        } else if body.start < body.end {
            payload_parts.push((info.eth_frame_index, body.clone()));
        }
    }

    (udp_header, payload_parts)
}

fn build_tcp_views(
    eth_frames: &[Buf<Vec<u8>>],
    fragments: &[IpFragmentInfo],
) -> (Option<TcpHeaderView>, Vec<(usize, Range<usize>)>) {
    let mut sorted: Vec<(u16, usize)> =
        fragments.iter().enumerate().map(|(i, f)| (f.fragment_offset, i)).collect();
    sorted.sort_by_key(|(offset, _)| *offset);

    let mut tcp_header = None;
    let mut payload_parts = Vec::new();

    for (offset, idx) in sorted {
        let info = &fragments[idx];
        let body = &info.ip_body_range;

        if offset == 0 {
            let frame = &eth_frames[info.eth_frame_index];
            if let Some(hdr) = parse_tcp_header(frame.as_ref(), info.eth_frame_index, body.start) {
                let payload_start = hdr.header_range.end;
                tcp_header = Some(hdr);
                if payload_start < body.end {
                    payload_parts.push((info.eth_frame_index, payload_start..body.end));
                }
            }
        } else if body.start < body.end {
            payload_parts.push((info.eth_frame_index, body.clone()));
        }
    }

    (tcp_header, payload_parts)
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU16;

    use alloc::vec;
    use alloc::vec::Vec;

    use net_types::ethernet::Mac;
    use net_types::ip::Ipv4Addr;
    use netstack3_base::testutil::FakeDeviceId;
    use netstack3_base::NetworkSerializationContext;
    use packet::{Buf, NestableSerializer as _, Serializer};
    use packet_formats::ethernet::{EtherType, ETHERNET_HDR_LEN_NO_TAG, EthernetFrameBuilder};
    use packet_formats::ip::{IpProto, Ipv4Proto};
    use packet_formats::tcp::TcpSegmentBuilder;
    use packet_formats::udp::UdpPacketBuilder;

    use super::*;
    use crate::context::IpsReceiveError;

    const DST: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
    const LOCAL_PORT: NonZeroU16 = NonZeroU16::new(100).unwrap();
    const REMOTE_PORT: NonZeroU16 = NonZeroU16::new(200).unwrap();
    const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
    const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    const FRAGMENT_BODY_LEN: usize = 104;

    fn remote(src_host: u8) -> Ipv4Addr {
        Ipv4Addr::new([192, 0, 2, src_host])
    }

    fn build_udp_fragment(
        src: Ipv4Addr,
        fragment_offset: u16,
        more_fragments: bool,
        payload_body: Vec<u8>,
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
        ip.fragment_offset(if fragment_offset == 0 {
            packet_formats::ip::FragmentOffset::ZERO
        } else {
            packet_formats::ip::FragmentOffset::new(fragment_offset).expect("valid offset")
        });
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let bytes = Buf::new(payload_body, ..)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        Buf::new(bytes, ..)
    }

    fn first_fragment_body(udp_total_len: usize, fill: u8) -> Vec<u8> {
        let mut body = vec![
            (REMOTE_PORT.get() >> 8) as u8,
            (REMOTE_PORT.get() & 0xff) as u8,
            (LOCAL_PORT.get() >> 8) as u8,
            (LOCAL_PORT.get() & 0xff) as u8,
            (udp_total_len >> 8) as u8,
            (udp_total_len & 0xff) as u8,
            0x00,
            0x00,
        ];
        body.resize(FRAGMENT_BODY_LEN, fill);
        body
    }

    struct Capture {
        views: Vec<ReceivedUdpDatagramView>,
    }

    impl IpsReceiveBindingsContext<FakeDeviceId> for Capture {
        fn receive_udp_datagram(
            &mut self,
            _device: &FakeDeviceId,
            view: ReceivedUdpDatagramView,
        ) -> Result<(), IpsReceiveError> {
            self.views.push(view);
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
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIcmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_igmp_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: ReceivedIgmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_pim_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedPimMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_ipsec_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIpsecMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }    }

    #[test]
    fn reassembles_interleaved_fragments_from_multiple_sources() {
        const PAYLOAD_LEN: usize = 200;
        const UDP_TOTAL: usize = 8 + PAYLOAD_LEN;

        let mut state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };

        // Each stream uses a distinct (src_ip, dst_ip, identification, UDP) cache key.
        let streams = [
            (remote(2), 0x1001_u16, 0xAA_u8),
            (remote(3), 0x1002_u16, 0xBB_u8),
            (remote(4), 0x1003_u16, 0xCC_u8),
        ];

        for &(src, id, fill) in &streams {
            let frag0 = build_udp_fragment(src, 0, true, first_fragment_body(UDP_TOTAL, fill), id);
            process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frag0).unwrap();
        }

        for &(src, id, fill) in &streams {
            let second_len = UDP_TOTAL - FRAGMENT_BODY_LEN;
            let frag1 = build_udp_fragment(
                src,
                13,
                false,
                vec![fill; second_len],
                id,
            );
            process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frag1).unwrap();
        }

        assert_eq!(handler.views.len(), 3, "all three sources must reassemble");

        let mut seen_sources = handler
            .views
            .iter()
            .map(|view| match view.addrs().0 {
                IpAddr::V4(v4) => v4,
                _ => panic!("expected IPv4"),
            })
            .collect::<Vec<_>>();
        seen_sources.sort_by_key(|addr| u32::from_be_bytes(addr.ipv4_bytes()));

        assert_eq!(
            seen_sources,
            vec![remote(2), remote(3), remote(4)],
            "distinct cache keys must not conflate assemblies"
        );

        for view in &handler.views {
            assert_eq!(
                view.ip_fragment_metadata().reassembly_outcome,
                ReassemblyOutcome::Complete
            );
            assert_eq!(view.payload_slices().iter().map(|s| s.len()).sum::<usize>(), PAYLOAD_LEN);
        }
    }

    #[test]
    fn delivers_unfragmented_tcp_segment_to_l7() {
        const PAYLOAD_LEN: usize = 64;
        let tcp = TcpSegmentBuilder::new(
            remote(2),
            DST,
            REMOTE_PORT,
            LOCAL_PORT,
            1000,
            None,
            65535,
        );
        let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            remote(2),
            DST,
            64,
            Ipv4Proto::Proto(IpProto::Tcp),
        );
        let eth = packet_formats::ethernet::EthernetFrameBuilder::new(
            SRC_MAC,
            DST_MAC,
            EtherType::Ipv4,
            0,
        );
        let frame = Buf::new(vec![0xCC; PAYLOAD_LEN], ..)
            .wrap_in(tcp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();

        struct TcpCapture {
            views: Vec<ReceivedTcpSegmentView>,
        }

        impl IpsReceiveBindingsContext<FakeDeviceId> for TcpCapture {
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
                self.views.push(view);
                Ok(())
            }

            fn receive_icmp_message(
                &mut self,
                _device: &FakeDeviceId,
                _view: crate::view::ReceivedIcmpMessageView,
            ) -> Result<(), IpsReceiveError> {
                Ok(())
            }

            fn receive_igmp_message(
                &mut self,
                _device: &FakeDeviceId,
                _view: ReceivedIgmpMessageView,
            ) -> Result<(), IpsReceiveError> {
                Ok(())
            }

        fn receive_pim_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedPimMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_ipsec_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIpsecMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }        }

        let mut state = IpsState::new();
        let mut handler = TcpCapture { views: Vec::new() };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, Buf::new(frame, ..)).unwrap();

        assert_eq!(handler.views.len(), 1);
        let view = &handler.views[0];
        assert!(view.tcp_header().is_some());
        assert_eq!(view.payload_len(), PAYLOAD_LEN);
        assert_eq!(view.tcp_header().unwrap().seq_num, 1000);
    }

    fn build_ipv4_eth_ip_frame(proto: IpProto, body: Vec<u8>) -> Buf<Vec<u8>> {
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let bytes = match proto {
            IpProto::Udp => {
                let udp = UdpPacketBuilder::new(remote(2), DST, Some(REMOTE_PORT), LOCAL_PORT);
                let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
                    remote(2),
                    DST,
                    64,
                    Ipv4Proto::Proto(IpProto::Udp),
                );
                Buf::new(body, ..)
                    .wrap_in(udp)
                    .wrap_in(ip)
                    .wrap_in(eth)
                    .serialize_vec_outer(&mut NetworkSerializationContext::default())
                    .unwrap()
                    .into_inner()
                    .into_inner()
            }
            IpProto::Tcp => {
                let tcp = TcpSegmentBuilder::new(
                    remote(2),
                    DST,
                    REMOTE_PORT,
                    LOCAL_PORT,
                    1000,
                    None,
                    65535,
                );
                let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
                    remote(2),
                    DST,
                    64,
                    Ipv4Proto::Proto(IpProto::Tcp),
                );
                Buf::new(body, ..)
                    .wrap_in(tcp)
                    .wrap_in(ip)
                    .wrap_in(eth)
                    .serialize_vec_outer(&mut NetworkSerializationContext::default())
                    .unwrap()
                    .into_inner()
                    .into_inner()
            }
            _ => panic!("unsupported proto"),
        };
        Buf::new(bytes, ..)
    }

    fn truncate_frame(mut frame: Buf<Vec<u8>>, new_len: usize) -> Buf<Vec<u8>> {
        let mut bytes = frame.into_inner();
        bytes.truncate(new_len);
        Buf::new(bytes, ..)
    }

    #[test]
    fn truncated_udp_ipv4_returns_frame_unhandled() {
        let frame = truncate_frame(
            build_ipv4_eth_ip_frame(IpProto::Udp, vec![0u8; 4]),
            packet_formats::ethernet::ETHERNET_HDR_LEN_NO_TAG + 24,
        );
        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        assert!(process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).is_err());
        assert!(handler.views.is_empty());
    }

    #[test]
    fn truncated_tcp_ipv4_returns_frame_unhandled() {
        let frame = truncate_frame(
            build_ipv4_eth_ip_frame(IpProto::Tcp, vec![0xCC; 32]),
            packet_formats::ethernet::ETHERNET_HDR_LEN_NO_TAG + 24,
        );
        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        assert!(process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).is_err());
    }

    struct QueueFullHandler {
        tcp_calls: usize,
        udp_calls: usize,
        reject_tcp: bool,
        reject_udp: bool,
    }

    impl IpsReceiveBindingsContext<FakeDeviceId> for QueueFullHandler {
        fn receive_udp_datagram(
            &mut self,
            _device: &FakeDeviceId,
            _view: ReceivedUdpDatagramView,
        ) -> Result<(), IpsReceiveError> {
            self.udp_calls += 1;
            if self.reject_udp {
                Err(IpsReceiveError::QueueFull)
            } else {
                Ok(())
            }
        }

        fn receive_tcp_segment(
            &mut self,
            _device: &FakeDeviceId,
            _view: ReceivedTcpSegmentView,
        ) -> Result<(), IpsReceiveError> {
            self.tcp_calls += 1;
            if self.reject_tcp {
                Err(IpsReceiveError::QueueFull)
            } else {
                Ok(())
            }
        }

        fn receive_icmp_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIcmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_igmp_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: ReceivedIgmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_pim_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedPimMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_ipsec_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIpsecMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }    }

    #[test]
    fn l7_queue_full_increments_drop_counter_and_still_consumes_frame() {
        let frame = build_ipv4_eth_ip_frame(IpProto::Tcp, vec![0xCC; 32]);
        let mut state = IpsState::new();
        let mut handler = QueueFullHandler {
            tcp_calls: 0,
            udp_calls: 0,
            reject_tcp: true,
            reject_udp: false,
        };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).unwrap();
        assert_eq!(handler.tcp_calls, 1);
        assert_eq!(state.l7_queue_full_drops(), 1);

        let udp_frame = build_ipv4_eth_ip_frame(IpProto::Udp, vec![0xDD; 16]);
        let mut udp_handler = QueueFullHandler {
            tcp_calls: 0,
            udp_calls: 0,
            reject_tcp: false,
            reject_udp: true,
        };
        process_ethernet_frame(&state, &mut udp_handler, &FakeDeviceId, udp_frame).unwrap();
        assert_eq!(udp_handler.udp_calls, 1);
        assert_eq!(state.l7_queue_full_drops(), 2);
    }

    fn build_ipv4_tcp_fragment(
        fragment_offset: u16,
        more_fragments: bool,
        body: Vec<u8>,
        fragment_id: u16,
    ) -> Buf<Vec<u8>> {
        let mut ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            remote(2),
            DST,
            64,
            Ipv4Proto::Proto(IpProto::Tcp),
        );
        ip.id(fragment_id);
        ip.mf_flag(more_fragments);
        ip.fragment_offset(if fragment_offset == 0 {
            packet_formats::ip::FragmentOffset::ZERO
        } else {
            packet_formats::ip::FragmentOffset::new(fragment_offset).expect("valid offset")
        });
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let bytes = Buf::new(body, ..)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        Buf::new(bytes, ..)
    }

    fn build_server_ack_with_sack(ack: u32, sack_left: u32, sack_right: u32) -> Buf<Vec<u8>> {
        const TCP_OPTION_KIND_SACK: u8 = 5;
        const TCP_OPTION_KIND_NOP: u8 = 1;

        let mut tcp = TcpSegmentBuilder::new(DST, remote(2), LOCAL_PORT, REMOTE_PORT, 5000, Some(ack), 65535);
        let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            DST,
            remote(2),
            64,
            Ipv4Proto::Proto(IpProto::Tcp),
        );
        let eth = EthernetFrameBuilder::new(DST_MAC, SRC_MAC, EtherType::Ipv4, 0);
        let mut frame = Buf::new(vec![0u8; 0], ..)
            .wrap_in(tcp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();

        let tcp_start =
            packet_formats::ethernet::ETHERNET_HDR_LEN_NO_TAG + packet_formats::ipv4::HDR_PREFIX_LEN;
        let mut sack = [0u8; 10];
        sack[0] = TCP_OPTION_KIND_SACK;
        sack[1] = 10;
        sack[2..6].copy_from_slice(&sack_left.to_be_bytes());
        sack[6..10].copy_from_slice(&sack_right.to_be_bytes());
        frame.resize(tcp_start + 32, 0);
        frame[tcp_start + 12] = 0x80; // data offset 32
        frame[tcp_start + 20..tcp_start + 30].copy_from_slice(&sack);
        frame[tcp_start + 30] = TCP_OPTION_KIND_NOP;
        frame[tcp_start + 31] = TCP_OPTION_KIND_NOP;
        Buf::new(frame, ..)
    }

    struct TcpInlineEditor<'a> {
        state: &'a IpsState,
        client_edits: u64,
        server_forwards: u64,
        last_server_ack: Option<u32>,
        last_sack_left: Option<u32>,
        last_sack_right: Option<u32>,
    }

    impl IpsReceiveBindingsContext<FakeDeviceId> for TcpInlineEditor<'_> {
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
            mut view: ReceivedTcpSegmentView,
        ) -> Result<(), IpsReceiveError> {
            use crate::tcp_flow::TcpFlowDirection;
            use crate::tcp_overwrite::{TcpForwardAction, TcpPayloadEdit};

            let hdr = view.tcp_header().expect("tcp header");
            let is_client_data =
                hdr.src_port == REMOTE_PORT.get() && hdr.dst_port == LOCAL_PORT.get();

            if is_client_data {
                const KEEP_LEN: usize = 160;
                self.state
                    .with_tcp_overwriter(&mut view, |mut overwriter| {
                        overwriter
                            .apply_edit(TcpPayloadEdit { keep_len: KEEP_LEN })
                            .expect("client edit");
                    })
                    .expect("client flow");
                self.client_edits += 1;
            } else {
                let action = self
                    .state
                    .with_tcp_overwriter(&mut view, |mut overwriter| overwriter.prepare_inbound())
                    .expect("server flow")
                    .expect("server prepare");
                assert_eq!(action, TcpForwardAction::Forward);
                let tcp_start = view.tcp_header().unwrap().header_range.start;
                let frame = view.eth_frames().next().unwrap();
                self.last_server_ack = Some(u32::from_be_bytes([
                    frame[tcp_start + 8],
                    frame[tcp_start + 9],
                    frame[tcp_start + 10],
                    frame[tcp_start + 11],
                ]));
                self.last_sack_left = Some(u32::from_be_bytes([
                    frame[tcp_start + 22],
                    frame[tcp_start + 23],
                    frame[tcp_start + 24],
                    frame[tcp_start + 25],
                ]));
                self.last_sack_right = Some(u32::from_be_bytes([
                    frame[tcp_start + 26],
                    frame[tcp_start + 27],
                    frame[tcp_start + 28],
                    frame[tcp_start + 29],
                ]));
                self.server_forwards += 1;
            }
            Ok(())
        }

        fn receive_icmp_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIcmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_igmp_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: ReceivedIgmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_pim_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedPimMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_ipsec_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIpsecMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }    }

    #[test]
    fn e2e_fragmented_tcp_edit_uses_state_tcp_flows_and_mangles_server_ack_and_sack() {
        const FRAGMENT_ID: u16 = 0x0077;
        const ORIGINAL_PAYLOAD: usize = 200;
        const FRAGMENT_BODY_LEN: usize = 104;

        let tcp = TcpSegmentBuilder::new(
            remote(2),
            DST,
            REMOTE_PORT,
            LOCAL_PORT,
            1000,
            None,
            65535,
        );
        let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            remote(2),
            DST,
            64,
            Ipv4Proto::Proto(IpProto::Tcp),
        );
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let frame = Buf::new(vec![0xAA; ORIGINAL_PAYLOAD], ..)
            .wrap_in(tcp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        let body_start =
            packet_formats::ethernet::ETHERNET_HDR_LEN_NO_TAG + packet_formats::ipv4::HDR_PREFIX_LEN;
        let ip_body = frame[body_start..].to_vec();
        let frag0 = build_ipv4_tcp_fragment(0, true, ip_body[..FRAGMENT_BODY_LEN].to_vec(), FRAGMENT_ID);
        let frag1 = build_ipv4_tcp_fragment(
            13,
            false,
            ip_body[FRAGMENT_BODY_LEN..].to_vec(),
            FRAGMENT_ID,
        );

        let mut state = IpsState::new();
        let mut handler = TcpInlineEditor {
            state: &state,
            client_edits: 0,
            server_forwards: 0,
            last_server_ack: None,
            last_sack_left: None,
            last_sack_right: None,
        };

        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frag0).unwrap();
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frag1).unwrap();
        assert_eq!(handler.client_edits, 1);
        assert_eq!(state.tcp_flow_count(), 1);

        let server_frame = build_server_ack_with_sack(1080, 1010, 1080);
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, server_frame).unwrap();

        assert_eq!(handler.server_forwards, 1);
        assert_eq!(handler.last_server_ack, Some(1040));
    }

    fn build_ipv4_frame_with_proto(proto: Ipv4Proto, body: Vec<u8>) -> Buf<Vec<u8>> {
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(remote(2), DST, 64, proto);
        let bytes = Buf::new(body, ..)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        Buf::new(bytes, ..)
    }

    fn build_unfragmented_udp_frame(payload: &[u8]) -> Buf<Vec<u8>> {
        let udp = UdpPacketBuilder::new(remote(2), DST, Some(REMOTE_PORT), LOCAL_PORT);
        let ip = packet_formats::ipv4::Ipv4PacketBuilder::new(
            remote(2),
            DST,
            64,
            Ipv4Proto::Proto(IpProto::Udp),
        );
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let bytes = Buf::new(payload.to_vec(), ..)
            .wrap_in(udp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        Buf::new(bytes, ..)
    }

    fn build_unfragmented_ipv6_udp_frame(payload: &[u8]) -> Buf<Vec<u8>> {
        use net_types::ip::Ipv6Addr;
        use packet_formats::ip::Ipv6Proto;
        use packet_formats::ipv6::Ipv6PacketBuilder;

        const SRC_V6: Ipv6Addr = Ipv6Addr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
        const DST_V6: Ipv6Addr = Ipv6Addr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2]);

        let udp = UdpPacketBuilder::new(SRC_V6, DST_V6, Some(REMOTE_PORT), LOCAL_PORT);
        let ip = Ipv6PacketBuilder::new(SRC_V6, DST_V6, 64, Ipv6Proto::Proto(IpProto::Udp));
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv6, 0);
        let bytes = Buf::new(payload.to_vec(), ..)
            .wrap_in(udp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        Buf::new(bytes, ..)
    }

    #[test]
    fn malformed_ethernet_frame_returns_unhandled() {
        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        let frame = Buf::new(vec![0u8; 8], ..);
        assert!(process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).is_err());
        assert!(handler.views.is_empty());
    }

    #[test]
    fn arp_ethertype_accepted_without_l7() {
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Arp, 0);
        let frame = Buf::new(vec![0u8; 28], ..)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, Buf::new(frame, ..)).unwrap();
        assert!(handler.views.is_empty());
    }

    #[test]
    fn unknown_ethertype_returns_frame_unhandled() {
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::from(0x9999), 0);
        let frame = Buf::new(vec![0u8; 8], ..)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        assert!(process_ethernet_frame(&state, &mut handler, &FakeDeviceId, Buf::new(frame, ..)).is_err());
        assert!(handler.views.is_empty());
    }

    #[test]
    fn non_l4_ipv4_returns_frame_unhandled() {
        let frame = build_ipv4_frame_with_proto(Ipv4Proto::from(47), vec![0x01, 0x02, 0x03, 0x04]);
        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        assert!(process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).is_err());
        assert!(handler.views.is_empty());
    }

    struct IgmpCapture {
        views: Vec<crate::view::ReceivedIgmpMessageView>,
    }

    impl IpsReceiveBindingsContext<FakeDeviceId> for IgmpCapture {
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
            _view: ReceivedTcpSegmentView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_icmp_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIcmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_igmp_message(
            &mut self,
            _device: &FakeDeviceId,
            view: crate::view::ReceivedIgmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            self.views.push(view);
            Ok(())
        }

        fn receive_pim_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedPimMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_ipsec_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIpsecMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }    }

    #[test]
    fn delivers_unfragmented_igmpv3_report_to_l7() {
        let frame = build_ipv4_frame_with_proto(
            Ipv4Proto::Igmp,
            vec![0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        );
        let state = IpsState::new();
        let mut handler = IgmpCapture { views: Vec::new() };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).unwrap();
        assert_eq!(handler.views.len(), 1);
        let hdr = handler.views[0].igmp_header().expect("igmp header");
        assert_eq!(hdr.msg_type, 0x22);
    }

    struct PimCapture {
        views: Vec<crate::view::ReceivedPimMessageView>,
    }

    impl IpsReceiveBindingsContext<FakeDeviceId> for PimCapture {
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
            _view: ReceivedTcpSegmentView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_icmp_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIcmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_igmp_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: ReceivedIgmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_pim_message(
            &mut self,
            _device: &FakeDeviceId,
            view: crate::view::ReceivedPimMessageView,
        ) -> Result<(), IpsReceiveError> {
            self.views.push(view);
            Ok(())
        }

        fn receive_ipsec_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIpsecMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }
    }

    #[test]
    fn delivers_unfragmented_pim_hello_to_l7() {
        let frame = build_ipv4_frame_with_proto(Ipv4Proto::from(103), vec![0x20, 0x00, 0x00, 0x00]);
        let state = IpsState::new();
        let mut handler = PimCapture { views: Vec::new() };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).unwrap();
        assert_eq!(handler.views.len(), 1);
        let hdr = handler.views[0].pim_header().expect("pim header");
        assert_eq!(hdr.version, 2);
        assert_eq!(hdr.msg_type, 0);
    }

    struct IpsecCapture {
        views: Vec<crate::view::ReceivedIpsecMessageView>,
    }

    impl IpsReceiveBindingsContext<FakeDeviceId> for IpsecCapture {
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
            _view: ReceivedTcpSegmentView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_icmp_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIcmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_igmp_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: ReceivedIgmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_pim_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedPimMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_ipsec_message(
            &mut self,
            _device: &FakeDeviceId,
            view: crate::view::ReceivedIpsecMessageView,
        ) -> Result<(), IpsReceiveError> {
            self.views.push(view);
            Ok(())
        }
    }

    #[test]
    fn delivers_unfragmented_esp_to_l7() {
        let frame = build_ipv4_frame_with_proto(
            Ipv4Proto::from(50),
            vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0xAA, 0xBB],
        );
        let state = IpsState::new();
        let mut handler = IpsecCapture { views: Vec::new() };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).unwrap();
        assert_eq!(handler.views.len(), 1);
        let hdr = handler.views[0].ipsec_header().expect("esp header");
        assert_eq!(hdr.protocol, crate::view::IpsecProtocol::Esp);
        assert_eq!(hdr.spi, 1);
        assert_eq!(hdr.sequence_number, 5);
    }

    #[test]
    fn delivers_unfragmented_ah_to_l7() {
        let frame = build_ipv4_frame_with_proto(
            Ipv4Proto::from(51),
            vec![
                0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0xCC,
            ],
        );
        let state = IpsState::new();
        let mut handler = IpsecCapture { views: Vec::new() };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).unwrap();
        assert_eq!(handler.views.len(), 1);
        let hdr = handler.views[0].ipsec_header().expect("ah header");
        assert_eq!(hdr.protocol, crate::view::IpsecProtocol::Ah);
        assert_eq!(hdr.spi, 2);
        assert_eq!(hdr.sequence_number, 7);
        assert_eq!(hdr.next_header, Some(0x04));
    }

    struct IcmpCapture {
        views: Vec<crate::view::ReceivedIcmpMessageView>,
    }

    impl IpsReceiveBindingsContext<FakeDeviceId> for IcmpCapture {
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
            _view: ReceivedTcpSegmentView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_icmp_message(
            &mut self,
            _device: &FakeDeviceId,
            view: crate::view::ReceivedIcmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            self.views.push(view);
            Ok(())
        }

        fn receive_igmp_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: ReceivedIgmpMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_pim_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedPimMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }

        fn receive_ipsec_message(
            &mut self,
            _device: &FakeDeviceId,
            _view: crate::view::ReceivedIpsecMessageView,
        ) -> Result<(), IpsReceiveError> {
            Ok(())
        }    }

    #[test]
    fn delivers_unfragmented_icmp_to_l7() {
        let frame = build_ipv4_frame_with_proto(Ipv4Proto::Icmp, vec![0, 0, 0, 0, 0x12, 0x34, 0, 1]);
        let state = IpsState::new();
        let mut handler = IcmpCapture { views: Vec::new() };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).unwrap();
        assert_eq!(handler.views.len(), 1);
        let view = &handler.views[0];
        let hdr = view.icmp_header().expect("icmp header");
        assert_eq!(hdr.msg_type, 0);
        assert_eq!(hdr.code, 0);
        match view.addrs() {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                assert_eq!(src, remote(2));
                assert_eq!(dst, DST);
            }
            _ => panic!("expected IPv4 addrs"),
        }
    }

    #[test]
    fn delivers_unfragmented_udp_to_l7() {
        const PAYLOAD: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let frame = build_unfragmented_udp_frame(PAYLOAD);
        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).unwrap();
        assert_eq!(handler.views.len(), 1);
        let view = &handler.views[0];
        assert_eq!(
            view.ip_fragment_metadata().reassembly_outcome,
            ReassemblyOutcome::NotApplicable
        );
        assert_eq!(view.payload_slices().iter().next().unwrap(), PAYLOAD);
        let eth = view.ethernet_header().expect("ethernet header");
        assert_eq!(eth.src_mac, SRC_MAC);
        assert_eq!(eth.dst_mac, DST_MAC);
        assert_eq!(eth.ethertype, Some(EtherType::Ipv4));
        match view.addrs() {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                assert_eq!(src, remote(2));
                assert_eq!(dst, DST);
            }
            _ => panic!("expected IPv4 addrs"),
        }
    }

    #[test]
    fn partial_reassembly_does_not_deliver_to_l7() {
        const PAYLOAD_LEN: usize = 200;
        const UDP_TOTAL: usize = 8 + PAYLOAD_LEN;
        let frag0 = build_udp_fragment(
            remote(2),
            0,
            true,
            first_fragment_body(UDP_TOTAL, 0xAA),
            0x2001,
        );
        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frag0).unwrap();
        assert!(handler.views.is_empty(), "incomplete assembly must not reach L7");
    }

    #[test]
    fn two_fragment_udp_reassembly_preserves_payload_bytes() {
        const PAYLOAD_LEN: usize = 120;
        const UDP_TOTAL: usize = 8 + PAYLOAD_LEN;
        const FILL: u8 = 0x55;

        let mut expected_payload = vec![FILL; PAYLOAD_LEN];
        let frag0 = build_udp_fragment(
            remote(2),
            0,
            true,
            first_fragment_body(UDP_TOTAL, FILL),
            0x2002,
        );
        let second_len = UDP_TOTAL - FRAGMENT_BODY_LEN;
        let frag1 = build_udp_fragment(remote(2), 13, false, vec![FILL; second_len], 0x2002);

        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frag0).unwrap();
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frag1).unwrap();

        assert_eq!(handler.views.len(), 1);
        let view = &handler.views[0];
        assert_eq!(
            view.ip_fragment_metadata().reassembly_outcome,
            ReassemblyOutcome::Complete
        );
        let mut actual = Vec::new();
        for slice in view.payload_slices().iter() {
            actual.extend_from_slice(slice);
        }
        assert_eq!(actual, expected_payload);
    }

    #[test]
    fn rfc5722_overlap_delivers_aborted_view_with_empty_payload() {
        const FRAG_ID: u16 = 0x3001;
        let frag0 = build_udp_fragment(remote(2), 12, true, vec![0xAA; 104], FRAG_ID);
        let frag1 = build_udp_fragment(remote(2), 6, true, vec![0xBB; 104], FRAG_ID);

        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frag0).unwrap();
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frag1).unwrap();

        assert_eq!(handler.views.len(), 1);
        let view = &handler.views[0];
        assert_eq!(
            view.ip_fragment_metadata().reassembly_outcome,
            ReassemblyOutcome::AbortedRfc5722Overlap
        );
        assert!(view.udp_header().is_none());
        assert_eq!(view.payload_slices().iter().map(|s| s.len()).sum::<usize>(), 0);
    }

    #[test]
    fn ipv6_unfragmented_udp_delivers_to_l7() {
        const PAYLOAD: &[u8] = &[0x11, 0x22, 0x33];
        let frame = build_unfragmented_ipv6_udp_frame(PAYLOAD);
        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).unwrap();
        assert_eq!(handler.views.len(), 1);
        match handler.views[0].addrs() {
            (IpAddr::V6(_), IpAddr::V6(_)) => {}
            _ => panic!("expected IPv6 addrs"),
        }
        assert_eq!(handler.views[0].payload_slices().iter().next().unwrap(), PAYLOAD);
        let eth = handler.views[0].ethernet_header().expect("ethernet header");
        assert_eq!(eth.src_mac, SRC_MAC);
        assert_eq!(eth.dst_mac, DST_MAC);
        assert_eq!(eth.ethertype, Some(EtherType::Ipv6));
    }

    #[test]
    fn truncated_before_udp_header_returns_frame_unhandled() {
        let frame = truncate_frame(build_unfragmented_udp_frame(&[0u8; 16]), ETHERNET_HDR_LEN_NO_TAG + 22);
        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        assert!(process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).is_err());
        assert!(handler.views.is_empty());
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn process_ethernet_frame_never_panics(raw in prop::collection::vec(any::<u8>(), 0..2048)) {
                let state = IpsState::new();
                let mut handler = Capture { views: Vec::new() };
                let _ = process_ethernet_frame(
                    &state,
                    &mut handler,
                    &FakeDeviceId,
                    Buf::new(raw, ..),
                );
            }
        }
    }
}
