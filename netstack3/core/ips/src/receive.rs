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
use packet_formats::ipv4::Ipv4Packet;
use packet_formats::ipv6::Ipv6Packet;

use crate::context::IpsReceiveBindingsContext;
use crate::fragment::{add_fragment, ipv4_key, store_fragment};
use crate::state::{
    assembly_metadata, ip_addr_v4, ip_addr_v6, AssemblyProgress, DatagramAssembly, IpsState,
};
use crate::view::{
    IpFragmentInfo, IpFragmentMetadata, ReceivedUdpDatagramView, ReassemblyOutcome, UdpHeaderView,
};

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
    let (src, dst, id, offset, mf, ip_packet_end, body_start) = {
        let packet = match Ipv4Packet::parse(&mut ip_bytes, ()) {
            Ok(p) => p,
            Err(_) => return Err(frame),
        };

        if !matches!(packet.proto(), Ipv4Proto::Proto(IpProto::Udp)) {
            return Err(frame);
        }

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
        )
    };

    let fragmented = mf || offset != 0;

    if !fragmented {
        return deliver_unfragmented_v4(
            bindings_ctx,
            device_id,
            frame,
            ip_offset,
            src,
            dst,
            id,
            body_start,
        );
    }

    let stored = store_fragment(
        frame,
        ip_offset..ip_packet_end,
        id,
        offset,
        mf,
        body_start..ip_packet_end,
    );

    let key = ipv4_key(src, dst, id);
    match add_fragment(&state.ipv4, key, stored) {
        AssemblyProgress::NeedMore => Ok(()),
        AssemblyProgress::Ready(assembly) => {
            deliver_assembly_v4(bindings_ctx, device_id, assembly, ReassemblyOutcome::Complete);
            Ok(())
        }
        AssemblyProgress::Aborted(assembly) => {
            deliver_assembly_v4(
                bindings_ctx,
                device_id,
                assembly,
                ReassemblyOutcome::AbortedRfc5722Overlap,
            );
            Ok(())
        }
    }
}

fn process_ipv6<D, BC>(
    _state: &IpsState,
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
    let (src, dst, body_start) = {
        let packet = match Ipv6Packet::parse(&mut ip_bytes, ()) {
            Ok(p) => p,
            Err(_) => return Err(frame),
        };

        let is_udp = matches!(packet.proto(), Ipv6Proto::Proto(IpProto::Udp)) || is_fragment;

        if !is_udp {
            return Err(frame);
        }

        let src = packet.src_ip();
        let dst = packet.dst_ip();
        let body_start = ip_offset + ParsablePacket::parse_metadata(&packet).header_len();
        (src, dst, body_start)
    };

    if is_fragment {
        return Err(frame);
    }

    deliver_unfragmented_v6(bindings_ctx, device_id, frame, ip_offset, src, dst, body_start)
}

fn ipv6_fragment_info(_frame: &[u8], _ip_offset: usize) -> (u16, bool, u32, bool) {
    // TODO(https://fxbug.dev/000000): IPv6 fragment metadata for IPS ingress.
    (0, false, 0, false)
}

fn deliver_unfragmented_v4<D, BC>(
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
    let payload_start = body_start + packet_formats::udp::HEADER_BYTES;
    let header_range = body_start..payload_start;

    let hdr = {
        let bytes = &frame.as_ref()[header_range.clone()];
        (
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
            u16::from_be_bytes([bytes[4], bytes[5]]),
        )
    };
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
        Some(UdpHeaderView {
            src_port: hdr.0,
            dst_port: hdr.1,
            length: hdr.2,
            eth_frame_index: 0,
            header_range,
        }),
        alloc::vec![(0, payload_start..frame_len)],
        IpAddr::V4(src),
        IpAddr::V4(dst),
    );

    let _ = bindings_ctx.receive_udp_datagram(device_id, view);
    Ok(())
}

fn deliver_unfragmented_v6<D, BC>(
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
    let payload_start = body_start + packet_formats::udp::HEADER_BYTES;
    let header_range = body_start..payload_start;

    let hdr = {
        let bytes = &frame.as_ref()[header_range.clone()];
        (
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
            u16::from_be_bytes([bytes[4], bytes[5]]),
        )
    };
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
        Some(UdpHeaderView {
            src_port: hdr.0,
            dst_port: hdr.1,
            length: hdr.2,
            eth_frame_index: 0,
            header_range,
        }),
        alloc::vec![(0, payload_start..frame_len)],
        IpAddr::V6(src),
        IpAddr::V6(dst),
    );

    let _ = bindings_ctx.receive_udp_datagram(device_id, view);
    Ok(())
}

fn deliver_assembly_v4<D, BC>(
    bindings_ctx: &mut BC,
    device_id: &D,
    assembly: DatagramAssembly<Ipv4>,
    outcome: ReassemblyOutcome,
) where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let (src, dst) = ip_addr_v4(assembly.src_ip, assembly.dst_ip);
    deliver_assembly_impl(bindings_ctx, device_id, assembly, outcome, src, dst);
}

fn deliver_assembly_v6<D, BC>(
    bindings_ctx: &mut BC,
    device_id: &D,
    assembly: DatagramAssembly<Ipv6>,
    outcome: ReassemblyOutcome,
) where
    D: StrongDeviceIdentifier,
    BC: IpsReceiveBindingsContext<D>,
{
    let (src, dst) = ip_addr_v6(assembly.src_ip, assembly.dst_ip);
    deliver_assembly_impl(bindings_ctx, device_id, assembly, outcome, src, dst);
}

fn deliver_assembly_impl<I, D, BC>(
    bindings_ctx: &mut BC,
    device_id: &D,
    assembly: DatagramAssembly<I>,
    outcome: ReassemblyOutcome,
    src: IpAddr,
    dst: IpAddr,
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
    let _ = bindings_ctx.receive_udp_datagram(device_id, view);
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
                let udp_start = body.start;
                let header_range = udp_start..udp_start + packet_formats::udp::HEADER_BYTES;
                let frame = &eth_frames[info.eth_frame_index];
                let hdr = &frame.as_ref()[udp_start..udp_start + packet_formats::udp::HEADER_BYTES];
                udp_header = Some(UdpHeaderView {
                    src_port: u16::from_be_bytes([hdr[0], hdr[1]]),
                    dst_port: u16::from_be_bytes([hdr[2], hdr[3]]),
                    length: u16::from_be_bytes([hdr[4], hdr[5]]),
                    eth_frame_index: info.eth_frame_index,
                    header_range,
                });
                let payload_start = udp_start + packet_formats::udp::HEADER_BYTES;
                if payload_start < body.end {
                    payload_parts.push((info.eth_frame_index, payload_start..body.end));
                }
            }
        } else if body.start < body.end {
            payload_parts.push((info.eth_frame_index, body.clone()));
        }
    }

    (udp_header, payload_parts)
}
