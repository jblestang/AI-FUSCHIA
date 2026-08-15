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
    use packet_formats::ethernet::{EtherType, EthernetFrameBuilder};
    use packet_formats::ip::{IpProto, Ipv4Proto};
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
    }

    #[test]
    fn reassembles_interleaved_fragments_from_multiple_sources() {
        const PAYLOAD_LEN: usize = 200;
        const UDP_TOTAL: usize = 8 + PAYLOAD_LEN;

        let state = IpsState::new();
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
}
