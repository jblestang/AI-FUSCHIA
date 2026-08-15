// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Layer 7 helpers for RFC 5722 overlapping IP fragment detection.

use crate::view::{FragmentEvent, ReceivedUdpDatagramView, ReassemblyOutcome};

/// An overlapping IP fragment observed during reassembly (RFC 5722).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rfc5722Overlap {
    /// IPv4/IPv6 fragment identification shared by the datagram.
    pub identification: u32,
    /// Fragment offset (8-octet units) of the overlapping fragment.
    pub fragment_offset: u16,
    /// Index into [`ReceivedUdpDatagramView::ip_fragments`] for the overlapping
    /// fragment that triggered the abort.
    pub conflicting_fragment_index: usize,
}

/// Returns `Some` when reassembly was aborted due to an overlapping fragment.
///
/// Overlap events are recorded by the IPS ingress path in
/// [`ReceivedUdpDatagramView::ip_fragment_metadata`]. The delivered view retains
/// all received fragment frames for zero-copy inspection even when the UDP
/// payload is empty.
pub fn detect_rfc5722_overlap(view: &ReceivedUdpDatagramView) -> Option<Rfc5722Overlap> {
    let meta = view.ip_fragment_metadata();

    for event in &meta.events {
        if let FragmentEvent::OverlappingFragment {
            identification,
            fragment_offset,
            conflicting_fragment_index,
        } = event
        {
            return Some(Rfc5722Overlap {
                identification: *identification,
                fragment_offset: *fragment_offset,
                conflicting_fragment_index: *conflicting_fragment_index,
            });
        }
    }

    if meta.reassembly_outcome == ReassemblyOutcome::AbortedRfc5722Overlap {
        // Outcome indicates overlap even if event details were not retained.
        let frag = view.ip_fragments().last()?;
        return Some(Rfc5722Overlap {
            identification: frag.identification,
            fragment_offset: frag.fragment_offset,
            conflicting_fragment_index: view.ip_fragments().len().saturating_sub(2),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use net_types::ethernet::Mac;
    use net_types::ip::Ipv4Addr;
    use netstack3_base::NetworkSerializationContext;
    use packet::{Buf, NestableSerializer as _, Serializer};
    use packet_formats::ethernet::{EtherType, ETHERNET_HDR_LEN_NO_TAG, EthernetFrameBuilder};
    use packet_formats::ip::{FragmentOffset, IpProto, Ipv4Proto};
    use packet_formats::ipv4::{HDR_PREFIX_LEN, Ipv4PacketBuilder};

    use super::*;
    use crate::view::{IpFragmentInfo, IpFragmentMetadata};

    const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
    const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 1]);
    const REMOTE_IP: Ipv4Addr = Ipv4Addr::new([192, 0, 2, 2]);
    const FRAGMENT_ID: u16 = 5;
    const FRAGMENT_BODY_LEN: usize = 104;

    fn build_ipv4_fragment(
        fragment_offset: FragmentOffset,
        more_fragments: bool,
        body: alloc::vec::Vec<u8>,
    ) -> Buf<alloc::vec::Vec<u8>> {
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

    fn view_with_overlap() -> ReceivedUdpDatagramView {
        let frame0 = build_ipv4_fragment(
            FragmentOffset::new(12).unwrap(),
            true,
            alloc::vec![0xAA; FRAGMENT_BODY_LEN],
        );
        let frame1 = build_ipv4_fragment(
            FragmentOffset::new(6).unwrap(),
            true,
            alloc::vec![0xBB; FRAGMENT_BODY_LEN],
        );
        let len0 = frame0.as_ref().len();
        let len1 = frame1.as_ref().len();
        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;

        ReceivedUdpDatagramView::new(
            alloc::vec![frame0, frame1],
            alloc::vec![
                IpFragmentInfo {
                    eth_frame_index: 0,
                    ip_packet_range: ip_offset..len0,
                    identification: u32::from(FRAGMENT_ID),
                    fragment_offset: 12,
                    more_fragments: true,
                    ip_body_range: ip_offset + HDR_PREFIX_LEN..len0,
                },
                IpFragmentInfo {
                    eth_frame_index: 1,
                    ip_packet_range: ip_offset..len1,
                    identification: u32::from(FRAGMENT_ID),
                    fragment_offset: 6,
                    more_fragments: true,
                    ip_body_range: ip_offset + HDR_PREFIX_LEN..len1,
                },
            ],
            IpFragmentMetadata {
                reassembly_outcome: ReassemblyOutcome::AbortedRfc5722Overlap,
                events: alloc::vec![FragmentEvent::OverlappingFragment {
                    identification: u32::from(FRAGMENT_ID),
                    fragment_offset: 6,
                    conflicting_fragment_index: 1,
                }],
                ..Default::default()
            },
            None,
            alloc::vec![],
            LOCAL_IP.into(),
            REMOTE_IP.into(),
        )
    }

    #[test]
    fn detect_rfc5722_overlap_from_metadata() {
        let view = view_with_overlap();
        let overlap = detect_rfc5722_overlap(&view).expect("overlap event");
        assert_eq!(overlap.identification, u32::from(FRAGMENT_ID));
        assert_eq!(overlap.fragment_offset, 6);
        assert_eq!(overlap.conflicting_fragment_index, 1);
    }

    #[test]
    fn detect_rfc5722_overlap_none_when_complete() {
        let view = ReceivedUdpDatagramView::new(
            alloc::vec![],
            alloc::vec![],
            IpFragmentMetadata {
                reassembly_outcome: ReassemblyOutcome::Complete,
                ..Default::default()
            },
            None,
            alloc::vec![],
            LOCAL_IP.into(),
            REMOTE_IP.into(),
        );
        assert!(detect_rfc5722_overlap(&view).is_none());
    }
}
