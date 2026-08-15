// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Wire-layout offsets derived from [`packet_formats`] header types.
//!
//! IPS overwrites patch length/checksum fields in place; offsets here are taken
//! from public `packet_formats` constants or `HeaderPrefix` field layout rather
//! than duplicated magic numbers.


pub(crate) use packet_formats::tcp::CHECKSUM_OFFSET as TCP_CHECKSUM_OFFSET;
pub(crate) use packet_formats::tcp::HDR_PREFIX_LEN as TCP_HDR_PREFIX_LEN;
pub(crate) use packet_formats::udp::CHECKSUM_OFFSET as UDP_CHECKSUM_OFFSET;
pub(crate) use packet_formats::udp::HEADER_BYTES as UDP_HEADER_BYTES;
pub(crate) use packet_formats::ipv4::testutil::IPV4_CHECKSUM_OFFSET as IPV4_HDR_CHECKSUM_OFFSET;

/// Byte offset of the IPv4 total-length field from the start of an IPv4 header.
///
/// Matches the on-wire layout validated in [`wire::tests`].
pub(crate) const IPV4_TOTAL_LEN_OFFSET: usize = 2;

/// Byte offset of the IPv4 flags/fragment-offset field from the start of an IPv4 header.
///
/// Matches the on-wire layout validated in [`wire::tests`].
pub(crate) const IPV4_FLAGS_FRAG_OFFSET: usize = 6;

/// Byte offset of the UDP length field from the start of a UDP header.
pub(crate) const UDP_LENGTH_OFFSET: usize = UDP_CHECKSUM_OFFSET - 2;

/// Byte offset of the TCP sequence-number field from the start of a TCP header.
pub(crate) const TCP_SEQ_OFFSET: usize = 4;

/// Byte offset of the TCP acknowledgement-number field from the start of a TCP header.
pub(crate) const TCP_ACK_OFFSET: usize = 8;

/// Byte offset of the TCP flags field from the start of a TCP header.
pub(crate) const TCP_FLAGS_OFFSET: usize = 13;

/// Byte offset of the TCP urgent pointer from the start of a TCP header.
pub(crate) const TCP_URG_OFFSET: usize = TCP_CHECKSUM_OFFSET + 2;

/// TCP FIN flag (RFC 793).
pub(crate) const TCP_FLAG_FIN: u8 = 0x01;

/// TCP PSH flag (RFC 793).
pub(crate) const TCP_FLAG_PSH: u8 = 0x08;

/// TCP URG flag (RFC 793).
pub(crate) const TCP_FLAG_URG: u8 = 0x20;

/// TCP ACK flag (RFC 793).
pub(crate) const TCP_FLAG_ACK: u8 = 0x10;

/// TCP option kind: End of Option List.
pub(crate) const TCP_OPTION_KIND_EOL: u8 = 0;

/// TCP option kind: No-Operation.
pub(crate) const TCP_OPTION_KIND_NOP: u8 = 1;

/// TCP option kind: SACK Permitted.
pub(crate) const TCP_OPTION_KIND_SACK_PERMITTED: u8 = 4;

/// TCP option kind: SACK.
pub(crate) const TCP_OPTION_KIND_SACK: u8 = 5;

#[cfg(test)]
mod tests {
    use alloc::vec;

    use core::num::NonZeroU16;

    use net_types::ip::Ipv4Addr;
    use netstack3_base::NetworkSerializationContext;
    use packet::{Buf, NestableSerializer as _, ParsablePacket, Serializer};
    use packet_formats::ethernet::{EtherType, ETHERNET_HDR_LEN_NO_TAG, EthernetFrameBuilder};
    use packet_formats::ip::{IpProto, Ipv4Proto};
    use packet_formats::ipv4::{Ipv4Header, Ipv4Packet, Ipv4PacketBuilder};
    use packet_formats::tcp::TcpSegmentBuilder;

    use super::*;

    #[test]
    fn ipv4_offsets_match_parsed_packet_layout() {
        let mut builder = Ipv4PacketBuilder::new(
            Ipv4Addr::new([10, 0, 0, 1]),
            Ipv4Addr::new([10, 0, 0, 2]),
            64,
            Ipv4Proto::Proto(IpProto::Udp),
        );
        builder.mf_flag(true);
        builder.fragment_offset(packet_formats::ip::FragmentOffset::new(8).unwrap());
        let eth = EthernetFrameBuilder::new(
            net_types::ethernet::Mac::new([1; 6]),
            net_types::ethernet::Mac::new([2; 6]),
            EtherType::Ipv4,
            0,
        );
        let bytes = Buf::new(vec![0xAA; 8], ..)
            .wrap_in(builder)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        let ip_offset = ETHERNET_HDR_LEN_NO_TAG;
        let mut ip_bytes = &bytes[ip_offset..];
        let packet = Ipv4Packet::parse(&mut ip_bytes, ()).expect("IPv4 packet");
        let ip_total = u16::try_from(packet.header_len() + packet.body().len()).unwrap();
        assert_eq!(
            u16::from_be_bytes([
                bytes[ip_offset + IPV4_TOTAL_LEN_OFFSET],
                bytes[ip_offset + IPV4_TOTAL_LEN_OFFSET + 1],
            ]),
            ip_total
        );
        assert_eq!(packet.mf_flag(), bytes[ip_offset + IPV4_FLAGS_FRAG_OFFSET] & 0x20 != 0);
        assert_eq!(
            packet.fragment_offset().into_raw(),
            u16::from_be_bytes([
                bytes[ip_offset + IPV4_FLAGS_FRAG_OFFSET],
                bytes[ip_offset + IPV4_FLAGS_FRAG_OFFSET + 1],
            ]) & 0x1FFF
        );
        assert_eq!(IPV4_HDR_CHECKSUM_OFFSET, 10);
    }

    #[test]
    fn udp_offsets_match_packet_formats() {
        assert_eq!(UDP_LENGTH_OFFSET, 4);
        assert_eq!(UDP_CHECKSUM_OFFSET, 6);
        assert_eq!(UDP_HEADER_BYTES, 8);
    }

    #[test]
    fn tcp_offsets_match_packet_formats() {
        assert_eq!(TCP_CHECKSUM_OFFSET, 16);
        assert_eq!(TCP_HDR_PREFIX_LEN, 20);
        assert_eq!(TCP_URG_OFFSET, 18);
        assert_eq!(TCP_FLAGS_OFFSET, 13);
    }

    #[test]
    fn tcp_flag_masks_match_built_segment() {
        const SRC: Ipv4Addr = Ipv4Addr::new([10, 0, 0, 1]);
        const DST: Ipv4Addr = Ipv4Addr::new([10, 0, 0, 2]);
        let mut fin_builder = TcpSegmentBuilder::new(
            SRC,
            DST,
            NonZeroU16::new(1).unwrap(),
            NonZeroU16::new(2).unwrap(),
            0,
            None,
            1024,
        );
        fin_builder.fin(true);
        let fin_bytes = Buf::new(vec![0xAA; 4], ..)
            .wrap_in(fin_builder)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        assert_ne!(fin_bytes[TCP_FLAGS_OFFSET] & TCP_FLAG_FIN, 0);

        let mut psh_builder = TcpSegmentBuilder::new(
            SRC,
            DST,
            NonZeroU16::new(1).unwrap(),
            NonZeroU16::new(2).unwrap(),
            0,
            Some(0),
            1024,
        );
        psh_builder.psh(true);
        let psh_bytes = Buf::new(vec![0xBB; 4], ..)
            .wrap_in(psh_builder)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        assert_ne!(psh_bytes[TCP_FLAGS_OFFSET] & TCP_FLAG_PSH, 0);
        assert_ne!(psh_bytes[TCP_FLAGS_OFFSET] & TCP_FLAG_ACK, 0);
    }
}
