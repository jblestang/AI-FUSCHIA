// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Structured ingress rejection reasons for passive capture / IDS logging.
//!
//! Mirrors the rejection branches in [`crate::receive::process_ethernet_frame`] without
//! mutating state or delivering to Layer 7.

use core::fmt;

use net_types::ip::IpAddr;
use packet::{ParseBuffer, ParsablePacket};
use packet_formats::ethernet::{EtherType, EthernetFrame, EthernetFrameLengthCheck};
use packet_formats::ip::{IpProto, Ipv4Proto, Ipv6Proto};
use packet_formats::ipv4::{Ipv4Header, Ipv4Packet};
use packet_formats::ipv6::{Ipv6Header, Ipv6Packet};

use crate::view::{parse_icmp_header, parse_tcp_header, parse_udp_header};

enum DiagnoseIpv4L4 {
    Udp,
    Tcp,
    Icmp,
}

/// One IPS ingress rejection stage (matches `process_ethernet_frame` error paths).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressRejectionStage {
    /// Ethernet header could not be parsed.
    EthernetParse,
    /// EtherType is not IPv4 or IPv6.
    UnsupportedEthertype,
    /// IPv4 header could not be parsed.
    Ipv4Parse,
    /// IPv4 next-header is not UDP or TCP (unfragmented datagram).
    UnsupportedIpv4Protocol,
    /// UDP header could not be parsed (IPv4 or IPv6 path).
    UdpHeaderParse,
    /// ICMP header could not be parsed (IPv4 or IPv6 path).
    IcmpHeaderParse,
    /// Frame ends before the UDP payload start (IPv4 only).
    FrameTruncated,
    /// TCP header could not be parsed (IPv4 only).
    TcpHeaderParse,
    /// IPv6 header could not be parsed.
    Ipv6Parse,
    /// IPv6 next header is not UDP/TCP and not a fragment extension.
    UnsupportedIpv6Protocol,
    /// IPv6 fragmentation is not supported on the IPS ingress path.
    Ipv6FragmentUnsupported,
}

impl IngressRejectionStage {
    /// Stable snake_case label for log lines.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EthernetParse => "ethernet_parse",
            Self::UnsupportedEthertype => "unsupported_ethertype",
            Self::Ipv4Parse => "ipv4_parse",
            Self::UnsupportedIpv4Protocol => "unsupported_ipv4_protocol",
            Self::UdpHeaderParse => "udp_header_parse",
            Self::IcmpHeaderParse => "icmp_header_parse",
            Self::FrameTruncated => "frame_truncated",
            Self::TcpHeaderParse => "tcp_header_parse",
            Self::Ipv6Parse => "ipv6_parse",
            Self::UnsupportedIpv6Protocol => "unsupported_ipv6_protocol",
            Self::Ipv6FragmentUnsupported => "ipv6_fragment_unsupported",
        }
    }

    fn default_reason(self) -> &'static str {
        match self {
            Self::EthernetParse => "malformed or truncated Ethernet header",
            Self::UnsupportedEthertype => "EtherType is not IPv4 (0x0800) or IPv6 (0x86DD)",
            Self::Ipv4Parse => "malformed or truncated IPv4 header",
            Self::UnsupportedIpv4Protocol => "IPv4 protocol is not UDP, TCP, or ICMP",
            Self::UdpHeaderParse => "malformed or truncated UDP header",
            Self::IcmpHeaderParse => "malformed or truncated ICMP header",
            Self::FrameTruncated => "frame shorter than UDP header + payload start",
            Self::TcpHeaderParse => "malformed or truncated TCP header",
            Self::Ipv6Parse => "malformed or truncated IPv6 header",
            Self::UnsupportedIpv6Protocol => "IPv6 next header is not UDP, TCP, or ICMPv6",
            Self::Ipv6FragmentUnsupported => "IPv6 fragments are not supported on ingress",
        }
    }
}

/// Parsed fields available when diagnosis reaches a given layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressRejectionDiagnosis {
    /// Which ingress check failed.
    pub stage: IngressRejectionStage,
    /// Human-readable explanation (derived from `stage` unless overridden).
    pub reason: &'static str,
    /// Raw EtherType field when Ethernet parsing succeeded.
    pub ethertype: Option<u16>,
    /// Source MAC when Ethernet parsing succeeded.
    pub src_mac: Option<[u8; 6]>,
    /// Destination MAC when Ethernet parsing succeeded.
    pub dst_mac: Option<[u8; 6]>,
    /// Source IP when IP parsing succeeded.
    pub src_ip: Option<IpAddr>,
    /// Destination IP when IP parsing succeeded.
    pub dst_ip: Option<IpAddr>,
    /// IP protocol / next-header byte when IP parsing succeeded.
    pub ip_protocol: Option<u8>,
    /// Minimum frame length implied by the failure (truncation cases).
    pub expected_min_len: Option<usize>,
}

impl IngressRejectionDiagnosis {
    fn with_stage(stage: IngressRejectionStage) -> Self {
        Self {
            stage,
            reason: stage.default_reason(),
            ethertype: None,
            src_mac: None,
            dst_mac: None,
            src_ip: None,
            dst_ip: None,
            ip_protocol: None,
            expected_min_len: None,
        }
    }
}

impl fmt::Display for IngressRejectionDiagnosis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stage={} reason=\"{}\"", self.stage.as_str(), self.reason)?;
        if let Some(et) = self.ethertype {
            write!(f, " ethertype=0x{et:04x}")?;
        }
        if let Some(mac) = self.src_mac {
            write!(f, " src_mac=")?;
            write_mac(f, mac)?;
        }
        if let Some(mac) = self.dst_mac {
            write!(f, " dst_mac=")?;
            write_mac(f, mac)?;
        }
        if let Some(src) = self.src_ip {
            write!(f, " src_ip={src}")?;
        }
        if let Some(dst) = self.dst_ip {
            write!(f, " dst_ip={dst}")?;
        }
        if let Some(proto) = self.ip_protocol {
            write!(f, " ip_proto={proto}")?;
        }
        if let Some(min) = self.expected_min_len {
            write!(f, " expected_min_len={min}")?;
        }
        Ok(())
    }
}

fn write_mac(f: &mut fmt::Formatter<'_>, mac: [u8; 6]) -> fmt::Result {
    for (i, octet) in mac.iter().enumerate() {
        if i > 0 {
            f.write_str(":")?;
        }
        write!(f, "{octet:02x}")?;
    }
    Ok(())
}

fn ipv6_fragment_info(_frame: &[u8], _ip_offset: usize) -> (u16, bool, u32, bool) {
    // Keep in sync with receive.rs stub until IPv6 fragment ingress lands.
    (0, false, 0, false)
}

fn reject(stage: IngressRejectionStage) -> IngressRejectionDiagnosis {
    IngressRejectionDiagnosis::with_stage(stage)
}

/// Returns `None` when the frame would be accepted at IPS ingress (same layers as
/// [`crate::receive::process_ethernet_frame`], excluding L7 queue-full).
pub fn diagnose_ingress_rejection(frame: &[u8]) -> Option<IngressRejectionDiagnosis> {
    let mut parse_buf = frame;
    let eth = match parse_buf.parse_with::<_, EthernetFrame<_>>(EthernetFrameLengthCheck::NoCheck)
    {
        Ok(v) => v,
        Err(_) => return Some(reject(IngressRejectionStage::EthernetParse)),
    };

    let ip_offset = ParsablePacket::parse_metadata(&eth).header_len();
    let ethertype = eth.ethertype();
    let src_mac = eth.src_mac().bytes();
    let dst_mac = eth.dst_mac().bytes();
    let mut diag = IngressRejectionDiagnosis {
        ethertype: ethertype.map(u16::from),
        src_mac: Some(src_mac),
        dst_mac: Some(dst_mac),
        ..IngressRejectionDiagnosis::with_stage(IngressRejectionStage::EthernetParse)
    };

    match ethertype {
        Some(EtherType::Ipv4) => diagnose_ipv4(frame, ip_offset, &mut diag),
        Some(EtherType::Ipv6) => diagnose_ipv6(frame, ip_offset, &mut diag),
        Some(et) if crate::receive::ingress_accepts_without_l7(et) => None,
        _ => {
            diag.stage = IngressRejectionStage::UnsupportedEthertype;
            diag.reason = diag.stage.default_reason();
            Some(diag)
        }
    }
}

fn diagnose_ipv4(
    frame: &[u8],
    ip_offset: usize,
    diag: &mut IngressRejectionDiagnosis,
) -> Option<IngressRejectionDiagnosis> {
    let mut ip_bytes = &frame[ip_offset..];
    let (src, dst, offset, mf, body_start, l4) = {
        let packet = match Ipv4Packet::parse(&mut ip_bytes, ()) {
            Ok(p) => p,
            Err(_) => {
                diag.stage = IngressRejectionStage::Ipv4Parse;
                diag.reason = diag.stage.default_reason();
                return Some(diag.clone());
            }
        };

        let l4 = match packet.proto() {
            Ipv4Proto::Proto(IpProto::Udp) => DiagnoseIpv4L4::Udp,
            Ipv4Proto::Proto(IpProto::Tcp) => DiagnoseIpv4L4::Tcp,
            Ipv4Proto::Icmp => DiagnoseIpv4L4::Icmp,
            other => {
                diag.stage = IngressRejectionStage::UnsupportedIpv4Protocol;
                diag.reason = diag.stage.default_reason();
                diag.ip_protocol = Some(other.into());
                diag.src_ip = Some(IpAddr::V4(packet.src_ip()));
                diag.dst_ip = Some(IpAddr::V4(packet.dst_ip()));
                return Some(diag.clone());
            }
        };

        let meta = ParsablePacket::parse_metadata(&packet);
        let body_start = ip_offset + meta.header_len();
        (
            packet.src_ip(),
            packet.dst_ip(),
            packet.fragment_offset().into_raw(),
            packet.mf_flag(),
            body_start,
            l4,
        )
    };

    diag.src_ip = Some(IpAddr::V4(src));
    diag.dst_ip = Some(IpAddr::V4(dst));
    diag.ip_protocol = Some(match l4 {
        DiagnoseIpv4L4::Udp => IpProto::Udp.into(),
        DiagnoseIpv4L4::Tcp => IpProto::Tcp.into(),
        DiagnoseIpv4L4::Icmp => Ipv4Proto::Icmp.into(),
    });

    let fragmented = mf || offset != 0;
    if fragmented {
        return if matches!(l4, DiagnoseIpv4L4::Icmp) {
            diag.stage = IngressRejectionStage::UnsupportedIpv4Protocol;
            diag.reason = "fragmented ICMP is not supported on ingress";
            Some(diag.clone())
        } else {
            None
        };
    }

    let frame_len = frame.len();
    match l4 {
        DiagnoseIpv4L4::Udp => {
            let udp_hdr = match parse_udp_header(frame, 0, body_start) {
                Some(hdr) => hdr,
                None => {
                    diag.stage = IngressRejectionStage::UdpHeaderParse;
                    diag.reason = diag.stage.default_reason();
                    return Some(diag.clone());
                }
            };
            let payload_start = udp_hdr.header_range.end;
            if frame_len < payload_start {
                diag.stage = IngressRejectionStage::FrameTruncated;
                diag.reason = diag.stage.default_reason();
                diag.expected_min_len = Some(payload_start);
                return Some(diag.clone());
            }
            None
        }
        DiagnoseIpv4L4::Tcp => {
            if parse_tcp_header(frame, 0, body_start).is_none() {
                diag.stage = IngressRejectionStage::TcpHeaderParse;
                diag.reason = diag.stage.default_reason();
                return Some(diag.clone());
            }
            None
        }
        DiagnoseIpv4L4::Icmp => {
            if parse_icmp_header(frame, 0, body_start).is_none() {
                diag.stage = IngressRejectionStage::IcmpHeaderParse;
                diag.reason = diag.stage.default_reason();
                return Some(diag.clone());
            }
            None
        }
        _ => {
            diag.stage = IngressRejectionStage::UnsupportedIpv4Protocol;
            diag.reason = diag.stage.default_reason();
            Some(diag.clone())
        }
    }
}

fn diagnose_ipv6(
    frame: &[u8],
    ip_offset: usize,
    diag: &mut IngressRejectionDiagnosis,
) -> Option<IngressRejectionDiagnosis> {
    let is_fragment = ipv6_fragment_info(frame, ip_offset).3;
    let mut ip_bytes = &frame[ip_offset..];
    let (src, dst, body_start, v6_proto) = {
        let packet = match Ipv6Packet::parse(&mut ip_bytes, ()) {
            Ok(p) => p,
            Err(_) => {
                diag.stage = IngressRejectionStage::Ipv6Parse;
                diag.reason = diag.stage.default_reason();
                return Some(diag.clone());
            }
        };

        let v6_proto = packet.proto();
        let proto_byte: u8 = v6_proto.into();
        let is_l4 = matches!(
            v6_proto,
            Ipv6Proto::Proto(IpProto::Udp | IpProto::Tcp) | Ipv6Proto::Icmpv6
        ) || is_fragment;

        if !is_l4 {
            diag.stage = IngressRejectionStage::UnsupportedIpv6Protocol;
            diag.reason = diag.stage.default_reason();
            diag.ip_protocol = Some(proto_byte);
            diag.src_ip = Some(IpAddr::V6(packet.src_ip()));
            diag.dst_ip = Some(IpAddr::V6(packet.dst_ip()));
            return Some(diag.clone());
        }

        let body_start = ip_offset + ParsablePacket::parse_metadata(&packet).header_len();
        (packet.src_ip(), packet.dst_ip(), body_start, v6_proto)
    };

    diag.src_ip = Some(IpAddr::V6(src));
    diag.dst_ip = Some(IpAddr::V6(dst));
    diag.ip_protocol = Some(v6_proto.into());

    if is_fragment {
        diag.stage = IngressRejectionStage::Ipv6FragmentUnsupported;
        diag.reason = diag.stage.default_reason();
        return Some(diag.clone());
    }

    match v6_proto {
        Ipv6Proto::Proto(IpProto::Udp) => {
            if parse_udp_header(frame, 0, body_start).is_none() {
                diag.stage = IngressRejectionStage::UdpHeaderParse;
                diag.reason = diag.stage.default_reason();
                return Some(diag.clone());
            }
            None
        }
        Ipv6Proto::Icmpv6 => {
            if parse_icmp_header(frame, 0, body_start).is_none() {
                diag.stage = IngressRejectionStage::IcmpHeaderParse;
                diag.reason = diag.stage.default_reason();
                return Some(diag.clone());
            }
            None
        }
        _ => {
            diag.stage = IngressRejectionStage::UnsupportedIpv6Protocol;
            diag.reason = diag.stage.default_reason();
            Some(diag.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use core::num::NonZeroU16;

    use net_types::ethernet::Mac;
    use net_types::ip::{Ipv4Addr, Ipv6Addr};
    use netstack3_base::testutil::FakeDeviceId;
    use netstack3_base::NetworkSerializationContext;
    use packet::{Buf, NestableSerializer as _, Serializer as _};
    use packet_formats::ethernet::{EtherType, ETHERNET_HDR_LEN_NO_TAG, EthernetFrameBuilder};
    use packet_formats::ip::{IpProto, Ipv4Proto, Ipv6Proto};
    use packet_formats::ipv4::Ipv4PacketBuilder;
    use packet_formats::ipv6::Ipv6PacketBuilder;
    use packet_formats::tcp::TcpSegmentBuilder;
    use packet_formats::udp::UdpPacketBuilder;

    use super::*;
    use crate::context::IpsReceiveError;
    use crate::receive::process_ethernet_frame;
    use crate::state::IpsState;
    use crate::view::ReceivedUdpDatagramView;

    const SRC_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x01]);
    const DST_MAC: Mac = Mac::new([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]);
    const REMOTE: Ipv4Addr = Ipv4Addr::new([10, 0, 0, 2]);
    const LOCAL: Ipv4Addr = Ipv4Addr::new([10, 0, 0, 1]);
    const REMOTE_PORT: NonZeroU16 = NonZeroU16::new(1234).unwrap();
    const LOCAL_PORT: NonZeroU16 = NonZeroU16::new(5678).unwrap();

    struct Capture {
        views: Vec<ReceivedUdpDatagramView>,
    }

    impl crate::context::IpsReceiveBindingsContext<FakeDeviceId> for Capture {
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
            _view: crate::view::ReceivedTcpSegmentView,
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
    }

    fn assert_diagnosis_matches_rejection(frame: Buf<Vec<u8>>) {
        let bytes = frame.as_ref().to_vec();
        let state = IpsState::new();
        let mut handler = Capture { views: Vec::new() };
        let rejected = process_ethernet_frame(&state, &mut handler, &FakeDeviceId, frame).is_err();
        let diagnosis = diagnose_ingress_rejection(&bytes);
        assert_eq!(
            rejected,
            diagnosis.is_some(),
            "process_ethernet_frame and diagnose_ingress_rejection disagree for len={}",
            bytes.len()
        );
    }

    #[test]
    fn diagnose_malformed_ethernet() {
        let bytes = vec![0u8; 8];
        let diag = diagnose_ingress_rejection(&bytes).expect("rejected");
        assert_eq!(diag.stage, IngressRejectionStage::EthernetParse);
    }

    #[test]
    fn diagnose_arp_has_no_diagnosis() {
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Arp, 0);
        let frame = Buf::new(vec![0u8; 28], ..)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        assert!(diagnose_ingress_rejection(&frame).is_none());
    }

    #[test]
    fn diagnose_unknown_ethertype() {
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::from(0x9999), 0);
        let frame = Buf::new(vec![0u8; 8], ..)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        let diag = diagnose_ingress_rejection(&frame).expect("rejected");
        assert_eq!(diag.stage, IngressRejectionStage::UnsupportedEthertype);
        assert_eq!(diag.ethertype, Some(0x9999));
    }

    #[test]
    fn diagnose_agrees_with_process_ethernet_frame_on_reject_samples() {
        let icmp = {
            let ip = Ipv4PacketBuilder::new(REMOTE, LOCAL, 64, Ipv4Proto::Icmp);
            let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
            Buf::new(vec![0, 0, 0, 0, 0x12, 0x34, 0, 1], ..)
                .wrap_in(ip)
                .wrap_in(eth)
                .serialize_vec_outer(&mut NetworkSerializationContext::default())
                .unwrap()
                .into_inner()
        };
        let icmp_bytes = icmp.as_ref().to_vec();
        assert!(diagnose_ingress_rejection(&icmp_bytes).is_none());
        assert_diagnosis_matches_rejection(Buf::new(icmp_bytes, ..));

        let igmp = {
            let ip = Ipv4PacketBuilder::new(REMOTE, LOCAL, 64, Ipv4Proto::Igmp);
            let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
            Buf::new(vec![0x11, 0x02, 0x00, 0x00], ..)
                .wrap_in(ip)
                .wrap_in(eth)
                .serialize_vec_outer(&mut NetworkSerializationContext::default())
                .unwrap()
                .into_inner()
        };
        assert_diagnosis_matches_rejection(igmp);

        let truncated_udp = {
            let udp = UdpPacketBuilder::new(REMOTE, LOCAL, Some(REMOTE_PORT), LOCAL_PORT);
            let ip = Ipv4PacketBuilder::new(REMOTE, LOCAL, 64, Ipv4Proto::Proto(IpProto::Udp));
            let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
            let mut bytes = Buf::new(vec![0u8; 4], ..)
                .wrap_in(udp)
                .wrap_in(ip)
                .wrap_in(eth)
                .serialize_vec_outer(&mut NetworkSerializationContext::default())
                .unwrap()
                .into_inner()
                .into_inner();
            bytes.truncate(ETHERNET_HDR_LEN_NO_TAG + 24);
            Buf::new(bytes, ..)
        };
        assert_diagnosis_matches_rejection(truncated_udp);

        let truncated_tcp = {
            let tcp = TcpSegmentBuilder::new(
                REMOTE,
                LOCAL,
                REMOTE_PORT,
                LOCAL_PORT,
                1000,
                None,
                65535,
            );
            let ip = Ipv4PacketBuilder::new(REMOTE, LOCAL, 64, Ipv4Proto::Proto(IpProto::Tcp));
            let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
            let mut bytes = Buf::new(vec![0xCC; 32], ..)
                .wrap_in(tcp)
                .wrap_in(ip)
                .wrap_in(eth)
                .serialize_vec_outer(&mut NetworkSerializationContext::default())
                .unwrap()
                .into_inner()
                .into_inner();
            bytes.truncate(ETHERNET_HDR_LEN_NO_TAG + 24);
            Buf::new(bytes, ..)
        };
        assert_diagnosis_matches_rejection(truncated_tcp);

        let v6_udp = {
            const SRC_V6: Ipv6Addr = Ipv6Addr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
            const DST_V6: Ipv6Addr = Ipv6Addr::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2]);
            let udp = UdpPacketBuilder::new(SRC_V6, DST_V6, Some(REMOTE_PORT), LOCAL_PORT);
            let ip = Ipv6PacketBuilder::new(SRC_V6, DST_V6, 64, Ipv6Proto::Proto(IpProto::Udp));
            let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv6, 0);
            Buf::new(vec![0x11, 0x22, 0x33], ..)
                .wrap_in(udp)
                .wrap_in(ip)
                .wrap_in(eth)
                .serialize_vec_outer(&mut NetworkSerializationContext::default())
                .unwrap()
                .into_inner()
        };
        assert_diagnosis_matches_rejection(v6_udp);
    }

    #[test]
    fn accepted_unfragmented_udp_has_no_diagnosis() {
        let udp = UdpPacketBuilder::new(REMOTE, LOCAL, Some(REMOTE_PORT), LOCAL_PORT);
        let ip = Ipv4PacketBuilder::new(REMOTE, LOCAL, 64, Ipv4Proto::Proto(IpProto::Udp));
        let eth = EthernetFrameBuilder::new(SRC_MAC, DST_MAC, EtherType::Ipv4, 0);
        let bytes = Buf::new(vec![0xDE, 0xAD, 0xBE, 0xEF], ..)
            .wrap_in(udp)
            .wrap_in(ip)
            .wrap_in(eth)
            .serialize_vec_outer(&mut NetworkSerializationContext::default())
            .unwrap()
            .into_inner()
            .into_inner();
        assert!(diagnose_ingress_rejection(&bytes).is_none());
    }
}
