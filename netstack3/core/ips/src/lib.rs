// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Zero-copy IPS UDP/TCP receive paths for Layer 7 analysis.
//!
//! IP fragment reassembly follows RFC 5722: overlapping fragments abort
//! reassembly and are surfaced via [`IpFragmentMetadata`].

#![cfg_attr(not(feature = "benchmark"), no_std)]
#![warn(missing_docs)]

#[cfg(feature = "benchmark")]
extern crate std;
extern crate alloc;

mod context;
mod frame_store;
mod fragment;
mod ingress_diagnose;
mod overwrite;
mod receive;
mod state;
mod tcp_flow;
mod tcp_overwrite;
mod view;
mod wire;

#[cfg(feature = "benchmark")]
pub mod benchmarks;

/// Layer 7 analysis helpers (TOS mismatch detection, etc.).
pub mod analysis;
pub use analysis::{
    detect_forced_ip_segmentation, detect_rfc5722_overlap, detect_tos_mismatch,
    ipv4_dscp_and_ecn, reassembled_ipv4_datagram_bytes, ETHERNET_IPV4_MTU, ForcedIpSegmentation,
    Rfc5722Overlap, TosMismatch,
};
pub use context::{
    IpsIngressHandler, IpsIngressResult, IpsReceiveBindingsContext, IpsReceiveError,
    TryIntoIpsFrame,
};
pub use overwrite::{UdpOverwriteChecksum, UdpOverwriteError, UdpOverwriter};
pub use ingress_diagnose::{
    diagnose_ingress_rejection, IngressRejectionDiagnosis, IngressRejectionStage,
};
pub use receive::{ingress_accepts_without_l7, process_ethernet_frame};
pub use state::IpsState;
pub use tcp_flow::{
    InboundSegmentClass, IpsTcpFlowTable, IpsTcpFlowTableConfig, TcpEditRecord, TcpFlowDirection,
    TcpFlowKey, TcpFlowState,
};
pub use tcp_overwrite::{
    TcpForwardAction, TcpOverwriteChecksum, TcpOverwriteError, TcpOverwriter, TcpPayloadEdit,
};
pub use view::{
    EthernetHeaderView, FragmentEvent, IgmpHeaderView, IcmpHeaderView, IpFragmentMetadata,
    IpFragmentInfo, IpsecHeaderView, IpsecProtocol, PayloadSliceView, PimHeaderView,
    ReceivedIcmpMessageView, ReceivedIgmpMessageView, ReceivedIpsecMessageView,
    ReceivedPimMessageView, ReceivedTcpSegmentView, ReceivedUdpDatagramView, ReassemblyOutcome,
    TcpHeaderView, UdpHeaderView,
};
