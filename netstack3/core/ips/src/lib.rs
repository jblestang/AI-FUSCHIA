// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Zero-copy IPS UDP receive path for Layer 7 analysis.
//!
//! This crate provides a driver-to-Layer-7 ingress path for UDP datagrams that
//! bypasses UDP sockets, filtering, and routing. Datagrams are delivered as
//! [`ReceivedUdpDatagramView`] values with multi-layer zero-copy access to
//! Ethernet frames, IP fragments, UDP headers, and iovec-style payloads.
//!
//! IP fragment reassembly follows RFC 5722: overlapping fragments abort
//! reassembly and are surfaced via [`IpFragmentMetadata`].

#![cfg_attr(not(feature = "benchmark"), no_std)]
#![warn(missing_docs)]

#[cfg(feature = "benchmark")]
extern crate std;
extern crate alloc;

mod context;
mod fragment;
mod receive;
mod state;
mod view;

#[cfg(feature = "benchmark")]
pub mod benchmarks;

/// Layer 7 analysis helpers (TOS mismatch detection, etc.).
pub mod analysis;
pub use analysis::{
    detect_rfc5722_overlap, detect_tos_mismatch, ipv4_dscp_and_ecn, Rfc5722Overlap, TosMismatch,
};
pub use context::{
    IpsIngressHandler, IpsIngressResult, IpsReceiveBindingsContext, IpsReceiveError,
    TryIntoIpsFrame,
};
pub use receive::process_ethernet_frame;
pub use state::IpsState;
pub use view::{
    FragmentEvent, IpFragmentMetadata, IpFragmentInfo, PayloadSliceView, ReceivedUdpDatagramView,
    ReassemblyOutcome, UdpHeaderView,
};
