// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! IPS bindings and handler traits.

extern crate alloc;

use alloc::vec::Vec;

use netstack3_base::StrongDeviceIdentifier;
use packet::{Buffer as _, BufferMut, GrowBuffer as _};

use crate::view::{
    ReceivedIcmpMessageView, ReceivedIgmpMessageView, ReceivedTcpSegmentView, ReceivedUdpDatagramView,
};

/// Errors encountered when delivering to Layer 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsReceiveError {
    /// The IPS receive queue or handler rejected the datagram.
    QueueFull,
}

/// Bindings context for zero-copy IPS delivery to Layer 7.
pub trait IpsReceiveBindingsContext<D: StrongDeviceIdentifier> {
    /// Delivers a reassembled or aborted (RFC 5722 overlap) UDP datagram view.
    fn receive_udp_datagram(
        &mut self,
        device_id: &D,
        view: ReceivedUdpDatagramView,
    ) -> Result<(), IpsReceiveError>;

    /// Delivers a reassembled or aborted TCP segment view.
    fn receive_tcp_segment(
        &mut self,
        device_id: &D,
        view: ReceivedTcpSegmentView,
    ) -> Result<(), IpsReceiveError>;

    /// Delivers an ICMP or ICMPv6 message view.
    fn receive_icmp_message(
        &mut self,
        device_id: &D,
        view: ReceivedIcmpMessageView,
    ) -> Result<(), IpsReceiveError>;

    /// Delivers an IGMP (IPv4 multicast) message view.
    fn receive_igmp_message(
        &mut self,
        device_id: &D,
        view: ReceivedIgmpMessageView,
    ) -> Result<(), IpsReceiveError>;
}

/// Whether the IPS ingress path consumed a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsIngressResult {
    /// IPS handled the frame; normal stack processing must not continue.
    Consumed,
    /// IPS did not handle the frame; continue normal stack processing.
    NotHandled,
}

/// Handler trait implemented by the core context for IPS ingress.
pub trait IpsIngressHandler<D: StrongDeviceIdentifier, BC: IpsReceiveBindingsContext<D>> {
    /// Returns true if IPS ingress is enabled for `device_id`.
    fn ips_enabled(&self, device_id: &D) -> bool;

    /// Processes one Ethernet frame for IPS ingress.
    fn handle_ips_ethernet_ingress(
        &mut self,
        bindings_ctx: &mut BC,
        device_id: &D,
        frame: packet::Buf<Vec<u8>>,
    ) -> Result<(), packet::Buf<Vec<u8>>>;
}

/// Converts an RX buffer into a full Ethernet frame buffer for IPS ingress.
///
/// Implementations must restore any consumed link-layer headers without copying
/// payload bytes. Returns `Err(self)` when zero-copy conversion is impossible.
pub trait TryIntoIpsFrame: BufferMut + Sized {
    /// Restores the full Ethernet frame in `self`.
    fn try_into_ips_frame(self, whole_frame_len: usize) -> Result<packet::Buf<Vec<u8>>, Self>;
}

impl TryIntoIpsFrame for packet::Buf<Vec<u8>> {
    fn try_into_ips_frame(mut self, whole_frame_len: usize) -> Result<packet::Buf<Vec<u8>>, Self> {
        let consumed = whole_frame_len.saturating_sub(self.as_ref().len());
        self.grow_front(consumed);
        Ok(self)
    }
}
