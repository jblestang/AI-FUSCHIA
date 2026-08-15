// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Optional IPS ingress hook at the device layer.

use alloc::vec::Vec;

use netstack3_base::IpsRxFrameBuffer;
use packet::Buf;
use packet_formats::ethernet::ETHERNET_HDR_LEN_NO_TAG;

/// Core context hook for IPS zero-copy ingress at L2.
pub trait IpsRxFrameHandler<BC> {
    /// Device identifier type.
    type DeviceId;

    /// Returns true when IPS ingress is enabled for `device_id`.
    fn ips_ingress_enabled(&self, device_id: &Self::DeviceId) -> bool {
        let _ = device_id;
        false
    }

    /// Attempt IPS processing of a full Ethernet frame buffer.
    ///
    /// Returns the frame back in `Err` when IPS did not consume it.
    fn try_ips_ingress(
        &mut self,
        bindings_ctx: &mut BC,
        device_id: &Self::DeviceId,
        frame: Buf<Vec<u8>>,
    ) -> Result<(), Buf<Vec<u8>>> {
        let _ = (bindings_ctx, device_id);
        Err(frame)
    }
}

fn is_ip_ethertype(frame: &[u8]) -> bool {
    if frame.len() < ETHERNET_HDR_LEN_NO_TAG {
        return false;
    }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0800 | 0x86DD => true,
        _ => false,
    }
}

/// Outcome of attempting IPS ingress before Ethernet parsing.
pub enum IpsPreParseResult<B> {
    /// IPS did not apply; continue with the same buffer.
    NotApplicable(B),
    /// IPS consumed the frame.
    Consumed,
    /// IPS did not consume the frame; continue normal stack processing.
    Continue(B),
}

/// Attempts IPS ingress before Ethernet parsing.
pub fn try_ips_ingress_before_parse<CC, BC, B, D>(
    core_ctx: &mut CC,
    bindings_ctx: &mut BC,
    device_id: &D,
    buffer: B,
) -> IpsPreParseResult<B>
where
    CC: IpsRxFrameHandler<BC, DeviceId = D>,
    B: IpsRxFrameBuffer,
{
    if !core_ctx.ips_ingress_enabled(device_id) {
        return IpsPreParseResult::NotApplicable(buffer);
    }
    if !is_ip_ethertype(buffer.as_ref()) {
        return IpsPreParseResult::NotApplicable(buffer);
    }
    let frame_len = buffer.as_ref().len();
    let full_frame = match buffer.into_ips_rx_frame(frame_len) {
        Ok(f) => f,
        Err(b) => return IpsPreParseResult::NotApplicable(b),
    };
    match core_ctx.try_ips_ingress(bindings_ctx, device_id, full_frame) {
        Ok(()) => IpsPreParseResult::Consumed,
        Err(restored) => IpsPreParseResult::Continue(B::from_ips_rx_frame(restored)),
    }
}
