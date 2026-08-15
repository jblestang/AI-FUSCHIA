// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! View-only transport access within IP datagram buffers.
//!
//! Transport bytes are passed as subslices of the IP buffer (`Buf::new(body, ..)`).
//! Payload views are built from [`ReceiveIpPacketMeta::frame_storage`].

use alloc::sync::Arc;
use core::ops::Range;

use packet::ParseMetadata;

use crate::internal::fragment_chain::{LayerRanges, SharedPacketView};

/// Computes byte ranges within pinned RX storage for layered inspection.
pub fn layer_ranges_in_frame(
    frame_len: usize,
    transport_start: usize,
    transport_parse: ParseMetadata,
) -> LayerRanges {
    let payload_start = transport_start.saturating_add(transport_parse.header_len());
    let payload_end = payload_start.saturating_add(transport_parse.body_len());
    LayerRanges {
        ip: 0..frame_len,
        transport: transport_start..payload_end.min(frame_len),
        payload: payload_start..payload_end.min(frame_len),
    }
}

/// Returns the transport-layer byte range of `transport` within `storage`.
pub fn transport_range_in_storage(storage: &Arc<[u8]>, transport: &[u8]) -> Range<usize> {
    let base = storage.as_ptr() as usize;
    let start = transport.as_ptr() as usize - base;
    start..start + transport.len()
}

/// Builds a [`SharedPacketView`] for a parsed transport packet within pinned RX storage.
pub fn transport_packet_view(
    frame_storage: &Option<Arc<[u8]>>,
    transport_before_parse: &[u8],
    parse_meta: ParseMetadata,
) -> SharedPacketView {
    if let Some(frame) = frame_storage {
        let transport_start = transport_range_in_storage(frame, transport_before_parse).start;
        let layers = layer_ranges_in_frame(frame.len(), transport_start, parse_meta);
        return SharedPacketView::contiguous(frame.clone(), layers);
    }
    let storage: Arc<[u8]> = Arc::from(transport_before_parse);
    let layers = layer_ranges_in_frame(storage.len(), 0, parse_meta);
    SharedPacketView::contiguous(storage, layers)
}
