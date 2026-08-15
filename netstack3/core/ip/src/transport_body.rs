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

/// Builds a [`SharedPacketView`] when transport start in the frame is already known.
pub fn shared_packet_view_at_transport_start(
    frame: Arc<[u8]>,
    transport_start: usize,
    parse_meta: ParseMetadata,
) -> SharedPacketView {
    let layers = layer_ranges_in_frame(frame.len(), transport_start, parse_meta);
    SharedPacketView::contiguous(frame, layers)
}

/// Computes the byte offset of a parsed transport header within pinned frame storage.
pub fn transport_start_in_frame(
    frame: &Arc<[u8]>,
    transport_body: &[u8],
    parse_meta: ParseMetadata,
) -> Option<usize> {
    let base = frame.as_ptr() as usize;
    let limit = base.saturating_add(frame.len());
    let body_start = transport_body.as_ptr() as usize;
    let header_len = parse_meta.header_len();
    body_start.checked_sub(base)?.checked_sub(header_len).filter(|&start| {
        let payload_end = start + header_len + parse_meta.body_len();
        start <= limit && payload_end <= limit
    })
}

/// Builds a [`SharedPacketView`] for parsed transport bytes in pinned RX storage.
///
/// Takes a single refcount on `frame_storage` when present; does not copy payload bytes.
pub fn shared_packet_view_for_transport(
    frame_storage: Option<&Arc<[u8]>>,
    transport_buffer: &[u8],
    parse_meta: ParseMetadata,
) -> SharedPacketView {
    match frame_storage {
        Some(frame) => {
            let transport_start = transport_range_in_storage(frame, transport_buffer).start;
            shared_packet_view_at_transport_start(Arc::clone(frame), transport_start, parse_meta)
        }
        None => {
            let storage: Arc<[u8]> = Arc::from(transport_buffer);
            let layers = layer_ranges_in_frame(storage.len(), 0, parse_meta);
            SharedPacketView::contiguous(storage, layers)
        }
    }
}

/// Builds a [`SharedPacketView`] for a parsed transport packet within pinned RX storage.
pub fn transport_packet_view(
    frame_storage: &Option<Arc<[u8]>>,
    transport_before_parse: &[u8],
    parse_meta: ParseMetadata,
) -> SharedPacketView {
    shared_packet_view_for_transport(frame_storage.as_ref(), transport_before_parse, parse_meta)
}
