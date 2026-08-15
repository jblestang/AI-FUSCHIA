// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! View-only UDP receive payload storage (no payload copies).

use alloc::sync::Arc;
use core::fmt;
use core::ops::Range;

use netstack3_ip::PacketSegment;
use packet::ParseMetadata;
use packet::{BufferMut, FragmentedBytes, ParseBuffer as _};

/// Payload bytes delivered to a UDP socket as a range view into shared RX storage.
///
/// Fan-out (multicast / multiple sockets) clones the view (Arc refcount + range only).
#[derive(Clone, PartialEq, Eq)]
pub struct UdpReceiveBuffer {
    segment: PacketSegment,
}

impl fmt::Debug for UdpReceiveBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpReceiveBuffer").field("len", &self.segment.len()).finish_non_exhaustive()
    }
}

impl UdpReceiveBuffer {
    /// Builds a payload view over shared storage.
    pub fn view(segment: PacketSegment) -> Self {
        Self { segment }
    }

    /// Views the UDP payload within `storage` using post-parse UDP metadata.
    pub fn payload_view(
        storage: Arc<[u8]>,
        transport_range: Range<usize>,
        parse_meta: ParseMetadata,
    ) -> Self {
        let start = transport_range.start + parse_meta.header_len();
        let end = start + parse_meta.body_len();
        Self::view(PacketSegment::view_in(storage, start..end))
    }

    /// Placeholder for `bench-receive` (no storage touched).
    #[cfg(feature = "bench-receive")]
    pub fn bench_receive_placeholder() -> Self {
        Self::view(netstack3_ip::PacketSegment::view_in(Arc::from([]), 0..0))
    }

    /// Returns the payload as a contiguous slice (zero-copy borrow of shared storage).
    pub fn as_slice(&self) -> &[u8] {
        self.segment.as_slice()
    }

    /// Returns a refcount-only clone suitable for fan-out delivery.
    pub fn share(&self) -> Self {
        Self { segment: self.segment.clone() }
    }

    /// Returns the underlying segment view.
    pub fn segment(&self) -> &PacketSegment {
        &self.segment
    }

    /// Invokes `f` with payload bytes as a [`FragmentedBytes`] view.
    pub fn with_payload<R, F>(&self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, '_>) -> R,
    {
        let slice = self.segment.as_slice();
        let mut slices = [slice];
        f(FragmentedBytes::new(&mut slices))
    }
}

/// Test-only: captures bytes into shared storage (one allocation).
#[cfg(any(test, feature = "testutils"))]
impl From<&[u8]> for UdpReceiveBuffer {
    fn from(slice: &[u8]) -> Self {
        Self::view(PacketSegment::capture(slice))
    }
}

#[cfg(any(test, feature = "testutils"))]
impl<const N: usize> From<[u8; N]> for UdpReceiveBuffer {
    fn from(arr: [u8; N]) -> Self {
        Self::view(PacketSegment::capture(&arr))
    }
}

/// Computes the transport-layer byte range within pinned storage for a parsed buffer view.
pub fn transport_range_in_storage<B: BufferMut>(
    storage: &Arc<[u8]>,
    buffer: &B,
) -> Range<usize> {
    let slice = buffer.as_ref();
    let storage = storage.as_ref();
    let start = slice.as_ptr() as usize - storage.as_ptr() as usize;
    start..start + slice.len()
}
