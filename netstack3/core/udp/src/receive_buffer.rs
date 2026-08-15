// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! View-only UDP receive payload storage (no payload copies).

use alloc::sync::Arc;
use core::fmt;

use netstack3_ip::{LayerRanges, SharedPacketView};
use packet::FragmentedBytes;

/// Payload bytes delivered to a UDP socket as a layer view into shared RX storage.
///
/// Shares the same [`SharedPacketView`] backing as [`crate::UdpRecvDatagram::view`];
/// fan-out clones refcount only (no payload copy).
#[derive(Clone, PartialEq, Eq)]
pub struct UdpReceiveBuffer {
    view: SharedPacketView,
}

impl fmt::Debug for UdpReceiveBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpReceiveBuffer").field("len", &self.as_slice().len()).finish_non_exhaustive()
    }
}

impl UdpReceiveBuffer {
    /// Payload view sharing storage and layer ranges with a datagram frame view.
    pub fn sharing(view: SharedPacketView) -> Self {
        Self { view }
    }

    /// Placeholder for `bench-receive` (no storage touched).
    #[cfg(feature = "bench-receive")]
    pub fn bench_receive_placeholder() -> Self {
        Self::sharing(SharedPacketView::contiguous(
            Arc::from([]),
            LayerRanges { ip: 0..0, transport: 0..0, payload: 0..0 },
        ))
    }

    /// Returns the payload as a contiguous slice (zero-copy borrow of shared storage).
    pub fn as_slice(&self) -> &[u8] {
        self.view.payload_as_slice()
    }

    /// Returns a refcount-only clone suitable for fan-out delivery.
    pub fn share(&self) -> Self {
        Self { view: self.view.clone() }
    }

    /// Shared frame view (payload is the `layers.payload` range).
    pub fn shared_view(&self) -> &SharedPacketView {
        &self.view
    }

    /// Invokes `f` with payload bytes as a [`FragmentedBytes`] view.
    pub fn with_payload<R, F>(&self, f: F) -> R
    where
        F: for<'b> FnOnce(FragmentedBytes<'b, '_>) -> R,
    {
        self.view.with_payload(f)
    }
}

/// Test-only: captures bytes into shared storage (one allocation).
#[cfg(any(test, feature = "testutils"))]
impl From<&[u8]> for UdpReceiveBuffer {
    fn from(slice: &[u8]) -> Self {
        let storage: Arc<[u8]> = Arc::from(slice);
        let len = storage.len();
        let layers = LayerRanges { ip: 0..len, transport: 0..len, payload: 0..len };
        Self::sharing(SharedPacketView::contiguous(storage, layers))
    }
}

#[cfg(any(test, feature = "testutils"))]
impl<const N: usize> From<[u8; N]> for UdpReceiveBuffer {
    fn from(arr: [u8; N]) -> Self {
        Self::from(&arr[..])
    }
}
