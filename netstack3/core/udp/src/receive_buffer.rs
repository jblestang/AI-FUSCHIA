// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Zero-copy UDP receive payload storage.

use alloc::sync::Arc;
use core::fmt;

use packet::Buf;

/// Payload bytes delivered to a UDP socket.
///
/// Backed by [`Arc`] so multicast / multi-recipient delivery can fan out with
/// refcount-only sharing instead of copying the datagram body.
#[derive(Clone, PartialEq, Eq)]
pub struct UdpReceiveBuffer {
    bytes: Arc<[u8]>,
}

impl fmt::Debug for UdpReceiveBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpReceiveBuffer").field("len", &self.bytes.len()).finish_non_exhaustive()
    }
}

impl UdpReceiveBuffer {
    /// Wraps already-shared payload bytes.
    pub fn from_arc(bytes: Arc<[u8]>) -> Self {
        Self { bytes }
    }

    /// Moves an owned vec into shared storage without copying payload bytes.
    pub fn from_vec(vec: alloc::vec::Vec<u8>) -> Self {
        Self { bytes: vec.into() }
    }

    /// Takes the UDP payload out of a [`Buf`] after parsing (zero-copy move).
    pub fn from_buf(mut buffer: Buf<alloc::vec::Vec<u8>>) -> Self {
        Self::from_vec(buffer.into_inner())
    }

    /// Copies `body` once into shared storage.
    ///
    /// Used when the underlying RX buffer is reused (e.g. benchmark hot loop).
    pub fn from_slice(body: &[u8]) -> Self {
        Self { bytes: Arc::from(body) }
    }

    /// Returns the payload as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns a refcount bump suitable for fan-out delivery.
    pub fn share(&self) -> Self {
        Self { bytes: Arc::clone(&self.bytes) }
    }

    /// Consumes the buffer and returns the underlying shared storage.
    pub fn into_arc(self) -> Arc<[u8]> {
        self.bytes
    }
}

impl From<alloc::vec::Vec<u8>> for UdpReceiveBuffer {
    fn from(vec: alloc::vec::Vec<u8>) -> Self {
        Self::from_vec(vec)
    }
}

impl From<&[u8]> for UdpReceiveBuffer {
    fn from(slice: &[u8]) -> Self {
        Self::from_slice(slice)
    }
}

impl<const N: usize> From<[u8; N]> for UdpReceiveBuffer {
    fn from(arr: [u8; N]) -> Self {
        Self::from_vec(arr.to_vec())
    }
}
