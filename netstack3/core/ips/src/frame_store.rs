// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Shared Ethernet frame buffer storage and mutation for IPS views.

use alloc::vec::Vec;
use core::mem;

use packet::{Buf, BufferMut};

/// Owned driver RX frame buffers with in-place mutation helpers.
#[derive(Debug, Default)]
pub(crate) struct EthFrameStore {
    frames: Vec<Buf<Vec<u8>>>,
}

impl EthFrameStore {
    pub(crate) fn from_frames(frames: Vec<Buf<Vec<u8>>>) -> Self {
        Self { frames }
    }

    pub(crate) fn into_frames(self) -> Vec<Buf<Vec<u8>>> {
        self.frames
    }

    pub(crate) fn frames(&self) -> &[Buf<Vec<u8>>] {
        &self.frames
    }

    pub(crate) fn eth_frames(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.frames.iter().map(|f| f.as_ref())
    }

    pub(crate) fn eth_frame_buf(&self, index: usize) -> Option<&[u8]> {
        Some(self.frames.get(index)?.as_ref())
    }

    pub(crate) fn eth_frame_buf_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        Some(self.frames.get_mut(index)?.as_mut())
    }

    pub(crate) fn truncate_eth_frame(&mut self, index: usize, new_len: usize) -> bool {
        let Some(frame) = self.frames.get_mut(index) else {
            return false;
        };
        if frame.as_ref().len() <= new_len {
            return true;
        }
        let placeholder = Buf::new(Vec::new(), 0..0);
        let (mut buf, body) = mem::replace(frame, placeholder).into_parts();
        buf.truncate(new_len);
        let body_start = body.start.min(new_len);
        *frame = Buf::new(buf, body_start..new_len);
        true
    }

    pub(crate) fn retain_eth_frames_through(&mut self, keep_through_index: usize) {
        if keep_through_index + 1 < self.frames.len() {
            self.frames.truncate(keep_through_index + 1);
        }
    }

    pub(crate) fn ensure_eth_frame_len(&mut self, index: usize, min_len: usize) -> bool {
        let Some(frame) = self.frames.get(index) else {
            return false;
        };
        if frame.as_ref().len() >= min_len {
            return true;
        }
        let mut bytes = frame.as_ref().to_vec();
        bytes.resize(min_len, 0);
        self.frames[index] = Buf::new(bytes, ..);
        true
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn truncate_eth_frame_shortens_buffer() {
        let mut store = EthFrameStore::from_frames(vec![Buf::new(vec![0u8; 100], ..)]);
        assert!(store.truncate_eth_frame(0, 60));
        assert_eq!(store.eth_frame_buf(0).unwrap().len(), 60);
    }
}
