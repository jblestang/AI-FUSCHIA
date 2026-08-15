// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Per-flow TCP stream state for inline sequence/ACK mangling.

use core::ops::Range;

use net_types::ip::IpAddr;
use netstack3_hashmap::hash_map::HashMap;

/// Normalized four-tuple with client endpoint first.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpFlowKey {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
}

impl TcpFlowKey {
    /// Builds a direction-independent flow key and whether `src` is the client.
    pub fn from_endpoints(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> (Self, bool) {
        let src_is_client = (src_ip, src_port) <= (dst_ip, dst_port);
        if src_is_client {
            (
                Self {
                    client_ip: src_ip,
                    client_port: src_port,
                    server_ip: dst_ip,
                    server_port: dst_port,
                },
                true,
            )
        } else {
            (
                Self {
                    client_ip: dst_ip,
                    client_port: dst_port,
                    server_ip: src_ip,
                    server_port: src_port,
                },
                false,
            )
        }
    }
}

/// Direction relative to the normalized client/server flow key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpFlowDirection {
    ClientToServer,
    ServerToClient,
}

impl TcpFlowDirection {
    fn reverse(self) -> Self {
        match self {
            Self::ClientToServer => Self::ServerToClient,
            Self::ServerToClient => Self::ClientToServer,
        }
    }

    fn state<'a>(&self, flow: &'a TcpFlowState) -> &'a TcpDirectionState {
        match self {
            Self::ClientToServer => &flow.c2s,
            Self::ServerToClient => &flow.s2c,
        }
    }

    fn state_mut<'a>(&self, flow: &'a mut TcpFlowState) -> &'a mut TcpDirectionState {
        match self {
            Self::ClientToServer => &mut flow.c2s,
            Self::ServerToClient => &mut flow.s2c,
        }
    }
}

/// Per-direction byte stream commit state in sender-original sequence space.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpDirectionState {
    /// Cumulative payload bytes removed (header translation).
    pub delta: u32,
    /// Exclusive end seq of bytes forwarded to the peer.
    pub committed_end: u32,
    /// Highest `seq + payload_len` observed from the sender.
    pub sender_hi_water: u32,
    /// Bytes dropped from the last edit, in sender-original space.
    pub dropped_range: Option<Range<u32>>,
    /// `(seq, keep_len)` from the last payload edit on this direction.
    pub last_edit: Option<(u32, u32)>,
}

/// Bidirectional flow state for one TCP connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpFlowState {
    pub c2s: TcpDirectionState,
    pub s2c: TcpDirectionState,
}

/// Classification of an inbound segment from the sender before L7 handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundSegmentClass {
    /// Entirely retransmitted bytes the IPS previously dropped.
    RetransmitDropped,
    /// Retransmit overlapping a previously edited segment; re-apply `keep_len`.
    RetransmitKeptPrefix,
    /// New sender data not yet classified as retransmit.
    NewData,
    /// Arrived before the contiguous committed stream; hold or drop in v1.
    OutOfOrderHold,
}

impl TcpFlowState {
    /// Cumulative delta for one direction (bytes removed from that stream).
    pub fn direction_delta(&self, dir: TcpFlowDirection) -> u32 {
        dir.state(self).delta
    }

    /// Records a prefix-keep edit and updates deltas / dropped ranges.
    pub fn apply_keep_edit(
        &mut self,
        dir: TcpFlowDirection,
        raw_seq: u32,
        raw_len: u32,
        keep_len: u32,
    ) {
        let removed = raw_len.saturating_sub(keep_len);
        let state = dir.state_mut(self);
        state.delta = state.delta.saturating_add(removed);
        state.committed_end = raw_seq.saturating_add(keep_len);
        state.last_edit = Some((raw_seq, keep_len));
        if removed > 0 {
            state.dropped_range =
                Some(raw_seq.saturating_add(keep_len)..raw_seq.saturating_add(raw_len));
        } else {
            state.dropped_range = None;
        }
        let seg_end = raw_seq.saturating_add(raw_len);
        state.sender_hi_water = state.sender_hi_water.max(seg_end);
    }

    /// Classifies an inbound segment from the sender (original seq space).
    pub fn classify_inbound(
        &mut self,
        dir: TcpFlowDirection,
        raw_seq: u32,
        payload_len: u32,
    ) -> InboundSegmentClass {
        let seg_end = raw_seq.saturating_add(payload_len);
        {
            let state = dir.state_mut(self);
            state.sender_hi_water = state.sender_hi_water.max(seg_end);
        }
        let state = dir.state(self).clone();

        if let Some(dropped) = &state.dropped_range {
            if raw_seq >= dropped.start && seg_end <= dropped.end {
                return InboundSegmentClass::RetransmitDropped;
            }
            if raw_seq < dropped.start && seg_end > dropped.start {
                return InboundSegmentClass::RetransmitKeptPrefix;
            }
        }

        if let Some((edit_seq, keep_len)) = state.last_edit {
            if raw_seq == edit_seq && payload_len > keep_len {
                return InboundSegmentClass::RetransmitKeptPrefix;
            }
        }

        if payload_len > 0 && seg_end <= state.committed_end {
            return InboundSegmentClass::RetransmitKeptPrefix;
        }

        if state.committed_end > 0 && raw_seq > state.committed_end && raw_seq < state.sender_hi_water
        {
            return InboundSegmentClass::OutOfOrderHold;
        }

        InboundSegmentClass::NewData
    }

    /// Returns the keep_len to re-apply for a [`InboundSegmentClass::RetransmitKeptPrefix`].
    pub fn retrim_keep_len(&self, dir: TcpFlowDirection, raw_seq: u32, payload_len: u32) -> u32 {
        let state = dir.state(self);
        if let Some((edit_seq, keep_len)) = state.last_edit {
            if raw_seq == edit_seq {
                return keep_len.min(payload_len);
            }
        }
        if payload_len > 0 && raw_seq.saturating_add(payload_len) <= state.committed_end {
            return payload_len;
        }
        state.last_edit.map(|(_, k)| k).unwrap_or(payload_len)
    }

    /// Translates seq/ack for an outbound segment (original → mangled wire values).
    pub fn translate_outbound(
        &self,
        dir: TcpFlowDirection,
        raw_seq: u32,
        raw_ack: Option<u32>,
        ack_flag: bool,
    ) -> (u32, Option<u32>) {
        let this = dir.state(self);
        let reverse = dir.reverse().state(self);
        let seq = raw_seq.wrapping_sub(this.delta);
        let ack = if ack_flag {
            raw_ack.map(|a| {
                let adjusted = a.wrapping_sub(reverse.delta);
        if reverse.committed_end > 0 {
                    adjusted.min(reverse.committed_end)
                } else {
                    adjusted
                }
            })
        } else {
            None
        };
        (seq, ack)
    }
}

/// LRU-capable TCP flow table (simple HashMap for v1).
#[derive(Debug, Default)]
pub struct IpsTcpFlowTable {
    flows: HashMap<TcpFlowKey, TcpFlowState>,
}

impl IpsTcpFlowTable {
    pub fn new() -> Self {
        Self { flows: HashMap::new() }
    }

    pub fn get_or_insert(&mut self, key: TcpFlowKey) -> &mut TcpFlowState {
        self.flows.entry(key).or_default()
    }

    pub fn get_mut(&mut self, key: &TcpFlowKey) -> Option<&mut TcpFlowState> {
        self.flows.get_mut(key)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use net_types::ip::Ipv4Addr;

    use super::*;

    fn v4(o: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(o))
    }

    #[test]
    fn delta_plus_committed_end_after_keep_edit() {
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);
        assert_eq!(flow.c2s.delta, 40);
        assert_eq!(flow.c2s.committed_end, 1040);
    }

    #[test]
    fn retransmit_of_dropped_tail_is_classified_suppress() {
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);
        let class = flow.classify_inbound(TcpFlowDirection::ClientToServer, 1040, 40);
        assert_eq!(class, InboundSegmentClass::RetransmitDropped);
    }

    #[test]
    fn retransmit_of_kept_prefix_is_retrimmed_not_suppressed() {
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);
        let class = flow.classify_inbound(TcpFlowDirection::ClientToServer, 1000, 80);
        assert_eq!(class, InboundSegmentClass::RetransmitKeptPrefix);
        assert_eq!(
            flow.retrim_keep_len(TcpFlowDirection::ClientToServer, 1000, 80),
            40
        );
    }

    #[test]
    fn ack_from_peer_clamped_to_committed_end() {
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);
        let (_, ack) = flow.translate_outbound(
            TcpFlowDirection::ServerToClient,
            5000,
            Some(1080),
            true,
        );
        assert_eq!(ack, Some(1040));
    }

    #[test]
    fn subsequent_new_data_seq_adjusted_by_delta() {
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);
        let (seq, _) = flow.translate_outbound(
            TcpFlowDirection::ClientToServer,
            1080,
            None,
            false,
        );
        assert_eq!(seq, 1040);
    }

    #[test]
    fn flow_key_normalizes_client_as_lower_endpoint() {
        let (key, src_is_client) =
            TcpFlowKey::from_endpoints(v4([192, 0, 2, 1]), 100, v4([192, 0, 2, 2]), 200);
        assert!(src_is_client);
        assert_eq!(key.client_port, 100);
        assert_eq!(key.server_port, 200);
    }
}
