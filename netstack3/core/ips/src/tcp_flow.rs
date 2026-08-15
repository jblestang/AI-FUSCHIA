// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Per-flow TCP stream state for inline sequence/ACK mangling.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
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

/// One prefix-keep edit on a direction, keyed by segment start seq.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpEditRecord {
    pub seq: u32,
    pub keep_len: u32,
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
    /// Payload ranges dropped by prefix-keep edits (sender-original space).
    pub dropped_ranges: Vec<Range<u32>>,
    /// Prefix-keep edits applied on this direction (oldest first).
    pub edits: Vec<TcpEditRecord>,
}

/// Bidirectional flow state for one TCP connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpFlowState {
    pub c2s: TcpDirectionState,
    pub s2c: TcpDirectionState,
    /// FIN seen on the client→server half.
    pub fin_c2s: bool,
    /// FIN seen on the server→client half.
    pub fin_s2c: bool,
    /// RST seen on either half (aborts the flow).
    pub rst_seen: bool,
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
    /// Returns true when the flow should be removed from the flow table.
    pub fn should_evict(&self) -> bool {
        self.rst_seen || (self.fin_c2s && self.fin_s2c)
    }

    /// Returns true when either direction has applied payload edits.
    pub fn has_mangling(&self) -> bool {
        self.c2s.delta > 0 || self.s2c.delta > 0
    }

    /// Records FIN/RST observation for flow-table lifecycle.
    pub fn note_control_flags(
        &mut self,
        dir: TcpFlowDirection,
        fin: bool,
        rst: bool,
    ) {
        if rst {
            self.rst_seen = true;
        }
        if fin {
            match dir {
                TcpFlowDirection::ClientToServer => self.fin_c2s = true,
                TcpFlowDirection::ServerToClient => self.fin_s2c = true,
            }
        }
    }

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
        state.committed_end = state.committed_end.max(raw_seq.saturating_add(keep_len));
        state.edits.push(TcpEditRecord { seq: raw_seq, keep_len });
        if removed > 0 {
            state.dropped_ranges.push(
                raw_seq.saturating_add(keep_len)..raw_seq.saturating_add(raw_len),
            );
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
        let prev_hi_water = dir.state(self).sender_hi_water;
        {
            let state = dir.state_mut(self);
            state.sender_hi_water = state.sender_hi_water.max(seg_end);
        }
        let state = dir.state(self).clone();

        for dropped in &state.dropped_ranges {
            if raw_seq >= dropped.start && seg_end <= dropped.end {
                return InboundSegmentClass::RetransmitDropped;
            }
        }

        for dropped in &state.dropped_ranges {
            if raw_seq < dropped.start && seg_end > dropped.start {
                return InboundSegmentClass::RetransmitKeptPrefix;
            }
        }

        for edit in &state.edits {
            if raw_seq == edit.seq && payload_len > edit.keep_len {
                return InboundSegmentClass::RetransmitKeptPrefix;
            }
        }

        if payload_len > 0
            && seg_end <= state.committed_end
            && !segment_overlaps_dropped_interior(raw_seq, seg_end, &state.dropped_ranges)
        {
            return InboundSegmentClass::RetransmitKeptPrefix;
        }

        if state.committed_end > 0 && raw_seq > state.committed_end && raw_seq < prev_hi_water {
            return InboundSegmentClass::OutOfOrderHold;
        }

        InboundSegmentClass::NewData
    }

    /// Returns the keep_len to re-apply for a [`InboundSegmentClass::RetransmitKeptPrefix`].
    pub fn retrim_keep_len(&self, dir: TcpFlowDirection, raw_seq: u32, payload_len: u32) -> u32 {
        let state = dir.state(self);
        let seg_end = raw_seq.saturating_add(payload_len);

        for edit in &state.edits {
            if raw_seq == edit.seq {
                return edit.keep_len.min(payload_len);
            }
        }

        for dropped in &state.dropped_ranges {
            if raw_seq < dropped.start && seg_end > dropped.start {
                return dropped.start.saturating_sub(raw_seq);
            }
        }

        if payload_len > 0 && seg_end <= state.committed_end {
            return payload_len;
        }

        state.edits.last().map(|e| e.keep_len).unwrap_or(payload_len)
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

    /// Translates a SACK block on the stream **opposite** to `dir` (original → mangled).
    ///
    /// Returns `None` when the block falls entirely in a dropped hole or collapses
    /// after clamping.
    pub fn translate_sack_block(
        &self,
        dir: TcpFlowDirection,
        left: u32,
        right: u32,
    ) -> Option<(u32, u32)> {
        translate_sack_block(dir.reverse().state(self), left, right)
    }
}

fn translate_sack_block(
    state: &TcpDirectionState,
    left: u32,
    right: u32,
) -> Option<(u32, u32)> {
    if right <= left {
        return None;
    }

    for hole in &state.dropped_ranges {
        if left >= hole.start && right <= hole.end {
            return None;
        }
    }

    let mut clamped_right = right;
    for hole in &state.dropped_ranges {
        if left < hole.start && clamped_right > hole.start {
            clamped_right = hole.start;
        }
    }
    if state.committed_end > 0 {
        clamped_right = clamped_right.min(state.committed_end);
    }
    if clamped_right <= left {
        return None;
    }

    let left_m = left.wrapping_sub(state.delta);
    let right_m = clamped_right.wrapping_sub(state.delta);
    if right_m <= left_m {
        return None;
    }
    Some((left_m, right_m))
}

fn segment_overlaps_dropped_interior(
    raw_seq: u32,
    seg_end: u32,
    dropped_ranges: &[Range<u32>],
) -> bool {
    dropped_ranges.iter().any(|dropped| {
        raw_seq < dropped.end && seg_end > dropped.start && !(raw_seq >= dropped.start && seg_end <= dropped.end)
    })
}

/// Configuration for [`IpsTcpFlowTable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpsTcpFlowTableConfig {
    /// Maximum concurrent flows before LRU eviction.
    pub max_flows: usize,
    /// Evict flows idle for this many table operation ticks.
    pub idle_ticks: u64,
}

impl Default for IpsTcpFlowTableConfig {
    fn default() -> Self {
        Self { max_flows: 4096, idle_ticks: 300_000 }
    }
}

struct TcpFlowEntry {
    state: TcpFlowState,
    last_tick: u64,
}

/// LRU flow table with idle eviction and FIN/RST teardown.
pub struct IpsTcpFlowTable {
    flows: HashMap<TcpFlowKey, TcpFlowEntry>,
    lru: VecDeque<TcpFlowKey>,
    tick: u64,
    config: IpsTcpFlowTableConfig,
}

impl Default for IpsTcpFlowTable {
    fn default() -> Self {
        Self::new()
    }
}

impl IpsTcpFlowTable {
    /// Creates an empty flow table with default limits.
    pub fn new() -> Self {
        Self::with_config(IpsTcpFlowTableConfig::default())
    }

    /// Creates an empty flow table with custom limits.
    pub fn with_config(config: IpsTcpFlowTableConfig) -> Self {
        Self { flows: HashMap::new(), lru: VecDeque::new(), tick: 0, config }
    }

    /// Returns the number of tracked flows.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Returns true when no flows are tracked.
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Removes a flow explicitly.
    pub fn remove(&mut self, key: &TcpFlowKey) {
        if self.flows.remove(key).is_some() {
            self.lru.retain(|k| k != key);
        }
    }

    /// Removes the flow when [`TcpFlowState::should_evict`] is true.
    pub fn remove_if_closed(&mut self, key: &TcpFlowKey, state: &TcpFlowState) {
        if state.should_evict() {
            self.remove(key);
        }
    }

    /// Looks up a flow without inserting or updating LRU.
    pub fn get_mut(&mut self, key: &TcpFlowKey) -> Option<&mut TcpFlowState> {
        self.flows.get_mut(key).map(|entry| &mut entry.state)
    }

    /// Returns or inserts flow state, pruning idle entries and enforcing LRU cap.
    pub fn get_or_insert(&mut self, key: TcpFlowKey) -> &mut TcpFlowState {
        self.tick = self.tick.wrapping_add(1);
        self.prune_idle();

        if self.flows.contains_key(&key) {
            self.touch_lru(&key);
            let tick = self.tick;
            let entry = self.flows.get_mut(&key).expect("present");
            entry.last_tick = tick;
            return &mut entry.state;
        }

        while self.flows.len() >= self.config.max_flows {
            self.evict_lru();
        }

        self.lru.push_back(key.clone());
        self.flows.insert(
            key.clone(),
            TcpFlowEntry { state: TcpFlowState::default(), last_tick: self.tick },
        );
        &mut self.flows.get_mut(&key).expect("just inserted").state
    }

    fn touch_lru(&mut self, key: &TcpFlowKey) {
        if let Some(pos) = self.lru.iter().position(|k| k == key) {
            self.lru.remove(pos);
        }
        self.lru.push_back(key.clone());
    }

    fn prune_idle(&mut self) {
        let tick = self.tick;
        let idle_ticks = self.config.idle_ticks;
        let stale: Vec<TcpFlowKey> = self
            .flows
            .iter()
            .filter(|(_, entry)| tick.wrapping_sub(entry.last_tick) > idle_ticks)
            .map(|(key, _)| key.clone())
            .collect();
        for key in stale {
            self.remove(&key);
        }
    }

    fn evict_lru(&mut self) {
        while let Some(key) = self.lru.pop_front() {
            if self.flows.remove(&key).is_some() {
                return;
            }
        }
    }
}

impl core::fmt::Debug for IpsTcpFlowTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IpsTcpFlowTable")
            .field("len", &self.flows.len())
            .field("tick", &self.tick)
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
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
        assert_eq!(flow.c2s.dropped_ranges, vec![1040..1080]);
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
    fn second_edit_still_suppresses_first_dropped_range_retransmit() {
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1080, 100, 60);

        assert_eq!(flow.c2s.dropped_ranges.len(), 2);
        assert_eq!(flow.c2s.dropped_ranges[0], 1040..1080);
        assert_eq!(flow.c2s.dropped_ranges[1], 1140..1180);

        let class = flow.classify_inbound(TcpFlowDirection::ClientToServer, 1040, 40);
        assert_eq!(class, InboundSegmentClass::RetransmitDropped);
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
    fn sack_block_translated_and_clamped_to_committed_end() {
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);
        let block = flow.translate_sack_block(
            TcpFlowDirection::ServerToClient,
            1010,
            1040,
        );
        assert_eq!(block, Some((970, 1000)));
    }

    #[test]
    fn sack_block_wholly_in_dropped_hole_is_removed() {
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);
        assert!(flow
            .translate_sack_block(TcpFlowDirection::ServerToClient, 1040, 1080)
            .is_none());
    }

    #[test]
    fn sack_block_spanning_hole_is_clamped() {
        let mut flow = TcpFlowState::default();
        flow.apply_keep_edit(TcpFlowDirection::ClientToServer, 1000, 80, 40);
        assert_eq!(
            flow.translate_sack_block(TcpFlowDirection::ServerToClient, 1020, 1060),
            Some((980, 1000))
        );
    }

    #[test]
    fn flow_key_normalizes_client_as_lower_endpoint() {
        let (key, src_is_client) =
            TcpFlowKey::from_endpoints(v4([192, 0, 2, 1]), 100, v4([192, 0, 2, 2]), 200);
        assert!(src_is_client);
        assert_eq!(key.client_port, 100);
        assert_eq!(key.server_port, 200);
    }

    #[test]
    fn should_evict_on_rst_or_both_fins() {
        let mut flow = TcpFlowState::default();
        assert!(!flow.should_evict());
        flow.note_control_flags(TcpFlowDirection::ClientToServer, true, false);
        assert!(!flow.should_evict());
        flow.note_control_flags(TcpFlowDirection::ServerToClient, true, false);
        assert!(flow.should_evict());

        let mut flow = TcpFlowState::default();
        flow.note_control_flags(TcpFlowDirection::ClientToServer, false, true);
        assert!(flow.should_evict());
    }

    #[test]
    fn flow_table_enforces_lru_cap() {
        let config = IpsTcpFlowTableConfig { max_flows: 2, idle_ticks: u64::MAX };
        let mut table = IpsTcpFlowTable::with_config(config);

        let key_a = TcpFlowKey {
            client_ip: v4([1, 0, 0, 1]),
            client_port: 1,
            server_ip: v4([1, 0, 0, 2]),
            server_port: 2,
        };
        let key_b = TcpFlowKey {
            client_ip: v4([1, 0, 0, 1]),
            client_port: 3,
            server_ip: v4([1, 0, 0, 2]),
            server_port: 4,
        };
        let key_c = TcpFlowKey {
            client_ip: v4([1, 0, 0, 1]),
            client_port: 5,
            server_ip: v4([1, 0, 0, 2]),
            server_port: 6,
        };

        table.get_or_insert(key_a.clone());
        table.get_or_insert(key_b.clone());
        table.get_or_insert(key_c.clone());

        assert_eq!(table.len(), 2);
        assert!(table.get_mut(&key_a).is_none(), "least recently used flow evicted");
        assert!(table.get_mut(&key_b).is_some());
        assert!(table.get_mut(&key_c).is_some());
    }

    #[test]
    fn flow_table_prunes_idle_entries() {
        let config = IpsTcpFlowTableConfig { max_flows: 16, idle_ticks: 2 };
        let mut table = IpsTcpFlowTable::with_config(config);
        let stale_key = TcpFlowKey {
            client_ip: v4([10, 0, 0, 1]),
            client_port: 80,
            server_ip: v4([10, 0, 0, 2]),
            server_port: 443,
        };
        table.get_or_insert(stale_key.clone());
        table.get_or_insert(TcpFlowKey {
            client_ip: v4([10, 0, 0, 3]),
            client_port: 1,
            server_ip: v4([10, 0, 0, 4]),
            server_port: 2,
        });
        table.get_or_insert(TcpFlowKey {
            client_ip: v4([10, 0, 0, 5]),
            client_port: 3,
            server_ip: v4([10, 0, 0, 6]),
            server_port: 4,
        });
        table.get_or_insert(TcpFlowKey {
            client_ip: v4([10, 0, 0, 7]),
            client_port: 5,
            server_ip: v4([10, 0, 0, 8]),
            server_port: 6,
        });
        assert!(table.get_mut(&stale_key).is_none(), "idle flow must be pruned");
    }
}
