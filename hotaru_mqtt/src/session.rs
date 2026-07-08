//! Logical MQTT session state, decoupled from the physical `MqttChannel`.
//!
//! A `MqttSession` holds inflight tracking and bind state for one logical
//! MQTT peer. In MVP it lives 1:1 with `MqttChannel`; spec-level
//! `clean_session=false` resume will later allow an old session to be
//! re-bound to a new channel (see `SessionStore`).
//!
//! All concurrency primitives are chosen per the "pragmatic lock-free" constraint:
//! `AtomicU16` for the packet-id counter, `OnceLock` for the one-time bind,
//! `DashMap` for per-packet-id inflight tracking.

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

use dashmap::DashMap;
use hotaru_core::connection::ConnStream;
use futures_channel::oneshot;

use crate::channel::MqttChannel;
use crate::error::{MqttError, Violation};
use crate::packet::{Packet, PublishPacket, incoming_from_packet};
use crate::request::{IncomingPublish, PacketId, QoS, SubackCode};
use crate::safety::DEFAULT_MAX_INFLIGHT_MESSAGES;

/// One-shot ack delivery slot. Each pending outbound op (P::send) registers
/// an `AckSlot` in `Session.pending_acks` keyed by allocated packet-id, then
/// awaits its receiver. The matching inbound ack handler removes the slot
/// and fires the sender.
///
/// When the channel closes, `MqttSession::abandon` clears all pending acks,
/// dropping every sender — every awaiter then receives `RecvError`, which
/// the P::send wrapper converts to `MqttError::ChannelClosed`.
pub enum AckSlot {
    Puback(oneshot::Sender<PacketId>),
    Pubrec(oneshot::Sender<PacketId>),
    Pubcomp(oneshot::Sender<PacketId>),
    Suback(oneshot::Sender<Vec<SubackCode>>),
    Unsuback(oneshot::Sender<()>),
}

/// Set once at CONNECT/CONNACK completion. Immutable after.
#[derive(Debug, Clone)]
pub struct BindInfo {
    pub client_id: Arc<str>,
    pub keep_alive: u16,
}

/// Logical MQTT session state.
///
/// Held inside `MqttChannel` via `Arc<MqttSession>`; cloning the channel
/// shares the same session handle. Spec-level `clean_session=false` resume
/// will store sessions in a `SessionStore` and rebind to new channels.
pub struct MqttSession {
    /// Outbound packet-id counter. Wraps at u16::MAX; allocation logic skips
    /// 0 and (future) checks inflight set for collisions.
    pub pkt_counter: AtomicU16,
    /// One-time bind: written once on CONNACK completion.
    pub bind: OnceLockBindInfo,
    /// Inbound QoS 2 half-state: keyed by peer-allocated packet-id, holds
    /// the PUBLISH awaiting PUBREL.
    pub(crate) qos2_recv: DashMap<u16, IncomingPublish>,
    /// Outbound inflight: keyed by our allocated packet-id, holds the
    /// pending ack slot. Cleared on `abandon`.
    pub(crate) pending_acks: DashMap<u16, AckSlot>,
    /// Outbound QoS≥1 inflight publishes — held for retransmit and to allow
    /// `clean_session=false` resume. Indexed by our packet-id.
    pub(crate) outbound_inflight: DashMap<u16, PublishPacket>,
    /// Client-side cap on simultaneously-outstanding ack-awaiting outbound
    /// ops (QoS≥1 PUBLISH + SUBSCRIBE + UNSUBSCRIBE). Seeded with the
    /// `MqttSafety` default and overridden by `handle_client` from the
    /// operator-configured safety. Only consulted by the client send path
    /// (`allocate_client_packet_id`); the broker enforces its own outbound
    /// cap against `outbound_inflight` and never reads this field. Closes
    /// SAFETY_PROOF F3 (client self-DoS via infallible packet-id allocation).
    max_inflight: AtomicUsize,
}

impl MqttSession {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pkt_counter: AtomicU16::new(0),
            bind: OnceLockBindInfo::new(),
            qos2_recv: DashMap::new(),
            pending_acks: DashMap::new(),
            outbound_inflight: DashMap::new(),
            max_inflight: AtomicUsize::new(DEFAULT_MAX_INFLIGHT_MESSAGES),
        })
    }

    /// Allocate the next outbound packet-id. Skips 0 (spec §2.3.1) and any id
    /// already in use — i.e. present in `outbound_inflight` (broker fanout
    /// in-use set) **or** `pending_acks` (client ack-await in-use set) —
    /// walking up to the full u16 space before giving up.
    ///
    /// SAFETY_PROOF G2 / second-audit G5 close: prior implementation
    /// wrapped at `u16::MAX` without consulting inflight; under deep
    /// inflight a colliding id could evict the existing entry and a
    /// later ack would misroute. The `pending_acks` clause is the F3
    /// follow-on: on the client, outbound QoS≥1 publishes are tracked via
    /// ack slots (not `outbound_inflight`), so consulting only the latter
    /// could hand out an id that is still awaiting its PUBACK/SUBACK and
    /// silently evict the live waiter. Returns `None` only when all 65 535
    /// ids are jointly held — well past any sane inflight cap.
    pub fn try_allocate_packet_id(&self) -> Option<u16> {
        for _ in 0..u16::MAX {
            let raw = self
                .pkt_counter
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            let id = if raw == 0 { 1 } else { raw };
            if !self.outbound_inflight.contains_key(&id) && !self.pending_acks.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }

    /// Client-side outbound allocation gate (SAFETY_PROOF F3 / #74(b)).
    ///
    /// Enforces `max_inflight` before handing out a packet-id, mirroring the
    /// broker-side `max_inflight_messages` cap (#61): if the session already
    /// has that many ack-awaiting outbound ops outstanding, or the u16 id
    /// space is genuinely exhausted, returns [`MqttError::TooManyInflight`]
    /// instead of the prior infallible `allocate_packet_id` panic. An
    /// off-by-one race under concurrent sends is tolerated — the cap is a
    /// soft bound and `try_allocate_packet_id` is the authoritative
    /// collision gate.
    pub fn allocate_client_packet_id(&self) -> Result<u16, MqttError> {
        let limit = self.max_inflight();
        if self.outstanding_ack_count() >= limit {
            return Err(MqttError::TooManyInflight { limit });
        }
        self.try_allocate_packet_id()
            .ok_or(MqttError::TooManyInflight { limit })
    }

    /// Count of outbound ops currently awaiting an ack (the client's
    /// in-flight set). Backs the [`Self::allocate_client_packet_id`] cap.
    pub fn outstanding_ack_count(&self) -> usize {
        self.pending_acks.len()
    }

    /// Override the client outbound inflight cap. Called once by
    /// `handle_client` from `MqttSafety.max_inflight_messages()`.
    pub fn set_max_inflight(&self, n: usize) {
        self.max_inflight.store(n.max(1), Ordering::Relaxed);
    }

    /// Current client outbound inflight cap.
    pub fn max_inflight(&self) -> usize {
        self.max_inflight.load(Ordering::Relaxed)
    }

    /// Back-compat wrapper used on hot fanout paths where the caller is
    /// not equipped to handle exhaustion. Panics on full inflight space —
    /// see [`Self::try_allocate_packet_id`] for the fallible API.
    pub fn allocate_packet_id(&self) -> u16 {
        self.try_allocate_packet_id().expect(
            "packet-id space exhausted — receive-maximum should bound inflight far below 65535",
        )
    }

    /// Called by `MqttChannel::close` on every disconnect. Drops only the
    /// pending ack waiters (so awaiting `Protocol::send` calls resolve to
    /// `Err(ChannelClosed)`).
    ///
    /// Outbound inflight + inbound QoS-2 half-state are intentionally kept
    /// so that a `clean_session=false` reconnect (Stage A P7) can resume
    /// them via [`SessionStore`]. For `clean_session=true` sessions, the
    /// broker calls [`Self::wipe`] explicitly during `unregister_session`
    /// to drop the inflight maps as well.
    pub fn abandon(&self) {
        self.pending_acks.clear();
    }

    /// Full teardown: ack waiters + outbound inflight + inbound QoS-2
    /// stash. Called by `Broker::unregister_session` when `clean_session=true`
    /// (or by `SessionStore` implementations during persistent-session
    /// destroy). Safe to call after `abandon` — both are idempotent.
    pub fn wipe(&self) {
        self.pending_acks.clear();
        self.qos2_recv.clear();
        self.outbound_inflight.clear();
    }

    /// Iterate every outbound inflight publish for retransmit on a
    /// `clean_session=false` reconnect (spec §3.1.2.4 + §4.4). Returned
    /// packets have `dup=true` set; caller re-allocates nothing.
    pub fn drain_outbound_for_retransmit(&self) -> Vec<(PacketId, PublishPacket)> {
        self.outbound_inflight
            .iter()
            .map(|e| {
                let id = *e.key();
                let mut p = e.value().clone();
                p.dup = true;
                (id, p)
            })
            .collect()
    }

    /// Move every inflight outbound publish, QoS-2 inbound stash entry,
    /// and the `pkt_counter` high watermark from `source` into `self`.
    ///
    /// Used by `Broker::register_session` on a `clean_session=false`
    /// reconnect: the new channel is constructed with a fresh
    /// `MqttSession` (no API surface for swapping the Arc post-clone), so
    /// the persistent session's state is *copied* into the fresh one.
    /// After this returns, `source` is left with empty maps and the new
    /// channel session owns all the resumable state.
    pub fn import_persistent_state(&self, source: &MqttSession) {
        for entry in source.outbound_inflight.iter() {
            self.outbound_inflight
                .insert(*entry.key(), entry.value().clone());
        }
        for entry in source.qos2_recv.iter() {
            self.qos2_recv.insert(*entry.key(), entry.value().clone());
        }
        source.outbound_inflight.clear();
        source.qos2_recv.clear();
        let watermark = source.pkt_counter.load(Ordering::Relaxed);
        self.pkt_counter.store(watermark, Ordering::Relaxed);
    }

    // ── pending_acks ────────────────────────────────────────────

    /// Install a one-shot ack slot keyed by `id`. Called from `Protocol::send`
    /// before the matching wire packet leaves the channel.
    pub fn install_ack_slot(&self, id: PacketId, slot: AckSlot) {
        self.pending_acks.insert(id, slot);
    }

    /// Remove and return an installed ack slot, if any.
    pub fn take_ack_slot(&self, id: PacketId) -> Option<AckSlot> {
        self.pending_acks.remove(&id).map(|(_, slot)| slot)
    }

    // ── qos2_recv ───────────────────────────────────────────────

    /// Stash an inbound QoS 2 PUBLISH awaiting its PUBREL.
    pub fn stash_qos2_inbound(&self, id: PacketId, incoming: IncomingPublish) {
        self.qos2_recv.insert(id, incoming);
    }

    /// Take a previously stashed inbound QoS 2 PUBLISH on PUBREL arrival.
    pub fn take_qos2_inbound(&self, id: PacketId) -> Option<IncomingPublish> {
        self.qos2_recv.remove(&id).map(|(_, v)| v)
    }

    // ── outbound_inflight ───────────────────────────────────────

    /// Stash an outbound QoS≥1 PUBLISH for retransmit / session resume.
    pub fn stash_outbound_inflight(&self, id: PacketId, packet: PublishPacket) {
        self.outbound_inflight.insert(id, packet);
    }

    /// Snapshot the current outbound inflight cardinality (G7 enforcement
    /// at the broker fanout cap site). DashMap's `len()` is a relaxed
    /// counter — exact under no concurrent insert/remove on this session,
    /// approximate otherwise; the comparison against
    /// `max_inflight_messages` tolerates an off-by-one race because
    /// `try_allocate_packet_id` is the authoritative gate.
    pub fn outbound_inflight_len(&self) -> usize {
        self.outbound_inflight.len()
    }

    /// Discharge a PUBACK arrival: remove the inflight publish and, if a
    /// `Puback` slot is also installed, fire its waiter.
    pub fn discharge_outbound_puback(&self, id: PacketId) {
        self.outbound_inflight.remove(&id);
        if let Some((_, AckSlot::Puback(tx))) = self.pending_acks.remove(&id) {
            let _ = tx.send(id); // W §3 silent on receiver gone
        }
    }

    /// Remove the inflight record for a packet-id without firing any slot.
    /// Used by outbound completion paths that fire their own slot directly.
    pub fn forget_outbound_inflight(&self, id: PacketId) {
        self.outbound_inflight.remove(&id);
    }
}

// ----------------------------------------------------------------------------
// QoS-pre-chain ack helper
// ----------------------------------------------------------------------------

/// Send PUBACK/PUBREC for QoS≥1 inbound publishes BEFORE the chain runs.
/// For QoS 2, also stash the publish in `qos2_recv` so the matching PUBREL
/// can dispatch later (§3.3.4 — exactly-once delivery requires the ack to
/// precede chain execution).
///
/// `receive_max` caps simultaneously-unacked inbound QoS-2 PUBLISHes per
/// session (second-audit G2). When the stash already holds `receive_max`
/// entries and a new `ExactlyOnce` PUBLISH arrives, no PUBREC is sent and
/// [`MqttError::Protocol`] with [`Violation::ReceiveMaximumExceeded`] is
/// returned — caller MUST close the connection.
///
/// Lives on the session module so any protocol implementation (client or
/// downstream server) can reuse it without duplicating QoS bookkeeping.
pub fn ack_inbound_publish_pre_chain<W: ConnStream, Rt: hotaru_core::app::runtime::RuntimeSpec>(
    channel: &MqttChannel<W, Rt>,
    publish: &PublishPacket,
    receive_max: usize,
) -> Result<(), MqttError> {
    match publish.qos {
        QoS::AtMostOnce => Ok(()),
        QoS::AtLeastOnce => {
            if let Some(id) = publish.packet_id {
                channel.send_packet(Packet::Puback(id))?;
            }
            Ok(())
        }
        QoS::ExactlyOnce => {
            if let Some(id) = publish.packet_id {
                let session = channel.session();
                // Allow re-stash on the SAME id (idempotent on duplicate
                // delivery — spec §4.3.3); only reject when adding a NEW
                // id would push the stash past the cap.
                if !session.qos2_recv.contains_key(&id) && session.qos2_recv.len() >= receive_max {
                    return Err(Violation::ReceiveMaximumExceeded { limit: receive_max }.into());
                }
                session.stash_qos2_inbound(id, incoming_from_packet(publish));
                channel.send_packet(Packet::Pubrec(id))?;
            }
            Ok(())
        }
    }
}

// ----------------------------------------------------------------------------
// OnceLockBindInfo — small wrapper over `std::sync::OnceLock<BindInfo>` so we
// can implement helpers without naming the path everywhere.
// ----------------------------------------------------------------------------

pub struct OnceLockBindInfo {
    inner: std::sync::OnceLock<BindInfo>,
}

impl OnceLockBindInfo {
    pub fn new() -> Self {
        Self {
            inner: std::sync::OnceLock::new(),
        }
    }

    pub fn set(&self, info: BindInfo) -> Result<(), BindInfo> {
        self.inner.set(info)
    }

    pub fn get(&self) -> Option<&BindInfo> {
        self.inner.get()
    }

    pub fn client_id(&self) -> Option<Arc<str>> {
        self.inner.get().map(|b| b.client_id.clone())
    }

    pub fn keep_alive(&self) -> Option<u16> {
        self.inner.get().map(|b| b.keep_alive)
    }
}

impl Default for OnceLockBindInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_slot() -> AckSlot {
        let (tx, _rx) = oneshot::channel();
        AckSlot::Puback(tx)
    }

    #[test]
    fn default_inflight_cap_matches_safety_default() {
        let s = MqttSession::new();
        assert_eq!(s.max_inflight(), DEFAULT_MAX_INFLIGHT_MESSAGES);
    }

    #[test]
    fn set_max_inflight_clamps_zero_to_one() {
        let s = MqttSession::new();
        s.set_max_inflight(0);
        // A zero cap would deadlock the client (no op could ever allocate);
        // clamp to 1 so at least one op is always permittable.
        assert_eq!(s.max_inflight(), 1);
    }

    #[test]
    fn client_allocator_rejects_over_inflight_cap() {
        // SAFETY_PROOF F3 / #74(b): once `max_inflight` ack-awaiting ops are
        // outstanding, the next client allocation fails closed instead of
        // panicking (old infallible `allocate_packet_id`) or colliding.
        let s = MqttSession::new();
        s.set_max_inflight(3);
        for i in 1..=3u16 {
            s.install_ack_slot(i, dummy_slot());
        }
        assert!(matches!(
            s.allocate_client_packet_id(),
            Err(MqttError::TooManyInflight { limit: 3 })
        ));
        // Drain one ack → capacity frees up → allocation succeeds again.
        let _ = s.take_ack_slot(1);
        assert!(s.allocate_client_packet_id().is_ok());
    }

    #[test]
    fn allocator_skips_ids_awaiting_acks() {
        // The client tracks inflight via `pending_acks`, not
        // `outbound_inflight`; the allocator must skip ids held there or it
        // would evict a live ack waiter (F3 collision clause).
        let s = MqttSession::new();
        s.install_ack_slot(1, dummy_slot());
        s.install_ack_slot(2, dummy_slot());
        // Counter starts at 0: 0→1 (held), 1→2 (held), 2→3 (free).
        let id = s.try_allocate_packet_id().expect("u16 space available");
        assert_eq!(id, 3);
    }

    #[test]
    fn outstanding_ack_count_tracks_pending_acks() {
        let s = MqttSession::new();
        assert_eq!(s.outstanding_ack_count(), 0);
        s.install_ack_slot(7, dummy_slot());
        assert_eq!(s.outstanding_ack_count(), 1);
        let _ = s.take_ack_slot(7);
        assert_eq!(s.outstanding_ack_count(), 0);
    }
}
