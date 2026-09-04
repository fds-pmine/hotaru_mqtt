//! Logical MQTT session state, decoupled from the physical `MqttChannel`.
//!
//! A `MqttSession` holds inflight tracking and bind state for one logical
//! MQTT client. In MVP it lives 1:1 with `MqttChannel`; future
//! `clean_session=false` reconnect (M phase) will allow an old session to
//! be re-bound to a new channel.
//!
//! All concurrency primitives are chosen per the "实用无锁" constraint:
//! `AtomicU16` for the packet-id counter, `OnceLock` for the one-time bind,
//! `DashMap` for per-packet-id inflight tracking.

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use dashmap::DashMap;
use tokio::sync::oneshot;

use crate::packet::PublishPacket;
use crate::request::{IncomingPublish, PacketId, SubackCode};

/// One-shot ack delivery slot. Each pending outbound op (P::send) registers
/// an `AckSlot` in `Session.pending_acks` keyed by allocated packet-id, then
/// awaits its receiver. The matching inbound ack handler removes the slot
/// and fires the sender.
///
/// When the channel closes, `MqttSession::abandon` clears all pending acks,
/// dropping every sender — every awaiter then receives `RecvError`, which
/// the P::send wrapper converts to `MqttError::ChannelClosed`.
/// Which ack a parked waiter is expecting.
///
/// A packet-id names a *flow*, not a step. A QoS 2 flow parks a `Pubrec`
/// waiter, then a `Pubcomp` waiter, under the same id — so "the slot for id 7"
/// is not enough to know what to do with it, and waking the wrong kind is not
/// a near miss. `AckKind` is what makes the question answerable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckKind {
    Puback,
    Pubrec,
    Pubcomp,
}

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
/// shares the same session handle. Cross-reconnect persistence (M phase)
/// will store sessions in a `SessionStore` and rebind to new channels.
pub struct MqttSession {
    /// Outbound packet-id counter. Wraps at u16::MAX; allocation logic skips
    /// 0 and (future) checks inflight set for collisions. Reachable only
    /// through `allocate_packet_id`, which is the whole of its contract.
    pkt_counter: AtomicU16,
    /// One-time bind: written once on CONNACK completion. Private so the
    /// one-shot discipline stays enforceable; reach it through `bind()`.
    bind: OnceLockBindInfo,
    /// Inbound QoS 2 half-state: keyed by peer-allocated packet-id, holds
    /// the PUBLISH awaiting PUBREL. Reach it through `stash_qos2_publish` and
    /// `take_qos2_publish`.
    qos2_recv: DashMap<u16, IncomingPublish>,
    /// Outbound inflight: keyed by our allocated packet-id, holds the
    /// pending ack slot. Cleared on `abandon`. Reach it through the
    /// `park_*` / `wake_*` / `cancel_ack_waiter` methods, which are what keep
    /// a slot's kind and its waiter in agreement.
    pending_acks: DashMap<u16, AckSlot>,
    /// Outbound QoS≥1 inflight publishes — held for retransmit and to allow
    /// session resume (M phase). Indexed by our packet-id. Reach it through
    /// `track_outbound_inflight` and `clear_outbound_inflight`.
    outbound_inflight: DashMap<u16, PublishPacket>,
}

impl MqttSession {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            pkt_counter: AtomicU16::new(0),
            bind: OnceLockBindInfo::new(),
            qos2_recv: DashMap::new(),
            pending_acks: DashMap::new(),
            outbound_inflight: DashMap::new(),
        })
    }

    /// The one-time bind slot, written on CONNACK completion.
    pub fn bind(&self) -> &OnceLockBindInfo {
        &self.bind
    }

    /// Allocate the next outbound packet-id. Skips 0 (reserved per spec).
    /// Does not check for collisions with existing inflight — collisions are
    /// statistically rare with u16 space and 5-deep typical inflight; on
    /// collision the caller may observe ack misrouting which surfaces as
    /// `AckTimeout`. Sufficient for MVP; tighter alloc is a J-phase concern.
    pub fn allocate_packet_id(&self) -> u16 {
        let id = self.pkt_counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if id == 0 { 1 } else { id }
    }

    /// Wake the waiter parked on `packet_id`, but only if it is waiting for
    /// `expected`. An ack of any other kind leaves the slot untouched.
    ///
    /// Resolution is connection-local by construction. The broker's session
    /// map is keyed on client_id alone, which stops telling two connections
    /// apart the moment a takeover is in flight, so a by-name lookup can
    /// settle an ack that belongs to the earlier connection against the
    /// session of the newer one — silently clearing an inflight entry that
    /// was never actually delivered. The caller already holds the channel the
    /// ack arrived on, so there is nothing to look up.
    /// Park a waiter for a publish-flow ack (PUBACK / PUBREC / PUBCOMP) under
    /// `packet_id`, and hand back the receiving half to await.
    ///
    /// The oneshot pair is created in here so that a call site cannot pair the
    /// wrong sender with the wrong slot kind — the kind decides the slot, in
    /// one place.
    pub fn park_publish_ack_waiter(
        &self,
        packet_id: PacketId,
        kind: AckKind,
    ) -> oneshot::Receiver<PacketId> {
        let (sender, receiver) = oneshot::channel();
        let slot = match kind {
            AckKind::Puback => AckSlot::Puback(sender),
            AckKind::Pubrec => AckSlot::Pubrec(sender),
            AckKind::Pubcomp => AckSlot::Pubcomp(sender),
        };
        self.pending_acks.insert(packet_id, slot);
        receiver
    }

    /// Park a waiter for the SUBACK answering the SUBSCRIBE sent as `packet_id`.
    pub fn park_suback_waiter(&self, packet_id: PacketId) -> oneshot::Receiver<Vec<SubackCode>> {
        let (sender, receiver) = oneshot::channel();
        self.pending_acks.insert(packet_id, AckSlot::Suback(sender));
        receiver
    }

    /// Park a waiter for the UNSUBACK answering the UNSUBSCRIBE sent as `packet_id`.
    pub fn park_unsuback_waiter(&self, packet_id: PacketId) -> oneshot::Receiver<()> {
        let (sender, receiver) = oneshot::channel();
        self.pending_acks.insert(packet_id, AckSlot::Unsuback(sender));
        receiver
    }

    /// Give up on a parked waiter (ack timeout). Removing the slot drops its
    /// sender, which resolves the abandoned receiver immediately — but the
    /// caller that parked it is the one abandoning it, so nobody is waiting.
    pub fn cancel_ack_waiter(&self, packet_id: PacketId) {
        self.pending_acks.remove(&packet_id);
    }

    /// Wake the waiter parked for the SUBACK of `packet_id`, delivering the
    /// per-filter verdicts. A slot of any other kind is left untouched, for
    /// the same reason `wake_ack_waiter` leaves mismatches alone: consuming a
    /// waiter this packet cannot satisfy fabricates a `ChannelClosed`.
    pub fn wake_suback_waiter(&self, packet_id: PacketId, return_codes: Vec<SubackCode>) {
        let Some(entry) = self.pending_acks.get(&packet_id) else {
            return; // nobody parked here — W §4 silent
        };
        let parked_is_suback = matches!(entry.value(), AckSlot::Suback(_));
        drop(entry); // release the read guard before removing under the same key
        if !parked_is_suback {
            return;
        }
        let Some((_, slot)) = self.pending_acks.remove(&packet_id) else {
            return; // raced with another waker; it did the work
        };
        match slot {
            AckSlot::Suback(waiter) => {
                let _ = waiter.send(return_codes); // W policy §3
            }
            other => {
                // Kind changed between the two lookups; this packet does not
                // own the slot. Put it back.
                self.pending_acks.insert(packet_id, other);
            }
        }
    }

    /// Wake the waiter parked for the UNSUBACK of `packet_id`. Same contract
    /// as [`MqttSession::wake_suback_waiter`].
    pub fn wake_unsuback_waiter(&self, packet_id: PacketId) {
        let Some(entry) = self.pending_acks.get(&packet_id) else {
            return; // nobody parked here — W §4 silent
        };
        let parked_is_unsuback = matches!(entry.value(), AckSlot::Unsuback(_));
        drop(entry);
        if !parked_is_unsuback {
            return;
        }
        let Some((_, slot)) = self.pending_acks.remove(&packet_id) else {
            return;
        };
        match slot {
            AckSlot::Unsuback(waiter) => {
                let _ = waiter.send(()); // W policy §3
            }
            other => {
                self.pending_acks.insert(packet_id, other);
            }
        }
    }

    pub fn wake_ack_waiter(&self, packet_id: PacketId, expected: AckKind) {
        let Some(entry) = self.pending_acks.get(&packet_id) else {
            return; // nobody parked here — W §4 silent
        };
        let parked_kind = match entry.value() {
            AckSlot::Puback(_) => Some(AckKind::Puback),
            AckSlot::Pubrec(_) => Some(AckKind::Pubrec),
            AckSlot::Pubcomp(_) => Some(AckKind::Pubcomp),
            AckSlot::Suback(_) | AckSlot::Unsuback(_) => None,
        };
        drop(entry); // release the read guard before removing under the same key

        if parked_kind != Some(expected) {
            // Leave it where it is. Removing a slot this ack cannot satisfy is
            // worse than ignoring the ack: dropping the sending half of the
            // oneshot resolves the waiter immediately with `RecvError`, which
            // the send path reports as `ChannelClosed` — a disconnection that
            // never happened, on a flow that may still be perfectly healthy.
            return;
        }

        let Some((_, slot)) = self.pending_acks.remove(&packet_id) else {
            return; // raced with another waker; it did the work
        };
        let waiter = match slot {
            AckSlot::Puback(waiter) | AckSlot::Pubrec(waiter) | AckSlot::Pubcomp(waiter) => waiter,
            other => {
                // Re-park what we removed: this ack does not own it. Reachable
                // only if the kind changed between the two lookups above.
                self.pending_acks.insert(packet_id, other);
                return;
            }
        };
        let _ = waiter.send(packet_id); // W policy §3
    }

    /// The outbound flow for `packet_id` is finished; drop its retransmit record.
    ///
    /// Separate from [`MqttSession::wake_ack_waiter`] because the two do not
    /// coincide. A QoS 2 PUBREC wakes a waiter but does *not* finish the flow —
    /// PUBREL and PUBCOMP are still to come, and the message must stay
    /// retransmittable until they do. Only PUBACK and PUBCOMP end a flow.
    pub fn clear_outbound_inflight(&self, packet_id: PacketId) {
        self.outbound_inflight.remove(&packet_id);
    }

    /// Hold an inbound QoS 2 PUBLISH until its PUBREL arrives.
    ///
    /// Keyed by the *peer's* packet-id, which is a different id space from the
    /// one `allocate_packet_id` hands out — the two tables can hold the same
    /// number at the same time meaning different messages.
    pub fn stash_qos2_publish(&self, packet_id: PacketId, publish: IncomingPublish) {
        self.qos2_recv.insert(packet_id, publish);
    }

    /// Release the PUBLISH held for `packet_id`, if PUBREL is the first one to
    /// ask. Returns `None` for a PUBREL that names an id we are not holding —
    /// a duplicate release, or one that was never stashed.
    pub fn take_qos2_publish(&self, packet_id: PacketId) -> Option<IncomingPublish> {
        self.qos2_recv.remove(&packet_id).map(|(_, publish)| publish)
    }

    /// Record an outbound QoS>=1 publish as inflight, so it stays
    /// retransmittable until the flow that owns `packet_id` finishes.
    ///
    /// Paired with [`MqttSession::clear_outbound_inflight`], which is the only
    /// thing that should end that record's life.
    pub fn track_outbound_inflight(&self, packet_id: PacketId, publish: PublishPacket) {
        self.outbound_inflight.insert(packet_id, publish);
    }

    /// Whether an outbound flow is still holding a retransmit record under
    /// `packet_id`. Exists so a caller can observe the record's lifetime
    /// without being handed the table it lives in.
    pub fn has_outbound_inflight(&self, packet_id: PacketId) -> bool {
        self.outbound_inflight.contains_key(&packet_id)
    }

    /// Tear down session inflight state, dropping all pending ack senders.
    /// Awaiting `P::send` calls will resolve to `Err(ChannelClosed)`.
    ///
    /// MVP: called from `MqttChannel::close`. Phase M (clean_session=false)
    /// will skip this on close so the session can survive across channel
    /// rebuilds.
    pub fn abandon(&self) {
        self.pending_acks.clear();
        self.qos2_recv.clear();
        self.outbound_inflight.clear();
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
mod test;
