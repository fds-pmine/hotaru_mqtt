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
    /// 0 and (future) checks inflight set for collisions.
    pub pkt_counter: AtomicU16,
    /// One-time bind: written once on CONNACK completion. Private so the
    /// one-shot discipline stays enforceable; reach it through `bind()`.
    bind: OnceLockBindInfo,
    /// Inbound QoS 2 half-state: keyed by peer-allocated packet-id, holds
    /// the PUBLISH awaiting PUBREL.
    pub qos2_recv: DashMap<u16, IncomingPublish>,
    /// Outbound inflight: keyed by our allocated packet-id, holds the
    /// pending ack slot. Cleared on `abandon`.
    pub pending_acks: DashMap<u16, AckSlot>,
    /// Outbound QoS≥1 inflight publishes — held for retransmit and to allow
    /// session resume (M phase). Indexed by our packet-id.
    pub outbound_inflight: DashMap<u16, PublishPacket>,
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
