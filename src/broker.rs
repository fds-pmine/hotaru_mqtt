//! MQTT broker — server-side state for cross-connection fanout.
//!
//! Per BCH §4 simplification: broker holds `MqttChannel<W>` clones directly
//! (Arc-backed), and `publish()` pushes `WriteCmd::Publish` straight into the
//! subscriber's `cmd_tx`. No separate fanout queue, no `serve_outbound` task.
//!
//! Subscription matching is hand-rolled (O(F) per publish where F = unique
//! filters) for MVP. The `walk_cursor` optimization (EFTU §1.3) is deferred
//! to Phase 5 perf tuning.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use hotaru_core::connection::ConnStream;

use crate::channel::MqttChannel;
use crate::packet::{ConnackReturnCode, ConnectPacket, PublishPacket};
use crate::request::{
    IncomingPublish, PacketId, QoS, SubackCode, TopicFilter, WillMessage,
};
use crate::safety::MqttSafety;

// ----------------------------------------------------------------------------
// Authenticator hook
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthResult {
    pub accepted: bool,
    pub return_code: ConnackReturnCode,
}

impl AuthResult {
    pub fn accept() -> Self {
        Self {
            accepted: true,
            return_code: ConnackReturnCode::Accepted,
        }
    }

    pub fn reject(code: ConnackReturnCode) -> Self {
        Self {
            accepted: false,
            return_code: code,
        }
    }
}

#[async_trait]
pub trait Authenticator: Send + Sync + 'static {
    async fn authenticate(
        &self,
        connect: &ConnectPacket,
        remote_addr: Option<SocketAddr>,
    ) -> AuthResult;
}

/// Default authenticator — accepts every CONNECT. Override in production
/// via `Broker::with_authenticator(Arc::new(YourAuth))`.
pub struct AcceptAllAuthenticator;

#[async_trait]
impl Authenticator for AcceptAllAuthenticator {
    async fn authenticate(
        &self,
        _connect: &ConnectPacket,
        _remote_addr: Option<SocketAddr>,
    ) -> AuthResult {
        AuthResult::accept()
    }
}

// ----------------------------------------------------------------------------
// SubscriberEntry — broker's per-client record
// ----------------------------------------------------------------------------

pub struct SubscriberEntry<W: ConnStream> {
    pub channel: MqttChannel<W>,
    pub filters: DashMap<Arc<str>, QoS>,
    pub will: Option<WillMessage>,
    pub clean_session: bool,
}

// ----------------------------------------------------------------------------
// SubscriptionTree — filter→subscriber set lookup
// ----------------------------------------------------------------------------

struct SubscriptionTree {
    /// filter (e.g. "sensors/+/temp") → set of (client_id, max_qos)
    subs: DashMap<Arc<str>, Arc<DashMap<Arc<str>, QoS>>>,
}

impl SubscriptionTree {
    fn new() -> Self {
        Self {
            subs: DashMap::new(),
        }
    }

    fn subscribe(&self, client_id: Arc<str>, filter: Arc<str>, qos: QoS) {
        let set = self
            .subs
            .entry(filter)
            .or_insert_with(|| Arc::new(DashMap::new()))
            .clone();
        set.insert(client_id, qos);
    }

    fn unsubscribe(&self, client_id: &Arc<str>, filter: &str) {
        if let Some(set) = self.subs.get(filter) {
            set.remove(client_id);
        }
    }

    /// Remove all subscriptions belonging to one client (used on disconnect).
    fn remove_client(&self, client_id: &Arc<str>) {
        for entry in self.subs.iter() {
            entry.value().remove(client_id);
        }
    }

    /// Return (client_id, max_qos) for every subscription matching the topic.
    fn matching(&self, topic: &str) -> Vec<(Arc<str>, QoS)> {
        let topic_segs: Vec<&str> = topic.split('/').collect();
        let mut results = Vec::new();
        for entry in self.subs.iter() {
            if filter_matches(entry.key(), &topic_segs) {
                for sub in entry.value().iter() {
                    results.push((sub.key().clone(), *sub.value()));
                }
            }
        }
        results
    }
}

/// MQTT 3.1.1 §4.7 topic filter matching.
fn filter_matches(filter: &str, topic_segs: &[&str]) -> bool {
    let filter_segs: Vec<&str> = filter.split('/').collect();
    let mut t = 0;
    let mut f = 0;

    while f < filter_segs.len() {
        match filter_segs[f] {
            "#" => return true,
            "+" => {
                if t >= topic_segs.len() {
                    return false;
                }
                t += 1;
                f += 1;
            }
            seg => {
                if t >= topic_segs.len() || seg != topic_segs[t] {
                    return false;
                }
                t += 1;
                f += 1;
            }
        }
    }
    t == topic_segs.len()
}

// ----------------------------------------------------------------------------
// Broker
// ----------------------------------------------------------------------------

pub struct Broker<W: ConnStream> {
    inner: Arc<BrokerInner<W>>,
}

struct BrokerInner<W: ConnStream> {
    sessions: DashMap<Arc<str>, SubscriberEntry<W>>,
    subscriptions: SubscriptionTree,
    authenticator: Arc<dyn Authenticator>,
    safety: MqttSafety,
}

impl<W: ConnStream> Clone for Broker<W> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<W: ConnStream> Default for Broker<W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W: ConnStream> Broker<W> {
    pub fn new() -> Self {
        Self::build(Arc::new(AcceptAllAuthenticator), MqttSafety::new())
    }

    pub fn with_authenticator(auth: Arc<dyn Authenticator>) -> Self {
        Self::build(auth, MqttSafety::new())
    }

    pub fn with_safety(safety: MqttSafety) -> Self {
        Self::build(Arc::new(AcceptAllAuthenticator), safety)
    }

    pub fn with_authenticator_and_safety(
        auth: Arc<dyn Authenticator>,
        safety: MqttSafety,
    ) -> Self {
        Self::build(auth, safety)
    }

    // Constructors rather than chained setters: `inner` is behind an `Arc` the
    // moment a broker exists, so a `self`-consuming setter would have to
    // rebuild it and would silently drop any sessions already registered.
    fn build(auth: Arc<dyn Authenticator>, safety: MqttSafety) -> Self {
        Self {
            inner: Arc::new(BrokerInner {
                sessions: DashMap::new(),
                subscriptions: SubscriptionTree::new(),
                authenticator: auth,
                safety,
            }),
        }
    }

    /// Wire-layer limits for connections this broker serves.
    pub fn safety(&self) -> &MqttSafety {
        &self.inner.safety
    }

    /// Number of registered sessions. Exposed so a caller can observe that a
    /// dead connection actually left the table — the leak this guards against
    /// is invisible from the wire, since the offending connection is closed
    /// either way.
    pub fn session_count(&self) -> usize {
        self.inner.sessions.len()
    }

    // ── Session lifecycle ────────────────────────────────────────

    pub async fn authenticate(
        &self,
        connect: &ConnectPacket,
        remote_addr: Option<SocketAddr>,
    ) -> AuthResult {
        self.inner
            .authenticator
            .authenticate(connect, remote_addr)
            .await
    }

    /// Register a new session. Returns `session_present` — true when
    /// `clean_session=false` and the broker found prior state for this
    /// client_id. (MVP: in-memory only; persistence is M phase.)
    pub async fn register_session(
        &self,
        client_id: Arc<str>,
        channel: MqttChannel<W>,
        will: Option<WillMessage>,
        clean_session: bool,
    ) -> bool {
        // MVP: check if there's an existing session entry; if clean_session is
        // false and one exists, that's "session present".
        let existing = self.inner.sessions.remove(&client_id);
        let session_present = !clean_session && existing.is_some();

        // If clean_session=true, also wipe old subscriptions.
        if clean_session {
            self.inner.subscriptions.remove_client(&client_id);
        }

        self.inner.sessions.insert(
            client_id,
            SubscriberEntry {
                channel,
                filters: DashMap::new(),
                will,
                clean_session,
            },
        );

        session_present
    }

    /// Tear down a session. If `graceful=false` and the session has a Will,
    /// publish it.
    pub async fn unregister_session(&self, client_id: &Arc<str>, graceful: bool) {
        let Some((_, entry)) = self.inner.sessions.remove(client_id) else {
            return;
        };

        // Remove all subscriptions for this client.
        self.inner.subscriptions.remove_client(client_id);

        // Non-graceful + will set → publish the will message.
        if !graceful
            && let Some(will) = entry.will
        {
            let will_packet = PublishPacket {
                topic: will.topic,
                payload: will.payload,
                dup: false,
                qos: will.qos,
                retain: will.retain,
                packet_id: None,
            };
            // No source_client_id — pass empty sentinel; self-fanout
            // suppression won't match any real subscriber.
            self.publish(&Arc::from(""), will_packet).await;
        }

        // Session entry dropped → Arc<MqttChannel> refcount -1 → channel
        // resources released when the last clone goes away.
    }

    // ── Subscription management ──────────────────────────────────

    pub async fn subscribe(
        &self,
        client_id: &Arc<str>,
        filters: &[TopicFilter],
    ) -> Vec<SubackCode> {
        let Some(entry) = self.inner.sessions.get(client_id) else {
            // Subscribing without a session — return all failure
            return filters.iter().map(|_| SubackCode::Failure).collect();
        };

        let mut codes = Vec::with_capacity(filters.len());
        for tf in filters {
            // Validate filter (could fail).
            match crate::topic::validate_subscribe_filter(&tf.filter) {
                Ok(()) => {
                    entry.filters.insert(tf.filter.clone(), tf.qos);
                    self.inner.subscriptions.subscribe(
                        client_id.clone(),
                        tf.filter.clone(),
                        tf.qos,
                    );
                    codes.push(SubackCode::Granted(tf.qos));
                }
                Err(_) => codes.push(SubackCode::Failure),
            }
        }
        codes
    }

    pub async fn unsubscribe(&self, client_id: &Arc<str>, topics: &[Arc<str>]) {
        let Some(entry) = self.inner.sessions.get(client_id) else {
            return;
        };
        for topic in topics {
            entry.filters.remove(topic);
            self.inner.subscriptions.unsubscribe(client_id, topic);
        }
    }

    // ── Publish fanout ───────────────────────────────────────────

    /// Fan out a PUBLISH to all matching subscribers. `source_client_id` is
    /// the original publisher — that subscription is skipped (self-fanout
    /// suppression).
    ///
    /// Per BCH §4 / G simplification: writes directly into each subscriber's
    /// `cmd_tx` (W policy §2: send-failure silent because subscriber may
    /// have just disconnected).
    pub async fn publish(&self, source_client_id: &Arc<str>, packet: PublishPacket) {
        let matching = self.inner.subscriptions.matching(&packet.topic);
        for (sub_id, sub_qos) in matching {
            // Self-fanout suppression (Mosquitto-style default).
            if sub_id.as_ref() == source_client_id.as_ref() {
                continue;
            }
            let Some(entry) = self.inner.sessions.get(&sub_id) else {
                continue;
            };

            // QoS down-mix per spec: min(publisher's qos, subscription's qos).
            let effective_qos = packet.qos.min(sub_qos);
            let packet_id = if effective_qos > QoS::AtMostOnce {
                let id = entry.channel.session().allocate_packet_id();
                // Store inflight for retransmit / session resume (M phase).
                entry
                    .channel
                    .session()
                    .outbound_inflight
                    .insert(id, packet.clone());
                Some(id)
            } else {
                None
            };

            // Zero-copy adjustment: topic and payload are Arc/Bytes clones.
            let adjusted = PublishPacket {
                topic: packet.topic.clone(),
                payload: packet.payload.clone(),
                dup: false,
                qos: effective_qos,
                retain: false,
                packet_id,
            };

            // W policy §2: subscriber's channel may have just closed —
            // send-failure is acceptable.
            let _ = entry.channel.send_publish(adjusted);
        }
    }

    // ── QoS 1/2 inflight tracking ────────────────────────────────

    /// Called when broker receives PUBACK from a subscriber.
    pub async fn ack_outbound(&self, client_id: &Arc<str>, packet_id: PacketId) {
        if let Some(entry) = self.inner.sessions.get(client_id) {
            entry.channel.session().outbound_inflight.remove(&packet_id);
            // Also fire pending_acks if there's an awaiter.
            if let Some((_, slot)) = entry.channel.session().pending_acks.remove(&packet_id)
                && let crate::session::AckSlot::Puback(tx) = slot
            {
                let _ = tx.send(packet_id); // W policy §3
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Helpers used by other modules
// ----------------------------------------------------------------------------

/// Convert wire `PublishPacket` into a user-facing `IncomingPublish`.
/// Topic/payload are Arc/Bytes clones (O(1)).
pub(crate) fn incoming_from_packet(p: &PublishPacket) -> IncomingPublish {
    IncomingPublish {
        topic: p.topic.clone(),
        payload: p.payload.clone(),
        qos: p.qos,
        retain: p.retain,
        dup: p.dup,
        packet_id: p.packet_id,
    }
}

#[cfg(test)]
mod test;
