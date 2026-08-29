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
use hotaru_core::protocol::Channel; // `close()` on the takeover path

use crate::channel::MqttChannel;
use crate::packet::{ConnackReturnCode, ConnectPacket, PublishPacket};
use crate::request::{
    IncomingPublish, QoS, SubackCode, TopicFilter, WillMessage,
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

/// Accepts every CONNECT, credentials or not.
///
/// No longer what `Broker::new` installs — reach it through
/// [`Broker::accept_all`], whose name says what it does at the call site.
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

/// Refuses every CONNECT with `NotAuthorized`. What `Broker::new` installs.
///
/// A broker that was never told who may connect cannot answer the question, and
/// the safe answer to a question you cannot answer is no. `NotAuthorized`
/// rather than `ServerUnavailable`: the server is up and the request was
/// well-formed; the peer simply is not on any list.
pub struct DenyAllAuthenticator;

#[async_trait]
impl Authenticator for DenyAllAuthenticator {
    async fn authenticate(
        &self,
        _connect: &ConnectPacket,
        _remote_addr: Option<SocketAddr>,
    ) -> AuthResult {
        AuthResult::reject(ConnackReturnCode::NotAuthorized)
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
    /// A broker that refuses every CONNECT until it is given an authenticator.
    ///
    /// This deliberately breaks with 0.8.2, where `new()` accepted everyone: a
    /// deployment that forgot to configure authentication was open, and nothing
    /// about the call site said so. Use [`Broker::with_authenticator`] to
    /// declare a policy, or [`Broker::accept_all`] to ask for the old
    /// behaviour by name.
    pub fn new() -> Self {
        Self::build(Arc::new(DenyAllAuthenticator), MqttSafety::new())
    }

    /// A broker that accepts every CONNECT, credentials or not.
    ///
    /// Kept in the public API rather than hidden behind a feature flag: tests,
    /// local development, and closed networks legitimately want it, and a
    /// caller that writes this name has said out loud what it is doing.
    pub fn accept_all() -> Self {
        Self::build(Arc::new(AcceptAllAuthenticator), MqttSafety::new())
    }

    pub fn with_authenticator(auth: Arc<dyn Authenticator>) -> Self {
        Self::build(auth, MqttSafety::new())
    }

    pub fn with_safety(safety: MqttSafety) -> Self {
        Self::build(Arc::new(DenyAllAuthenticator), safety)
    }

    /// [`Broker::accept_all`] with wire-layer limits attached.
    pub fn accept_all_with_safety(safety: MqttSafety) -> Self {
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
    /// client_id.
    ///
    /// A second CONNECT carrying a client_id that is already connected is a
    /// takeover: MQTT-3.1.4-2 requires the earlier connection to be closed.
    /// Dropping the map entry does not do that — the earlier `handle_server`
    /// holds its own channel clone and its own reader, and would sit there
    /// until keep-alive elapsed, which the client chooses and may set to
    /// 65535 seconds.
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

        if let Some((_, prev)) = existing {
            // Close is idempotent: it flips the channel's open flag and fires
            // the shutdown notify, both of which the earlier read loop is
            // selecting on, so that loop wakes and leaves through its own
            // teardown rather than being abandoned.
            prev.channel.close();
            // The earlier connection's teardown will find a newer
            // connection_id and no-op, so its Will has to be published here.
            // A takeover ends the earlier connection non-gracefully by
            // construction, which is exactly when MQTT-3.1.2-5 requires it.
            self.publish_will(prev.will).await;
        }

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

    /// Publish a session's Will, if it has one. Split out of
    /// `unregister_session` because the takeover path in `register_session`
    /// has to discharge the same obligation for a session whose own teardown
    /// is about to become a no-op.
    async fn publish_will(&self, will: Option<WillMessage>) {
        let Some(will) = will else { return };
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

    /// Tear down a session. If `graceful=false` and the session has a Will,
    /// publish it.
    ///
    /// `connection_id` is the caller's own `MqttChannel::connection_id`, which
    /// is assigned per channel and copied verbatim by `Clone`, so every clone of
    /// one connection reports the same value and no two connections share one.
    /// Removal is conditional on it: after a takeover the earlier connection
    /// still runs this, and an unconditional remove would delete the live
    /// session that replaced it, taking its subscriptions and inflight state
    /// with it.
    pub async fn unregister_session(
        &self,
        client_id: &Arc<str>,
        connection_id: u64,
        graceful: bool,
    ) {
        let Some((_, entry)) = self
            .inner
            .sessions
            .remove_if(client_id, |_, session_entry| {
                session_entry.channel.connection_id() == connection_id
            })
        else {
            return;
        };

        // Remove all subscriptions for this client.
        self.inner.subscriptions.remove_client(client_id);

        // Non-graceful + will set → publish the will message.
        if !graceful {
            self.publish_will(entry.will).await;
        }

        // Session entry dropped → Arc<MqttChannel> refcount -1 → channel
        // resources released when the last clone goes away.
    }

    // ── Subscription management ──────────────────────────────────

    /// `connection_id` is checked against the entry for the same reason
    /// `unregister_session` checks it: during a takeover the client_id names
    /// the newer session, so a SUBSCRIBE the earlier connection had already
    /// read off its socket would otherwise mutate the newer session's
    /// subscription set.
    pub async fn subscribe(
        &self,
        client_id: &Arc<str>,
        connection_id: u64,
        filters: &[TopicFilter],
    ) -> Vec<SubackCode> {
        let Some(entry) = self
            .inner
            .sessions
            .get(client_id)
            .filter(|session_entry| {
                session_entry.channel.connection_id() == connection_id
            })
        else {
            // No session, or it belongs to a different connection — all failure
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

    /// See [`Broker::subscribe`] for why `connection_id` is checked.
    pub async fn unsubscribe(
        &self,
        client_id: &Arc<str>,
        connection_id: u64,
        topics: &[Arc<str>],
    ) {
        let Some(entry) = self
            .inner
            .sessions
            .get(client_id)
            .filter(|session_entry| {
                session_entry.channel.connection_id() == connection_id
            })
        else {
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
                    .track_outbound_inflight(id, packet.clone());
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
