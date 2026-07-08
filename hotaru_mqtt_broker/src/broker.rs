//! MQTT broker — server-side state for cross-connection fanout.
//!
//! Holds `MqttChannel<W>` clones directly (Arc-backed); `publish()` pushes
//! `WriteCmd::Publish` straight into each subscriber's `cmd_tx`. No separate
//! fanout queue, no `serve_outbound` task.
//!
//! Subscription matching is hand-rolled (O(F) per publish where F = unique
//! filters). The `walk_cursor` optimization is deferred to Stage A P3 perf
//! tuning.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use bytes::Bytes;
use dashmap::DashMap;
use hotaru_core::app::runtime::RuntimeSpec;
use hotaru_core::connection::ConnStream;
use hotaru_rt_tokio::TokioRuntime;

use hotaru_core::protocol::Channel as _;
use hotaru_mqtt::MqttSafety;
use hotaru_mqtt::channel::MqttChannel;
use hotaru_mqtt::error::MqttError;
use hotaru_mqtt::packet::{ConnectPacket, Packet, PublishPacket};
use hotaru_mqtt::request::{PacketId, QoS, SubackCode, TopicFilter, WillMessage};
use hotaru_mqtt::topic;

use tracing::warn;

use crate::defaults::{
    AcceptAllAuthenticator, AllowAllAclChecker, DefaultRetainedStore, DefaultSessionStore,
    DenyAllAuthenticator, SingleTenantResolver, is_dollar_topic,
};
use crate::safety::BrokerSafety;
use crate::traits::{
    AclChecker, AclDecision, AuthResult, Authenticator, RetainedStore, SessionStore, TenantId,
    TenantResolver,
};

// ----------------------------------------------------------------------------
// SubscriberEntry — broker's per-client record
// ----------------------------------------------------------------------------

/// Outcome of [`Broker::shutdown`]. Surfaces whether the grace period
/// drained all sessions or timed out with some still live.
#[derive(Debug, Clone)]
pub struct ShutdownReport {
    /// Live connection count at the moment `shutdown` was called.
    pub initial: usize,
    /// Connections still live when `shutdown` returned (zero on
    /// clean drain).
    pub remaining: usize,
    /// Wall-clock spent waiting for the drain to complete.
    pub elapsed: std::time::Duration,
    /// `true` when the grace period elapsed before all sessions exited.
    pub timed_out: bool,
}

pub struct SubscriberEntry<W: ConnStream, Rt: RuntimeSpec = TokioRuntime> {
    pub channel: MqttChannel<W, Rt>,
    pub filters: DashMap<Arc<str>, QoS>,
    pub will: Option<WillMessage>,
    pub clean_session: bool,
    /// Tenant assigned to this connection by `TenantResolver` at CONNECT.
    /// `None` in single-tenant deployments.
    pub tenant: Option<TenantId>,
    /// Username from the CONNECT packet, used by `AclChecker` for
    /// per-action authorization. None when CONNECT carried no creds.
    pub username: Option<Arc<str>>,
    /// V3 — monotonic generation id assigned by `register_session` from
    /// `BrokerInner.next_connection_id`. `unregister_session` compares
    /// against this so a late-running prior `handle_server` exit cannot
    /// remove (or wipe / will-fire) the session a takeover has already
    /// installed in this slot.
    pub connection_id: u64,
}

/// Composite key for every broker-internal state container. Two tenants
/// with the same `client_id` MUST NOT collide (audit finding F5), so every
/// map keys on the tenant + client_id pair.
pub type SessionKey = (Option<TenantId>, Arc<str>);

// ----------------------------------------------------------------------------
// SubscriptionTree — filter→subscriber set lookup
// ----------------------------------------------------------------------------

struct SubscriptionTree {
    /// (tenant, filter) → set of (client_id, max_qos) within that tenant.
    /// Tenant scoping at the key level guarantees `matching(t, topic)` only
    /// ever returns subscribers from tenant `t` — audit finding F6.
    subs: DashMap<(Option<TenantId>, Arc<str>), Arc<DashMap<Arc<str>, QoS>>>,
}

impl SubscriptionTree {
    fn new() -> Self {
        Self {
            subs: DashMap::new(),
        }
    }

    fn subscribe(&self, tenant: Option<TenantId>, client_id: Arc<str>, filter: Arc<str>, qos: QoS) {
        // U4 correctness: write into the inner set while still holding the
        // outer shard guard from `entry(...)`. This serialises a concurrent
        // `subscribe` against the `remove_if` / `retain` reclaim paths below
        // — they all contend on the same outer shard lock, so a reclaim can
        // never observe an empty set, drop the bucket, and then lose a
        // subscription a racing `subscribe` was about to add.
        let set = self
            .subs
            .entry((tenant, filter))
            .or_insert_with(|| Arc::new(DashMap::new()));
        set.insert(client_id, qos);
    }

    fn unsubscribe(&self, tenant: &Option<TenantId>, client_id: &Arc<str>, filter: &str) {
        // DashMap key is (tenant, Arc<str>); we only have &str for the
        // filter, so reconstruct the owned key to look the bucket up.
        let key = (tenant.clone(), Arc::<str>::from(filter));
        // U4: reclaim the outer (tenant, filter) entry once its inner set
        // empties. Without this, a client that subscribes to many DISTINCT
        // filters and unsubscribes leaves empty `Arc<DashMap>` shells behind
        // forever, so `subs` grows without bound and `matching` — which is
        // O(#filters) — slows every publish (a soft DoS). `remove_if` runs
        // the emptiness check while holding the shard lock, so we never drop
        // a bucket a concurrent `subscribe` just re-populated.
        if let Some(set) = self.subs.get(&key) {
            set.remove(client_id);
        }
        self.subs.remove_if(&key, |_, set| set.is_empty());
    }

    /// Remove all subscriptions belonging to one client within a tenant
    /// (used on disconnect / clean_session=true).
    fn remove_client(&self, tenant: &Option<TenantId>, client_id: &Arc<str>) {
        // First drop this client from every bucket within the tenant.
        for entry in self.subs.iter() {
            if &entry.key().0 == tenant {
                entry.value().remove(client_id);
            }
        }
        // U4: then reclaim any buckets this left empty. Done as a second
        // pass via `retain` (the write path) so we don't remove entries
        // while holding the read guard from the loop above. Only this
        // tenant's now-empty buckets are dropped; other tenants' buckets
        // are untouched (we never emptied them).
        self.subs
            .retain(|key, set| &key.0 != tenant || !set.is_empty());
    }

    /// Return (client_id, max_qos) for every subscription within `tenant`
    /// that matches `topic`. Cross-tenant matches are not surfaced.
    fn matching(&self, tenant: &Option<TenantId>, topic: &str) -> Vec<(Arc<str>, QoS)> {
        let topic_segs: Vec<&str> = topic.split('/').collect();
        let mut results = Vec::new();
        for entry in self.subs.iter() {
            let (t, filter) = entry.key();
            if t != tenant {
                continue;
            }
            if filter_matches(filter, &topic_segs) {
                for sub in entry.value().iter() {
                    results.push((sub.key().clone(), *sub.value()));
                }
            }
        }
        results
    }

    /// Number of distinct `(tenant, filter)` buckets currently tracked.
    /// Used by the U4 leak-reclaim regression tests to assert empty buckets
    /// are removed rather than accumulating.
    #[cfg(test)]
    fn filter_bucket_count(&self) -> usize {
        self.subs.len()
    }
}

/// MQTT 3.1.1 §4.7 topic filter matching.
///
/// §4.7.2 — wildcard filters in the first position MUST NOT match `$`-prefixed
/// topics. Uses [`topic::is_dollar_prefixed_first_segment`] as the canonical
/// guard. `pub(crate)` so the ACL layer (`auth::acl`) can re-use the exact
/// same matcher for filter↔topic checks.
pub(crate) fn filter_matches(filter: &str, topic_segs: &[&str]) -> bool {
    let filter_segs: Vec<&str> = filter.split('/').collect();

    // spec §4.7.2 guard
    if matches!(filter_segs.first(), Some(&"+") | Some(&"#"))
        && topic_segs.first().is_some_and(|t| t.starts_with('$'))
    {
        let _ = topic::is_dollar_prefixed_first_segment;
        return false;
    }

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
// RetainedMessage — kept as a public type for downstream callers that want
// the raw (payload, qos) tuple. The actual store is now `RetainedStore`.
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RetainedMessage {
    pub payload: Bytes,
    pub qos: QoS,
}

// ----------------------------------------------------------------------------
// Broker
// ----------------------------------------------------------------------------

pub struct Broker<W: ConnStream, Rt: RuntimeSpec = TokioRuntime> {
    inner: Arc<BrokerInner<W, Rt>>,
}

struct BrokerInner<W: ConnStream, Rt: RuntimeSpec> {
    /// Keyed by `(tenant, client_id)` so cross-tenant collisions cannot
    /// silently evict (audit F5).
    sessions: DashMap<SessionKey, SubscriberEntry<W, Rt>>,
    subscriptions: SubscriptionTree,
    authenticator: Arc<dyn Authenticator>,
    acl_checker: Arc<dyn AclChecker>,
    tenant_resolver: Arc<dyn TenantResolver>,
    /// Retained-message store. Default = `DefaultRetainedStore` (in-memory,
    /// non-persistent). Swap via `Broker::with_retained_store`.
    retained_store: Arc<dyn RetainedStore>,
    /// Persistent-session store backing `clean_session=false` reconnect
    /// (Stage A P7). Default = `DefaultSessionStore` (in-memory). Disk-backed
    /// stores swap via `Broker::with_session_store`.
    session_store: Arc<dyn SessionStore>,
    /// Stage A P6: one-shot guard so `init_sys()` populates the static
    /// `$SYS/broker/*` retained values exactly once per broker instance.
    sys_initialized: AtomicBool,
    safety: MqttSafety,
    broker_safety: BrokerSafety,
    /// Live connection count. `try_admit_connection` checks against
    /// `broker_safety.max_connections()` before accepting CONNECT; the
    /// handle_server loop decrements via `release_connection` on exit.
    active_connections: AtomicUsize,
    /// V3 — broker-wide monotonic counter for `SubscriberEntry.connection_id`.
    /// Wraps in u64 space (never reached at any realistic broker uptime), so
    /// the generation guard in `unregister_session` is collision-free for
    /// the lifetime of the process.
    next_connection_id: AtomicU64,
}

impl<W: ConnStream, Rt: RuntimeSpec> Clone for Broker<W, Rt> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<W: ConnStream, Rt: RuntimeSpec> Default for Broker<W, Rt> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W: ConnStream, Rt: RuntimeSpec> Broker<W, Rt> {
    /// Construct a broker that is **secure by default** (attack-surface
    /// finding AS2). The default authenticator is [`DenyAllAuthenticator`],
    /// so a broker that is bound to the network without an explicit
    /// `Broker::with_authenticator(...)` constructor call refuses every
    /// CONNECT with `NotAuthorized` instead of silently accepting anonymous
    /// clients.
    ///
    /// The ACL checker still defaults to [`AllowAllAclChecker`]: once a
    /// client has authenticated, authorization is the operator's policy
    /// choice, and a deny-all ACL would make even a correctly-authenticated
    /// client unable to do anything. Install [`with_acl_checker`] for
    /// per-topic authorization.
    ///
    /// For dev / tests / throwaway scaffolds that genuinely want the old
    /// "accept everyone" behaviour, call [`Broker::insecure`] — it is named
    /// to make the choice explicit and greppable in review.
    ///
    /// [`with_acl_checker`]: Broker::with_acl_checker
    pub fn new() -> Self {
        Self::build(
            Arc::new(DenyAllAuthenticator),
            Arc::new(AllowAllAclChecker),
            Arc::new(SingleTenantResolver),
            Arc::new(DefaultRetainedStore::new()),
            Arc::new(DefaultSessionStore::new()),
            MqttSafety::new(),
            BrokerSafety::new(),
        )
    }

    /// Construct a broker with the **open** dev/test defaults:
    /// [`AcceptAllAuthenticator`] + [`AllowAllAclChecker`]. Accepts every
    /// client and permits every publish / subscribe.
    ///
    /// **DO NOT use on a network-reachable deployment.** Production code
    /// MUST use [`Broker::new`] (deny-all) and install a real authenticator
    /// via `Broker::with_authenticator(...)`. This constructor exists so
    /// tests and local scaffolds opt into the insecure posture explicitly
    /// rather than inheriting it silently from `new()` (attack-surface
    /// finding AS2).
    ///
    /// A loud one-shot `warn!` fires at construction so the open posture is
    /// operator-visible if it ever reaches a real process; silence it in
    /// tests via your tracing subscriber if it is noisy.
    pub fn insecure() -> Self {
        warn!(
            target: "hotaru_mqtt_broker",
            authenticator = "AcceptAllAuthenticator",
            acl_checker = "AllowAllAclChecker",
            "Broker::insecure() initialized with open accept-all/allow-all \
             defaults — every client is accepted and every publish/subscribe \
             permitted. Use Broker::with_authenticator(...) before \
             binding to a network. See SAFETY_PROOF AS2."
        );
        Self::build(
            Arc::new(AcceptAllAuthenticator),
            Arc::new(AllowAllAclChecker),
            Arc::new(SingleTenantResolver),
            Arc::new(DefaultRetainedStore::new()),
            Arc::new(DefaultSessionStore::new()),
            MqttSafety::new(),
            BrokerSafety::new(),
        )
    }

    pub fn with_authenticator(auth: Arc<dyn Authenticator>) -> Self {
        Self::build(
            auth,
            Arc::new(AllowAllAclChecker),
            Arc::new(SingleTenantResolver),
            Arc::new(DefaultRetainedStore::new()),
            Arc::new(DefaultSessionStore::new()),
            MqttSafety::new(),
            BrokerSafety::new(),
        )
    }

    pub fn with_safety(mut self, safety: MqttSafety) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("Broker safety must be set before cloning")
            .safety = safety;
        self
    }

    pub fn with_broker_safety(mut self, broker_safety: BrokerSafety) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("Broker safety must be set before cloning")
            .broker_safety = broker_safety;
        self
    }

    pub fn with_acl_checker(mut self, acl: Arc<dyn AclChecker>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("Broker ACL must be set before cloning")
            .acl_checker = acl;
        self
    }

    pub fn with_tenant_resolver(mut self, resolver: Arc<dyn TenantResolver>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("Broker TenantResolver must be set before cloning")
            .tenant_resolver = resolver;
        self
    }

    pub fn with_retained_store(mut self, store: Arc<dyn RetainedStore>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("Broker RetainedStore must be set before cloning")
            .retained_store = store;
        self
    }

    pub fn with_session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("Broker SessionStore must be set before cloning")
            .session_store = store;
        self
    }

    fn build(
        authenticator: Arc<dyn Authenticator>,
        acl_checker: Arc<dyn AclChecker>,
        tenant_resolver: Arc<dyn TenantResolver>,
        retained_store: Arc<dyn RetainedStore>,
        session_store: Arc<dyn SessionStore>,
        safety: MqttSafety,
        broker_safety: BrokerSafety,
    ) -> Self {
        Self {
            inner: Arc::new(BrokerInner {
                sessions: DashMap::new(),
                subscriptions: SubscriptionTree::new(),
                authenticator,
                acl_checker,
                tenant_resolver,
                retained_store,
                session_store,
                sys_initialized: AtomicBool::new(false),
                safety,
                broker_safety,
                active_connections: AtomicUsize::new(0),
                next_connection_id: AtomicU64::new(0),
            }),
        }
    }

    pub fn session_store(&self) -> &Arc<dyn SessionStore> {
        &self.inner.session_store
    }

    pub fn safety(&self) -> &MqttSafety {
        &self.inner.safety
    }

    pub fn broker_safety(&self) -> &BrokerSafety {
        &self.inner.broker_safety
    }

    /// Stage A P8 — graceful shutdown (D24). Signals every live session
    /// to wind down (each channel's `close()` flips its open flag and
    /// notifies the per-connection handle loop). Waits up to
    /// `BrokerSafety.shutdown_grace_period()` for `active_connections` to
    /// reach zero, then returns regardless. Callers (the embedding
    /// process) drop their listener BEFORE calling this so no new
    /// CONNECT can race with the drain.
    pub async fn shutdown(&self) -> ShutdownReport {
        let grace = self.inner.broker_safety.shutdown_grace_period();
        let initial = self.inner.active_connections.load(Ordering::Acquire);
        for entry in self.inner.sessions.iter() {
            entry.value().channel.close();
        }
        // Scheduling stays runtime-agnostic: the drain deadline lives in
        // Rt::timeout, not in an Instant comparison (RuntimeSpec's Instant
        // is opaque). The std clock below is observation only — it feeds
        // the ShutdownReport.elapsed diagnostic, never a scheduling
        // decision, and the broker is a std-only component anyway.
        let start = std::time::Instant::now();
        let _ = Rt::timeout(grace, async {
            while self.inner.active_connections.load(Ordering::Acquire) > 0 {
                Rt::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await;
        let remaining = self.inner.active_connections.load(Ordering::Acquire);
        ShutdownReport {
            initial,
            remaining,
            elapsed: start.elapsed(),
            timed_out: remaining > 0,
        }
    }

    /// Reserve one connection slot if under `max_connections`. Returns
    /// `false` when at capacity — caller MUST refuse the CONNECT with
    /// CONNACK 0x03 ServerUnavailable. Pairs 1:1 with
    /// `release_connection` on disconnect.
    pub fn try_admit_connection(&self) -> bool {
        let max = self.inner.broker_safety.max_connections();
        let prev = self.inner.active_connections.fetch_add(1, Ordering::AcqRel);
        if prev >= max {
            self.inner.active_connections.fetch_sub(1, Ordering::AcqRel);
            false
        } else {
            true
        }
    }

    pub fn release_connection(&self) {
        self.inner.active_connections.fetch_sub(1, Ordering::AcqRel);
    }

    pub fn active_connection_count(&self) -> usize {
        self.inner.active_connections.load(Ordering::Acquire)
    }

    // ── Session lifecycle ────────────────────────────────────────

    /// Resolve which tenant this CONNECT belongs to. Called before
    /// [`authenticate`](Self::authenticate) so the authenticator can
    /// scope its lookup. `None` for single-tenant deployments (the
    /// `SingleTenantResolver` default returns it unconditionally).
    pub async fn resolve_tenant(
        &self,
        connect: &ConnectPacket,
        remote_addr: Option<SocketAddr>,
    ) -> Option<TenantId> {
        self.inner
            .tenant_resolver
            .resolve(connect, remote_addr)
            .await
    }

    /// Authenticate a CONNECT within a tenant scope. `tenant` is the value
    /// returned by [`resolve_tenant`](Self::resolve_tenant); pass through
    /// so the authenticator's per-tenant credential lookup works.
    pub async fn authenticate(
        &self,
        tenant: Option<&TenantId>,
        connect: &ConnectPacket,
        remote_addr: Option<SocketAddr>,
    ) -> AuthResult {
        self.inner
            .authenticator
            .authenticate(tenant, connect, remote_addr)
            .await
    }

    /// Register a new session. Returns `session_present` — true when
    /// `clean_session=false` and the broker found prior state for this
    /// `(tenant, client_id)` pair. (MVP: in-memory only; persistence is
    /// Stage A P7.)
    ///
    /// `tenant` is the identity returned by `TenantResolver::resolve` (None in
    /// single-tenant deployments). Stored on the `SubscriberEntry` so ACL /
    /// retained / `$SYS` lookups don't have to round-trip a resolver per call.
    /// Register the freshly-accepted connection. Stage A P7: when
    /// `clean_session=false` AND [`Self::session_store`] holds a
    /// persistent session for `(tenant, client_id)`, this method imports
    /// the inflight + QoS-2 stash + packet-id watermark into `channel`'s
    /// own session via [`MqttSession::import_persistent_state`] and
    /// returns `true` for the CONNACK `session_present` bit
    /// (spec §3.2.2.2). On `clean_session=true`, any persisted session is
    /// destroyed and `session_present` is always `false`.
    pub async fn register_session(
        &self,
        tenant: Option<TenantId>,
        client_id: Arc<str>,
        username: Option<Arc<str>>,
        channel: MqttChannel<W, Rt>,
        will: Option<WillMessage>,
        clean_session: bool,
    ) -> (bool, u64) {
        let key = (tenant.clone(), client_id.clone());
        // Takeover semantics (spec §3.1.4-2 + SAFETY_PROOF v3 U2): the
        // prior session for `(tenant, client_id)` MUST terminate "as soon
        // as possible". Removing from the map alone only drops one channel
        // clone — the prior `handle_server` keeps holding its own clone +
        // its `active_connections` slot until keep-alive elapses (up to
        // ~27h with `keep_alive=65535`). Explicitly `close()` here so the
        // prior loop's `select!` wakes on its `shutdown` notify and exits.
        // The prior loop runs through to `release_connection()` at its
        // own scope exit; this code path MUST NOT double-release.
        //
        // V3 — prev's cleanup (Will dispatch + persistent save + sub
        // teardown) runs SYNCHRONOUSLY here, BEFORE the new entry is
        // installed. Without this, prev's eventual `unregister_session`
        // call (now generation-guarded) would no-op and prev's Will would
        // never fire — §3.1.2.5 requires the Will to publish whenever the
        // network connection closes non-gracefully, and takeover closes
        // prev non-gracefully by construction. Doing prev's persistent
        // save here also means the very next clean_session=false load
        // below can pick up prev's freshly-stashed state instead of an
        // older snapshot (intent of §3.1.2.4).
        if let Some((_, prev)) = self.inner.sessions.remove(&key) {
            prev.channel.close();
            self.cleanup_session_state(&client_id, prev, false).await;
        }

        let mut session_present = false;
        if clean_session {
            // CleanSession=1 sweeps subscriptions AND any persisted state
            // accumulated by a prior persistent session for this client.
            self.inner.subscriptions.remove_client(&tenant, &client_id);
            self.inner
                .session_store
                .destroy(tenant.as_ref(), client_id.as_ref())
                .await;
        } else if let Some(persisted) = self
            .inner
            .session_store
            .load(tenant.as_ref(), client_id.as_ref())
            .await
        {
            // Resume: copy inflight + qos2_recv + pkt_counter watermark
            // into the fresh channel's session. Subscriptions are already
            // live in the SubscriptionTree (we skipped `remove_client` on
            // the prior persistent disconnect). The loaded Arc is dropped
            // after import completes — its DashMaps have been moved.
            channel.session().import_persistent_state(&persisted);
            session_present = true;
        }

        let connection_id = self
            .inner
            .next_connection_id
            .fetch_add(1, Ordering::Relaxed);
        self.inner.sessions.insert(
            key,
            SubscriberEntry {
                channel,
                filters: DashMap::new(),
                will,
                clean_session,
                tenant,
                username,
                connection_id,
            },
        );

        (session_present, connection_id)
    }

    /// Look up the tenant for a registered `(tenant, client_id)` key. With
    /// the F5 keying refactor, callers normally already have the tenant in
    /// hand — kept for symmetry / smoke tests.
    pub fn tenant_of(&self, tenant: &Option<TenantId>, client_id: &Arc<str>) -> Option<TenantId> {
        self.inner
            .sessions
            .get(&(tenant.clone(), client_id.clone()))
            .and_then(|e| e.tenant.clone())
    }

    /// Tear down a session. If `graceful=false` and the session has a Will,
    /// publish it within the SAME tenant (audit F7).
    ///
    /// Stage A P7 dispatch:
    /// - `clean_session=true` → drop subscriptions + destroy any prior
    ///   persistent state + wipe the session's inflight maps.
    /// - `clean_session=false` → KEEP subscriptions in the tree (spec
    ///   §3.1.2.4) + persist the [`MqttSession`] handle so a later
    ///   reconnect with the same `client_id` can resume outbound inflight
    ///   and QoS-2 inbound half-state.
    ///
    /// V3 — `connection_id` is the value `register_session` returned for
    /// this connection. The slot is removed ONLY if the entry there still
    /// carries that id; a later-registered session (from a takeover) has
    /// a fresh id and is left untouched. The takeover path inside
    /// `register_session` already ran the prior connection's cleanup
    /// synchronously, so this no-op branch is the correct outcome.
    pub async fn unregister_session(
        &self,
        tenant: &Option<TenantId>,
        client_id: &Arc<str>,
        connection_id: u64,
        graceful: bool,
    ) {
        let key = (tenant.clone(), client_id.clone());
        let removed = self
            .inner
            .sessions
            .remove_if(&key, |_, entry| entry.connection_id == connection_id);
        let Some((_, entry)) = removed else {
            return;
        };
        self.cleanup_session_state(client_id, entry, graceful).await;
    }

    /// V3 — extracted session teardown shared by `unregister_session`
    /// (normal disconnect / read-loop error) and `register_session`'s
    /// takeover path. The `entry` argument has already been removed from
    /// `self.inner.sessions`; this function performs persistent-state
    /// handling, subscription cleanup, session wipe (clean-session only),
    /// and Will dispatch.
    ///
    /// The Will's publisher username is the entry's captured username, so
    /// the downstream ACL check sees the same identity the broker
    /// authenticated at CONNECT (SAFETY_PROOF G5 / second-audit G6) even
    /// though `sessions[(t,c)]` is already gone by the time this runs.
    async fn cleanup_session_state(
        &self,
        client_id: &Arc<str>,
        entry: SubscriberEntry<W, Rt>,
        graceful: bool,
    ) {
        let session_tenant = entry.tenant.clone();
        let clean_session = entry.clean_session;
        let persisted_session = entry.channel.session().clone();
        let will_publisher_username = entry.username.clone();

        if clean_session {
            self.inner
                .subscriptions
                .remove_client(&session_tenant, client_id);
            self.inner
                .session_store
                .destroy(session_tenant.as_ref(), client_id.as_ref())
                .await;
            persisted_session.wipe();
        } else {
            // Persistent session: keep subscriptions live in the tree so
            // matching against fresh publishes during the disconnected
            // window queues into outbound_inflight via reconnect retry,
            // and stash the session handle for the next CONNECT to pick
            // up. The Will is per-CONNECT (spec §3.1.2.5), so it is NOT
            // re-saved beyond this disconnect's potential fire below.
            //
            // SAFETY_PROOF v5 T2(d): cap stored `clean_session=false`
            // sessions per tenant. Over cap: skip the save (the session
            // simply won't resume on the next CONNECT — the client sees
            // `session_present=0`). Subscriptions still need to be torn
            // down so the SubscriptionTree doesn't accumulate orphan
            // entries pointing at a discarded session blob. This mirrors
            // the `clean_session=true` cleanup, except we don't call
            // `destroy` on the store (there's nothing stored).
            let cap = self
                .inner
                .broker_safety
                .max_persistent_sessions_per_tenant();
            let current = self
                .inner
                .session_store
                .count(session_tenant.as_ref())
                .await;
            if current >= cap {
                warn!(
                    target: "hotaru_mqtt_broker",
                    tenant = ?session_tenant.as_deref(),
                    client_id = %client_id,
                    current,
                    cap,
                    "persistent-sessions-per-tenant cap hit: dropping session blob"
                );
                self.inner
                    .subscriptions
                    .remove_client(&session_tenant, client_id);
                persisted_session.wipe();
            } else {
                self.inner
                    .session_store
                    .save(
                        session_tenant.as_ref(),
                        client_id.clone(),
                        persisted_session,
                    )
                    .await;
            }
        }

        if !graceful && let Some(will) = entry.will {
            let will_packet = PublishPacket {
                properties: Default::default(),
                topic: will.topic,
                payload: will.payload,
                dup: false,
                qos: will.qos,
                retain: will.retain,
                packet_id: None,
            };
            // Empty source client_id never matches a real subscriber, so
            // self-fanout suppression is a no-op here. Tenant scope is
            // what actually constrains the fanout (F7). Pass the captured
            // username so a strict ACL can recognize the dying client.
            self.publish_with_source_username(
                &session_tenant,
                &Arc::from(""),
                will_publisher_username,
                will_packet,
            )
            .await;
        }
    }

    /// Stage A P7: replay every outbound inflight PUBLISH from a freshly
    /// rebound persistent session through the new channel (`dup=1` per
    /// spec §3.3.1.1 + §4.4). Called by `handle_server` AFTER CONNACK.
    ///
    /// Silent on writer-actor backpressure (W §1) — the client will see
    /// the publish via the broker's normal retransmit path on the next
    /// reconnect if this delivery falls on the floor.
    pub fn retransmit_inflight(&self, channel: &MqttChannel<W, Rt>) {
        for (_id, publish) in channel.session().drain_outbound_for_retransmit() {
            // W §1 — backpressure on the writer actor's bounded cmd_tx is
            // silently absorbed; the broker still holds outbound_inflight
            // and will retransmit again on the next reconnect.
            let _ = channel.send_packet(Packet::Publish(publish));
        }
    }

    // ── Subscription management ──────────────────────────────────

    pub async fn subscribe(
        &self,
        tenant: &Option<TenantId>,
        client_id: &Arc<str>,
        filters: &[TopicFilter],
    ) -> Vec<SubackCode> {
        let key = (tenant.clone(), client_id.clone());
        // Resolve username + channel handle without holding a DashMap Ref
        // across `.await` (DashMap shard locks + cross-await suspend = nope).
        let (username, channel) = {
            let Some(entry) = self.inner.sessions.get(&key) else {
                return filters.iter().map(|_| SubackCode::Failure).collect();
            };
            (entry.username.clone(), entry.channel.clone())
        };

        let mut codes = Vec::with_capacity(filters.len());
        let mut granted_filters: Vec<(Arc<str>, QoS)> = Vec::new();
        for tf in filters {
            if topic::validate_subscribe_filter(&tf.filter).is_err() {
                codes.push(SubackCode::Failure);
                continue;
            }
            // ACL gate (spec §4.7 + plan D25): deny → SUBACK 0x80 Failure
            // and skip the actual subscription insert.
            let decision = self
                .inner
                .acl_checker
                .check_subscribe(tenant.as_ref(), client_id, username.as_ref(), &tf.filter)
                .await;
            if decision == AclDecision::Deny {
                codes.push(SubackCode::Failure);
                continue;
            }
            // Re-fetch the entry to write into its per-client filter map.
            // The session might have been concurrently removed; in that
            // case the SUBACK still says Granted but no actual subscription
            // got installed — the SubscriptionTree insert below still
            // happens, so a subsequent re-register will pick it up via
            // the same key (clean_session semantics).
            //
            // SAFETY_PROOF v5 T2(c): cap total subscriptions per client.
            // `SubscriberEntry.filters` is authoritative for the count;
            // when full, surface `SubackCode::Failure` and skip both the
            // entry write AND the SubscriptionTree insert so the limit
            // is observed end-to-end (no orphan entries in the tree).
            // Re-subscribe to the same filter is a no-op against the cap
            // (DashMap.insert overwrites; len stays the same).
            let cap = self.inner.broker_safety.max_subscriptions_per_client();
            if let Some(entry) = self.inner.sessions.get(&key) {
                let already_has = entry.filters.contains_key(&tf.filter);
                if !already_has && entry.filters.len() >= cap {
                    warn!(
                        target: "hotaru_mqtt_broker",
                        tenant = ?tenant.as_deref(),
                        client_id = %client_id,
                        filter = %tf.filter,
                        cap,
                        "subscriptions-per-client cap hit: rejecting filter with SUBACK Failure"
                    );
                    codes.push(SubackCode::Failure);
                    continue;
                }
                entry.filters.insert(tf.filter.clone(), tf.qos);
            }
            self.inner.subscriptions.subscribe(
                tenant.clone(),
                client_id.clone(),
                tf.filter.clone(),
                tf.qos,
            );
            codes.push(SubackCode::Granted(tf.qos));
            granted_filters.push((tf.filter.clone(), tf.qos));
        }

        // Retained replay does NOT happen here — the dispatcher sends
        // SUBACK first (spec convention + plan D18), then calls
        // [`Self::replay_retained_for_subscribe`] with the granted filters.
        // The `granted_filters` we computed here are stored on the channel
        // session via the SubscriptionTree insert above, so the
        // dispatcher can re-derive them by zipping `filters` ⨯ `codes`.
        let _ = granted_filters; // intentionally unused — see comment
        let _ = channel;
        codes
    }

    /// Send retained-message replays to the just-subscribed client. Must be
    /// called by the dispatcher AFTER SUBACK has been queued so the wire
    /// order is `SUBACK → retained PUBLISH...` per spec convention (D18).
    ///
    /// `granted` carries the `(filter, granted_qos)` pairs the dispatcher
    /// derived from zipping the original SUBSCRIBE filters with the codes
    /// returned by [`subscribe`].
    pub async fn replay_retained_for_subscribe(
        &self,
        tenant: &Option<TenantId>,
        client_id: &Arc<str>,
        granted: &[(Arc<str>, QoS)],
    ) {
        if granted.is_empty() {
            return;
        }
        let key = (tenant.clone(), client_id.clone());
        let channel = match self.inner.sessions.get(&key) {
            Some(entry) => entry.channel.clone(),
            None => return,
        };
        let policy = self.inner.broker_safety.slow_consumer_policy();
        let max_inflight = self.inner.broker_safety.max_inflight_messages();
        'replay: for (filter, granted_qos) in granted {
            let entries = self
                .inner
                .retained_store
                .matching(tenant.as_ref(), filter)
                .await;
            for r in entries {
                let qos = r.qos.min(*granted_qos);
                let packet_id = if qos > QoS::AtMostOnce {
                    // G7 — same cap + fallible allocator pattern as
                    // `publish_with_source_username` above.
                    let session = channel.session();
                    let over_cap = session.outbound_inflight_len() >= max_inflight;
                    let id_opt = if over_cap {
                        None
                    } else {
                        session.try_allocate_packet_id()
                    };
                    match id_opt {
                        Some(id) => {
                            session.stash_outbound_inflight(
                                id,
                                PublishPacket {
                                    properties: Default::default(),
                                    topic: r.topic.clone(),
                                    payload: r.payload.clone(),
                                    dup: false,
                                    qos,
                                    retain: true,
                                    packet_id: Some(id),
                                },
                            );
                            Some(id)
                        }
                        None => {
                            if policy.should_close_on_overflow(qos) {
                                channel.close();
                                break 'replay;
                            }
                            continue;
                        }
                    }
                } else {
                    None
                };
                let replay = PublishPacket {
                    // Deferred: RetainedStore entries don't carry v5
                    // properties yet, so retained replays deliver without
                    // them (tracked in the v5 PR notes).
                    properties: Default::default(),
                    topic: r.topic,
                    payload: r.payload,
                    dup: false,
                    qos,
                    retain: true,
                    packet_id,
                };
                match channel.send_publish(replay) {
                    Ok(_) | Err(MqttError::ChannelClosed) => {}
                    Err(MqttError::Backpressure) => {
                        if policy.should_close_on_overflow(qos) {
                            channel.close();
                            break 'replay;
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }

    pub async fn unsubscribe(
        &self,
        tenant: &Option<TenantId>,
        client_id: &Arc<str>,
        topics: &[Arc<str>],
    ) {
        let key = (tenant.clone(), client_id.clone());
        let Some(entry) = self.inner.sessions.get(&key) else {
            return;
        };
        for t in topics {
            entry.filters.remove(t);
            self.inner.subscriptions.unsubscribe(tenant, client_id, t);
        }
    }

    // ── Publish fanout ───────────────────────────────────────────

    /// Fan out a PUBLISH to all matching subscribers WITHIN THE SAME TENANT
    /// (audit F6). `source_client_id` is the original publisher — that
    /// subscription is skipped (self-fanout suppression).
    ///
    /// Writes directly into each subscriber's `cmd_tx` (W policy §2: send
    /// failure is silent because subscriber may have just disconnected).
    pub async fn publish(
        &self,
        source_tenant: &Option<TenantId>,
        source_client_id: &Arc<str>,
        packet: PublishPacket,
    ) {
        self.publish_with_source_username(source_tenant, source_client_id, None, packet)
            .await;
    }

    /// Internal entry point that lets callers pre-supply the publisher's
    /// username when the `sessions` entry has already been removed (Will
    /// dispatch from `unregister_session`). When `source_username` is
    /// `None`, the username is looked up via the live session entry the
    /// normal way.
    async fn publish_with_source_username(
        &self,
        source_tenant: &Option<TenantId>,
        source_client_id: &Arc<str>,
        source_username: Option<Arc<str>>,
        packet: PublishPacket,
    ) {
        // spec §4.7.2 + D19 + SAFETY_PROOF v3 U3: clients MUST NOT
        // publish to the `$SYS/*` (and other `$`-prefixed) namespace at
        // ALL — retained or not. Prior version only guarded `retain=1`,
        // letting a `retain=0` publish spoof `$SYS/broker/version` to any
        // literal subscriber (the broker's own `init_sys` populates that
        // topic by default, so legitimate subscribers exist out of the
        // box). The privileged broker-internal write path is
        // `publish_sys_retained`, which bypasses this guard by design.
        // Purely topic-based, no auth involved, so it runs first.
        if is_dollar_topic(&packet.topic) {
            return;
        }

        // ACL gate (D16): publish ACL is checked AGAINST the publisher's
        // identity. MUST precede every state mutation below (retained
        // store + fanout) so a denied publisher cannot modify or delete
        // retained values on topics they lack publish permission for
        // (SAFETY_PROOF §7 G1).
        //
        // Deny path:
        //   - QoS 0: silent drop (the ack was a no-op anyway)
        //   - QoS≥1: spec-required PUBACK/PUBREC was already sent
        //            pre-chain (O.2), so we simply skip the fanout.
        // Either way we never propagate the message — callers don't see a
        // distinction, which matches the "no privilege information" rule.
        let publisher_username = source_username.or_else(|| {
            self.inner
                .sessions
                .get(&(source_tenant.clone(), source_client_id.clone()))
                .and_then(|e| e.username.clone())
        });
        let decision = self
            .inner
            .acl_checker
            .check_publish(
                source_tenant.as_ref(),
                source_client_id,
                publisher_username.as_ref(),
                &packet.topic,
            )
            .await;
        if decision == AclDecision::Deny {
            return;
        }

        // spec §3.3.1.3: retain=1 + non-empty payload → store; retain=1 +
        // empty payload → delete any stored entry. Fanout still happens
        // for the CURRENT delivery in both cases (subscribers see retain=0
        // on the current-delivery copy below — that's the spec rule).
        // Only reachable after ACL allow.
        if packet.retain {
            if packet.payload.is_empty() {
                self.inner
                    .retained_store
                    .remove(source_tenant.as_ref(), &packet.topic)
                    .await;
            } else {
                // SAFETY_PROOF v5 T2(a)/T2(b) — cap retained-message COUNT
                // and BYTES per tenant. Over either cap: drop the `store`
                // call but DO continue fanout (the in-flight subscribers
                // still see this publish; only the long-term retention is
                // suppressed). Operator gets a structured warn so the leak
                // is visible.
                let count_cap = self.inner.broker_safety.max_retained_messages_per_tenant();
                let byte_cap = self.inner.broker_safety.max_retained_bytes_per_tenant();
                let current_count = self
                    .inner
                    .retained_store
                    .count(source_tenant.as_ref())
                    .await;
                let current_bytes = self
                    .inner
                    .retained_store
                    .bytes(source_tenant.as_ref())
                    .await;
                let new_bytes = packet.payload.len();
                if current_count >= count_cap {
                    warn!(
                        target: "hotaru_mqtt_broker",
                        tenant = ?source_tenant.as_deref(),
                        topic = %packet.topic,
                        current = current_count,
                        cap = count_cap,
                        "retained-message count cap hit: dropping store call (fanout still proceeds)"
                    );
                } else if current_bytes.saturating_add(new_bytes) > byte_cap {
                    // Pessimistic on same-topic overwrite (doesn't subtract
                    // the replaced entry's size) — acceptable: the threat is
                    // a single oversized retained payload, which this gate
                    // rejects even on an empty tenant.
                    warn!(
                        target: "hotaru_mqtt_broker",
                        tenant = ?source_tenant.as_deref(),
                        topic = %packet.topic,
                        current_bytes,
                        new_bytes,
                        cap = byte_cap,
                        "retained-byte cap hit: dropping store call (fanout still proceeds)"
                    );
                } else {
                    self.inner
                        .retained_store
                        .store(
                            source_tenant.as_ref(),
                            packet.topic.clone(),
                            packet.payload.clone(),
                            packet.qos,
                        )
                        .await;
                }
            }
        }

        let matching = self
            .inner
            .subscriptions
            .matching(source_tenant, &packet.topic);
        for (sub_id, sub_qos) in matching {
            if sub_id.as_ref() == source_client_id.as_ref() {
                continue;
            }
            let Some(entry) = self
                .inner
                .sessions
                .get(&(source_tenant.clone(), sub_id.clone()))
            else {
                continue;
            };

            let effective_qos = packet.qos.min(sub_qos);
            // G7 — enforce `max_inflight_messages` BEFORE stashing
            // outbound_inflight. Prior to this gate the map could grow
            // unbounded on a `clean_session=false` subscriber that never
            // ACKs, and a final `allocate_packet_id` exhaustion panicked
            // the connection task. Now the cap is consulted, the fallible
            // allocator is used, and either path routes through the
            // configured `SlowConsumerPolicy`.
            let packet_id = if effective_qos > QoS::AtMostOnce {
                let session = entry.channel.session();
                let max_inflight = self.inner.broker_safety.max_inflight_messages();
                let over_cap = session.outbound_inflight_len() >= max_inflight;
                let id_opt = if over_cap {
                    None
                } else {
                    session.try_allocate_packet_id()
                };
                match id_opt {
                    Some(id) => Some(id),
                    None => {
                        // No packet-id available (cap reached or u16 space
                        // exhausted). Apply the slow-consumer policy to
                        // decide drop-vs-close; for QoS≥1 the policy
                        // always closes (no silent drop is spec-safe).
                        if self
                            .inner
                            .broker_safety
                            .slow_consumer_policy()
                            .should_close_on_overflow(effective_qos)
                        {
                            let laggard = entry.channel.clone();
                            drop(entry);
                            laggard.close();
                        }
                        continue;
                    }
                }
            } else {
                None
            };

            let adjusted = PublishPacket {
                // v5 §3.3.2.3: Response Topic / Correlation Data / Content
                // Type / User Properties are forwarded unaltered.
                properties: packet.properties.clone(),
                topic: packet.topic.clone(),
                payload: packet.payload.clone(),
                dup: false,
                qos: effective_qos,
                retain: false,
                packet_id,
            };

            // V1 — stash the SUBSCRIBER-shaped packet (adjusted), not the
            // publisher's original. A reconnect retransmit of the stashed
            // entry must match what we already sent: subscriber-allocated
            // packet_id, downgraded `effective_qos`, and `retain=false`
            // (the current-delivery copy is never retain=1 per §3.3.1.3).
            // Stashing `packet.clone()` previously sent the publisher's
            // packet_id / qos / retain on retransmit, leaving subscriber
            // ACKs unable to clear the entry and possibly tripping the
            // inflight cap. `$SYS` and retained-replay paths already do
            // this correctly.
            if let Some(id) = packet_id {
                entry
                    .channel
                    .session()
                    .stash_outbound_inflight(id, adjusted.clone());
            }

            // P3.D: apply slow-consumer policy when the subscriber's cmd_tx
            // is full. W policy §2 covers ChannelClosed (transient) silently;
            // Backpressure routes through the configured `SlowConsumerPolicy`.
            match entry.channel.send_publish(adjusted) {
                Ok(_) | Err(MqttError::ChannelClosed) => {}
                Err(MqttError::Backpressure) => {
                    if self
                        .inner
                        .broker_safety
                        .slow_consumer_policy()
                        .should_close_on_overflow(effective_qos)
                    {
                        let laggard = entry.channel.clone();
                        drop(entry);
                        laggard.close();
                    }
                }
                Err(_) => {}
            }
        }
    }

    // ── QoS 1/2 inflight tracking ────────────────────────────────

    // ── $SYS subsystem (Stage A P6) ──────────────────────────────

    /// Broker-internal retained PUBLISH on a `$`-prefixed topic. Bypasses
    /// the D19 silent-drop guard (which exists to stop **clients** from
    /// polluting `$SYS`) and the ACL `check_publish` hook (the broker IS
    /// the source of truth for its own status topics). Stores via the
    /// configured `RetainedStore` and fans out to current literal
    /// subscribers — spec §4.7.2 wildcard restriction is enforced by the
    /// SubscriptionTree matcher, so `#` subscribers cannot snoop `$SYS`.
    pub async fn publish_sys_retained(
        &self,
        tenant: &Option<TenantId>,
        topic: Arc<str>,
        payload: Bytes,
        qos: QoS,
    ) {
        debug_assert!(
            is_dollar_topic(&topic),
            "publish_sys_retained called with non-$-prefixed topic: {topic}"
        );

        // 1. Store retained so future subscribers see it on SUBACK replay.
        self.inner
            .retained_store
            .store(tenant.as_ref(), topic.clone(), payload.clone(), qos)
            .await;

        // 2. Fan out to current literal subscribers within the same tenant.
        //    No source self-suppression (broker has no client_id), no ACL
        //    (broker is privileged for `$SYS`).
        let matching = self.inner.subscriptions.matching(tenant, &topic);
        let policy = self.inner.broker_safety.slow_consumer_policy();
        let max_inflight = self.inner.broker_safety.max_inflight_messages();
        for (sub_id, sub_qos) in matching {
            let Some(entry) = self.inner.sessions.get(&(tenant.clone(), sub_id.clone())) else {
                continue;
            };
            let effective_qos = qos.min(sub_qos);
            // U1 (v3 audit) — same cap-check + fallible allocator pattern
            // as the G7-fixed `publish_with_source_username`. Prior to this
            // a $SYS subscriber that never ACKs could panic the broker at
            // `allocate_packet_id`'s exhaustion expect.
            let packet_id = if effective_qos > QoS::AtMostOnce {
                let session = entry.channel.session();
                let over_cap = session.outbound_inflight_len() >= max_inflight;
                let id_opt = if over_cap {
                    None
                } else {
                    session.try_allocate_packet_id()
                };
                match id_opt {
                    Some(id) => {
                        session.stash_outbound_inflight(
                            id,
                            PublishPacket {
                                properties: Default::default(),
                                topic: topic.clone(),
                                payload: payload.clone(),
                                dup: false,
                                qos: effective_qos,
                                retain: false,
                                packet_id: Some(id),
                            },
                        );
                        Some(id)
                    }
                    None => {
                        if policy.should_close_on_overflow(effective_qos) {
                            let laggard = entry.channel.clone();
                            drop(entry);
                            laggard.close();
                        }
                        continue;
                    }
                }
            } else {
                None
            };
            let p = PublishPacket {
                properties: Default::default(),
                topic: topic.clone(),
                payload: payload.clone(),
                dup: false,
                qos: effective_qos,
                retain: false,
                packet_id,
            };
            match entry.channel.send_publish(p) {
                Ok(_) | Err(MqttError::ChannelClosed) => {}
                Err(MqttError::Backpressure) => {
                    if policy.should_close_on_overflow(effective_qos) {
                        let laggard = entry.channel.clone();
                        drop(entry);
                        laggard.close();
                    }
                }
                Err(_) => {}
            }
        }
    }

    /// Idempotently populate the static `$SYS/broker/*` retained values
    /// for the default (`None`) tenant. Called by `handle_server` once
    /// before the main packet loop so subscribers connecting later get
    /// the values via `replay_retained_for_subscribe` (D18).
    ///
    /// Currently emits:
    /// - `$SYS/broker/version` — crate version
    ///
    /// Live counters (uptime, clients/connected) are out of MVP scope and
    /// can be added by operators via their own periodic task on top of
    /// `publish_sys_retained`.
    pub async fn init_sys(&self) {
        if self.inner.sys_initialized.swap(true, Ordering::AcqRel) {
            return;
        }
        self.publish_sys_retained(
            &None,
            Arc::from("$SYS/broker/version"),
            Bytes::from_static(env!("CARGO_PKG_VERSION").as_bytes()),
            QoS::AtMostOnce,
        )
        .await;
    }

    /// Called when broker receives PUBACK from a subscriber.
    pub async fn ack_outbound(
        &self,
        tenant: &Option<TenantId>,
        client_id: &Arc<str>,
        packet_id: PacketId,
    ) {
        if let Some(entry) = self
            .inner
            .sessions
            .get(&(tenant.clone(), client_id.clone()))
        {
            entry.channel.session().discharge_outbound_puback(packet_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_matches_literal() {
        let segs: Vec<&str> = "a/b/c".split('/').collect();
        assert!(filter_matches("a/b/c", &segs));
        assert!(!filter_matches("a/b/d", &segs));
    }

    #[test]
    fn filter_matches_plus() {
        let segs: Vec<&str> = "a/b/c".split('/').collect();
        assert!(filter_matches("a/+/c", &segs));
        assert!(filter_matches("+/+/+", &segs));
        assert!(!filter_matches("a/+/d", &segs));
        assert!(!filter_matches("a/+", &segs));
    }

    #[test]
    fn filter_matches_hash() {
        let segs: Vec<&str> = "a/b/c".split('/').collect();
        assert!(filter_matches("a/#", &segs));
        assert!(filter_matches("#", &segs));
        assert!(filter_matches("a/b/#", &segs));
        assert!(!filter_matches("b/#", &segs));
    }

    #[test]
    fn filter_matches_partial() {
        let segs: Vec<&str> = "a/b".split('/').collect();
        assert!(!filter_matches("a/b/c", &segs));
        assert!(filter_matches("a/b", &segs));
    }

    // ── F5 / F6 / F7: multi-tenant isolation ──────────────────────

    fn ten(name: &str) -> Option<TenantId> {
        Some(Arc::from(name))
    }

    #[test]
    fn subscription_tree_isolates_tenants_on_matching() {
        // F6: `matching(t, topic)` returns subscriptions only within tenant `t`.
        // Tenant B subscribes to `#`; tenant A's publish on any topic must
        // NOT surface tenant B's subscriber.
        let tree = SubscriptionTree::new();
        let ta = ten("ta");
        let tb = ten("tb");

        tree.subscribe(
            ta.clone(),
            Arc::from("alice"),
            Arc::from("home/temp"),
            QoS::AtMostOnce,
        );
        tree.subscribe(
            tb.clone(),
            Arc::from("bob"),
            Arc::from("#"),
            QoS::AtMostOnce,
        );

        let ta_matches = tree.matching(&ta, "home/temp");
        assert_eq!(ta_matches.len(), 1);
        assert_eq!(ta_matches[0].0.as_ref(), "alice");
        assert!(
            !ta_matches.iter().any(|(c, _)| c.as_ref() == "bob"),
            "tenant B's `#` MUST NOT leak across into tenant A"
        );

        let tb_matches = tree.matching(&tb, "home/temp");
        assert_eq!(tb_matches.len(), 1);
        assert_eq!(tb_matches[0].0.as_ref(), "bob");
        assert!(
            !tb_matches.iter().any(|(c, _)| c.as_ref() == "alice"),
            "tenant A's subscribers MUST NOT surface in tenant B's lookup"
        );
    }

    #[test]
    fn subscription_tree_remove_client_is_tenant_scoped() {
        // Two tenants both have a client named "alice". Removing alice from
        // tenant A's bucket MUST leave tenant B's alice untouched.
        let tree = SubscriptionTree::new();
        let ta = ten("ta");
        let tb = ten("tb");
        let alice: Arc<str> = Arc::from("alice");

        tree.subscribe(ta.clone(), alice.clone(), Arc::from("x"), QoS::AtMostOnce);
        tree.subscribe(tb.clone(), alice.clone(), Arc::from("x"), QoS::AtMostOnce);

        tree.remove_client(&ta, &alice);

        assert!(tree.matching(&ta, "x").is_empty());
        assert_eq!(tree.matching(&tb, "x").len(), 1);
    }

    #[test]
    fn subscription_tree_none_tenant_isolated_from_named_tenants() {
        // `None` (single-tenant default) is also a distinct namespace — a
        // None-tenant publish must not reach Some("t") subscribers and vice
        // versa. Catches the "did we accidentally treat None as wildcard"
        // class of bugs.
        let tree = SubscriptionTree::new();
        let none_t: Option<TenantId> = None;
        let some_t = ten("paying-customer");

        tree.subscribe(
            none_t.clone(),
            Arc::from("free"),
            Arc::from("#"),
            QoS::AtMostOnce,
        );
        tree.subscribe(
            some_t.clone(),
            Arc::from("vip"),
            Arc::from("billing/+"),
            QoS::AtMostOnce,
        );

        let bill_in_paying = tree.matching(&some_t, "billing/invoice");
        assert_eq!(bill_in_paying.len(), 1);
        assert_eq!(bill_in_paying[0].0.as_ref(), "vip");

        // None-tenant subscriber must not see paying-tenant's billing topic.
        let bill_in_default = tree.matching(&none_t, "billing/invoice");
        assert!(
            !bill_in_default.iter().any(|(c, _)| c.as_ref() == "vip"),
            "Some(...) subscriptions must not surface under None"
        );
        // But the None-tenant `#` still covers its own namespace.
        let own = tree.matching(&none_t, "billing/invoice");
        assert!(own.iter().any(|(c, _)| c.as_ref() == "free"));
    }

    #[test]
    fn filter_matches_dollar_guard() {
        // spec §4.7.2 — wildcards in first position must not match $-prefixed topics
        let sys: Vec<&str> = "$SYS/broker/version".split('/').collect();
        assert!(!filter_matches("#", &sys));
        assert!(!filter_matches("+/broker/version", &sys));
        assert!(!filter_matches("+/#", &sys));
        // Literal $SYS prefix still matches.
        assert!(filter_matches("$SYS/broker/version", &sys));
        assert!(filter_matches("$SYS/#", &sys));
        assert!(filter_matches("$SYS/+/version", &sys));
    }

    #[test]
    fn subs_map_shrinks_after_unsubscribe_all() {
        // U4: subscribing to many DISTINCT filters then unsubscribing each
        // must leave NO residual empty buckets. Pre-fix, `unsubscribe` only
        // emptied the inner set and `subs` grew without bound.
        let tree = SubscriptionTree::new();
        let t = ten("t");
        let alice: Arc<str> = Arc::from("alice");

        for i in 0..100 {
            tree.subscribe(
                t.clone(),
                alice.clone(),
                Arc::from(format!("a/{i}").as_str()),
                QoS::AtMostOnce,
            );
        }
        assert_eq!(tree.filter_bucket_count(), 100);

        for i in 0..100 {
            tree.unsubscribe(&t, &alice, &format!("a/{i}"));
        }
        assert_eq!(
            tree.filter_bucket_count(),
            0,
            "empty (tenant, filter) buckets must be reclaimed on unsubscribe"
        );
    }

    #[test]
    fn unsubscribe_keeps_bucket_with_other_subscribers() {
        // U4 must NOT over-reclaim: a bucket with a remaining subscriber
        // stays, and the still-subscribed client keeps matching.
        let tree = SubscriptionTree::new();
        let t = ten("t");
        let alice: Arc<str> = Arc::from("alice");
        let bob: Arc<str> = Arc::from("bob");
        let filter: Arc<str> = Arc::from("shared/topic");

        tree.subscribe(t.clone(), alice.clone(), filter.clone(), QoS::AtMostOnce);
        tree.subscribe(t.clone(), bob.clone(), filter.clone(), QoS::AtMostOnce);
        assert_eq!(tree.filter_bucket_count(), 1);

        tree.unsubscribe(&t, &alice, "shared/topic");
        assert_eq!(tree.filter_bucket_count(), 1, "bucket still has bob");
        let m = tree.matching(&t, "shared/topic");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].0.as_ref(), "bob");

        tree.unsubscribe(&t, &bob, "shared/topic");
        assert_eq!(tree.filter_bucket_count(), 0, "last subscriber gone → reclaim");
    }

    #[test]
    fn remove_client_reclaims_empty_buckets_tenant_scoped() {
        // U4: disconnect (remove_client) must reclaim buckets it empties,
        // but only within the client's tenant and only when no other
        // subscriber remains.
        let tree = SubscriptionTree::new();
        let ta = ten("ta");
        let tb = ten("tb");
        let alice: Arc<str> = Arc::from("alice");
        let bob: Arc<str> = Arc::from("bob");

        // Tenant A: alice alone on a/f1, alice+bob share a/shared.
        tree.subscribe(ta.clone(), alice.clone(), Arc::from("a/f1"), QoS::AtMostOnce);
        tree.subscribe(ta.clone(), alice.clone(), Arc::from("a/shared"), QoS::AtMostOnce);
        tree.subscribe(ta.clone(), bob.clone(), Arc::from("a/shared"), QoS::AtMostOnce);
        // Tenant B: a same-named alice on her own filter — must be untouched.
        tree.subscribe(tb.clone(), alice.clone(), Arc::from("b/f1"), QoS::AtMostOnce);
        // Buckets: a/f1, a/shared (alice+bob share one bucket), b/f1 = 3.
        assert_eq!(tree.filter_bucket_count(), 3);

        tree.remove_client(&ta, &alice);

        // a/f1 emptied → reclaimed; a/shared kept (bob remains); b/f1 kept.
        assert_eq!(tree.filter_bucket_count(), 2);
        assert!(tree.matching(&ta, "a/f1").is_empty());
        let shared = tree.matching(&ta, "a/shared");
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].0.as_ref(), "bob");
        assert_eq!(tree.matching(&tb, "b/f1").len(), 1, "other tenant untouched");
    }
}
