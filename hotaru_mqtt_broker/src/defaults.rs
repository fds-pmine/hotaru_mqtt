//! Default trait impls — accept-all / allow-all / single-tenant +
//! in-memory retained store / session store.
//!
//! These are starter implementations selected by `Broker::new()`. The
//! `accept-all` / `allow-all` ones are production-unsafe and MUST be
//! replaced; `DefaultRetainedStore` is a real in-memory store, fine for
//! single-node deployments where retained durability across broker
//! restarts isn't required.

use core::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;

use hotaru_mqtt::packet::ConnectPacket;
use hotaru_mqtt::request::QoS;
use hotaru_mqtt::session::MqttSession;
use hotaru_mqtt::topic;

use crate::broker::filter_matches;
use crate::traits::{
    AclChecker, AclDecision, AuthResult, Authenticator, RetainedEntry, RetainedStore, SessionStore,
    TenantId, TenantResolver,
};

// ============================================================================
// AcceptAllAuthenticator
// ============================================================================

/// Authenticator that accepts every CONNECT. Useful for tests and dev
/// scaffolds. **DO NOT** use in production.
pub struct AcceptAllAuthenticator;

#[async_trait]
impl Authenticator for AcceptAllAuthenticator {
    async fn authenticate(
        &self,
        _tenant: Option<&TenantId>,
        _connect: &ConnectPacket,
        _remote_addr: Option<SocketAddr>,
    ) -> AuthResult {
        AuthResult::accept()
    }
}

// ============================================================================
// DenyAllAuthenticator
// ============================================================================

/// Authenticator that rejects every CONNECT with `NotAuthorized`. This is the
/// secure-by-default authenticator wired by [`crate::broker::Broker::new`]
/// (attack-surface finding AS2): an operator who forgets to install a real
/// authenticator gets a broker that refuses all clients rather than one that
/// silently accepts every anonymous connection. Swap in a real
/// [`Authenticator`] via `Broker::with_authenticator(...)`, or opt into the
/// open dev defaults explicitly with `Broker::insecure()`.
pub struct DenyAllAuthenticator;

#[async_trait]
impl Authenticator for DenyAllAuthenticator {
    async fn authenticate(
        &self,
        _tenant: Option<&TenantId>,
        _connect: &ConnectPacket,
        _remote_addr: Option<SocketAddr>,
    ) -> AuthResult {
        AuthResult::reject(hotaru_mqtt::packet::ConnackReturnCode::NotAuthorized)
    }
}

// ============================================================================
// AllowAllAclChecker
// ============================================================================

/// AclChecker that allows every subscribe and publish. Useful for tests and
/// dev scaffolds. **DO NOT** use in production.
pub struct AllowAllAclChecker;

#[async_trait]
impl AclChecker for AllowAllAclChecker {
    async fn check_subscribe(
        &self,
        _tenant: Option<&TenantId>,
        _client_id: &Arc<str>,
        _username: Option<&Arc<str>>,
        _filter: &str,
    ) -> AclDecision {
        AclDecision::Allow
    }

    async fn check_publish(
        &self,
        _tenant: Option<&TenantId>,
        _client_id: &Arc<str>,
        _username: Option<&Arc<str>>,
        _topic: &str,
    ) -> AclDecision {
        AclDecision::Allow
    }
}

// ============================================================================
// SingleTenantResolver
// ============================================================================

/// TenantResolver that always returns `None`, i.e. every connection lives in
/// the default unnamed tenant. This is the right default for single-tenant
/// deployments — broker state containers key by `Option<TenantId>` and a
/// `None` key collapses to one global namespace.
pub struct SingleTenantResolver;

#[async_trait]
impl TenantResolver for SingleTenantResolver {
    async fn resolve(
        &self,
        _connect: &ConnectPacket,
        _remote_addr: Option<SocketAddr>,
    ) -> Option<TenantId> {
        None
    }
}

// ============================================================================
// DefaultRetainedStore — in-memory retained-message store
// ============================================================================

/// Per-entry storage: payload + QoS. Topic is the map key so we don't
/// duplicate it inside.
#[derive(Clone)]
struct RetainedRecord {
    payload: Bytes,
    qos: QoS,
}

/// One tenant's retained state: the topic→record map plus a running total
/// of retained payload bytes. Both are `Arc` so a cloned `TenantBucket`
/// (returned by `tenant_map`) shares the same map and counter.
#[derive(Clone)]
struct TenantBucket {
    entries: Arc<DashMap<Arc<str>, RetainedRecord>>,
    /// Running sum of `payload.len()` across `entries`. Maintained on every
    /// `store`/`remove` so `bytes()` is O(1) — backs the
    /// `max_retained_bytes_per_tenant` cap (SAFETY_PROOF v5 T2(b) / #74(a)).
    bytes: Arc<AtomicUsize>,
}

impl TenantBucket {
    fn new() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            bytes: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// In-memory `RetainedStore`. Two-level keying (SAFETY_PROOF v3 U6):
/// outer map keyed by `Option<TenantId>`, inner map keyed by topic.
/// `matching` / `remove` / `count` walk ONLY the requesting tenant's
/// inner map, so a noisy tenant cannot degrade other tenants' SUBSCRIBE
/// retained-replay cost. Prior single-level `DashMap<(tenant, topic),
/// _>` was O(global N) per call.
///
/// Persistence across broker restarts is out of scope — operators who need
/// it implement [`RetainedStore`] over their own storage layer.
pub struct DefaultRetainedStore {
    tenants: DashMap<Option<TenantId>, TenantBucket>,
}

impl DefaultRetainedStore {
    pub fn new() -> Self {
        Self {
            tenants: DashMap::new(),
        }
    }

    fn tenant_map(&self, tenant: Option<&TenantId>) -> TenantBucket {
        self.tenants
            .entry(tenant.cloned())
            .or_insert_with(TenantBucket::new)
            .clone()
    }

    fn try_tenant_map(&self, tenant: Option<&TenantId>) -> Option<TenantBucket> {
        self.tenants
            .get(&tenant.cloned())
            .map(|r| r.value().clone())
    }
}

impl Default for DefaultRetainedStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RetainedStore for DefaultRetainedStore {
    async fn store(&self, tenant: Option<&TenantId>, topic: Arc<str>, payload: Bytes, qos: QoS) {
        let bucket = self.tenant_map(tenant);
        let new_len = payload.len();
        // `insert` returns the prior record (if this topic was already
        // retained). Adjust the byte counter by the signed delta so an
        // overwrite is accounted exactly, not double-counted.
        let prev = bucket.entries.insert(topic, RetainedRecord { payload, qos });
        let old_len = prev.map(|r| r.payload.len()).unwrap_or(0);
        if new_len >= old_len {
            bucket.bytes.fetch_add(new_len - old_len, Ordering::Relaxed);
        } else {
            bucket.bytes.fetch_sub(old_len - new_len, Ordering::Relaxed);
        }
    }

    async fn remove(&self, tenant: Option<&TenantId>, topic: &str) {
        let Some(bucket) = self.try_tenant_map(tenant) else {
            return;
        };
        // Borrow-walk only THIS tenant's inner map to match the topic
        // against the owned `Arc<str>` key — at most O(per-tenant N),
        // not O(global N).
        let mut victim: Option<Arc<str>> = None;
        for e in bucket.entries.iter() {
            if e.key().as_ref() == topic {
                victim = Some(e.key().clone());
                break;
            }
        }
        if let Some(k) = victim
            && let Some((_, rec)) = bucket.entries.remove(&k)
        {
            bucket.bytes.fetch_sub(rec.payload.len(), Ordering::Relaxed);
        }
    }

    async fn matching(&self, tenant: Option<&TenantId>, filter: &str) -> Vec<RetainedEntry> {
        let Some(bucket) = self.try_tenant_map(tenant) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for e in bucket.entries.iter() {
            // spec §4.7.2 is enforced by `filter_matches` — wildcards in the
            // first position MUST NOT match `$`-prefixed topics, so a
            // subscribe `#` cannot harvest retained `$SYS` entries.
            let topic = e.key().as_ref();
            let segs: Vec<&str> = topic.split('/').collect();
            if filter_matches(filter, &segs) {
                out.push(RetainedEntry {
                    topic: e.key().clone(),
                    payload: e.value().payload.clone(),
                    qos: e.value().qos,
                });
            }
        }
        out
    }

    async fn count(&self, tenant: Option<&TenantId>) -> usize {
        self.try_tenant_map(tenant)
            .map(|b| b.entries.len())
            .unwrap_or(0)
    }

    async fn bytes(&self, tenant: Option<&TenantId>) -> usize {
        self.try_tenant_map(tenant)
            .map(|b| b.bytes.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

// ============================================================================
// DefaultSessionStore — in-memory persistent-session store (Stage A P7)
// ============================================================================

/// In-memory [`SessionStore`] backing `clean_session=false` reconnect
/// (spec §3.1.2.4 + §4.1). Keys on `(tenant, client_id)` so two tenants
/// reusing the same `client_id` cannot collide (mirrors broker session
/// map keying — audit F5).
///
/// Survives across reconnects within a single broker process; does NOT
/// survive broker restart. Disk-backed implementations (SQLite, Redis,
/// etc.) plug in via the [`SessionStore`] trait — callers supply their
/// own and wire it through [`crate::Broker::with_session_store`].
pub struct DefaultSessionStore {
    store: DashMap<(Option<TenantId>, Arc<str>), Arc<MqttSession>>,
}

impl DefaultSessionStore {
    pub fn new() -> Self {
        Self {
            store: DashMap::new(),
        }
    }
}

impl Default for DefaultSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionStore for DefaultSessionStore {
    async fn load(&self, tenant: Option<&TenantId>, client_id: &str) -> Option<Arc<MqttSession>> {
        let key = (tenant.cloned(), Arc::<str>::from(client_id));
        self.store.remove(&key).map(|(_, session)| session)
    }

    async fn save(
        &self,
        tenant: Option<&TenantId>,
        client_id: Arc<str>,
        session: Arc<MqttSession>,
    ) {
        self.store.insert((tenant.cloned(), client_id), session);
    }

    async fn destroy(&self, tenant: Option<&TenantId>, client_id: &str) {
        let key = (tenant.cloned(), Arc::<str>::from(client_id));
        if let Some((_, session)) = self.store.remove(&key) {
            // Full teardown — anything still pending was dropped by the
            // client's explicit `clean_session=true` reconnect.
            session.wipe();
        }
    }

    async fn count(&self, tenant: Option<&TenantId>) -> usize {
        // SAFETY_PROOF v5 T2(d): used by
        // `BrokerSafety::max_persistent_sessions_per_tenant` cap-check
        // at `unregister_session(clean_session=false)`. O(N) over the
        // global map but only runs on the disconnect path — a low-
        // frequency lifecycle event, not the hot path.
        let want = tenant.cloned();
        self.store.iter().filter(|e| e.key().0 == want).count()
    }
}

/// Whether `topic` would be silent-dropped under D19 (`$`-prefixed
/// `retain=1` PUBLISH). Exposed so the broker's publish path can call it
/// from one place.
pub fn is_dollar_topic(topic: &str) -> bool {
    topic::is_dollar_prefixed_first_segment(topic)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ten(s: &str) -> Option<TenantId> {
        Some(Arc::from(s))
    }

    #[tokio::test]
    async fn store_and_match_round_trip() {
        let s = DefaultRetainedStore::new();
        s.store(
            None,
            Arc::from("home/temp"),
            Bytes::from_static(b"21C"),
            QoS::AtMostOnce,
        )
        .await;

        let hits = s.matching(None, "home/temp").await;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].topic.as_ref(), "home/temp");
        assert_eq!(&hits[0].payload[..], b"21C");
    }

    #[tokio::test]
    async fn store_overwrites_prior_entry_for_same_topic() {
        let s = DefaultRetainedStore::new();
        s.store(
            None,
            Arc::from("x"),
            Bytes::from_static(b"1"),
            QoS::AtMostOnce,
        )
        .await;
        s.store(
            None,
            Arc::from("x"),
            Bytes::from_static(b"2"),
            QoS::AtMostOnce,
        )
        .await;
        let hits = s.matching(None, "x").await;
        assert_eq!(hits.len(), 1);
        assert_eq!(&hits[0].payload[..], b"2");
    }

    #[tokio::test]
    async fn remove_clears_entry() {
        let s = DefaultRetainedStore::new();
        s.store(
            None,
            Arc::from("x"),
            Bytes::from_static(b"v"),
            QoS::AtMostOnce,
        )
        .await;
        s.remove(None, "x").await;
        assert!(s.matching(None, "x").await.is_empty());
    }

    #[tokio::test]
    async fn wildcard_filter_does_not_match_dollar_prefix() {
        // §4.7.2: even if a $SYS retain somehow lands in the store, a `#`
        // subscriber MUST NOT see it. The matcher (shared with broker
        // subscriptions) enforces this.
        let s = DefaultRetainedStore::new();
        s.store(
            None,
            Arc::from("$SYS/broker/version"),
            Bytes::from_static(b"1.0"),
            QoS::AtMostOnce,
        )
        .await;
        let via_hash = s.matching(None, "#").await;
        assert!(via_hash.is_empty(), "`#` MUST NOT harvest $SYS topics");
        // Explicit literal still works.
        let via_literal = s.matching(None, "$SYS/broker/version").await;
        assert_eq!(via_literal.len(), 1);
    }

    #[tokio::test]
    async fn tenants_are_isolated() {
        let s = DefaultRetainedStore::new();
        let ta = ten("ta");
        let tb = ten("tb");
        s.store(
            ta.as_ref(),
            Arc::from("x"),
            Bytes::from_static(b"A"),
            QoS::AtMostOnce,
        )
        .await;
        s.store(
            tb.as_ref(),
            Arc::from("x"),
            Bytes::from_static(b"B"),
            QoS::AtMostOnce,
        )
        .await;

        let a = s.matching(ta.as_ref(), "x").await;
        assert_eq!(a.len(), 1);
        assert_eq!(&a[0].payload[..], b"A");
        let b = s.matching(tb.as_ref(), "x").await;
        assert_eq!(b.len(), 1);
        assert_eq!(&b[0].payload[..], b"B");
        let none = s.matching(None, "x").await;
        assert!(none.is_empty());
    }

    // SAFETY_PROOF v5 T2(b) / #74(a) — per-tenant retained byte accounting
    // backs `BrokerSafety::max_retained_bytes_per_tenant`.

    #[tokio::test]
    async fn bytes_accumulates_across_topics() {
        let s = DefaultRetainedStore::new();
        assert_eq!(s.bytes(None).await, 0);
        s.store(None, Arc::from("a"), Bytes::from_static(b"hello"), QoS::AtMostOnce)
            .await;
        s.store(None, Arc::from("b"), Bytes::from_static(b"hi"), QoS::AtMostOnce)
            .await;
        assert_eq!(s.bytes(None).await, 7); // 5 + 2
    }

    #[tokio::test]
    async fn bytes_tracks_overwrite_delta_not_sum() {
        let s = DefaultRetainedStore::new();
        s.store(None, Arc::from("x"), Bytes::from_static(b"1234"), QoS::AtMostOnce)
            .await;
        assert_eq!(s.bytes(None).await, 4);
        // Overwrite same topic with a shorter payload → counter shrinks, not
        // double-counts.
        s.store(None, Arc::from("x"), Bytes::from_static(b"9"), QoS::AtMostOnce)
            .await;
        assert_eq!(s.bytes(None).await, 1);
    }

    #[tokio::test]
    async fn bytes_decrements_on_remove() {
        let s = DefaultRetainedStore::new();
        s.store(None, Arc::from("x"), Bytes::from_static(b"abcd"), QoS::AtMostOnce)
            .await;
        s.store(None, Arc::from("y"), Bytes::from_static(b"ef"), QoS::AtMostOnce)
            .await;
        assert_eq!(s.bytes(None).await, 6);
        s.remove(None, "x").await;
        assert_eq!(s.bytes(None).await, 2);
        // Removing the empty-payload way (clear) zeroes it out.
        s.remove(None, "y").await;
        assert_eq!(s.bytes(None).await, 0);
    }

    #[tokio::test]
    async fn bytes_are_tenant_scoped() {
        let s = DefaultRetainedStore::new();
        let ta = ten("ta");
        let tb = ten("tb");
        s.store(ta.as_ref(), Arc::from("x"), Bytes::from_static(b"AAAA"), QoS::AtMostOnce)
            .await;
        s.store(tb.as_ref(), Arc::from("x"), Bytes::from_static(b"B"), QoS::AtMostOnce)
            .await;
        assert_eq!(s.bytes(ta.as_ref()).await, 4);
        assert_eq!(s.bytes(tb.as_ref()).await, 1);
        assert_eq!(s.bytes(None).await, 0);
    }

    #[test]
    fn dollar_topic_detection_matches_topic_helper() {
        assert!(is_dollar_topic("$SYS/broker/version"));
        assert!(is_dollar_topic("$SYS"));
        assert!(!is_dollar_topic("home/temp"));
        assert!(!is_dollar_topic("nodollar"));
    }

    // SAFETY_PROOF v5 T2(d) — DefaultSessionStore::count powers the
    // persistent-sessions-per-tenant cap. Must be tenant-scoped.

    #[tokio::test]
    async fn session_store_count_returns_tenant_scoped_size() {
        let s = DefaultSessionStore::new();
        let session = MqttSession::new();

        // Stash three persistent sessions: two for tenant A, one for tenant B,
        // and one in the default (None) tenant.
        s.save(ten("ta").as_ref(), Arc::from("alice"), session.clone()).await;
        s.save(ten("ta").as_ref(), Arc::from("bob"), session.clone()).await;
        s.save(ten("tb").as_ref(), Arc::from("carol"), session.clone()).await;
        s.save(None, Arc::from("dave"), session.clone()).await;

        assert_eq!(s.count(ten("ta").as_ref()).await, 2);
        assert_eq!(s.count(ten("tb").as_ref()).await, 1);
        assert_eq!(s.count(None).await, 1);
        // Unknown tenant → zero, no allocation.
        assert_eq!(s.count(ten("nope").as_ref()).await, 0);
    }

    #[tokio::test]
    async fn session_store_count_drops_to_zero_after_destroy() {
        let s = DefaultSessionStore::new();
        let session = MqttSession::new();
        s.save(ten("ta").as_ref(), Arc::from("alice"), session).await;
        assert_eq!(s.count(ten("ta").as_ref()).await, 1);
        s.destroy(ten("ta").as_ref(), "alice").await;
        assert_eq!(s.count(ten("ta").as_ref()).await, 0);
    }
}
