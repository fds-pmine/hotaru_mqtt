//! Default trait impls — accept-all / allow-all / single-tenant +
//! in-memory retained store / session store.
//!
//! These are starter implementations selected by `Broker::new()`. The
//! `accept-all` / `allow-all` ones are production-unsafe and MUST be
//! replaced; `DefaultRetainedStore` is a real in-memory store, fine for
//! single-node deployments where retained durability across broker
//! restarts isn't required.

use std::net::SocketAddr;
use std::sync::Arc;

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
    tenants: DashMap<Option<TenantId>, Arc<DashMap<Arc<str>, RetainedRecord>>>,
}

impl DefaultRetainedStore {
    pub fn new() -> Self {
        Self {
            tenants: DashMap::new(),
        }
    }

    fn tenant_map(&self, tenant: Option<&TenantId>) -> Arc<DashMap<Arc<str>, RetainedRecord>> {
        self.tenants
            .entry(tenant.cloned())
            .or_insert_with(|| Arc::new(DashMap::new()))
            .clone()
    }

    fn try_tenant_map(
        &self,
        tenant: Option<&TenantId>,
    ) -> Option<Arc<DashMap<Arc<str>, RetainedRecord>>> {
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
        let inner = self.tenant_map(tenant);
        inner.insert(topic, RetainedRecord { payload, qos });
    }

    async fn remove(&self, tenant: Option<&TenantId>, topic: &str) {
        let Some(inner) = self.try_tenant_map(tenant) else {
            return;
        };
        // Borrow-walk only THIS tenant's inner map to match the topic
        // against the owned `Arc<str>` key — at most O(per-tenant N),
        // not O(global N).
        let mut victim: Option<Arc<str>> = None;
        for e in inner.iter() {
            if e.key().as_ref() == topic {
                victim = Some(e.key().clone());
                break;
            }
        }
        if let Some(k) = victim {
            inner.remove(&k);
        }
    }

    async fn matching(&self, tenant: Option<&TenantId>, filter: &str) -> Vec<RetainedEntry> {
        let Some(inner) = self.try_tenant_map(tenant) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for e in inner.iter() {
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
        self.try_tenant_map(tenant).map(|m| m.len()).unwrap_or(0)
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
