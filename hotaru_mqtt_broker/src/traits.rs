//! Broker-side abstractions.
//!
//! These traits define the policy hooks the broker calls on every CONNECT,
//! every SUBSCRIBE, every PUBLISH, and every session lifecycle event. Most
//! production deployments will swap the default impls for ones backed by a
//! real password DB, ACL file, tenant directory, or persistence layer.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use hotaru_core::Value;
use hotaru_mqtt::error::MqttError;
use hotaru_mqtt::packet::{ConnackReturnCode, ConnectPacket};
use hotaru_mqtt::request::{IncomingPublish, QoS, SubackCode};
use hotaru_mqtt::session::MqttSession;

// ============================================================================
// Type aliases
// ============================================================================

/// Tenant identifier used to scope every broker-internal state container.
///
/// `None` everywhere in single-tenant mode (default). Multi-tenant deployments
/// supply a `TenantResolver` that maps each incoming connection to a tenant.
pub type TenantId = Arc<str>;

// ============================================================================
// Auth + ACL
// ============================================================================

/// Result of an `Authenticator::authenticate` call.
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

/// ACL verdict produced for one subscribe or publish decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    Allow,
    Deny,
}

/// CONNECT-time authentication hook. Called once per connection after the
/// `TenantResolver` (if any) has determined which tenant the client belongs
/// to. `tenant=None` in single-tenant deployments.
#[async_trait]
pub trait Authenticator: Send + Sync + 'static {
    async fn authenticate(
        &self,
        tenant: Option<&TenantId>,
        connect: &ConnectPacket,
        remote_addr: Option<SocketAddr>,
    ) -> AuthResult;
}

/// Per-action authorization hook for SUBSCRIBE and PUBLISH operations.
#[async_trait]
pub trait AclChecker: Send + Sync + 'static {
    async fn check_subscribe(
        &self,
        tenant: Option<&TenantId>,
        client_id: &Arc<str>,
        username: Option<&Arc<str>>,
        filter: &str,
    ) -> AclDecision;

    async fn check_publish(
        &self,
        tenant: Option<&TenantId>,
        client_id: &Arc<str>,
        username: Option<&Arc<str>>,
        topic: &str,
    ) -> AclDecision;
}

// ============================================================================
// Tenant resolution
// ============================================================================

/// Resolves an incoming connection to a tenant identity.
///
/// Called at the start of CONNECT handling, before authentication. The
/// returned `TenantId` (if any) is stored on the session and threaded through
/// every subsequent broker call: auth, ACL, fanout, retained, session store.
///
/// Default deployments use [`crate::defaults::SingleTenantResolver`] which
/// always returns `None`.
#[async_trait]
pub trait TenantResolver: Send + Sync + 'static {
    async fn resolve(
        &self,
        connect: &ConnectPacket,
        remote_addr: Option<SocketAddr>,
    ) -> Option<TenantId>;
}

// ============================================================================
// Retained messages
// ============================================================================

/// One retained message entry returned by [`RetainedStore::matching`].
#[derive(Debug, Clone)]
pub struct RetainedEntry {
    pub topic: Arc<str>,
    pub payload: Bytes,
    pub qos: QoS,
}

/// Storage for retained PUBLISH messages.
///
/// Per MQTT 3.1.1 §3.3.1.3: a `retain=1` publish replaces the broker's stored
/// message for that topic. An empty-payload `retain=1` deletes the stored
/// entry. On SUBSCRIBE, the broker queries `matching(tenant, filter)` and
/// replays the results to the new subscriber.
///
/// Implementations MUST respect spec §4.7.2 — wildcard filters in the first
/// position MUST NOT match `$`-prefixed topics. The
/// [`hotaru_mqtt::topic::is_dollar_prefixed_first_segment`] helper is the
/// canonical guard.
#[async_trait]
pub trait RetainedStore: Send + Sync + 'static {
    /// Insert or replace the retained message for `topic`.
    async fn store(&self, tenant: Option<&TenantId>, topic: Arc<str>, payload: Bytes, qos: QoS);

    /// Delete the retained message for `topic` (retain=1 + empty payload).
    async fn remove(&self, tenant: Option<&TenantId>, topic: &str);

    /// Return all retained messages matching `filter`. Used at SUBSCRIBE
    /// time to replay state to a new subscriber.
    async fn matching(&self, tenant: Option<&TenantId>, filter: &str) -> Vec<RetainedEntry>;

    /// Total retained-message count for the tenant. Powers
    /// `$SYS/broker/retained messages/count`.
    async fn count(&self, tenant: Option<&TenantId>) -> usize;

    /// Total retained-message *payload bytes* for the tenant. Backs the
    /// `BrokerSafety::max_retained_bytes_per_tenant` cap (SAFETY_PROOF v5
    /// T2(b) / #74(a)). Default returns 0 so stores that don't track byte
    /// usage silently waive the cap — operators who need byte-budget DoS
    /// hardening MUST override this on their custom store, or rely on
    /// [`crate::DefaultRetainedStore`] which tracks it natively. Mirrors the
    /// silent-waive contract of [`SessionStore::count`].
    async fn bytes(&self, _tenant: Option<&TenantId>) -> usize {
        0
    }

    /// Bulk export — akari Value channel. Default impl returns empty Dict;
    /// in-memory / disk-backed stores may override to serialize the full
    /// retained-message set for backup or migration.
    async fn snapshot(&self, _tenant: Option<&TenantId>) -> Value {
        Value::Dict(std::collections::HashMap::new())
    }

    /// Bulk import — inverse of [`snapshot`]. Default impl noop.
    async fn restore(&self, _tenant: Option<&TenantId>, _snapshot: Value) -> Result<(), MqttError> {
        Ok(())
    }
}

// ============================================================================
// Session storage
// ============================================================================

/// Persistence layer for `MqttSession`. Enables `clean_session=false`
/// reconnect semantics across broker restarts and tenant migrations.
///
/// In-memory default keeps sessions in a `DashMap`. Disk-backed impls
/// (SQLite / Redis) are out-of-scope for this crate — users supply their own
/// by implementing this trait.
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    async fn load(&self, tenant: Option<&TenantId>, client_id: &str) -> Option<Arc<MqttSession>>;

    async fn save(&self, tenant: Option<&TenantId>, client_id: Arc<str>, session: Arc<MqttSession>);

    async fn destroy(&self, tenant: Option<&TenantId>, client_id: &str);

    /// Number of currently-stored persistent sessions for `tenant`.
    /// Powers the `BrokerSafety::max_persistent_sessions_per_tenant` cap
    /// (SAFETY_PROOF v5 T2(d)). Default returns 0 so impls that don't
    /// track this silently waive the cap — operators who need DoS
    /// hardening MUST override this on their custom store, or rely on
    /// [`crate::DefaultSessionStore`] which implements it natively.
    async fn count(&self, _tenant: Option<&TenantId>) -> usize {
        0
    }

    async fn snapshot(&self, _tenant: Option<&TenantId>) -> Value {
        Value::Dict(std::collections::HashMap::new())
    }

    async fn restore(&self, _tenant: Option<&TenantId>, _snapshot: Value) -> Result<(), MqttError> {
        Ok(())
    }
}

// ============================================================================
// Inbound publish helper exposed to downstream — convenience re-export
// ============================================================================

/// Re-exported for downstream broker impls that need to construct
/// [`IncomingPublish`] from wire packets.
pub use hotaru_mqtt::packet::incoming_from_packet;

/// Type used by ACL middleware and inbound dispatch when surfacing the
/// raw incoming publish to user code. Re-exported for convenience.
pub type IncomingPublishView = IncomingPublish;

/// SUBACK code surfaced from `Broker::subscribe`. Re-exported.
pub type Suback = SubackCode;
