//! `hotaru_mqtt_broker` — MQTT 3.1.1 broker built on `hotaru_mqtt`.
//!
//! Provides the server-side runtime for hosting MQTT clients: session
//! management, subscription routing, fanout, retained messages,
//! authentication, ACL, and multi-tenant primitives.
//!
//! For client / sensor use cases that only PUBLISH or SUBSCRIBE to an
//! external broker, depend on `hotaru_mqtt` alone and skip this crate.
//!
//! Design memos (in repo root):
//! - `MQTT_AOI_DESIGN.md` — outpoint shape / inbound dispatch / topic matching
//! - `MQTT_PRODUCTION_PLAN.md` — Stage A P0-P8 path to mosquitto-grade
//! - `MQTT_SPEC_GAPS.md` — severity-ranked spec compliance audit
//!
//! # Module map
//!
//! - [`broker`] — `Broker`, `SubscriberEntry`, `RetainedMessage`
//! - [`protocol`] — `MqttServerProtocol`, `MQTT_SERVER`
//! - [`traits`] — `Authenticator`, `AclChecker`, `TenantResolver`,
//!   `RetainedStore`, `SessionStore` + supporting types
//! - [`safety`] — `BrokerSafety` resource limits
//! - [`statics`] — runtime statics keys
//! - [`defaults`] — default trait impls (accept-all / allow-all / single-tenant)

// SAFETY_PROOF M1 enforcement — any future PR introducing `unsafe` must
// explicitly justify it by lifting this lint (and updating the proof).
#![forbid(unsafe_code)]

pub mod auth;
pub mod broker;
pub mod defaults;
pub mod protocol;
pub mod safety;
pub mod statics;
pub mod traits;

// ── Re-exports for user-facing API ───────────────────────────────

pub use auth::{
    DefaultPasswordVerifier, JsonAclChecker, JsonAuthenticator, PasswordHash, PasswordVerifier,
    verify_password,
};
pub use broker::{Broker, RetainedMessage, ShutdownReport, SubscriberEntry};
pub use defaults::{
    AcceptAllAuthenticator, AllowAllAclChecker, DefaultRetainedStore, DefaultSessionStore,
    SingleTenantResolver,
};
pub use protocol::{DefaultMqttTransport, MQTT_SERVER, MqttServerProtocol};
#[cfg(feature = "tls")]
pub use protocol::{MQTTS_SERVER, MqttTlsServerProtocol};
pub use safety::{BrokerSafety, SlowConsumerPolicy};
pub use statics::BROKER_STATICS_KEY;
pub use traits::{
    AclChecker, AclDecision, AuthResult, Authenticator, RetainedEntry, RetainedStore,
    SessionStore, TenantId, TenantResolver,
};
