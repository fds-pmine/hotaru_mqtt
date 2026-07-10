//! User-facing request / response types and shared data types.
//!
//! `MqttRequest` / `MqttResponse` are the protocol's `RequestContext::Request`
//! / `Response`. All three outpoint operations (`Publish` / `Subscribe` /
//! `Unsubscribe`) go through this enum via `run!(...)`.

use alloc::sync::Arc;
use alloc::vec::Vec;

use bytes::Bytes;

/// MQTT Quality of Service level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum QoS {
    AtMostOnce = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
}

impl QoS {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::AtMostOnce),
            1 => Some(Self::AtLeastOnce),
            2 => Some(Self::ExactlyOnce),
            _ => None,
        }
    }
}

/// Wire-level packet identifier (16-bit per MQTT spec).
pub type PacketId = u16;

// ----------------------------------------------------------------------------
// Outpoint request enum
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum MqttRequest {
    Publish(PublishRequest),
    Subscribe(Vec<TopicFilter>),
    Unsubscribe(Vec<Arc<str>>),
}

#[derive(Debug, Clone)]
pub enum MqttResponse {
    Published(PublishAck),
    Subscribed(Vec<SubackCode>),
    Unsubscribed,
}

// ----------------------------------------------------------------------------
// User-facing PUBLISH constructs
// ----------------------------------------------------------------------------

/// What the user constructs to publish.
#[derive(Debug, Clone)]
pub struct PublishRequest {
    pub topic: Arc<str>,
    pub payload: Bytes,
    pub qos: QoS,
    pub retain: bool,
}

impl Default for PublishRequest {
    fn default() -> Self {
        Self {
            topic: Arc::from(""),
            payload: Bytes::new(),
            qos: QoS::AtMostOnce,
            retain: false,
        }
    }
}

/// What the user receives from an inbound PUBLISH (server or client side).
#[derive(Debug, Clone)]
pub struct IncomingPublish {
    pub topic: Arc<str>,
    pub payload: Bytes,
    pub qos: QoS,
    pub retain: bool,
    pub dup: bool,
    pub packet_id: Option<PacketId>,
    /// MQTT 5.0 properties carried by the wire PUBLISH (response topic,
    /// correlation data, user properties, …). Empty for v3.1.1 peers.
    /// Rides the inbound stash so QoS 2 release and endpoint dispatch
    /// both see what the publisher sent.
    pub properties: crate::properties::Properties,
}

impl IncomingPublish {
    pub fn topic(&self) -> &str {
        self.topic.as_ref()
    }
    pub fn payload(&self) -> &[u8] {
        self.payload.as_ref()
    }
}

/// Result returned by `Protocol::send` for a PUBLISH operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishAck {
    /// QoS 0: sent on the wire, no acknowledgement expected.
    Sent,
    /// QoS 1: PUBACK received from peer.
    Acknowledged(PacketId),
    /// QoS 2: full PUBREC + PUBREL + PUBCOMP handshake completed.
    Completed(PacketId),
}

// ----------------------------------------------------------------------------
// SUBSCRIBE / UNSUBSCRIBE constructs
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TopicFilter {
    pub filter: Arc<str>,
    pub qos: QoS,
}

impl TopicFilter {
    pub fn new(filter: impl Into<Arc<str>>, qos: QoS) -> Self {
        Self {
            filter: filter.into(),
            qos,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubackCode {
    Granted(QoS),
    Failure,
}

impl SubackCode {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Granted(q) => q.as_u8(),
            Self::Failure => 0x80,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Granted(QoS::AtMostOnce)),
            1 => Some(Self::Granted(QoS::AtLeastOnce)),
            2 => Some(Self::Granted(QoS::ExactlyOnce)),
            0x80 => Some(Self::Failure),
            _ => None,
        }
    }
}

// ----------------------------------------------------------------------------
// CONNECT-time constructs
// ----------------------------------------------------------------------------

/// CONNECT-time authentication payload.
///
/// `Debug` is hand-written to redact the password bytes — SAFETY_PROOF v4
/// flagged that a derived `Debug` would let user code accidentally leak
/// the plaintext via `tracing::debug!("creds = {:?}", creds)` or any
/// other `{:?}`-style logging path. The server-side analogue
/// (`PasswordHash::Debug`) was already redacted (audit G3).
#[derive(Clone)]
pub struct Credentials {
    pub username: Arc<str>,
    pub password: Bytes,
}

impl core::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field(
                "password",
                &format_args!("<redacted: {} bytes>", self.password.len()),
            )
            .finish()
    }
}

impl Credentials {
    pub fn new(username: impl Into<Arc<str>>, password: impl Into<Bytes>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

#[cfg(test)]
mod credentials_debug_tests {
    use super::*;

    #[test]
    fn credentials_debug_redacts_password_bytes() {
        // SAFETY_PROOF v4 regression: the literal password bytes must
        // not appear in the Debug rendering, only the byte length.
        let c = Credentials::new("alice", Bytes::from_static(b"super-secret-pw"));
        let rendered = format!("{:?}", c);
        assert!(rendered.contains("alice"), "username should be visible");
        assert!(
            !rendered.contains("super-secret-pw"),
            "password bytes MUST NOT appear in Debug; got {rendered:?}"
        );
        assert!(
            rendered.contains("<redacted: 15 bytes>"),
            "Debug should show byte length only; got {rendered:?}"
        );
    }
}

/// Last Will and Testament — published by broker when this client crashes.
#[derive(Debug, Clone)]
pub struct WillMessage {
    pub topic: Arc<str>,
    pub payload: Bytes,
    pub qos: QoS,
    pub retain: bool,
}

impl WillMessage {
    pub fn new(
        topic: impl Into<Arc<str>>,
        payload: impl Into<Bytes>,
        qos: QoS,
        retain: bool,
    ) -> Self {
        Self {
            topic: topic.into(),
            payload: payload.into(),
            qos,
            retain,
        }
    }
}
