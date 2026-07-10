//! MQTT error type hierarchy.
//!
//! `MqttError` is the single error type produced by every MQTT operation.
//! Sub-enums (`TimeoutKind`, `Violation`, `CodecError`) provide structured
//! detail without flattening into the top-level.
//!
//! All variants are non-recoverable: `ProtocolError::can_continue` returns
//! `false` for all of them via the `DefaultProtocolError` blanket impl.
//! MQTT-level error recovery means "reconnect", which is a user-level
//! concern, not a framework retry.

use alloc::{boxed::Box, string::String};
use core::fmt;

use hotaru_core::protocol::DefaultProtocolError;

use crate::packet::ConnackReturnCode;

#[derive(Debug)]
pub enum MqttError {
    /// A wire error from the underlying transport, kept abstract so the codec
    /// is not pinned to one backend: it holds tokio's `std::io::Error`,
    /// embassy's `EmbeddedIoError`, or any other `HotaruRead`/`HotaruWrite`
    /// error (the framework bounds that associated type to
    /// `core::error::Error + Send + Sync + 'static`). Boxed via `alloc`, so it
    /// stays available under `no_std`.
    Io(Box<dyn core::error::Error + Send + Sync>),
    ChannelClosed,
    AckTimeout,
    Timeout(TimeoutKind),
    Configuration(String),
    NotConnected(String),
    Protocol(Violation),
    Codec(CodecError),
    /// Bounded channel rejected a write because the queue was full. Producers
    /// experiencing this must apply a slow-consumer policy (see
    /// `hotaru_mqtt_broker::SlowConsumerPolicy`); P1.B introduces the error,
    /// P3 wires the enforcement.
    Backpressure,
    /// The client's outbound `Protocol::send` could not allocate a packet-id
    /// because `MqttSafety.max_inflight_messages()` outstanding ack-awaiting
    /// ops are already in flight (or the u16 id space is exhausted). Mirrors
    /// the broker-side `max_inflight` cap (#61); closes SAFETY_PROOF F3 — the
    /// prior infallible allocator could collide a live packet-id under a
    /// self-inflicted flood. Caller should back off and retry after acks drain.
    TooManyInflight {
        limit: usize,
    },
    /// Temporary stub for features not yet implemented. Should not appear in
    /// production code paths once Phase 2 implementation completes — new
    /// occurrences require PR review.
    Unsupported(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutKind {
    /// Client waited for CONNACK after sending CONNECT.
    Connack,
    /// Server waited for CONNECT after accepting the wire.
    ConnectReceive,
    /// `Protocol::send` waited for PUBACK/PUBREC/PUBCOMP/SUBACK/UNSUBACK.
    Ack,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    ExpectedConnack,
    ExpectedConnect,
    ConnectionRefused(ConnackReturnCode),
    UnexpectedPacket {
        expected: &'static str,
        got: &'static str,
    },
    InvalidProtocolName,
    UnsupportedProtocolLevel(u8),
    EmptyTopic,
    TopicTooLong,
    WildcardInPublishTopic,
    HashWildcardNotTerminal,
    WildcardMixedWithLiteral,
    SessionAlreadyBound,
    // ── Stage A P1 hardening (spec §1.3 / §2.2 / §2.3 / §3.1) ──────────
    /// PUBLISH with DUP=1 and QoS=0 — spec §3.3.1.1.
    DupSetOnQos0,
    /// PUBLISH (or any ack) carrying packet_id=0 — spec §2.3.1.
    PacketIdZero,
    /// PUBLISH with zero-length topic — spec §3.3.2.1.
    EmptyPublishTopic,
    /// Reserved header bits set on a fixed header that defines them as 0.
    /// Used by P2 strict CONNECT parsing. P1 only adds the variant.
    ReservedHeaderBits,
    /// CONNACK first byte has bits 1-7 set (only bit 0 = SessionPresent
    /// is defined) — spec §3.2.2.1.
    ConnackReservedBits,
    /// CONNACK SessionPresent=1 paired with non-Accepted return code —
    /// spec §3.2.2.2.
    SessionPresentWithError,
    /// UTF-8 string contains U+0000 NUL — spec §1.5.3 forbids.
    Utf8NullCharacter,
    /// Packet remaining length exceeds the configured `max_packet_size`.
    /// Carries (declared, limit) bytes for diagnostics.
    PacketTooLarge {
        len: usize,
        max: usize,
    },
    // ── Stage A P3.A: fixed-header flag strictness (spec §1.6 / §2.1) ─────
    /// SUBSCRIBE fixed-header low nibble MUST be `0010` (§3.8.1).
    SubscribeReservedBits,
    /// UNSUBSCRIBE fixed-header low nibble MUST be `0010` (§3.10.1).
    UnsubscribeReservedBits,
    // ── hardening additions ───────────────────────────────────────────────
    /// Per-session inbound QoS-2 stash would exceed the configured cap
    /// (`MqttSafety.receive_maximum_inbound()`). Connection MUST close.
    ReceiveMaximumExceeded {
        limit: usize,
    },
    /// SUBSCRIBE / UNSUBSCRIBE filter count exceeds
    /// `MqttSafety.max_filters_per_subscribe()`. Connection MUST close.
    TooManyFilters {
        count: usize,
        max: usize,
    },
    // ── MQTT 5.0 (v5 spec §2.2.2 / §3.3.2.3.4 / §3.15) ───────────────────
    /// A non-repeatable v5 property appeared more than once in one block —
    /// v5 spec: "It is a Protocol Error to include [it] more than once."
    DuplicateProperty(u8),
    /// v5 property value is structurally invalid (e.g. Subscription
    /// Identifier of 0, which the spec forbids).
    MalformedProperty(u8),
    /// v5 property identifier not defined by the spec (§2.2.2.2 table).
    UnknownProperty(u8),
    /// Peer sent a Topic Alias but we never advertise a non-zero Topic
    /// Alias Maximum, so the effective maximum is 0 — v5 §3.3.2.3.4.
    TopicAliasNotAccepted,
    /// AUTH packet received, but no Authentication Method was negotiated
    /// on CONNECT — v5 §4.12: enhanced auth must be agreed first.
    UnexpectedAuthPacket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    UnexpectedEof,
    InvalidPacketType(u8),
    MalformedLength,
    InvalidUtf8,
    PayloadTooLong {
        len: usize,
        max: usize,
    },
    QosInvalid(u8),
    ReservedFlagSet,
    /// Encode-side: a length-prefixed string or bytes field exceeds the
    /// u16 wire encoding (spec §1.5.3 / §1.5.4 — MUST be ≤ 65 535).
    /// Surfacing this surfaces F2 (second-audit): prior `as u16` truncation
    /// would silently corrupt the wire frame.
    FieldTooLong {
        kind: &'static str,
        len: usize,
    },
    /// Encode-side: a `PublishPacket` with `qos > AtMostOnce` was passed
    /// with `packet_id = None` (or zero). Spec §3.3.2.2: QoS ≥ 1 PUBLISH
    /// MUST carry a non-zero packet identifier. SAFETY_PROOF v6 F5 — the
    /// prior encode path silently omitted the packet-id bytes, emitting
    /// a malformed wire frame.
    QosRequiresPacketId,
}

impl fmt::Display for MqttError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {}", e),
            Self::ChannelClosed => f.write_str("channel closed"),
            Self::AckTimeout => f.write_str("ack timeout"),
            Self::Timeout(k) => write!(f, "timeout: {:?}", k),
            Self::Configuration(m) => write!(f, "configuration: {}", m),
            Self::NotConnected(m) => write!(f, "not connected: {}", m),
            Self::Protocol(v) => write!(f, "protocol violation: {:?}", v),
            Self::Codec(c) => write!(f, "codec: {:?}", c),
            Self::Backpressure => f.write_str("write queue full (backpressure)"),
            Self::TooManyInflight { limit } => {
                write!(f, "too many inflight outbound ops (limit {})", limit)
            }
            Self::Unsupported(m) => write!(f, "unsupported: {}", m),
        }
    }
}

impl MqttError {
    /// Wrap any backend wire error (tokio `std::io::Error`, embassy
    /// `EmbeddedIoError`, …) into the abstract `Io` variant. Codec/channel
    /// call sites use `.map_err(MqttError::io)?` instead of a concrete
    /// `From<std::io::Error>`, which is what lets one MQTT crate serve every
    /// `HotaruRead`/`HotaruWrite` backend.
    pub fn io<E: core::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::Io(Box::new(e))
    }
}

impl core::error::Error for MqttError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

/// std-only convenience: lets tokio-backend call sites keep using `?` on
/// `std::io::Error`. no_std backends go through [`MqttError::io`] instead.
#[cfg(feature = "std")]
impl From<std::io::Error> for MqttError {
    fn from(e: std::io::Error) -> Self {
        Self::io(e)
    }
}

impl From<CodecError> for MqttError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

impl From<Violation> for MqttError {
    fn from(v: Violation) -> Self {
        Self::Protocol(v)
    }
}

// Blanket `ProtocolError` impl with default `can_continue() = false`.
// All MQTT errors are non-recoverable at the framework layer.
impl DefaultProtocolError for MqttError {}
