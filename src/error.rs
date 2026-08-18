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

use std::fmt;

use hotaru_core::protocol::DefaultProtocolError;

use crate::packet::ConnackReturnCode;

#[derive(Debug)]
pub enum MqttError {
    Io(std::io::Error),
    ChannelClosed,
    AckTimeout,
    Timeout(TimeoutKind),
    Configuration(String),
    NotConnected(String),
    Protocol(Violation),
    Codec(CodecError),
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
    /// MQTT 5 property which may occur only once was repeated.
    DuplicateProperty(u8),
    /// MQTT 5 property value is outside the range defined by the protocol.
    MalformedProperty(u8),
    /// Property identifier is not defined by MQTT 5.
    UnknownProperty(u8),
    /// MQTT UTF-8 strings must not contain U+0000.
    Utf8NullCharacter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    UnexpectedEof,
    InvalidPacketType(u8),
    MalformedLength,
    InvalidUtf8,
    PayloadTooLong { len: usize, max: usize },
    QosInvalid(u8),
    ReservedFlagSet,
    /// A two-byte-length-prefixed field cannot represent this many bytes.
    FieldTooLong { kind: &'static str, len: usize },
    /// MQTT Variable Byte Integers are limited to 268,435,455.
    VariableByteIntegerOutOfRange { value: usize },
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
            Self::Unsupported(m) => write!(f, "unsupported: {}", m),
        }
    }
}

impl std::error::Error for MqttError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for MqttError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
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
