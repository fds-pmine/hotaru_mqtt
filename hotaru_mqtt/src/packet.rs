//! MQTT 3.1.1 wire packet types.
//!
//! All payload bytes use `Bytes` (Arc-backed) and topics use `Arc<str>` so
//! that cloning a packet across N consumers costs N Arc-clones, no `memcpy`.
//!
//! `Packet` is the framework's `Message` type for `MqttProtocol`. Encoding
//! and decoding live in `codec.rs`; this module is plain data definitions.

use core::fmt;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use bitflags::bitflags;
use bytes::{Bytes, BytesMut};
use zeroize::Zeroizing;

use hotaru_core::protocol::Message;

use crate::codec::{decode_packet_from_bytes, encode_packet};
use crate::error::MqttError;
use crate::properties::Properties;
use crate::request::{IncomingPublish, PacketId, QoS, SubackCode};

// ----------------------------------------------------------------------------
// Protocol version
// ----------------------------------------------------------------------------

/// MQTT protocol level negotiated per connection (CONNECT byte 7).
///
/// The codec is version-driven: v3.1.1 frames stay byte-identical to the
/// pre-v5 implementation; v5 frames add reason codes and property blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtocolVersion {
    /// MQTT 3.1.1 (protocol level 4). Default: existing deployments and
    /// the framework `Message` hook (which has no session context) stay
    /// on the old wire format unless a peer negotiates v5.
    #[default]
    V311,
    /// MQTT 5.0 (protocol level 5).
    V5,
}

impl ProtocolVersion {
    /// Wire protocol-level byte (CONNECT variable header).
    pub fn level(self) -> u8 {
        match self {
            Self::V311 => 4,
            Self::V5 => 5,
        }
    }

    /// Parse the CONNECT protocol-level byte.
    pub fn from_level(level: u8) -> Option<Self> {
        match level {
            4 => Some(Self::V311),
            5 => Some(Self::V5),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Packet {
    Connect(ConnectPacket),
    Connack(ConnackPacket),
    Publish(PublishPacket),
    Puback(PacketId),
    Pubrec(PacketId),
    Pubrel(PacketId),
    Pubcomp(PacketId),
    Subscribe(SubscribePacket),
    Suback(SubackPacket),
    Unsubscribe(UnsubscribePacket),
    Unsuback(UnsubackPacket),
    Pingreq,
    Pingresp,
    Disconnect,
}

impl Packet {
    /// Static name for error reporting / logging.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Connect(_) => "CONNECT",
            Self::Connack(_) => "CONNACK",
            Self::Publish(_) => "PUBLISH",
            Self::Puback(_) => "PUBACK",
            Self::Pubrec(_) => "PUBREC",
            Self::Pubrel(_) => "PUBREL",
            Self::Pubcomp(_) => "PUBCOMP",
            Self::Subscribe(_) => "SUBSCRIBE",
            Self::Suback(_) => "SUBACK",
            Self::Unsubscribe(_) => "UNSUBSCRIBE",
            Self::Unsuback(_) => "UNSUBACK",
            Self::Pingreq => "PINGREQ",
            Self::Pingresp => "PINGRESP",
            Self::Disconnect => "DISCONNECT",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PublishPacket {
    pub topic: Arc<str>,
    pub payload: Bytes,
    pub dup: bool,
    pub qos: QoS,
    pub retain: bool,
    pub packet_id: Option<PacketId>,
    /// MQTT 5.0 properties. Empty (and not encoded) on v3.1.1 wires.
    /// Stored on the packet so broker fanout forwards Response Topic /
    /// Correlation Data / Content Type / User Properties unaltered, as
    /// spec §3.3.2.3 requires.
    pub properties: Properties,
}

impl PublishPacket {
    /// Clone with a different packet_id (used when re-targeting an outbound
    /// PUBLISH onto a different inflight slot).
    pub fn with_id(mut self, id: PacketId) -> Self {
        self.packet_id = Some(id);
        self
    }
}

#[derive(Clone)]
pub struct ConnectPacket {
    /// Negotiated protocol level. Set from the wire on decode; drives the
    /// CONNECT frame layout on encode.
    pub version: ProtocolVersion,
    /// MQTT 5.0 CONNECT properties (session expiry, receive maximum, …).
    /// Empty on v3.1.1.
    pub properties: Properties,
    pub client_id: Arc<str>,
    pub clean_session: bool,
    pub keep_alive: u16,
    pub username: Option<Arc<str>>,
    /// CONNECT password. Wrapped in `Zeroizing<Vec<u8>>` so the plaintext
    /// is wiped when the packet drops — SAFETY_PROOF v5 §7 F1 / #69 closure.
    /// The codec copies the wire bytes into an owned `Vec<u8>` rather than
    /// holding a `Bytes` view, because `Bytes` may be refcounted and cannot
    /// reliably be zeroized at a single drop site.
    pub password: Option<Zeroizing<Vec<u8>>>,
    pub will: Option<WillPacket>,
}

/// Hand-written `Debug` that **redacts** `password`. Spec audit L1: a
/// downstream `tracing::debug!("{connect:?}")` (the derived impl) would dump
/// the cleartext password into logs. Username is left visible because it is
/// identity, not secret; will payload is also kept verbatim because it is
/// broadcast on the wire anyway.
impl fmt::Debug for ConnectPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectPacket")
            .field("version", &self.version)
            .field("properties", &self.properties)
            .field("client_id", &self.client_id)
            .field("clean_session", &self.clean_session)
            .field("keep_alive", &self.keep_alive)
            .field("username", &self.username)
            .field(
                "password",
                &self
                    .password
                    .as_ref()
                    .map(|p| format_args!("<redacted: {} bytes>", p.len()).to_string()),
            )
            .field("will", &self.will)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct WillPacket {
    pub topic: Arc<str>,
    pub payload: Bytes,
    pub qos: QoS,
    pub retain: bool,
    /// MQTT 5.0 Will properties block. Empty on v3.1.1.
    pub properties: Properties,
}

#[derive(Debug, Clone)]
pub struct ConnackPacket {
    pub session_present: bool,
    pub return_code: ConnackReturnCode,
    /// MQTT 5.0 CONNACK properties. Empty on v3.1.1.
    pub properties: Properties,
}

#[derive(Debug, Clone)]
pub struct SubscribePacket {
    pub packet_id: PacketId,
    pub subscriptions: Vec<TopicSubscription>,
}

#[derive(Debug, Clone)]
pub struct TopicSubscription {
    pub topic: Arc<str>,
    pub qos: QoS,
}

#[derive(Debug, Clone)]
pub struct SubackPacket {
    pub packet_id: PacketId,
    pub return_codes: Vec<SubackCode>,
}

#[derive(Debug, Clone)]
pub struct UnsubscribePacket {
    pub packet_id: PacketId,
    pub topics: Vec<Arc<str>>,
}

#[derive(Debug, Clone)]
pub struct UnsubackPacket {
    pub packet_id: PacketId,
    /// MQTT 5.0 per-filter reason codes (0x00 = success). Empty on
    /// v3.1.1, where UNSUBACK is just the packet id.
    pub reason_codes: Vec<u8>,
}

impl UnsubackPacket {
    /// v3-shaped constructor: bare acknowledgement, no reason codes.
    pub fn new(packet_id: PacketId) -> Self {
        Self {
            packet_id,
            reason_codes: Vec::new(),
        }
    }
}

// ----------------------------------------------------------------------------
// Numeric / flag types
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Connect = 1,
    Connack = 2,
    Publish = 3,
    Puback = 4,
    Pubrec = 5,
    Pubrel = 6,
    Pubcomp = 7,
    Subscribe = 8,
    Suback = 9,
    Unsubscribe = 10,
    Unsuback = 11,
    Pingreq = 12,
    Pingresp = 13,
    Disconnect = 14,
    /// MQTT 5.0 enhanced-authentication exchange (spec §3.15). Parsed at
    /// the codec boundary; since this implementation never offers an
    /// Authentication Method, receiving one is a protocol violation.
    Auth = 15,
}

impl TryFrom<u8> for PacketType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Connect),
            2 => Ok(Self::Connack),
            3 => Ok(Self::Publish),
            4 => Ok(Self::Puback),
            5 => Ok(Self::Pubrec),
            6 => Ok(Self::Pubrel),
            7 => Ok(Self::Pubcomp),
            8 => Ok(Self::Subscribe),
            9 => Ok(Self::Suback),
            10 => Ok(Self::Unsubscribe),
            11 => Ok(Self::Unsuback),
            12 => Ok(Self::Pingreq),
            13 => Ok(Self::Pingresp),
            14 => Ok(Self::Disconnect),
            15 => Ok(Self::Auth),
            _ => Err(()),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FixedHeaderFlags: u8 {
        const Bypass = 0b0000_0000;
        const Retain = 0b0000_0001;
        const QoS = 0b0000_0110;
        const Dup = 0b0000_1000;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ConnectFlags: u8 {
        const Username = 0b1000_0000;
        const Password = 0b0100_0000;
        const WillRetain = 0b0010_0000;
        const WillQoSMask = 0b0001_1000;
        const WillFlag = 0b0000_0100;
        const CleanSession = 0b0000_0010;
        const Reserved = 0b0000_0001;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnackReturnCode {
    Accepted = 0,
    UnacceptableProtocolVersion = 1,
    IdentifierRejected = 2,
    ServerUnavailable = 3,
    BadUsernameOrPassword = 4,
    NotAuthorized = 5,
}

impl ConnackReturnCode {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Map to the MQTT 5.0 CONNACK reason-code space (spec §3.2.2.2).
    /// The struct keeps the v3 logical code so client/broker logic stays
    /// version-agnostic; only the wire byte differs.
    pub fn to_v5_reason(self) -> u8 {
        match self {
            Self::Accepted => 0x00,
            Self::UnacceptableProtocolVersion => 0x84, // Unsupported Protocol Version
            Self::IdentifierRejected => 0x85,          // Client Identifier not valid
            Self::ServerUnavailable => 0x88,           // Server unavailable
            Self::BadUsernameOrPassword => 0x86,       // Bad User Name or Password
            Self::NotAuthorized => 0x87,               // Not authorized
        }
    }

    /// Map an MQTT 5.0 CONNACK reason code back to the logical v3 code.
    /// Unlisted v5 codes collapse to the closest v3 bucket so callers can
    /// keep a single refusal path.
    pub fn from_v5_reason(code: u8) -> Result<Self, ()> {
        match code {
            0x00 => Ok(Self::Accepted),
            0x84 => Ok(Self::UnacceptableProtocolVersion),
            0x85 => Ok(Self::IdentifierRejected),
            0x86 => Ok(Self::BadUsernameOrPassword),
            0x87 | 0x9C | 0x9D => Ok(Self::NotAuthorized), // incl. Use another server / Server moved
            0x88 | 0x89 | 0x97 => Ok(Self::ServerUnavailable), // incl. Server busy / Quota exceeded
            0x80..=0xFF => Ok(Self::ServerUnavailable),    // generic unspecified failures
            _ => Err(()),
        }
    }
}

impl TryFrom<u8> for ConnackReturnCode {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::UnacceptableProtocolVersion),
            2 => Ok(Self::IdentifierRejected),
            3 => Ok(Self::ServerUnavailable),
            4 => Ok(Self::BadUsernameOrPassword),
            5 => Ok(Self::NotAuthorized),
            _ => Err(()),
        }
    }
}

impl core::fmt::Display for ConnackReturnCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Accepted => write!(f, "Accepted"),
            Self::UnacceptableProtocolVersion => write!(f, "Unacceptable Protocol Version"),
            Self::IdentifierRejected => write!(f, "Identifier Rejected"),
            Self::ServerUnavailable => write!(f, "Server Unavailable"),
            Self::BadUsernameOrPassword => write!(f, "Bad Username or Password"),
            Self::NotAuthorized => write!(f, "Not Authorized"),
        }
    }
}

// ----------------------------------------------------------------------------
// Message impl — connects Packet to hotaru_core's protocol Message trait
// ----------------------------------------------------------------------------

impl Message for Packet {
    type BytesMut = BytesMut;
    type Error = MqttError;

    fn encode(&self, buf: &mut Self::BytesMut) -> Result<(), MqttError> {
        // The framework hook has no session context, so it encodes on the
        // default (v3.1.1) wire format. Version-negotiated paths encode
        // through the writer actor, which knows the channel version.
        let bytes = encode_packet(self, ProtocolVersion::default())?;
        buf.extend_from_slice(&bytes);
        Ok(())
    }

    fn decode(buf: &mut Self::BytesMut) -> Result<Option<Self>, MqttError> {
        // The `Message::decode` framework hook lacks an `MqttSafety`
        // handle, so we fall back to the spec hard cap (§2.2.3). The
        // per-connection read path in `protocol.rs` uses `read_packet`
        // with the user-configured `MqttSafety.max_packet_size()`, which
        // is the security-relevant boundary. Same story for the protocol
        // version: no session context here, so v3.1.1 framing.
        decode_packet_from_bytes(buf, MQTT_SPEC_MAX_PACKET_SIZE, ProtocolVersion::default())
    }
}

/// MQTT 3.1.1 §2.2.3 hard cap on the remaining-length VBI (4 bytes max).
pub const MQTT_SPEC_MAX_PACKET_SIZE: usize = 268_435_455;

// ----------------------------------------------------------------------------
// Wire-to-user conversion
// ----------------------------------------------------------------------------

/// Build a user-facing [`IncomingPublish`] from a wire [`PublishPacket`].
///
/// Topic and payload are `Arc<str>` / `Bytes` clones (O(1)). Used by both
/// client-side inbound dispatch and broker-side server dispatch.
pub fn incoming_from_packet(p: &PublishPacket) -> IncomingPublish {
    IncomingPublish {
        topic: p.topic.clone(),
        payload: p.payload.clone(),
        qos: p.qos,
        retain: p.retain,
        dup: p.dup,
        packet_id: p.packet_id,
        properties: p.properties.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_packet_debug_redacts_password() {
        let conn = ConnectPacket {
            properties: Default::default(),
            version: Default::default(),
            client_id: Arc::from("cid"),
            clean_session: true,
            keep_alive: 60,
            username: Some(Arc::from("alice")),
            password: Some(Zeroizing::new(b"supersecret-2025".to_vec())),
            will: None,
        };
        let dbg = format!("{conn:?}");
        // Cleartext MUST NOT appear.
        assert!(
            !dbg.contains("supersecret"),
            "password leaked into Debug: {dbg}"
        );
        // Marker that confirms our redaction ran (not just any random Debug).
        assert!(
            dbg.contains("redacted"),
            "debug missing redaction marker: {dbg}"
        );
        // Non-secret fields are still visible.
        assert!(dbg.contains("alice"));
        assert!(dbg.contains("cid"));
    }

    #[test]
    fn connect_packet_debug_keeps_none_password_visible() {
        let conn = ConnectPacket {
            properties: Default::default(),
            version: Default::default(),
            client_id: Arc::from("cid"),
            clean_session: true,
            keep_alive: 60,
            username: None,
            password: None,
            will: None,
        };
        let dbg = format!("{conn:?}");
        // None should print as None — confirms we don't show "<redacted>"
        // when there's nothing there.
        assert!(dbg.contains("password: None"), "{dbg}");
    }
}
