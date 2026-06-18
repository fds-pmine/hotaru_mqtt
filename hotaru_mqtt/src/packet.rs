//! MQTT 3.1.1 wire packet types.
//!
//! All payload bytes use `Bytes` (Arc-backed) and topics use `Arc<str>` so
//! that cloning a packet across N consumers costs N Arc-clones, no `memcpy`.
//!
//! `Packet` is the framework's `Message` type for `MqttProtocol`. Encoding
//! and decoding live in `codec.rs`; this module is plain data definitions.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use bitflags::bitflags;
use bytes::{Bytes, BytesMut};

use hotaru_core::protocol::Message;

use crate::codec::{decode_packet_from_bytes, encode_packet};
use crate::request::{IncomingPublish, PacketId, QoS, SubackCode};

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
    Unsuback(PacketId),
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
    pub client_id: Arc<str>,
    pub clean_session: bool,
    pub keep_alive: u16,
    pub username: Option<Arc<str>>,
    pub password: Option<Bytes>,
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
}

#[derive(Debug, Clone)]
pub struct ConnackPacket {
    pub session_present: bool,
    pub return_code: ConnackReturnCode,
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

impl std::fmt::Display for ConnackReturnCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

    fn encode(&self, buf: &mut Self::BytesMut) -> Result<(), Box<dyn Error + Send + Sync>> {
        let bytes =
            encode_packet(self).map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })?;
        buf.extend_from_slice(&bytes);
        Ok(())
    }

    fn decode(buf: &mut Self::BytesMut) -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        // The `Message::decode` framework hook lacks an `MqttSafety`
        // handle, so we fall back to the spec hard cap (§2.2.3). The
        // per-connection read path in `protocol.rs` uses `read_packet`
        // with the user-configured `MqttSafety.max_packet_size()`, which
        // is the security-relevant boundary.
        decode_packet_from_bytes(buf, MQTT_SPEC_MAX_PACKET_SIZE)
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_packet_debug_redacts_password() {
        let conn = ConnectPacket {
            client_id: Arc::from("cid"),
            clean_session: true,
            keep_alive: 60,
            username: Some(Arc::from("alice")),
            password: Some(Bytes::from_static(b"supersecret-2025")),
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
