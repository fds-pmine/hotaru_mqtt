//! `hotaru_mqtt` — MQTT 3.1.1 protocol core + client built on `hotaru_core`.
//!
//! For broker / server-side hosting, depend on `hotaru_mqtt_broker` (which
//! pulls in this crate transitively).
//!
//! Design memos (in repo root):
//! - `MQTT_AOI_DESIGN.md` — outpoint shape / inbound dispatch / topic matching
//! - `MQTT_PRODUCTION_PLAN.md` — Stage A P0-P8 path to mosquitto-grade
//! - `MQTT_SPEC_GAPS.md` — severity-ranked spec compliance audit

// SAFETY_PROOF M1 enforcement — any future PR introducing `unsafe` must
// explicitly justify it by lifting this lint (and updating the proof).
#![forbid(unsafe_code)]
// no_std port: without the `std` feature the crate builds on `core` +
// `alloc` only (heap required — packets, topic strings, queues). Runtime
// and IO come from whatever `RuntimeSpec` / `ConnStream` backend the
// embedding application supplies (e.g. hotaru_rt_embassy + a follow-up
// embedded transport).
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod channel;
pub mod client;
pub mod codec;
pub mod context;
pub mod error;
pub mod packet;
mod pmap;
pub mod properties;
pub mod protocol;
pub mod request;
pub mod safety;
pub mod session;
pub mod topic;
pub mod transport;

// ─── Re-exports for user-facing API ───────────────────────────────

pub use channel::{MqttChannel, WriteCmd};
pub use client::MqttClientConfig;
pub use context::MqttContext;
pub use error::{CodecError, MqttError, TimeoutKind, Violation};
#[cfg(feature = "tls")]
pub use hotaru_tls::{
    ClientAuth, TlsClientConfig, TlsClientConfigBuilder, TlsConfig, TlsConfigBuilder, TlsMeta,
    TlsOutbound, TlsOutboundTarget, TlsStream, TlsTransport,
};
pub use packet::{
    ConnackPacket, ConnackReturnCode, ConnectPacket, Packet, ProtocolVersion, PublishPacket,
    SubackPacket, SubscribePacket, TopicSubscription, UnsubackPacket, UnsubscribePacket,
    WillPacket, incoming_from_packet,
};
pub use properties::Properties;
pub use protocol::{CLIENT_CONFIG_STATICS_KEY, DefaultInboundHandler, MqttClientProtocol};
#[cfg(feature = "std")]
pub use protocol::{DefaultMqttTransport, MQTT};
#[cfg(feature = "tls")]
pub use protocol::{MQTTS, MqttTlsProtocol};
pub use request::{
    Credentials, IncomingPublish, MqttRequest, MqttResponse, PacketId, PublishAck, PublishRequest,
    QoS, SubackCode, TopicFilter, WillMessage,
};
pub use safety::{MqttSafety, SPEC_MAX_PACKET_SIZE};
pub use session::{AckSlot, BindInfo, MqttSession, ack_inbound_publish_pre_chain};
pub use topic::{
    is_dollar_prefixed_first_segment, parse_publish_topic, parse_subscribe_filter,
    path_to_wire_filter, validate_publish_topic, validate_subscribe_filter,
};
