//! `hotaru_mqtt` — MQTT 3.1.1 broker + client built on `hotaru_core`.
//!
//! Design memos (in repo root):
//! - `MQTT_AOI_DESIGN.md` — outpoint shape / inbound dispatch / topic matching
//! - `MQTT_BCH_DESIGN.md` — Channel / Context / Lifecycle
//! - `MQTT_EFTU_DESIGN.md` — Broker API / Topic module / zero-copy / MqttError
//! - `MQTT_W_POLICY.md` — silent-error policy

pub mod broker;
pub mod channel;
pub mod client;
pub mod codec;
pub mod context;
pub mod error;
pub mod packet;
pub mod protocol;
pub mod request;
pub mod session;
pub mod topic;
pub mod transport;

// ─── Re-exports for user-facing API ───────────────────────────────

pub use broker::{
    AcceptAllAuthenticator, AuthResult, Authenticator, Broker, SubscriberEntry,
};
pub use channel::{MqttChannel, WriteCmd};
pub use client::MqttClientConfig;
pub use context::MqttContext;
pub use error::{CodecError, MqttError, TimeoutKind, Violation};
pub use packet::{
    ConnackPacket, ConnackReturnCode, ConnectPacket, Packet, PublishPacket,
    SubackPacket, SubscribePacket, TopicSubscription, UnsubscribePacket,
    WillPacket,
};
pub use protocol::{
    DefaultInboundHandler, DefaultMqttTransport, MQTT, MqttProtocol,
    BROKER_STATICS_KEY, CLIENT_CONFIG_STATICS_KEY,
};
pub use request::{
    Credentials, IncomingPublish, MqttRequest, MqttResponse, PacketId, PublishAck,
    PublishRequest, QoS, SubackCode, TopicFilter, WillMessage,
};
pub use session::{AckSlot, BindInfo, MqttSession};
pub use topic::{
    parse_publish_topic, parse_subscribe_filter, path_to_wire_filter,
    validate_publish_topic, validate_subscribe_filter,
};
