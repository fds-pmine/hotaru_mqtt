//! `MqttClientConfig` — startup configuration for an MQTT client session.
//!
//! Registered into runtime statics under `protocol::CLIENT_CONFIG_STATICS_KEY`
//! before `Client::build()`. `handle_client` reads it from runtime statics on
//! startup to construct the CONNECT packet and initial SUBSCRIBE.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use bytes::Bytes;

use crate::protocol::DefaultInboundHandler;
use crate::request::{Credentials, QoS, TopicFilter, WillMessage};
use crate::safety::MqttSafety;

/// All settings required to bring up an MQTT client session.
pub struct MqttClientConfig {
    pub client_id: Arc<str>,
    /// Wire protocol version for this session. Defaults to MQTT 3.1.1;
    /// opt into 5.0 with [`MqttClientConfig::protocol_version`].
    pub protocol_version: crate::packet::ProtocolVersion,
    pub clean_session: bool,
    pub keep_alive_secs: u16,
    pub connect_timeout: Duration,
    pub credentials: Option<Credentials>,
    pub initial_subscriptions: Vec<TopicFilter>,
    pub will: Option<WillMessage>,
    /// Fallback for inbound publishes that don't match any registered endpoint.
    pub default_inbound: Option<Arc<dyn DefaultInboundHandler>>,
    /// Wire-layer resource limits applied to this client session.
    pub safety: MqttSafety,
}

impl MqttClientConfig {
    pub fn new(client_id: impl Into<Arc<str>>) -> Self {
        Self {
            client_id: client_id.into(),
            protocol_version: crate::packet::ProtocolVersion::default(),
            clean_session: true,
            keep_alive_secs: 60,
            connect_timeout: Duration::from_secs(30),
            credentials: None,
            initial_subscriptions: Vec::new(),
            will: None,
            default_inbound: None,
            safety: MqttSafety::new(),
        }
    }

    pub fn clean_session(mut self, value: bool) -> Self {
        self.clean_session = value;
        self
    }

    pub fn keep_alive(mut self, secs: u16) -> Self {
        self.keep_alive_secs = secs;
        self
    }

    pub fn connect_timeout(mut self, t: Duration) -> Self {
        self.connect_timeout = t;
        self
    }

    pub fn with_credentials(
        mut self,
        username: impl Into<Arc<str>>,
        password: impl Into<Bytes>,
    ) -> Self {
        self.credentials = Some(Credentials::new(username, password));
        self
    }

    pub fn with_initial_subscribe(mut self, filter: impl Into<Arc<str>>, qos: QoS) -> Self {
        self.initial_subscriptions
            .push(TopicFilter::new(filter, qos));
        self
    }

    pub fn with_will(mut self, will: WillMessage) -> Self {
        self.will = Some(will);
        self
    }

    pub fn with_default_inbound(mut self, handler: Arc<dyn DefaultInboundHandler>) -> Self {
        self.default_inbound = Some(handler);
        self
    }

    pub fn with_safety(mut self, safety: MqttSafety) -> Self {
        self.safety = safety;
        self
    }
}
