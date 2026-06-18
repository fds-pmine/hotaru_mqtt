//! Runtime statics keys.

/// `RuntimeConfig` statics key for `Broker` lookup on server side. Used by
/// [`crate::MqttServerProtocol::handle`] to retrieve the broker instance
/// registered via `set_statics`.
pub const BROKER_STATICS_KEY: &str = "hotaru_mqtt::broker";
