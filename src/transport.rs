//! Transport-level helpers.
//!
//! In the BCH redesign, connection metadata (id / role / addrs / client_id /
//! keep_alive) all live on `MqttChannel` directly. The legacy `MqttTransport`
//! and `MqttConnection` snapshot types are no longer needed.
//!
//! `next_connection_id` (Q decision: `u64` + `AtomicU64`) lives in
//! `channel.rs`.

// Intentionally near-empty — kept as a module marker for future transport
// concerns (TLS unwrap helpers, WebSocket adapters, etc.).
