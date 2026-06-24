//! `MqttSafety` — wire-layer resource limits applied by both client and server.
//!
//! Symmetric to `hotaru_http::HttpSafety` (and `hotaru_mqtt_broker::BrokerSafety`,
//! which extends with server-only fields). Stored on `MqttClientConfig` for
//! the client path and on `Broker` for the server path; both call sites read
//! getters with secure defaults so unset fields never produce surprising
//! "infinity" behaviour.
//!
//! Fields are `Option<T>`-wrapped per the `HttpSafety` pattern so a partial
//! builder doesn't tie us to caller-side defaults — the canonical defaults
//! live here and can shift without breaking call sites.

use std::time::Duration;

/// Resource limits applied at the wire / connection layer.
#[derive(Debug, Clone, Default)]
pub struct MqttSafety {
    max_packet_size: Option<usize>,
    max_inflight_messages: Option<usize>,
    max_queued_messages: Option<usize>,
    worker_idle_timeout: Option<Duration>,
    /// Per-connection cap on simultaneously-unacknowledged inbound QoS-2
    /// PUBLISHes (second-audit G2: defends against an open-ended
    /// `qos2_recv` stash). Borrowed from MQTT-5 "Receive Maximum"
    /// semantics applied retroactively to 3.1.1.
    receive_maximum_inbound: Option<usize>,
    /// Maximum filter count in a single SUBSCRIBE or UNSUBSCRIBE packet
    /// (hardening F1 — defends against amplification via 65 535-filter
    /// SUBSCRIBEs which would saturate matching cost).
    max_filters_per_subscribe: Option<usize>,
}

// ── Default constants ─────────────────────────────────────────────

/// Spec §2.2.3 hard cap (4-byte VBI remaining-length max). This is the
/// absolute ceiling the wire format can express; it is NOT a safe default
/// because a single 5-byte fixed header can declare a ~256 MiB body and
/// force `read_packet` to `vec![0u8; remaining]` BEFORE authentication
/// (attack-surface finding AS1). We therefore default well below it and
/// only widen on explicit operator opt-in.
pub use crate::packet::MQTT_SPEC_MAX_PACKET_SIZE as SPEC_MAX_PACKET_SIZE;

/// Secure default packet-size cap (1 MiB). Chosen so an unconfigured
/// `MqttSafety::new()` cannot be coerced into a multi-hundred-MiB
/// per-connection allocation by an unauthenticated peer (AS1). Operators
/// who legitimately exchange larger payloads raise it explicitly via
/// [`MqttSafety::with_max_packet_size`] (clamped to [`SPEC_MAX_PACKET_SIZE`]).
const DEFAULT_MAX_PACKET_SIZE: usize = 1024 * 1024;
/// Default outbound inflight cap. `pub(crate)` so `MqttSession` can seed its
/// own pre-CONNECT guard with the same value before `handle_client` overrides
/// it from the operator-configured `MqttSafety`.
pub(crate) const DEFAULT_MAX_INFLIGHT_MESSAGES: usize = 20;
const DEFAULT_MAX_QUEUED_MESSAGES: usize = 1000;
const DEFAULT_RECEIVE_MAXIMUM_INBOUND: usize = 64;
const DEFAULT_MAX_FILTERS_PER_SUBSCRIBE: usize = 64;

impl MqttSafety {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Getters with secure defaults ────────────────────────────

    /// Maximum declared remaining-length the codec will accept before
    /// allocating the body buffer. Defaults to 1 MiB, NOT the spec hard
    /// cap, to keep an unconfigured broker from being OOM-poked by an
    /// unauthenticated peer (AS1). The spec ceiling is still enforced
    /// upstream in `read_remaining_length`.
    pub fn max_packet_size(&self) -> usize {
        self.max_packet_size.unwrap_or(DEFAULT_MAX_PACKET_SIZE)
    }

    pub fn max_inflight_messages(&self) -> usize {
        self.max_inflight_messages
            .unwrap_or(DEFAULT_MAX_INFLIGHT_MESSAGES)
    }

    pub fn max_queued_messages(&self) -> usize {
        self.max_queued_messages
            .unwrap_or(DEFAULT_MAX_QUEUED_MESSAGES)
    }

    /// `None` = workers stay alive until channel close (P3 default).
    pub fn worker_idle_timeout(&self) -> Option<Duration> {
        self.worker_idle_timeout
    }

    pub fn receive_maximum_inbound(&self) -> usize {
        self.receive_maximum_inbound
            .unwrap_or(DEFAULT_RECEIVE_MAXIMUM_INBOUND)
    }

    pub fn max_filters_per_subscribe(&self) -> usize {
        self.max_filters_per_subscribe
            .unwrap_or(DEFAULT_MAX_FILTERS_PER_SUBSCRIBE)
    }

    // ── Builder-style setters ───────────────────────────────────

    pub fn with_max_packet_size(mut self, n: usize) -> Self {
        // Values above the MQTT remaining-length wire ceiling cannot be
        // expressed by a conforming packet. Clamp so `max_packet_size()`
        // always advertises a meaningful cap while still allowing callers
        // to opt all the way up to the spec maximum.
        self.max_packet_size = Some(n.min(SPEC_MAX_PACKET_SIZE));
        self
    }

    pub fn with_max_inflight_messages(mut self, n: usize) -> Self {
        self.max_inflight_messages = Some(n);
        self
    }

    pub fn with_max_queued_messages(mut self, n: usize) -> Self {
        self.max_queued_messages = Some(n);
        self
    }

    pub fn with_worker_idle_timeout(mut self, d: Duration) -> Self {
        self.worker_idle_timeout = Some(d);
        self
    }

    pub fn with_receive_maximum_inbound(mut self, n: usize) -> Self {
        self.receive_maximum_inbound = Some(n);
        self
    }

    pub fn with_max_filters_per_subscribe(mut self, n: usize) -> Self {
        self.max_filters_per_subscribe = Some(n);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_secure() {
        let s = MqttSafety::new();
        // AS1: the secure default is 1 MiB, deliberately far below the spec
        // hard cap so an unauthenticated peer cannot force a ~256 MiB
        // pre-auth allocation on an unconfigured broker.
        assert_eq!(s.max_packet_size(), 1024 * 1024);
        assert!(s.max_packet_size() < SPEC_MAX_PACKET_SIZE);
        assert_eq!(s.max_inflight_messages(), 20);
        assert_eq!(s.max_queued_messages(), 1000);
        assert!(s.worker_idle_timeout().is_none());
        assert_eq!(s.receive_maximum_inbound(), 64);
        assert_eq!(s.max_filters_per_subscribe(), 64);
    }

    #[test]
    fn max_packet_size_override_clamps_to_spec_ceiling() {
        let s = MqttSafety::new().with_max_packet_size(usize::MAX);
        assert_eq!(s.max_packet_size(), SPEC_MAX_PACKET_SIZE);
    }

    #[test]
    fn builder_overrides_apply() {
        let s = MqttSafety::new()
            .with_max_packet_size(1024)
            .with_max_queued_messages(8)
            .with_worker_idle_timeout(Duration::from_secs(5))
            .with_receive_maximum_inbound(16)
            .with_max_filters_per_subscribe(8);
        assert_eq!(s.max_packet_size(), 1024);
        assert_eq!(s.max_queued_messages(), 8);
        assert_eq!(s.worker_idle_timeout(), Some(Duration::from_secs(5)));
        assert_eq!(s.max_inflight_messages(), 20);
        assert_eq!(s.receive_maximum_inbound(), 16);
        assert_eq!(s.max_filters_per_subscribe(), 8);
    }
}
