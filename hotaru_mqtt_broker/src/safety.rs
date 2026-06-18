//! Broker-side resource limits.
//!
//! Separate from `hotaru_mqtt::MqttSafety` (wire-layer / client+server
//! shared) so sensor / client-only builds don't surface broker fields they
//! can't use. Composes via the `inner` field once `MqttSafety` lands in
//! `hotaru_mqtt` (P1 of the production plan).

use std::time::Duration;

// ============================================================================
// BrokerSafety
// ============================================================================

/// Server-side resource limits and operational policies.
///
/// Fields are `Option<T>`-wrapped so unset values fall back to secure
/// defaults at read time. Matches the pattern used by
/// `hotaru_http::HttpSafety`.
#[derive(Debug, Clone, Default)]
pub struct BrokerSafety {
    max_inflight_messages: Option<usize>,
    max_queued_messages: Option<usize>,
    max_connections: Option<usize>,
    slow_consumer_policy: Option<SlowConsumerPolicy>,
    shutdown_grace_period: Option<Duration>,
}

/// What to do when a subscriber's bounded queue overflows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowConsumerPolicy {
    /// Drop the offending QoS 0 publish silently; for QoS ≥ 1 disconnect
    /// the slow channel (we can't drop a QoS ≥ 1 — spec promises delivery,
    /// so closing the channel surfaces the loss to the client instead of
    /// hiding it). Note: mpsc has no "drop OLDEST" primitive, so this
    /// drops the new message — the wall-clock effect on memory is the
    /// same, and QoS 0 has no delivery guarantee to break.
    DropOldestQos0,
    /// Disconnect the channel on any overflow, regardless of QoS.
    DisconnectLaggard,
}

impl Default for SlowConsumerPolicy {
    fn default() -> Self {
        SlowConsumerPolicy::DropOldestQos0
    }
}

impl SlowConsumerPolicy {
    /// Decide whether an overflow at the bounded queue should close the
    /// affected channel. Caller is responsible for the actual `close()`
    /// — this is a pure decision function so it stays trivial to test and
    /// can be re-used from both the inbound fanout coordinator and the
    /// outbound per-subscriber cmd_tx call sites.
    pub fn should_close_on_overflow(self, qos: hotaru_mqtt::request::QoS) -> bool {
        use hotaru_mqtt::request::QoS;
        match self {
            Self::DropOldestQos0 => qos != QoS::AtMostOnce,
            Self::DisconnectLaggard => true,
        }
    }
}

// ----------------------------------------------------------------------------
// Default constants
// ----------------------------------------------------------------------------

const DEFAULT_MAX_INFLIGHT: usize = 20;
const DEFAULT_MAX_QUEUED: usize = 1000;
const DEFAULT_MAX_CONNECTIONS: usize = 10_000;
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

impl BrokerSafety {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Getters with secure defaults ────────────────────────────

    pub fn max_inflight_messages(&self) -> usize {
        self.max_inflight_messages.unwrap_or(DEFAULT_MAX_INFLIGHT)
    }

    pub fn max_queued_messages(&self) -> usize {
        self.max_queued_messages.unwrap_or(DEFAULT_MAX_QUEUED)
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS)
    }

    pub fn slow_consumer_policy(&self) -> SlowConsumerPolicy {
        self.slow_consumer_policy.unwrap_or_default()
    }

    pub fn shutdown_grace_period(&self) -> Duration {
        self.shutdown_grace_period.unwrap_or(DEFAULT_SHUTDOWN_GRACE)
    }

    // ── Builder-style setters ───────────────────────────────────

    pub fn with_max_inflight_messages(mut self, n: usize) -> Self {
        self.max_inflight_messages = Some(n);
        self
    }

    pub fn with_max_queued_messages(mut self, n: usize) -> Self {
        self.max_queued_messages = Some(n);
        self
    }

    pub fn with_max_connections(mut self, n: usize) -> Self {
        self.max_connections = Some(n);
        self
    }

    pub fn with_slow_consumer_policy(mut self, p: SlowConsumerPolicy) -> Self {
        self.slow_consumer_policy = Some(p);
        self
    }

    pub fn with_shutdown_grace_period(mut self, d: Duration) -> Self {
        self.shutdown_grace_period = Some(d);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hotaru_mqtt::request::QoS;

    #[test]
    fn drop_oldest_qos0_keeps_qos0_drops_higher() {
        let p = SlowConsumerPolicy::DropOldestQos0;
        assert!(!p.should_close_on_overflow(QoS::AtMostOnce));
        assert!(p.should_close_on_overflow(QoS::AtLeastOnce));
        assert!(p.should_close_on_overflow(QoS::ExactlyOnce));
    }

    #[test]
    fn disconnect_laggard_closes_every_qos() {
        let p = SlowConsumerPolicy::DisconnectLaggard;
        assert!(p.should_close_on_overflow(QoS::AtMostOnce));
        assert!(p.should_close_on_overflow(QoS::AtLeastOnce));
        assert!(p.should_close_on_overflow(QoS::ExactlyOnce));
    }

    #[test]
    fn default_policy_is_drop_oldest_qos0() {
        let bs = BrokerSafety::new();
        assert_eq!(bs.slow_consumer_policy(), SlowConsumerPolicy::DropOldestQos0);
    }
}
