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
    /// SAFETY_PROOF v5 T2(a): cap retained-message count per tenant. A
    /// `retain=1` publish that would push the tenant past this cap skips
    /// the `RetainedStore::store` call (fanout still delivers).
    /// `None` = unlimited; default is 65_536.
    max_retained_messages_per_tenant: Option<usize>,
    /// SAFETY_PROOF v5 T2(b) / #74(a): cap total retained-message *bytes*
    /// per tenant. The count cap alone bounds entry *number* but not size —
    /// 65_536 entries × the 1 MiB packet ceiling is ~64 GiB worst case. A
    /// `retain=1` publish whose payload would push the tenant's retained
    /// byte total past this cap skips the `store` call (fanout still
    /// delivers). `None` = unlimited; default is 16 MiB.
    max_retained_bytes_per_tenant: Option<usize>,
    /// SAFETY_PROOF v5 T2(c): cap total subscriptions per client. A
    /// SUBSCRIBE filter that would push the client past this cap gets
    /// `SubackCode::Failure` instead of `Granted`. `None` = unlimited;
    /// default is 1_024.
    max_subscriptions_per_client: Option<usize>,
    /// SAFETY_PROOF v5 T2(d): cap stored `clean_session=false` sessions
    /// per tenant. A disconnect that would push the tenant past this cap
    /// drops the session (treats as `clean_session=true` at exit). `None`
    /// = unlimited; default is 4_096.
    max_persistent_sessions_per_tenant: Option<usize>,
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
const DEFAULT_MAX_RETAINED_PER_TENANT: usize = 65_536;
const DEFAULT_MAX_RETAINED_BYTES_PER_TENANT: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_SUBS_PER_CLIENT: usize = 1_024;
const DEFAULT_MAX_PERSISTENT_PER_TENANT: usize = 4_096;

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

    pub fn max_retained_messages_per_tenant(&self) -> usize {
        self.max_retained_messages_per_tenant
            .unwrap_or(DEFAULT_MAX_RETAINED_PER_TENANT)
    }

    pub fn max_retained_bytes_per_tenant(&self) -> usize {
        self.max_retained_bytes_per_tenant
            .unwrap_or(DEFAULT_MAX_RETAINED_BYTES_PER_TENANT)
    }

    pub fn max_subscriptions_per_client(&self) -> usize {
        self.max_subscriptions_per_client
            .unwrap_or(DEFAULT_MAX_SUBS_PER_CLIENT)
    }

    pub fn max_persistent_sessions_per_tenant(&self) -> usize {
        self.max_persistent_sessions_per_tenant
            .unwrap_or(DEFAULT_MAX_PERSISTENT_PER_TENANT)
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

    pub fn with_max_retained_messages_per_tenant(mut self, n: usize) -> Self {
        self.max_retained_messages_per_tenant = Some(n);
        self
    }

    pub fn with_max_retained_bytes_per_tenant(mut self, n: usize) -> Self {
        self.max_retained_bytes_per_tenant = Some(n);
        self
    }

    pub fn with_max_subscriptions_per_client(mut self, n: usize) -> Self {
        self.max_subscriptions_per_client = Some(n);
        self
    }

    pub fn with_max_persistent_sessions_per_tenant(mut self, n: usize) -> Self {
        self.max_persistent_sessions_per_tenant = Some(n);
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
        assert_eq!(
            bs.slow_consumer_policy(),
            SlowConsumerPolicy::DropOldestQos0
        );
    }

    // SAFETY_PROOF v5 T2 — defaults + builders for the three bounded-memory caps.

    #[test]
    fn v5_caps_have_sensible_secure_defaults() {
        let bs = BrokerSafety::new();
        assert_eq!(bs.max_retained_messages_per_tenant(), 65_536);
        assert_eq!(bs.max_retained_bytes_per_tenant(), 16 * 1024 * 1024);
        assert_eq!(bs.max_subscriptions_per_client(), 1_024);
        assert_eq!(bs.max_persistent_sessions_per_tenant(), 4_096);
    }

    #[test]
    fn v5_caps_round_trip_through_builders() {
        let bs = BrokerSafety::new()
            .with_max_retained_messages_per_tenant(7)
            .with_max_retained_bytes_per_tenant(99)
            .with_max_subscriptions_per_client(13)
            .with_max_persistent_sessions_per_tenant(21);
        assert_eq!(bs.max_retained_messages_per_tenant(), 7);
        assert_eq!(bs.max_retained_bytes_per_tenant(), 99);
        assert_eq!(bs.max_subscriptions_per_client(), 13);
        assert_eq!(bs.max_persistent_sessions_per_tenant(), 21);
    }
}
