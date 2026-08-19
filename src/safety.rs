//! `MqttSafety` — wire-layer resource limits applied by both client and server.
//!
//! Shaped after `hotaru_http::HttpSafety`: every field is `Option<T>` and the
//! canonical default lives in the getter, not in the caller. A partially-built
//! config therefore never inherits a caller-side default, and a default can be
//! revised without touching call sites.
//!
//! Only `max_packet_size` exists today because it is the only limit this
//! baseline is able to enforce. Fields are added here as the code that reads
//! them lands, so the type never advertises a knob that does nothing.

/// Spec §2.2.3 hard cap: the largest remaining-length a 4-byte variable-byte
/// integer can express.
///
/// This is the ceiling of the *wire format*, not a safe allocation size: a
/// 5-byte fixed header can declare a ~256 MiB body, and `read_packet`
/// allocates that body before a single payload byte is read and before
/// CONNECT is parsed. Defaults must sit well below it.
pub use crate::packet::MQTT_SPEC_MAX_PACKET_SIZE as SPEC_MAX_PACKET_SIZE;

/// Secure default packet-size cap (1 MiB).
///
/// Chosen so an unconfigured broker cannot be pushed into a multi-hundred-MiB
/// per-connection allocation by a peer that has not authenticated. MQTT does
/// not specify a value here — anything below the spec ceiling is conforming —
/// so the number is a policy choice, and the policy is "small enough that
/// exhausting memory needs many connections rather than one". Deployments that
/// legitimately exchange larger payloads raise it explicitly through
/// [`MqttSafety::with_max_packet_size`].
const DEFAULT_MAX_PACKET_SIZE: usize = 1024 * 1024;

/// Resource limits applied at the wire layer.
#[derive(Debug, Clone, Default)]
pub struct MqttSafety {
    max_packet_size: Option<usize>,
}

impl MqttSafety {
    pub fn new() -> Self {
        Self::default()
    }

    /// Largest declared remaining-length the codec will accept before it
    /// allocates the body buffer. Defaults to 1 MiB rather than the spec
    /// ceiling — see [`DEFAULT_MAX_PACKET_SIZE`].
    pub fn max_packet_size(&self) -> usize {
        self.max_packet_size.unwrap_or(DEFAULT_MAX_PACKET_SIZE)
    }

    /// Raise (or lower) the cap. Values above the wire ceiling cannot be
    /// expressed by a conforming packet, so they are clamped: callers may opt
    /// all the way up to [`SPEC_MAX_PACKET_SIZE`], never past it.
    pub fn with_max_packet_size(mut self, n: usize) -> Self {
        self.max_packet_size = Some(n.min(SPEC_MAX_PACKET_SIZE));
        self
    }
}

#[cfg(test)]
mod test;
