//! `MqttSafety` — wire-layer resource limits applied by both client and server.
//!
//! Shaped after `hotaru_http::HttpSafety`: every field is `Option<T>` and the
//! canonical default lives in the getter, not in the caller. A partially-built
//! config therefore never inherits a caller-side default, and a default can be
//! revised without touching call sites.
//!
//! Fields are added here as the code that reads them lands, so the type never
//! advertises a knob that does nothing.

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

/// Secure default ceiling on a peer-requested keep-alive (one hour).
///
/// The value a peer sends in CONNECT is a promise about how often it will
/// speak, and the server converts it into a read deadline. A large value is
/// therefore a resource commitment the peer takes unilaterally, before it has
/// authenticated. One hour is far above any interactive client's needs and far
/// below "until the process dies".
const DEFAULT_MAX_KEEP_ALIVE: u16 = 3600;

/// Resource limits applied at the wire layer.
#[derive(Debug, Clone, Default)]
pub struct MqttSafety {
    max_packet_size: Option<usize>,
    max_keep_alive: Option<u16>,
    allow_disabled_keep_alive: Option<bool>,
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

    /// Longest keep-alive, in seconds, a peer may request in CONNECT.
    /// Defaults to one hour — see [`DEFAULT_MAX_KEEP_ALIVE`].
    pub fn max_keep_alive(&self) -> u16 {
        self.max_keep_alive.unwrap_or(DEFAULT_MAX_KEEP_ALIVE)
    }

    /// Raise (or lower) the ceiling on a peer-requested keep-alive.
    ///
    /// Unlike `with_max_packet_size`, a CONNECT above this is refused rather
    /// than silently clamped. The distinction is who chose the number:
    /// the packet-size cap is the operator's own value, so clamping it to what
    /// the wire can express loses nothing, while a keep-alive is the peer's
    /// declaration. Clamping it would leave that peer believing it has a grace
    /// period it does not have, and the disagreement would surface much later
    /// as an unexplained disconnect.
    pub fn with_max_keep_alive(mut self, secs: u16) -> Self {
        self.max_keep_alive = Some(secs);
        self
    }

    /// Whether a peer may ask for no inactivity deadline at all by sending
    /// `keep_alive = 0`. Defaults to `false`.
    ///
    /// This is a deliberate departure from spec §3.1.2.10, which says the
    /// server is *not required* to disconnect such a client on the grounds of
    /// inactivity. Not required is not the same as obliged to keep it: an
    /// unauthenticated peer would otherwise be able to pin a connection, its
    /// session entry, and its channel for as long as the process lives. This is
    /// the same shape as the packet-size hole — the wire format permits it, and
    /// the default policy should not.
    pub fn allows_disabled_keep_alive(&self) -> bool {
        self.allow_disabled_keep_alive.unwrap_or(false)
    }

    /// Accept `keep_alive = 0`, restoring the letter of §3.1.2.10.
    ///
    /// Deployments that genuinely need it opt in here and should pair it with
    /// authentication. Note that an always-on device has no other way to ask:
    /// 24 hours is 86400 seconds, past the `u16` ceiling of 65535, so it has to
    /// send 0.
    pub fn allow_disabled_keep_alive(mut self) -> Self {
        self.allow_disabled_keep_alive = Some(true);
        self
    }
}

#[cfg(test)]
mod test;
