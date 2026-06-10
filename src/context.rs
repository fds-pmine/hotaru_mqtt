//! `MqttContext` — the `RequestContext` for `MqttProtocol`.
//!
//! Carries:
//! - `request` / `response` (outpoint path via `run!`)
//! - `incoming` (endpoint inbound dispatch path)
//! - `channel` (installed by `Protocol::install_channel` after acquire)
//! - `fanout` (server-side chain may suppress broker fanout via `suppress_fanout`)
//!
//! `request` and `incoming` are mutually exclusive in normal flow — outpoint
//! body reads `request`, endpoint body reads `incoming`. The framework guarantees
//! this; user code that needs to inspect both should use `match`.

use std::sync::Arc;

use hotaru_core::connection::TransportSpec;
use hotaru_core::extensions::{Locals, Params};
use hotaru_core::protocol::{ProtocolRole, RequestContext};
use hotaru_core::url::UrlNode;

use crate::channel::MqttChannel;
use crate::error::MqttError;
use crate::request::{
    IncomingPublish, MqttRequest, MqttResponse, PublishAck, PublishRequest,
};

pub struct MqttContext<TS: TransportSpec = hotaru_core::connection::tcp::TcpTransport> {
    /// `run!` path: injected by `RequestContext::inject_request`.
    pub request: MqttRequest,

    /// `run!` path: filled by `Protocol::send`.
    pub response: MqttResponse,

    /// Endpoint inbound dispatch path: filled by `handle_*` before
    /// `node.run(ctx)`. `None` on outpoint path.
    pub incoming: Option<IncomingPublish>,

    /// Channel installed by `Protocol::install_channel` (called from
    /// `Client::request_fn` after `acquire_channel`, or directly by
    /// `handle_*` for inbound dispatch).
    channel: Option<MqttChannel<TS::Wire>>,

    /// Server-side endpoint can suppress broker fanout via `suppress_fanout()`.
    fanout: bool,

    /// For endpoint URL captures (named segments via `<id>`).
    endpoint: Option<Arc<UrlNode<MqttContext<TS>, TS>>>,

    pub params: Params,
    pub locals: Locals,
}

impl<TS: TransportSpec> Default for MqttContext<TS> {
    fn default() -> Self {
        Self {
            request: MqttRequest::Publish(PublishRequest::default()),
            response: MqttResponse::Published(PublishAck::Sent),
            incoming: None,
            channel: None,
            fanout: true,
            endpoint: None,
            params: Default::default(),
            locals: Default::default(),
        }
    }
}

impl<TS: TransportSpec> MqttContext<TS> {
    // ── pub(crate) channel slot accessors ───────────────────────

    pub(crate) fn install_channel(&mut self, ch: MqttChannel<TS::Wire>) {
        self.channel = Some(ch);
    }

    pub(crate) fn channel(&self) -> Option<&MqttChannel<TS::Wire>> {
        self.channel.as_ref()
    }

    pub(crate) fn set_incoming(&mut self, p: IncomingPublish) {
        self.incoming = Some(p);
    }

    pub(crate) fn set_endpoint(&mut self, node: Arc<UrlNode<MqttContext<TS>, TS>>) {
        self.endpoint = Some(node);
    }

    // ── Public fanout control (server-side) ─────────────────────

    pub fn should_fanout(&self) -> bool {
        self.fanout
    }

    pub fn suppress_fanout(&mut self) {
        self.fanout = false;
    }

    // ── Public convenience for endpoint bodies ──────────────────

    /// The incoming publish's topic, if any.
    pub fn topic(&self) -> Option<&str> {
        self.incoming.as_ref().map(|p| p.topic.as_ref())
    }

    /// The incoming publish's payload, if any.
    pub fn payload(&self) -> Option<&[u8]> {
        self.incoming.as_ref().map(|p| p.payload.as_ref())
    }

    /// Captured segment by name (via `<id>` in endpoint path).
    pub fn param(&self, name: &str) -> Option<String> {
        let topic = self.topic()?;
        let endpoint = self.endpoint.as_ref()?;
        let idx = endpoint.match_seg_name_with_index(name)?;
        topic.split('/').nth(idx).map(|s| s.to_string())
    }

    /// Client identifier of the current session.
    pub fn client_id(&self) -> Option<Arc<str>> {
        self.channel.as_ref().and_then(|c| c.client_id())
    }
}

impl<TS: TransportSpec> RequestContext for MqttContext<TS> {
    type Request = MqttRequest;
    type Response = MqttResponse;
    type Error = MqttError;
    type Channel = MqttChannel<TS::Wire>;

    fn handle_error(&mut self) {
        // MQTT has no "500 error response" concept. Suppress fanout
        // defensively so an in-flight chain failure doesn't leak the
        // half-processed message to other subscribers.
        self.fanout = false;
    }

    fn role(&self) -> ProtocolRole {
        self.channel
            .as_ref()
            .map(|c| c.role())
            .unwrap_or(ProtocolRole::Client)
    }

    fn inject_request(&mut self, req: MqttRequest) {
        self.request = req;
    }

    fn into_response(self) -> MqttResponse {
        self.response
    }
}
