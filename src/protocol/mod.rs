//! `MqttProtocol` — the framework `Protocol` implementation.
//!
//! - **Server mode**: each inbound connection produces a fresh `MqttChannel`;
//!   `handle_server` runs CONNECT → CONNACK → main select loop → unregister.
//! - **Client mode**: first `open_channel` stashes the channel in
//!   `session_channel: Arc<OnceLock<MqttChannel>>`. Later `acquire_channel`
//!   calls (from `Client::request_fn` etc.) clone-return the same channel,
//!   so all `run!` ops reuse the session.

use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use hotaru_core::app::common::RuntimeConfig;
use hotaru_core::connection::{ConnStream, HotaruRead, HotaruWrite, TransportSpec};
use hotaru_core::protocol::{Channel as _, CtxError, Protocol, ProtocolFlow, ProtocolRole};
use hotaru_core::url::UrlRoot;

use crate::broker::incoming_from_packet;
use crate::channel::MqttChannel;
use crate::context::MqttContext;
use crate::error::MqttError;
use crate::packet::{
    Packet, PublishPacket,
};
use crate::request::QoS;

// ----------------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------------

/// Server-side timeout for the initial CONNECT packet after wire is accepted.
const CONNECT_RECEIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default ack-wait timeout for QoS 1/2 outbound ops if user doesn't override.
const DEFAULT_ACK_TIMEOUT: Duration = Duration::from_secs(30);

/// Runtime statics key for `Broker` lookup on server side.
pub const BROKER_STATICS_KEY: &str = "hotaru_mqtt::broker";

/// Runtime statics key for `MqttClientConfig` lookup on client side.
pub const CLIENT_CONFIG_STATICS_KEY: &str = "hotaru_mqtt::client_config";

// ----------------------------------------------------------------------------
// MqttProtocol
// ----------------------------------------------------------------------------

pub type DefaultMqttTransport = hotaru_io_tokio::TcpTransport;
pub type MQTT = MqttProtocol<hotaru_io_tokio::TcpStream, DefaultMqttTransport>;

pub struct MqttProtocol<
    W: ConnStream = hotaru_io_tokio::TcpStream,
    TS: TransportSpec<Wire = W> = DefaultMqttTransport,
> {
    role: ProtocolRole,
    /// Client mode: shared session channel slot. Cloned across protocol
    /// clones via `Arc`. First `open_channel` calls `set`; subsequent
    /// `acquire_channel` calls `get` and clones.
    session_channel: Option<Arc<OnceLock<MqttChannel<W>>>>,
    _ts: PhantomData<fn() -> TS>,
}

impl<W: ConnStream, TS: TransportSpec<Wire = W>> Clone for MqttProtocol<W, TS> {
    fn clone(&self) -> Self {
        Self {
            role: self.role,
            session_channel: self.session_channel.clone(),
            _ts: PhantomData,
        }
    }
}

impl<W: ConnStream, TS: TransportSpec<Wire = W>> MqttProtocol<W, TS> {
    pub fn server() -> Self {
        Self {
            role: ProtocolRole::Server,
            session_channel: None,
            _ts: PhantomData,
        }
    }

    pub fn client() -> Self {
        Self {
            role: ProtocolRole::Client,
            session_channel: Some(Arc::new(OnceLock::new())),
            _ts: PhantomData,
        }
    }
}

impl<W, TS> Protocol for MqttProtocol<W, TS>
where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
    // 0.8.5 dropped the global `RequestContext::Error: From<std::io::Error>`
    // bound in favour of a per-transport one; the trait now demands this of
    // every implementor. Pinned to std::io::Error for the same reason as the
    // codec bounds - the per-transport generalisation is #103's decision.
    MqttError: From<<TS as TransportSpec>::IoError>,
    W::ReadHalf: HotaruRead<Error = std::io::Error>,
    W::WriteHalf: HotaruWrite<Error = std::io::Error>,
{
    type Wire = W;
    type TS = TS;
    type Channel = MqttChannel<W>;
    type Stream = ();
    type Message = Packet;
    type Context = MqttContext<TS>;

    fn name(&self) -> &'static str {
        "mqtt"
    }

    fn role(&self) -> ProtocolRole {
        self.role
    }

    fn default_connection_timeout(&self) -> Option<Duration> {
        None
    }

    fn detect(initial_bytes: &[u8]) -> bool {
        // MQTT 3.1.1: first byte of CONNECT is 0x10
        initial_bytes
            .first()
            .map(|b| (b >> 4) == 1)
            .unwrap_or(false)
    }

    fn open_channel(
        self,
        reader: <<<Self::TS as TransportSpec>::Wire as ConnStream>::ReadHalf as HotaruRead>::Buffered,
        writer: <<<Self::TS as TransportSpec>::Wire as ConnStream>::WriteHalf as HotaruWrite>::Buffered,
        meta: <<Self::TS as TransportSpec>::Wire as ConnStream>::Meta,
    ) -> Self::Channel {
        let channel = MqttChannel::new(reader, writer, &meta, self.role);

        // Client mode: stash for acquire_channel reuse.
        if let Some(slot) = &self.session_channel {
            // `set` returns Err if already set; the first call wins, later
            // open_channel attempts on the same protocol instance are no-ops
            // for stash purposes (they still return their own channel, but
            // that channel can't be acquired by run! — only the first one is).
            let _ = slot.set(channel.clone());
        }

        channel
    }

    async fn handle(
        channel: &Self::Channel,
        runtime: Arc<RuntimeConfig>,
        root: Arc<UrlRoot<Self::Context, Self::TS>>,
    ) -> Result<ProtocolFlow, CtxError<Self>> {
        let role = channel.role();
        let result = match role {
            ProtocolRole::Server => handle_server(channel, runtime, root).await,
            ProtocolRole::Client => handle_client(channel, runtime, root).await,
        };
        // Whatever happened, the channel is done after one handle() invocation.
        channel.close();
        result
    }

    async fn acquire_channel(
        &self,
        _runtime: &Arc<RuntimeConfig>,
        _outbound: Arc<<Self::TS as TransportSpec>::Outbound>,
    ) -> Result<Self::Channel, CtxError<Self>> {
        let slot = self.session_channel.as_ref().ok_or_else(|| {
            MqttError::Configuration(
                "acquire_channel called on Server-mode MqttProtocol".into(),
            )
        })?;
        let channel = slot.get().ok_or_else(|| {
            MqttError::NotConnected(
                "call client.run_wire(wire) to establish session first".into(),
            )
        })?;
        Ok(channel.clone())
    }

    async fn send(ctx: Self::Context) -> Result<Self::Context, CtxError<Self>> {
        send_impl(ctx).await
    }

    fn install_channel(ctx: &mut Self::Context, channel: Self::Channel) {
        ctx.install_channel(channel);
    }
}


// ----------------------------------------------------------------------------
// Shared across both roles
// ----------------------------------------------------------------------------

// ============================================================================
// Inbound dispatch — common logic for server & client
// ============================================================================

/// Send PUBACK/PUBREC for QoS≥1 publishes BEFORE the chain runs.
/// For QoS 2, also stash in `qos2_recv` so PUBREL can dispatch later.
fn ack_inbound_publish_pre_chain<W: ConnStream>(
    channel: &MqttChannel<W>,
    publish: &PublishPacket,
) -> Result<(), MqttError> {
    match publish.qos {
        QoS::AtMostOnce => Ok(()),
        QoS::AtLeastOnce => {
            if let Some(id) = publish.packet_id {
                channel.send_packet(Packet::Puback(id))?;
            }
            Ok(())
        }
        QoS::ExactlyOnce => {
            if let Some(id) = publish.packet_id {
                // Stash for PUBREL dispatch
                channel
                    .session()
                    .stash_qos2_publish(id, incoming_from_packet(publish));
                channel.send_packet(Packet::Pubrec(id))?;
            }
            Ok(())
        }
    }
}


/// User-supplied fallback for inbound publishes that don't match any
/// registered endpoint. Registered in `MqttClientConfig.default_inbound`.
#[async_trait]
pub trait DefaultInboundHandler: Send + Sync + 'static {
    async fn handle(&self, incoming: crate::request::IncomingPublish);
}


// ----------------------------------------------------------------------------
// Role modules
//
// The seam is the call graph, not taste: `handle_client` and `handle_server`
// reach disjoint sets of helpers, and the only things both sides touch are the
// outbound send path and `ack_inbound_publish_pre_chain`. Splitting here is
// what makes the broker/client crate split (#77) a file move rather than a
// rewrite.
// ----------------------------------------------------------------------------

mod client;
mod send;
mod server;

use client::handle_client;
use send::send_impl;
use server::handle_server;

// (shutdown_signal lives on MqttChannel as pub(crate))

#[cfg(test)]
mod test;
