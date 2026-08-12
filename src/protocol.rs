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
use hotaru_core::connection::{ConnStream, TransportSpec};
use hotaru_core::protocol::{Channel as _, CtxError, Protocol, ProtocolFlow, ProtocolRole};
use hotaru_core::url::UrlRoot;
use tokio::io::BufReader;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::broker::{Broker, incoming_from_packet};
use crate::channel::MqttChannel;
use crate::client::MqttClientConfig;
use crate::codec::read_packet;
use crate::context::MqttContext;
use crate::error::{MqttError, TimeoutKind, Violation};
use crate::packet::{
    ConnackPacket, ConnackReturnCode, ConnectPacket, Packet, PublishPacket, SubackPacket,
    SubscribePacket, TopicSubscription, UnsubscribePacket, WillPacket,
};
use crate::request::{
    MqttRequest, MqttResponse, PublishAck, PublishRequest, QoS, TopicFilter,
};
use crate::session::{AckSlot, BindInfo};

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

pub type DefaultMqttTransport = hotaru_core::connection::tcp::TcpTransport;
pub type MQTT = MqttProtocol<tokio::net::TcpStream, DefaultMqttTransport>;

pub struct MqttProtocol<
    W: ConnStream = tokio::net::TcpStream,
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

#[async_trait]
impl<W, TS> Protocol for MqttProtocol<W, TS>
where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
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
        reader: BufReader<<<Self::TS as TransportSpec>::Wire as ConnStream>::ReadHalf>,
        writer: <<Self::TS as TransportSpec>::Wire as ConnStream>::WriteHalf,
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

// ============================================================================
// handle_client — client-side persistent session loop
// ============================================================================

async fn handle_client<W, TS>(
    channel: &MqttChannel<W>,
    runtime: Arc<RuntimeConfig>,
    root: Arc<UrlRoot<MqttContext<TS>, TS>>,
) -> Result<ProtocolFlow, MqttError>
where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
{
    let config = runtime
        .get_static::<Arc<MqttClientConfig>>(CLIENT_CONFIG_STATICS_KEY)
        .ok_or_else(|| {
            MqttError::Configuration(
                "MqttClientConfig not registered in runtime statics".into(),
            )
        })?;

    let max_packet_size = config.safety.max_packet_size();

    // 1. Take exclusive reader ownership (single-take).
    let mut reader = channel
        .take_reader()
        .await
        .ok_or_else(|| MqttError::Configuration("reader already taken".into()))?;

    // 2. Send CONNECT
    let connect = build_connect(&config);
    channel.send_packet(Packet::Connect(connect))?;

    // 3. Wait for CONNACK with timeout
    let connack_packet =
        timeout(config.connect_timeout, read_packet(&mut reader, max_packet_size))
        .await
        .map_err(|_| MqttError::Timeout(TimeoutKind::Connack))??;
    let Packet::Connack(ack) = connack_packet else {
        return Err(Violation::ExpectedConnack.into());
    };
    if ack.return_code != ConnackReturnCode::Accepted {
        return Err(Violation::ConnectionRefused(ack.return_code).into());
    }

    // Bind session.
    let _ = channel.session().bind().set(BindInfo {
        client_id: config.client_id.clone(),
        keep_alive: config.keep_alive_secs,
    });

    // 4. Initial subscriptions (if any)
    if !config.initial_subscriptions.is_empty() {
        // Use the same path P::send takes — via cmd_tx + pending_acks.
        let pkt_id = channel.session().allocate_packet_id();
        let (tx, rx) = oneshot::channel();
        channel
            .session()
            .pending_acks
            .insert(pkt_id, AckSlot::Suback(tx));
        let subs: Vec<TopicSubscription> = config
            .initial_subscriptions
            .iter()
            .map(|tf| TopicSubscription {
                topic: tf.filter.clone(),
                qos: tf.qos,
            })
            .collect();
        channel.send_packet(Packet::Subscribe(SubscribePacket {
            packet_id: pkt_id,
            subscriptions: subs,
        }))?;
        let _ = timeout(DEFAULT_ACK_TIMEOUT, rx)
            .await
            .map_err(|_| MqttError::Timeout(TimeoutKind::Ack))?
            .map_err(|_| MqttError::ChannelClosed)?;
    }

    // 5. Main select loop
    let ping_interval = Duration::from_secs(config.keep_alive_secs.max(1) as u64);
    let mut ping_timer = tokio::time::interval(ping_interval);
    ping_timer.tick().await; // skip first immediate tick
    let shutdown = channel.shutdown_signal();

    loop {
        if !channel.is_open() {
            break;
        }
        tokio::select! {
            inbound = read_packet(&mut reader, max_packet_size) => {
                match inbound {
                    Ok(p) => {
                        if dispatch_client_inbound(channel.clone(), p, runtime.clone(), root.clone(), &config).await? {
                            break;  // disconnect
                        }
                    }
                    Err(MqttError::Io(_)) => break,    // wire closed
                    Err(e) => return Err(e),
                }
            }
            _ = ping_timer.tick() => {
                // PINGREQ failure means writer is dead → break (W must-propagate)
                if channel.send_packet(Packet::Pingreq).is_err() {
                    break;
                }
            }
            _ = shutdown.notified() => break,
        }
    }

    // 6. Graceful DISCONNECT (W policy §1 — silent OK)
    let _ = channel.send_packet(Packet::Disconnect);
    Ok(ProtocolFlow::Close)
}

/// Returns `Ok(true)` if loop should break (DISCONNECT received).
async fn dispatch_client_inbound<W, TS>(
    channel: MqttChannel<W>,
    packet: Packet,
    runtime: Arc<RuntimeConfig>,
    root: Arc<UrlRoot<MqttContext<TS>, TS>>,
    config: &MqttClientConfig,
) -> Result<bool, MqttError>
where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
{
    match packet {
        Packet::Publish(publish) => {
            // QoS≥1: ack BEFORE chain (O.2)
            ack_inbound_publish_pre_chain(&channel, &publish)?;
            // For QoS 2: stored in qos2_recv on ack; dispatch happens when PUBREL arrives.
            if publish.qos == QoS::ExactlyOnce {
                return Ok(false);
            }
            dispatch_inbound_to_endpoints(channel, &publish, runtime, root, config.default_inbound.as_ref()).await;
            Ok(false)
        }
        Packet::Puback(id) => {
            fire_ack(&channel, id, AckKind::Puback);
            channel.session().outbound_inflight.remove(&id);
            Ok(false)
        }
        Packet::Pubrec(id) => {
            // QoS 2 phase 1: send PUBREL, wait for PUBCOMP
            fire_ack(&channel, id, AckKind::Pubrec);
            channel.send_packet(Packet::Pubrel(id))?;
            Ok(false)
        }
        Packet::Pubcomp(id) => {
            fire_ack(&channel, id, AckKind::Pubcomp);
            channel.session().outbound_inflight.remove(&id);
            Ok(false)
        }
        Packet::Pubrel(id) => {
            // Inbound QoS 2: take stored qos2_recv and dispatch
            if let Some((_, publish)) = channel.session().qos2_recv.remove(&id) {
                dispatch_incoming_to_endpoints_owned(channel.clone(), publish, runtime, root, config.default_inbound.as_ref()).await;
            }
            channel.send_packet(Packet::Pubcomp(id))?;
            Ok(false)
        }
        Packet::Suback(s) => {
            fire_suback(&channel, s);
            Ok(false)
        }
        Packet::Unsuback(id) => {
            fire_unsuback(&channel, id);
            Ok(false)
        }
        Packet::Pingresp => Ok(false),
        Packet::Disconnect => Ok(true),
        _ => Ok(false), // Connect/Connack/Subscribe/Unsubscribe are not expected here
    }
}

// ============================================================================
// handle_server — server-side per-connection session loop
// ============================================================================

async fn handle_server<W, TS>(
    channel: &MqttChannel<W>,
    runtime: Arc<RuntimeConfig>,
    root: Arc<UrlRoot<MqttContext<TS>, TS>>,
) -> Result<ProtocolFlow, MqttError>
where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
{
    let broker = runtime
        .get_static::<Broker<W>>(BROKER_STATICS_KEY)
        .ok_or_else(|| MqttError::Configuration("Broker not registered".into()))?;

    let mut reader = channel
        .take_reader()
        .await
        .ok_or_else(|| MqttError::Configuration("reader already taken".into()))?;

    // Read the cap before the first packet: it has to bind on the CONNECT
    // read itself, which happens before authentication, so the peer that
    // gets to declare a body size has not proven anything yet.
    let max_packet_size = broker.safety().max_packet_size();

    // 1. Read CONNECT with timeout
    let connect_packet =
        timeout(CONNECT_RECEIVE_TIMEOUT, read_packet(&mut reader, max_packet_size))
        .await
        .map_err(|_| MqttError::Timeout(TimeoutKind::ConnectReceive))??;
    let Packet::Connect(connect) = connect_packet else {
        return Err(Violation::ExpectedConnect.into());
    };

    // 2. Authenticate
    let auth = broker.authenticate(&connect, channel.remote_addr()).await;
    if !auth.accepted {
        let _ = channel.send_packet(Packet::Connack(ConnackPacket {
            session_present: false,
            return_code: auth.return_code,
        }));
        return Err(Violation::ConnectionRefused(auth.return_code).into());
    }

    // MQTT 3.1.1: empty client_id is allowed only when clean_session=true;
    // broker MUST then assign a unique identifier.
    let client_id: Arc<str> = if connect.client_id.is_empty() {
        let id = format!("hotaru-auto-{}", channel.connection_id());
        Arc::from(id.as_str())
    } else {
        connect.client_id.clone()
    };
    let keep_alive = connect.keep_alive;
    let clean_session = connect.clean_session;
    let will = connect.will.as_ref().map(|w| crate::request::WillMessage {
        topic: w.topic.clone(),
        payload: w.payload.clone(),
        qos: w.qos,
        retain: w.retain,
    });

    // 3. Register session (broker takes channel clone)
    let session_present = broker
        .register_session(client_id.clone(), channel.clone(), will, clean_session)
        .await;

    let _ = channel.session().bind().set(BindInfo {
        client_id: client_id.clone(),
        keep_alive,
    });

    // 4. Send CONNACK
    //
    // The session is already registered at this point, so a failure here has
    // to unregister before it propagates — the same obligation the read loop
    // below discharges through `terminal_error`.
    if let Err(e) = channel.send_packet(Packet::Connack(ConnackPacket {
        session_present,
        return_code: ConnackReturnCode::Accepted,
    })) {
        broker.unregister_session(&client_id, false).await;
        return Err(e);
    }

    // 5. Main select loop with keep-alive timeout (1.5× grace per spec)
    let keep_alive_secs = keep_alive.max(1) as u64;
    let read_timeout = Duration::from_secs((keep_alive_secs * 3) / 2);
    let mut graceful = false;
    // Every terminal condition sets state and breaks; nothing returns from
    // inside the loop. Teardown is written after the loop, so a `return` there
    // would skip it — which is exactly what used to happen on a malformed
    // packet: the session stayed in the broker's table with its subscriptions
    // live, and the Will was never published even though the connection had
    // died non-gracefully.
    let mut terminal_error: Option<MqttError> = None;
    let shutdown = channel.shutdown_signal();

    loop {
        if !channel.is_open() {
            break;
        }
        tokio::select! {
            packet = timeout(read_timeout, read_packet(&mut reader, max_packet_size)) => {
                match packet {
                    Err(_) => break,                              // keep-alive timeout = crash
                    Ok(Err(MqttError::Io(_))) => break,           // wire closed = crash
                    Ok(Err(e)) => {
                        terminal_error = Some(e);
                        break;
                    }
                    Ok(Ok(Packet::Disconnect)) => {
                        graceful = true;
                        break;
                    }
                    Ok(Ok(p)) => {
                        if let Err(e) = dispatch_server_inbound(
                            channel.clone(),
                            broker.clone(),
                            &client_id,
                            p,
                            runtime.clone(),
                            root.clone(),
                        ).await {
                            terminal_error = Some(e);
                            break;
                        }
                    }
                }
            }
            _ = shutdown.notified() => break,
        }
    }

    // 6. Unregister (graceful flag drives Will trigger). Single exit: this runs
    //    on every path out of the loop, including the failing ones.
    broker.unregister_session(&client_id, graceful).await;
    if let Some(e) = terminal_error {
        // Still reported to the framework, just after cleanup rather than
        // instead of it. `graceful` stays false on this path, which is what
        // makes the Will fire (MQTT-3.1.2-5).
        return Err(e);
    }
    Ok(ProtocolFlow::Close)
}

async fn dispatch_server_inbound<W, TS>(
    channel: MqttChannel<W>,
    broker: Broker<W>,
    client_id: &Arc<str>,
    packet: Packet,
    runtime: Arc<RuntimeConfig>,
    root: Arc<UrlRoot<MqttContext<TS>, TS>>,
) -> Result<(), MqttError>
where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
{
    match packet {
        Packet::Publish(publish) => {
            // Ack BEFORE chain (O.2)
            ack_inbound_publish_pre_chain(&channel, &publish)?;
            // For QoS 2: stored in qos2_recv on ack; fanout happens when PUBREL arrives.
            if publish.qos == QoS::ExactlyOnce {
                return Ok(());
            }
            // QoS 0 / 1: Run endpoint chain then broker fanout
            let fanout_packet = run_server_chain_then_decide_fanout(
                channel.clone(),
                publish.clone(),
                runtime,
                root,
            )
            .await;
            if let Some(p) = fanout_packet {
                broker.publish(client_id, p).await;
            }
            Ok(())
        }
        Packet::Subscribe(s) => {
            let filters: Vec<TopicFilter> = s
                .subscriptions
                .iter()
                .map(|ts| TopicFilter {
                    filter: ts.topic.clone(),
                    qos: ts.qos,
                })
                .collect();
            let codes = broker.subscribe(client_id, &filters).await;
            channel.send_packet(Packet::Suback(SubackPacket {
                packet_id: s.packet_id,
                return_codes: codes,
            }))?;
            Ok(())
        }
        Packet::Unsubscribe(u) => {
            broker.unsubscribe(client_id, &u.topics).await;
            channel.send_packet(Packet::Unsuback(u.packet_id))?;
            Ok(())
        }
        Packet::Pingreq => {
            channel.send_packet(Packet::Pingresp)?;
            Ok(())
        }
        Packet::Puback(id) => {
            broker.ack_outbound(client_id, id).await;
            Ok(())
        }
        Packet::Pubrec(id) => {
            // QoS 2 outbound from broker to this sub, phase 1
            channel.send_packet(Packet::Pubrel(id))?;
            Ok(())
        }
        Packet::Pubcomp(id) => {
            broker.ack_outbound(client_id, id).await;
            Ok(())
        }
        Packet::Pubrel(id) => {
            // QoS 2 inbound publish phase 2: dispatch stored qos2_recv
            if let Some((_, stored)) = channel.session().qos2_recv.remove(&id) {
                // Re-build into a wire PublishPacket to run chain + fanout
                let publish = PublishPacket {
                    topic: stored.topic.clone(),
                    payload: stored.payload.clone(),
                    dup: false,
                    qos: stored.qos,
                    retain: stored.retain,
                    packet_id: Some(id),
                };
                let fanout_packet = run_server_chain_then_decide_fanout(
                    channel.clone(),
                    publish,
                    runtime.clone(),
                    root.clone(),
                )
                .await;
                if let Some(p) = fanout_packet {
                    broker.publish(client_id, p).await;
                }
            }
            channel.send_packet(Packet::Pubcomp(id))?;
            Ok(())
        }
        Packet::Connect(_) => Err(Violation::SessionAlreadyBound.into()),
        _ => Ok(()), // Other inbound types are protocol violations or noise — silent (W §4)
    }
}

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
                    .qos2_recv
                    .insert(id, incoming_from_packet(publish));
                channel.send_packet(Packet::Pubrec(id))?;
            }
            Ok(())
        }
    }
}

/// Walk all endpoints matching `publish.topic`, spawn dispatch per match.
/// On client side, return value is ignored (fire-and-forget). On server side
/// chain decides fanout via `run_server_chain_then_decide_fanout`.
async fn dispatch_inbound_to_endpoints<W, TS>(
    channel: MqttChannel<W>,
    publish: &PublishPacket,
    _runtime: Arc<RuntimeConfig>,
    root: Arc<UrlRoot<MqttContext<TS>, TS>>,
    default_handler: Option<&Arc<dyn DefaultInboundHandler>>,
) where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
{
    let topic = publish.topic.clone();
    let segments: Vec<&str> = topic.split('/').collect();
    let mut cursor = root.walk_cursor(&topic);
    let mut matched = false;

    while let Some(node) = cursor.find_next(&segments) {
        matched = true;
        // Spawn per-match dispatch (O.1 concurrent)
        let ctx_channel = channel.clone();
        let ctx_publish = publish.clone();
        let ctx_node = node;
        tokio::spawn(async move {
            let mut ctx = MqttContext::<TS>::default();
            ctx.set_incoming(incoming_from_packet(&ctx_publish));
            ctx.install_channel(ctx_channel);
            ctx.set_endpoint(ctx_node.clone());
            let _ = ctx_node.run(ctx).await;
        });
    }

    if !matched
        && let Some(handler) = default_handler
    {
        // Fallback inbound handler (MqttClientConfig.default_inbound)
        let handler = handler.clone();
        let inc = incoming_from_packet(publish);
        tokio::spawn(async move {
            handler.handle(inc).await;
        });
    }
}

/// Owned-publish variant for QoS 2 PUBREL dispatch where the stored
/// `IncomingPublish` is already owned.
async fn dispatch_incoming_to_endpoints_owned<W, TS>(
    channel: MqttChannel<W>,
    incoming: crate::request::IncomingPublish,
    _runtime: Arc<RuntimeConfig>,
    root: Arc<UrlRoot<MqttContext<TS>, TS>>,
    default_handler: Option<&Arc<dyn DefaultInboundHandler>>,
) where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
{
    let topic = incoming.topic.clone();
    let segments: Vec<&str> = topic.split('/').collect();
    let mut cursor = root.walk_cursor(&topic);
    let mut matched = false;

    while let Some(node) = cursor.find_next(&segments) {
        matched = true;
        let ctx_channel = channel.clone();
        let ctx_inc = incoming.clone();
        let ctx_node = node;
        tokio::spawn(async move {
            let mut ctx = MqttContext::<TS>::default();
            ctx.set_incoming(ctx_inc);
            ctx.install_channel(ctx_channel);
            ctx.set_endpoint(ctx_node.clone());
            let _ = ctx_node.run(ctx).await;
        });
    }

    if !matched && let Some(handler) = default_handler {
        let handler = handler.clone();
        tokio::spawn(async move {
            handler.handle(incoming).await;
        });
    }
}

/// Server-side: run any matching endpoint chain, return the packet to fan out
/// if the chain didn't suppress it. Sequential (await), unlike client-side
/// which fires-and-forgets, because the chain may mutate the packet before
/// broker fanout (O.4 — chain first, then fanout).
async fn run_server_chain_then_decide_fanout<W, TS>(
    channel: MqttChannel<W>,
    publish: PublishPacket,
    _runtime: Arc<RuntimeConfig>,
    root: Arc<UrlRoot<MqttContext<TS>, TS>>,
) -> Option<PublishPacket>
where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
{
    let topic = publish.topic.clone();
    let segments: Vec<&str> = topic.split('/').collect();
    let mut cursor = root.walk_cursor(&topic);
    let mut fanout = true;
    let mut current = publish;

    while let Some(node) = cursor.find_next(&segments) {
        let mut ctx = MqttContext::<TS>::default();
        ctx.set_incoming(incoming_from_packet(&current));
        ctx.install_channel(channel.clone());
        ctx.set_endpoint(node.clone());
        match node.run(ctx).await {
            Ok(out) => {
                if !out.should_fanout() {
                    fanout = false;
                }
                // If chain mutated the incoming, propagate it back to the wire packet
                if let Some(inc) = out.incoming {
                    current.topic = inc.topic;
                    current.payload = inc.payload;
                    current.qos = inc.qos;
                    current.retain = inc.retain;
                }
            }
            Err(_) => {
                fanout = false;
            }
        }
    }

    if fanout { Some(current) } else { None }
}

// ============================================================================
// Protocol::send — outpoint outbound execution
// ============================================================================

async fn send_impl<TS>(mut ctx: MqttContext<TS>) -> Result<MqttContext<TS>, MqttError>
where
    TS: TransportSpec,
{
    let channel = ctx
        .channel()
        .cloned()
        .ok_or(MqttError::NotConnected("no channel installed in ctx".into()))?;

    let request = std::mem::replace(
        &mut ctx.request,
        MqttRequest::Publish(PublishRequest::default()),
    );

    let response = match request {
        MqttRequest::Publish(req) => send_publish(&channel, req).await?,
        MqttRequest::Subscribe(filters) => send_subscribe(&channel, filters).await?,
        MqttRequest::Unsubscribe(topics) => send_unsubscribe(&channel, topics).await?,
    };

    ctx.response = response;
    Ok(ctx)
}

async fn send_publish<W: ConnStream>(
    channel: &MqttChannel<W>,
    req: PublishRequest,
) -> Result<MqttResponse, MqttError> {
    let packet_id = if req.qos != QoS::AtMostOnce {
        Some(channel.session().allocate_packet_id())
    } else {
        None
    };

    let packet = PublishPacket {
        topic: req.topic,
        payload: req.payload,
        dup: false,
        qos: req.qos,
        retain: req.retain,
        packet_id,
    };

    match req.qos {
        QoS::AtMostOnce => {
            channel.send_publish(packet)?;
            Ok(MqttResponse::Published(PublishAck::Sent))
        }
        QoS::AtLeastOnce => {
            let id = packet_id.expect("alloc'd above");
            let (tx, rx) = oneshot::channel();
            channel
                .session()
                .pending_acks
                .insert(id, AckSlot::Puback(tx));
            channel.send_publish(packet)?;
            let acked = timeout(DEFAULT_ACK_TIMEOUT, rx)
                .await
                .map_err(|_| {
                    channel.session().pending_acks.remove(&id);
                    MqttError::Timeout(TimeoutKind::Ack)
                })?
                .map_err(|_| MqttError::ChannelClosed)?;
            Ok(MqttResponse::Published(PublishAck::Acknowledged(acked)))
        }
        QoS::ExactlyOnce => {
            let id = packet_id.expect("alloc'd above");
            // Two-phase: PUBREC first, then PUBCOMP after we send PUBREL.
            let (rec_tx, rec_rx) = oneshot::channel();
            channel
                .session()
                .pending_acks
                .insert(id, AckSlot::Pubrec(rec_tx));
            channel.send_publish(packet)?;
            timeout(DEFAULT_ACK_TIMEOUT, rec_rx)
                .await
                .map_err(|_| {
                    channel.session().pending_acks.remove(&id);
                    MqttError::Timeout(TimeoutKind::Ack)
                })?
                .map_err(|_| MqttError::ChannelClosed)?;

            // PUBREL was sent by the inbound dispatch when PUBREC fired.
            // Now wait for PUBCOMP.
            let (comp_tx, comp_rx) = oneshot::channel();
            channel
                .session()
                .pending_acks
                .insert(id, AckSlot::Pubcomp(comp_tx));
            let comp_id = timeout(DEFAULT_ACK_TIMEOUT, comp_rx)
                .await
                .map_err(|_| {
                    channel.session().pending_acks.remove(&id);
                    MqttError::Timeout(TimeoutKind::Ack)
                })?
                .map_err(|_| MqttError::ChannelClosed)?;
            Ok(MqttResponse::Published(PublishAck::Completed(comp_id)))
        }
    }
}

async fn send_subscribe<W: ConnStream>(
    channel: &MqttChannel<W>,
    filters: Vec<TopicFilter>,
) -> Result<MqttResponse, MqttError> {
    let packet_id = channel.session().allocate_packet_id();
    let (tx, rx) = oneshot::channel();
    channel
        .session()
        .pending_acks
        .insert(packet_id, AckSlot::Suback(tx));
    let subs: Vec<TopicSubscription> = filters
        .into_iter()
        .map(|f| TopicSubscription {
            topic: f.filter,
            qos: f.qos,
        })
        .collect();
    channel.send_packet(Packet::Subscribe(SubscribePacket {
        packet_id,
        subscriptions: subs,
    }))?;
    let codes = timeout(DEFAULT_ACK_TIMEOUT, rx)
        .await
        .map_err(|_| {
            channel.session().pending_acks.remove(&packet_id);
            MqttError::Timeout(TimeoutKind::Ack)
        })?
        .map_err(|_| MqttError::ChannelClosed)?;
    Ok(MqttResponse::Subscribed(codes))
}

async fn send_unsubscribe<W: ConnStream>(
    channel: &MqttChannel<W>,
    topics: Vec<Arc<str>>,
) -> Result<MqttResponse, MqttError> {
    let packet_id = channel.session().allocate_packet_id();
    let (tx, rx) = oneshot::channel();
    channel
        .session()
        .pending_acks
        .insert(packet_id, AckSlot::Unsuback(tx));
    channel.send_packet(Packet::Unsubscribe(UnsubscribePacket {
        packet_id,
        topics,
    }))?;
    timeout(DEFAULT_ACK_TIMEOUT, rx)
        .await
        .map_err(|_| {
            channel.session().pending_acks.remove(&packet_id);
            MqttError::Timeout(TimeoutKind::Ack)
        })?
        .map_err(|_| MqttError::ChannelClosed)?;
    Ok(MqttResponse::Unsubscribed)
}

// ============================================================================
// Ack delivery helpers
// ============================================================================

enum AckKind {
    Puback,
    Pubrec,
    Pubcomp,
}

fn fire_ack<W: ConnStream>(channel: &MqttChannel<W>, id: u16, kind: AckKind) {
    if let Some((_, slot)) = channel.session().pending_acks.remove(&id) {
        match (slot, kind) {
            (AckSlot::Puback(tx), AckKind::Puback) => {
                let _ = tx.send(id); // W §3
            }
            (AckSlot::Pubrec(tx), AckKind::Pubrec) => {
                let _ = tx.send(id);
            }
            (AckSlot::Pubcomp(tx), AckKind::Pubcomp) => {
                let _ = tx.send(id);
            }
            _ => {
                // Mismatched ack kind — protocol noise (W §4 silent)
            }
        }
    }
}

fn fire_suback<W: ConnStream>(channel: &MqttChannel<W>, packet: SubackPacket) {
    if let Some((_, slot)) = channel
        .session()
        .pending_acks
        .remove(&packet.packet_id)
    {
        if let AckSlot::Suback(tx) = slot {
            let _ = tx.send(packet.return_codes);
        }
    }
}

fn fire_unsuback<W: ConnStream>(channel: &MqttChannel<W>, id: u16) {
    if let Some((_, slot)) = channel.session().pending_acks.remove(&id) {
        if let AckSlot::Unsuback(tx) = slot {
            let _ = tx.send(());
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn build_connect(config: &MqttClientConfig) -> ConnectPacket {
    ConnectPacket {
        client_id: config.client_id.clone(),
        clean_session: config.clean_session,
        keep_alive: config.keep_alive_secs,
        username: config.credentials.as_ref().map(|c| c.username.clone()),
        password: config.credentials.as_ref().map(|c| c.password.clone()),
        will: config.will.as_ref().map(|w| WillPacket {
            topic: w.topic.clone(),
            payload: w.payload.clone(),
            qos: w.qos,
            retain: w.retain,
        }),
    }
}

/// User-supplied fallback for inbound publishes that don't match any
/// registered endpoint. Registered in `MqttClientConfig.default_inbound`.
#[async_trait]
pub trait DefaultInboundHandler: Send + Sync + 'static {
    async fn handle(&self, incoming: crate::request::IncomingPublish);
}

// (shutdown_signal lives on MqttChannel as pub(crate))
