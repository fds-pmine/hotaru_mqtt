//! `MqttClientProtocol` — client-side framework `Protocol` implementation.
//!
//! - First `open_channel` stashes the channel in
//!   `session_channel: Arc<OnceLock<MqttChannel>>`. Later `acquire_channel`
//!   calls (from `Client::request_fn` etc.) clone-return the same channel,
//!   so all `run!` ops reuse the session.
//!
//! The server-side counterpart (`MqttServerProtocol`) and its broker live in
//! a separate downstream crate so client / sensor builds don't pay for them.

use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;
use hotaru_core::app::common::RuntimeConfig;
use hotaru_core::connection::{ConnStream, TransportSpec};
use hotaru_core::protocol::{Channel as _, CtxError, Protocol, ProtocolFlow, ProtocolRole};
use hotaru_core::url::{UrlNode, UrlRoot};
use tokio::io::BufReader;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use crate::channel::MqttChannel;
use crate::client::MqttClientConfig;
use crate::codec::read_packet;
use crate::context::MqttContext;
use crate::error::{MqttError, TimeoutKind, Violation};
use crate::packet::{
    ConnackReturnCode, ConnectPacket, Packet, PublishPacket, SubackPacket, SubscribePacket,
    TopicSubscription, UnsubscribePacket, WillPacket, incoming_from_packet,
};
use crate::request::{
    IncomingPublish, MqttRequest, MqttResponse, PublishAck, PublishRequest, QoS, TopicFilter,
};
use crate::session::{AckSlot, BindInfo, ack_inbound_publish_pre_chain};

// ----------------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------------

/// Default ack-wait timeout for QoS 1/2 outbound ops if user doesn't override.
const DEFAULT_ACK_TIMEOUT: Duration = Duration::from_secs(30);

/// Runtime statics key for `MqttClientConfig` lookup on client side.
pub const CLIENT_CONFIG_STATICS_KEY: &str = "hotaru_mqtt::client_config";

/// Initial cmd_tx buffer size at `open_channel` time — kept in sync with
/// `MqttSafety` default. `handle_client` cannot resize an already-spawned
/// writer actor, so this is a static lower bound; if a caller's `MqttSafety`
/// raises `max_queued_messages` past this, P3's per-endpoint queue work
/// will pick that up at the dispatcher level.
const INITIAL_CMD_BUFFER_SIZE: usize = 1000;

// ----------------------------------------------------------------------------
// MqttClientProtocol
// ----------------------------------------------------------------------------

pub type DefaultMqttTransport = hotaru_core::connection::tcp::TcpTransport;
pub type MQTT = MqttClientProtocol<tokio::net::TcpStream, DefaultMqttTransport>;

/// MQTT over TLS (gated by `tls` feature). Mirrors `hotaru_http::HTTPS`.
#[cfg(feature = "tls")]
pub type MqttTlsProtocol = MqttClientProtocol<hotaru_tls::TlsStream, hotaru_tls::TlsTransport>;

/// `MQTTS` alias (MQTT over TLS), enabled by `tls` feature.
#[cfg(feature = "tls")]
#[allow(non_camel_case_types)]
pub type MQTTS = MqttTlsProtocol;

pub struct MqttClientProtocol<
    W: ConnStream = tokio::net::TcpStream,
    TS: TransportSpec<Wire = W> = DefaultMqttTransport,
> {
    /// Shared session channel slot. Cloned across protocol clones via `Arc`.
    /// First `open_channel` calls `set`; subsequent `acquire_channel` calls
    /// `get` and clones.
    session_channel: Arc<OnceLock<MqttChannel<W>>>,
    _ts: PhantomData<fn() -> TS>,
}

impl<W: ConnStream, TS: TransportSpec<Wire = W>> Clone for MqttClientProtocol<W, TS> {
    fn clone(&self) -> Self {
        Self {
            session_channel: self.session_channel.clone(),
            _ts: PhantomData,
        }
    }
}

impl<W: ConnStream, TS: TransportSpec<Wire = W>> Default for MqttClientProtocol<W, TS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W: ConnStream, TS: TransportSpec<Wire = W>> MqttClientProtocol<W, TS> {
    pub fn new() -> Self {
        Self {
            session_channel: Arc::new(OnceLock::new()),
            _ts: PhantomData,
        }
    }
}

#[async_trait]
impl<W, TS> Protocol for MqttClientProtocol<W, TS>
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
        ProtocolRole::Client
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

    fn tokenize_url(
        input: &str,
    ) -> Result<Vec<hotaru_core::url::RawToken>, hotaru_core::url::PatternError> {
        // Closes hotaru #4 (RFC_TRANS_ENDPOINT_DECOUPLE.md) on the client side:
        // user `endpoint!("sensors/+/temp", ...)` now natively understands
        // MQTT topic syntax (`/` separator, `+` single-level wildcard, `#`
        // multi-level wildcard) instead of the default HTTP URL lexer
        // mangling `+`/`#` into literal characters.
        crate::topic::tokenize_mqtt_filter(input)
    }

    fn lit_parser<'a>(input: &'a str) -> Vec<&'a str> {
        // MQTT topic at dispatch time: split on '/', no leading-empty
        // handling (MQTT topics have no leading '/' unlike HTTP URLs).
        // Empty input → empty Vec → root-endpoint slot (per upstream
        // Protocol::lit_parser docstring).
        crate::topic::split_mqtt_topic(input)
    }

    fn open_channel(
        self,
        reader: BufReader<<<Self::TS as TransportSpec>::Wire as ConnStream>::ReadHalf>,
        writer: <<Self::TS as TransportSpec>::Wire as ConnStream>::WriteHalf,
        meta: <<Self::TS as TransportSpec>::Wire as ConnStream>::Meta,
    ) -> Self::Channel {
        let channel = MqttChannel::new(
            reader,
            writer,
            &meta,
            ProtocolRole::Client,
            INITIAL_CMD_BUFFER_SIZE,
        );
        // First call wins; later open_channel attempts return their own channel
        // but only the first one is stash-acquirable.
        let _ = self.session_channel.set(channel.clone());
        channel
    }

    async fn handle(
        channel: &Self::Channel,
        runtime: Arc<RuntimeConfig>,
        root: Arc<UrlRoot<Self::Context, Self::TS>>,
    ) -> Result<ProtocolFlow, CtxError<Self>> {
        let result = handle_client(channel, runtime, root).await;
        // Whatever happened, the channel is done after one handle() invocation.
        channel.close();
        result
    }

    async fn acquire_channel(
        &self,
        _runtime: &Arc<RuntimeConfig>,
        _outbound: Arc<<Self::TS as TransportSpec>::Outbound>,
    ) -> Result<Self::Channel, CtxError<Self>> {
        let channel = self.session_channel.get().ok_or_else(|| {
            MqttError::NotConnected("call client.run_wire(wire) to establish session first".into())
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
            MqttError::Configuration("MqttClientConfig not registered in runtime statics".into())
        })?;

    // 1. Take exclusive reader ownership (single-take).
    let mut reader = channel
        .take_reader()
        .await
        .ok_or_else(|| MqttError::Configuration("reader already taken".into()))?;

    // 2. Send CONNECT
    let connect = build_connect(&config);
    channel.send_packet(Packet::Connect(connect))?;

    let max_packet_size = config.safety.max_packet_size();

    // 3. Wait for CONNACK with timeout
    let connack_packet = timeout(
        config.connect_timeout,
        read_packet(&mut reader, max_packet_size),
    )
    .await
    .map_err(|_| MqttError::Timeout(TimeoutKind::Connack))??;
    let Packet::Connack(ack) = connack_packet else {
        return Err(Violation::ExpectedConnack.into());
    };
    if ack.return_code != ConnackReturnCode::Accepted {
        return Err(Violation::ConnectionRefused(ack.return_code).into());
    }

    // Bind session.
    let _ = channel.session().bind.set(BindInfo {
        client_id: config.client_id.clone(),
        keep_alive: config.keep_alive_secs,
    });

    // 4. Initial subscriptions (if any)
    if !config.initial_subscriptions.is_empty() {
        let pkt_id = channel.session().allocate_packet_id();
        let (tx, rx) = oneshot::channel();
        channel
            .session()
            .install_ack_slot(pkt_id, AckSlot::Suback(tx));
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

    // 5. Per-endpoint FIFO dispatcher (spec §4.6). Each matched endpoint gets
    //    a lazy-spawned worker that drains its mpsc queue in arrival order.
    //    On `handle_client` return, the dispatcher drops → senders drop →
    //    workers drain queues, then exit.
    let dispatcher = EndpointDispatcher::<W, TS>::new(
        channel.clone(),
        config.default_inbound.clone(),
        config.safety.worker_idle_timeout(),
        config.safety.max_queued_messages().max(1),
    );

    // 6. Main select loop. Spec §3.1.2.10: keep_alive=0 disables the timer
    //    on both sides — we hold an interval value purely to satisfy the
    //    arm's type, then gate it with `if keep_alive_enabled`.
    let keep_alive_enabled = config.keep_alive_secs > 0;
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
                        if dispatch_client_inbound(
                            channel.clone(),
                            p,
                            &root,
                            &dispatcher,
                            config.safety.receive_maximum_inbound(),
                        )
                        .await?
                        {
                            break;  // disconnect
                        }
                    }
                    Err(MqttError::Io(_)) => break,    // wire closed
                    Err(e) => return Err(e),
                }
            }
            _ = ping_timer.tick(), if keep_alive_enabled => {
                // PINGREQ failure means writer is dead → break (W must-propagate)
                if channel.send_packet(Packet::Pingreq).is_err() {
                    break;
                }
            }
            _ = shutdown.notified() => break,
        }
    }

    // 7. Graceful DISCONNECT (W policy §1 — silent OK)
    let _ = channel.send_packet(Packet::Disconnect);
    // Dispatcher drops here → in-flight per-endpoint workers drain + exit.
    Ok(ProtocolFlow::Close)
}

/// Returns `Ok(true)` if loop should break (DISCONNECT received).
async fn dispatch_client_inbound<W, TS>(
    channel: MqttChannel<W>,
    packet: Packet,
    root: &Arc<UrlRoot<MqttContext<TS>, TS>>,
    dispatcher: &EndpointDispatcher<W, TS>,
    receive_max: usize,
) -> Result<bool, MqttError>
where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
{
    match packet {
        Packet::Publish(publish) => {
            // QoS≥1: ack BEFORE chain (O.2)
            ack_inbound_publish_pre_chain(&channel, &publish, receive_max)?;
            // For QoS 2: stashed on the session at ack time; dispatched when PUBREL arrives.
            if publish.qos == QoS::ExactlyOnce {
                return Ok(false);
            }
            dispatch_incoming(incoming_from_packet(&publish), root, dispatcher);
            Ok(false)
        }
        Packet::Puback(id) => {
            fire_ack(&channel, id, AckKind::Puback);
            channel.session().forget_outbound_inflight(id);
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
            channel.session().forget_outbound_inflight(id);
            Ok(false)
        }
        Packet::Pubrel(id) => {
            // Inbound QoS 2: take stored publish and dispatch
            if let Some(incoming) = channel.session().take_qos2_inbound(id) {
                dispatch_incoming(incoming, root, dispatcher);
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

/// Walk all endpoints matching `incoming.topic`, push each match to its
/// per-endpoint FIFO queue. Falls back to the default handler if no endpoint
/// matched. Sync (not async) — submission is non-blocking, chains run on
/// dispatcher workers.
fn dispatch_incoming<W, TS>(
    incoming: IncomingPublish,
    root: &UrlRoot<MqttContext<TS>, TS>,
    dispatcher: &EndpointDispatcher<W, TS>,
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
        dispatcher.dispatch_endpoint(node, incoming.clone());
    }

    if !matched {
        dispatcher.dispatch_fallback(incoming);
    }
}

// ============================================================================
// EndpointDispatcher — per-endpoint FIFO worker pool (spec §4.6 client side)
// ============================================================================
//
// One dispatcher per `handle_client` invocation; owns lazy-spawned workers,
// one per matched endpoint (keyed by `Arc::as_ptr(&node)`) plus a single
// fallback worker for the default inbound handler. Dispatcher drops when
// `handle_client` returns, which closes all queue senders; workers drain
// their remaining items then exit.

/// Key identifying one endpoint by its `Arc<UrlNode>` pointer identity.
type NodeKey = usize;

fn node_key<TS: TransportSpec>(node: &Arc<UrlNode<MqttContext<TS>, TS>>) -> NodeKey {
    Arc::as_ptr(node) as *const () as usize
}

type EndpointQueueMap<TS> =
    DashMap<NodeKey, mpsc::Sender<(IncomingPublish, Arc<UrlNode<MqttContext<TS>, TS>>)>>;

struct EndpointDispatcher<W: ConnStream, TS: TransportSpec<Wire = W>> {
    channel: MqttChannel<W>,
    /// Per-endpoint FIFO queues keyed by `node_key`. Lazy-spawned on first
    /// dispatch to that endpoint. Wrapped in `Arc` so each spawned worker
    /// can remove its own entry on idle-timeout exit (P3.E).
    endpoint_queues: Arc<EndpointQueueMap<TS>>,
    /// Lazy-spawned single FIFO worker for the default inbound handler.
    fallback_queue: std::sync::OnceLock<mpsc::Sender<IncomingPublish>>,
    default_handler: Option<Arc<dyn DefaultInboundHandler>>,
    /// `MqttSafety.worker_idle_timeout()`. `None` = workers stay alive
    /// until the channel drops them.
    idle_timeout: Option<Duration>,
    /// Per-queue capacity sourced from `MqttSafety.max_queued_messages()`.
    /// Bounds client-side inbound memory under a flooding/malicious broker
    /// (SAFETY_PROOF second-audit G1) — overflow drops silently the same
    /// way an idle-timed-out worker drops, see `dispatch_endpoint` below.
    queue_capacity: usize,
}

impl<W: ConnStream, TS: TransportSpec<Wire = W>> EndpointDispatcher<W, TS> {
    fn new(
        channel: MqttChannel<W>,
        default_handler: Option<Arc<dyn DefaultInboundHandler>>,
        idle_timeout: Option<Duration>,
        queue_capacity: usize,
    ) -> Self {
        Self {
            channel,
            endpoint_queues: Arc::new(DashMap::new()),
            fallback_queue: std::sync::OnceLock::new(),
            default_handler,
            idle_timeout,
            queue_capacity,
        }
    }

    fn dispatch_endpoint(
        &self,
        node: Arc<UrlNode<MqttContext<TS>, TS>>,
        incoming: IncomingPublish,
    ) {
        let key = node_key::<TS>(&node);
        let tx = self
            .endpoint_queues
            .entry(key)
            .or_insert_with(|| {
                let (tx, rx) = mpsc::channel(self.queue_capacity);
                tokio::spawn(endpoint_worker::<W, TS>(
                    rx,
                    self.channel.clone(),
                    self.endpoint_queues.clone(),
                    key,
                    self.idle_timeout,
                ));
                tx
            })
            .clone();
        // W §2 covers three drop modes here:
        //   - worker exited (channel closed) → bucket stale, next dispatch
        //     lazy-spawns afresh
        //   - idle-timeout self-remove → same as above
        //   - queue full (slow endpoint vs. flooding broker) → drop the
        //     new publish; the broker-receiver invariant (server holds an
        //     IS_QUEUE_FULL state on QoS≥1 inflight) handles redelivery on
        //     reconnect for persistent sessions. Per audit guidance, this
        //     bounds client memory under malicious/buggy upstream brokers.
        let _ = tx.try_send((incoming, node));
    }

    fn dispatch_fallback(&self, incoming: IncomingPublish) {
        let Some(handler) = self.default_handler.as_ref() else {
            return;
        };
        let tx = self.fallback_queue.get_or_init(|| {
            let (tx, rx) = mpsc::channel(self.queue_capacity);
            tokio::spawn(fallback_worker(rx, handler.clone(), self.idle_timeout));
            tx
        });
        // Same overflow semantics as `dispatch_endpoint` above.
        let _ = tx.try_send(incoming);
    }
}

async fn endpoint_worker<W, TS>(
    mut rx: mpsc::Receiver<(IncomingPublish, Arc<UrlNode<MqttContext<TS>, TS>>)>,
    channel: MqttChannel<W>,
    queues: Arc<EndpointQueueMap<TS>>,
    self_key: NodeKey,
    idle_timeout: Option<Duration>,
) where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
{
    loop {
        let next = match idle_timeout {
            Some(d) => match tokio::time::timeout(d, rx.recv()).await {
                Ok(item) => item,
                Err(_) => {
                    // Idle timeout — release the slot so dispatch_endpoint
                    // lazy-spawns a fresh worker on the next hit. There is
                    // a tiny race with a concurrent dispatch_endpoint that
                    // grabs `tx` just before we exit — that message gets
                    // dropped (W §2 acceptable for idle-bound workers).
                    queues.remove(&self_key);
                    return;
                }
            },
            None => rx.recv().await,
        };
        let Some((incoming, node)) = next else { return };
        let ctx = MqttContext::<TS>::for_inbound_dispatch(channel.clone(), incoming, node.clone());
        let _ = node.run(ctx).await;
    }
}

async fn fallback_worker(
    mut rx: mpsc::Receiver<IncomingPublish>,
    handler: Arc<dyn DefaultInboundHandler>,
    idle_timeout: Option<Duration>,
) {
    loop {
        let next = match idle_timeout {
            Some(d) => match tokio::time::timeout(d, rx.recv()).await {
                Ok(item) => item,
                Err(_) => return, // fallback is OnceLock-backed; we can't
                                  // lazy-respawn anyway, so just exit and
                                  // accept future drops silently.
            },
            None => rx.recv().await,
        };
        let Some(incoming) = next else { return };
        handler.handle(incoming).await;
    }
}

// ============================================================================
// Protocol::send — outpoint outbound execution
// ============================================================================

async fn send_impl<TS>(mut ctx: MqttContext<TS>) -> Result<MqttContext<TS>, MqttError>
where
    TS: TransportSpec,
{
    let channel = ctx.channel().cloned().ok_or(MqttError::NotConnected(
        "no channel installed in ctx".into(),
    ))?;

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
            channel.session().install_ack_slot(id, AckSlot::Puback(tx));
            channel.send_publish(packet)?;
            let acked = timeout(DEFAULT_ACK_TIMEOUT, rx)
                .await
                .map_err(|_| {
                    let _ = channel.session().take_ack_slot(id);
                    MqttError::Timeout(TimeoutKind::Ack)
                })?
                .map_err(|_| MqttError::ChannelClosed)?;
            Ok(MqttResponse::Published(PublishAck::Acknowledged(acked)))
        }
        QoS::ExactlyOnce => {
            let id = packet_id.expect("alloc'd above");
            let (rec_tx, rec_rx) = oneshot::channel();
            channel
                .session()
                .install_ack_slot(id, AckSlot::Pubrec(rec_tx));
            channel.send_publish(packet)?;
            timeout(DEFAULT_ACK_TIMEOUT, rec_rx)
                .await
                .map_err(|_| {
                    let _ = channel.session().take_ack_slot(id);
                    MqttError::Timeout(TimeoutKind::Ack)
                })?
                .map_err(|_| MqttError::ChannelClosed)?;

            let (comp_tx, comp_rx) = oneshot::channel();
            channel
                .session()
                .install_ack_slot(id, AckSlot::Pubcomp(comp_tx));
            let comp_id = timeout(DEFAULT_ACK_TIMEOUT, comp_rx)
                .await
                .map_err(|_| {
                    let _ = channel.session().take_ack_slot(id);
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
        .install_ack_slot(packet_id, AckSlot::Suback(tx));
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
            let _ = channel.session().take_ack_slot(packet_id);
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
        .install_ack_slot(packet_id, AckSlot::Unsuback(tx));
    channel.send_packet(Packet::Unsubscribe(UnsubscribePacket { packet_id, topics }))?;
    timeout(DEFAULT_ACK_TIMEOUT, rx)
        .await
        .map_err(|_| {
            let _ = channel.session().take_ack_slot(packet_id);
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
    if let Some(slot) = channel.session().take_ack_slot(id) {
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
    if let Some(AckSlot::Suback(tx)) = channel.session().take_ack_slot(packet.packet_id) {
        let _ = tx.send(packet.return_codes);
    }
}

fn fire_unsuback<W: ConnStream>(channel: &MqttChannel<W>, id: u16) {
    if let Some(AckSlot::Unsuback(tx)) = channel.session().take_ack_slot(id) {
        let _ = tx.send(());
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
