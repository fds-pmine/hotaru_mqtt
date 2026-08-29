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
use tokio::sync::mpsc;
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
use crate::session::{AckKind, BindInfo};

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
// keep-alive
// ============================================================================

/// The inactivity deadline a server enforces for a client's declared
/// `keep_alive`, or `None` when the client asked for none.
///
/// Spec §3.1.2.10: the client owes traffic at least every `keep_alive` seconds,
/// and the server disconnects it after 1.5× that without hearing anything. The
/// 1.5 is the grace — a client pinging on schedule must survive ordinary jitter.
/// `keep_alive == 0` turns the mechanism off, and the server must then NOT
/// disconnect for inactivity, so it is `None` rather than any duration.
///
/// Milliseconds rather than `(secs * 3) / 2`: integer division truncates, which
/// loses half a second on every odd value and the whole grace at `keep_alive`
/// of 1. Multiplying 1500 ms per second is exact for every input, and `u64`
/// leaves the largest legal value — 65535 × 1500 ms, roughly 27 hours — nowhere
/// near overflow.
fn server_read_deadline(keep_alive: u16) -> Option<Duration> {
    if keep_alive == 0 {
        None
    } else {
        Some(Duration::from_millis(keep_alive as u64 * 1500))
    }
}

/// How often a client sends PINGREQ, or `None` when it declared no keep-alive.
///
/// The client's obligation is its own `keep_alive`, not the server's 1.5× grace:
/// pinging on the grace period would be late by construction.
fn client_ping_interval(keep_alive: u16) -> Option<Duration> {
    if keep_alive == 0 {
        None
    } else {
        Some(Duration::from_secs(keep_alive as u64))
    }
}

/// What one attempt to read a packet under a deadline can end as.
///
/// A named three-way outcome instead of `Option<Result<Packet, MqttError>>`:
/// the nesting made callers pattern-match through two layers whose meanings
/// are easy to confuse, and none of the three cases is an "absence" or a
/// generic failure — each has a name of its own.
enum ReadOutcome {
    /// A whole packet arrived before the deadline.
    Packet(Packet),
    /// The read itself failed (wire closed, malformed bytes, ...).
    Failed(MqttError),
    /// The deadline elapsed with nothing read. Only possible when a deadline
    /// exists — with `keep_alive = 0` there is none and this never happens.
    DeadlineElapsed,
}

/// Read one packet, giving up if `deadline` elapses first.
/// A `deadline` of `None` waits forever, which is what `keep_alive = 0` asks for.
async fn read_packet_before<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    max_size: usize,
    deadline: Option<Duration>,
) -> ReadOutcome {
    let read_result = match deadline {
        Some(limit) => match timeout(limit, read_packet(reader, max_size)).await {
            Ok(finished_in_time) => finished_in_time,
            Err(_elapsed) => return ReadOutcome::DeadlineElapsed,
        },
        None => read_packet(reader, max_size).await,
    };
    match read_result {
        Ok(packet) => ReadOutcome::Packet(packet),
        Err(error) => ReadOutcome::Failed(error),
    }
}

/// Tick, or never fire at all when the client declared no keep-alive.
/// `pending()` is a future that never completes, so the `select!` arm holding it
/// simply never wins — no timer, no wakeups.
async fn tick_or_never(timer: &mut Option<tokio::time::Interval>) {
    match timer {
        Some(t) => {
            t.tick().await;
        }
        None => std::future::pending::<()>().await,
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
    //
    // Sent, not awaited. Waiting for the SUBACK here cannot work: this function
    // owns the reader and does not poll it until the loop below, so nothing
    // drains the socket while the wait is in progress and `fire_suback` — the
    // only thing that resolves the slot — is only reachable from that loop. An
    // awaited SUBACK therefore always expired, and the session died with
    // `Timeout(Ack)`, so every client configured with an initial subscription
    // failed to connect.
    //
    // Nothing was lost by dropping the wait: the SUBACK's return codes were
    // discarded (`let _ =`) rather than surfaced, so the wait bought delay and
    // no information. The loop dispatches the SUBACK normally; with no slot
    // registered for it, `fire_suback` ignores it per the W §4 silent policy.
    if !config.initial_subscriptions.is_empty() {
        let pkt_id = channel.session().allocate_packet_id();
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
    }

    // 5. Main select loop
    let mut ping_timer = match client_ping_interval(config.keep_alive_secs) {
        Some(interval) => {
            let mut t = tokio::time::interval(interval);
            t.tick().await; // skip first immediate tick
            Some(t)
        }
        None => None,
    };
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
            _ = tick_or_never(&mut ping_timer) => {
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
        Packet::Puback(packet_id) => {
            channel.session().wake_ack_waiter(packet_id, AckKind::Puback);
            channel.session().clear_outbound_inflight(packet_id);
            Ok(false)
        }
        Packet::Pubrec(packet_id) => {
            // QoS 2 phase 1: send PUBREL, wait for PUBCOMP
            channel.session().wake_ack_waiter(packet_id, AckKind::Pubrec);
            channel.send_packet(Packet::Pubrel(packet_id))?;
            Ok(false)
        }
        Packet::Pubcomp(packet_id) => {
            channel.session().wake_ack_waiter(packet_id, AckKind::Pubcomp);
            channel.session().clear_outbound_inflight(packet_id);
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
        Packet::Suback(suback) => {
            channel
                .session()
                .wake_suback_waiter(suback.packet_id, suback.return_codes);
            Ok(false)
        }
        Packet::Unsuback(packet_id) => {
            channel.session().wake_unsuback_waiter(packet_id);
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

    // 2. Enforce the keep-alive policy before anything is allocated for this
    //    peer. A keep-alive is the peer's own declaration, so an out-of-policy
    //    value is refused rather than clamped: clamping would leave the client
    //    believing it has a grace period it does not have. `ServerUnavailable`
    //    is the closest 3.1.1 return code — the connection is refused on the
    //    server's terms, not because the credentials or the identifier are bad.
    let safety = broker.safety();
    let keep_alive_refused = if connect.keep_alive == 0 {
        !safety.allows_disabled_keep_alive()
    } else {
        connect.keep_alive > safety.max_keep_alive()
    };
    if keep_alive_refused {
        let return_code = ConnackReturnCode::ServerUnavailable;
        let _ = channel.send_packet(Packet::Connack(ConnackPacket {
            session_present: false,
            return_code,
        }));
        return Err(Violation::ConnectionRefused(return_code).into());
    }

    // 3. Authenticate
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

    // The channel already carries an id that is unique per connection and
    // stable across its clones; the client_id stops being unique the moment a
    // takeover is in flight, so every broker call that means "this connection"
    // rather than "this name" takes this alongside it.
    let connection_id = channel.connection_id();

    // 4. Register session (broker takes channel clone)
    let session_present = broker
        .register_session(client_id.clone(), channel.clone(), will, clean_session)
        .await;

    let _ = channel.session().bind().set(BindInfo {
        client_id: client_id.clone(),
        keep_alive,
    });

    // 5. Send CONNACK
    //
    // The session is already registered at this point, so a failure here has
    // to unregister before it propagates — the same obligation the read loop
    // below discharges through `terminal_error`.
    if let Err(e) = channel.send_packet(Packet::Connack(ConnackPacket {
        session_present,
        return_code: ConnackReturnCode::Accepted,
    })) {
        broker.unregister_session(&client_id, connection_id, false).await;
        return Err(e);
    }

    // 6. Main select loop with keep-alive deadline (1.5× grace per spec). A
    //    `None` deadline means keep_alive = 0, which only reaches here when the
    //    operator opted in through `MqttSafety::allow_disabled_keep_alive`.
    let read_deadline = server_read_deadline(keep_alive);

    // Endpoint chains and fanout run on their own task (finding: an endpoint
    // publishing QoS >= 1 over this same connection parks waiting for an ack
    // that only this reader can deliver — with the chain inline, the reader
    // was the thing being blocked). The queue is the handoff; see
    // `run_publish_chain_worker` for the ordering contract.
    let (publish_work_queue, publish_work) = mpsc::unbounded_channel::<PublishPacket>();
    let chain_worker = tokio::spawn(run_publish_chain_worker(
        channel.clone(),
        broker.clone(),
        client_id.clone(),
        runtime.clone(),
        root.clone(),
        publish_work,
    ));

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
            outcome = read_packet_before(&mut reader, max_packet_size, read_deadline) => {
                match outcome {
                    ReadOutcome::DeadlineElapsed => break,             // keep-alive deadline = crash
                    ReadOutcome::Failed(MqttError::Io(_)) => break,    // wire closed = crash
                    ReadOutcome::Failed(error) => {
                        terminal_error = Some(error);
                        break;
                    }
                    ReadOutcome::Packet(Packet::Disconnect) => {
                        graceful = true;
                        break;
                    }
                    ReadOutcome::Packet(inbound) => {
                        if let Err(error) = dispatch_server_inbound(
                            channel.clone(),
                            broker.clone(),
                            &client_id,
                            connection_id,
                            inbound,
                            &publish_work_queue,
                        ).await {
                            terminal_error = Some(error);
                            break;
                        }
                    }
                }
            }
            _ = shutdown.notified() => break,
        }
    }

    // 6. Wind down the chain worker before unregistering, so the Will cannot
    //    overtake publishes this connection already delivered. Dropping the
    //    queue ends the worker's input; closing the channel resolves any ack
    //    the worker is parked on (abandon drops the slot senders, which the
    //    send path reports as ChannelClosed) — without the close, a worker
    //    stuck waiting for an ack only our now-stopped reader could deliver
    //    would hold teardown for the full ack timeout. Close is idempotent;
    //    the framework closes again after handle() returns.
    drop(publish_work_queue);
    channel.close();
    let _ = chain_worker.await;

    //    Unregister (graceful flag drives Will trigger). Single exit: this runs
    //    on every path out of the loop, including the failing ones.
    broker.unregister_session(&client_id, connection_id, graceful).await;
    if let Some(e) = terminal_error {
        // Still reported to the framework, just after cleanup rather than
        // instead of it. `graceful` stays false on this path, which is what
        // makes the Will fire (MQTT-3.1.2-5).
        return Err(e);
    }
    Ok(ProtocolFlow::Close)
}

/// The per-connection worker that runs endpoint chains and fanout, off the
/// reader task.
///
/// One worker per connection, fed in arrival order over an unbounded queue, so
/// this connection's publishes still reach the chain and the broker in the
/// order they were sent — a `tokio::spawn` per publish would lose that. What
/// the handoff buys is that the reader keeps draining the socket while a chain
/// runs: the acks a chain-originated publish waits for can now actually
/// arrive, which is the deadlock this split removes.
///
/// Exits when the sender side is dropped (connection teardown) and the queue
/// is drained.
async fn run_publish_chain_worker<W, TS>(
    channel: MqttChannel<W>,
    broker: Broker<W>,
    source_client_id: Arc<str>,
    runtime: Arc<RuntimeConfig>,
    root: Arc<UrlRoot<MqttContext<TS>, TS>>,
    mut publish_work: mpsc::UnboundedReceiver<PublishPacket>,
) where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
{
    while let Some(publish) = publish_work.recv().await {
        let fanout_packet = run_server_chain_then_decide_fanout(
            channel.clone(),
            publish,
            runtime.clone(),
            root.clone(),
        )
        .await;
        if let Some(packet) = fanout_packet {
            broker.publish(&source_client_id, packet).await;
        }
    }
}

async fn dispatch_server_inbound<W>(
    channel: MqttChannel<W>,
    broker: Broker<W>,
    client_id: &Arc<str>,
    connection_id: u64,
    packet: Packet,
    publish_work_queue: &mpsc::UnboundedSender<PublishPacket>,
) -> Result<(), MqttError>
where
    W: ConnStream,
{
    match packet {
        Packet::Publish(publish) => {
            // Ack BEFORE chain (O.2) — still on the reader, before the
            // handoff, so the ordering invariant is untouched by the split.
            ack_inbound_publish_pre_chain(&channel, &publish)?;
            // For QoS 2: stored in qos2_recv on ack; fanout happens when PUBREL arrives.
            if publish.qos == QoS::ExactlyOnce {
                return Ok(());
            }
            // QoS 0 / 1: hand the chain + fanout to the worker. The reader
            // must not run user code — an endpoint publishing QoS >= 1 back
            // over this connection waits for an ack only this reader can
            // deliver.
            publish_work_queue
                .send(publish)
                .map_err(|_worker_gone| MqttError::ChannelClosed)?;
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
            let codes = broker.subscribe(client_id, connection_id, &filters).await;
            channel.send_packet(Packet::Suback(SubackPacket {
                packet_id: s.packet_id,
                return_codes: codes,
            }))?;
            Ok(())
        }
        Packet::Unsubscribe(u) => {
            broker.unsubscribe(client_id, connection_id, &u.topics).await;
            channel.send_packet(Packet::Unsuback(u.packet_id))?;
            Ok(())
        }
        Packet::Pingreq => {
            channel.send_packet(Packet::Pingresp)?;
            Ok(())
        }
        Packet::Puback(packet_id) => {
            // Settled against the channel the ack arrived on, not by looking
            // the client_id up in the broker: during a takeover that name
            // resolves to the newer connection and this ack belongs to the
            // earlier one. The PUBREL arm below already resolves this way.
            channel.session().wake_ack_waiter(packet_id, AckKind::Puback);
            channel.session().clear_outbound_inflight(packet_id);
            Ok(())
        }
        Packet::Pubrec(packet_id) => {
            // QoS 2 phase 1. Waking the waiter is what lets `send_publish`
            // proceed to park its PUBCOMP waiter; without it the flow stalls
            // for the full ack timeout even though the peer answered.
            channel.session().wake_ack_waiter(packet_id, AckKind::Pubrec);
            // Deliberately no `clear_outbound_inflight`: the flow is half done,
            // and the message has to stay retransmittable until PUBCOMP.
            channel.send_packet(Packet::Pubrel(packet_id))?;
            Ok(())
        }
        Packet::Pubcomp(packet_id) => {
            channel.session().wake_ack_waiter(packet_id, AckKind::Pubcomp);
            channel.session().clear_outbound_inflight(packet_id);
            Ok(())
        }
        Packet::Pubrel(packet_id) => {
            // QoS 2 inbound publish phase 2: release the stored publish to the
            // worker. PUBCOMP is sent from the reader right away — the peer's
            // handshake must not wait on the chain.
            if let Some((_, stored)) = channel.session().qos2_recv.remove(&packet_id) {
                let publish = PublishPacket {
                    topic: stored.topic.clone(),
                    payload: stored.payload.clone(),
                    dup: false,
                    qos: stored.qos,
                    retain: stored.retain,
                    packet_id: Some(packet_id),
                };
                publish_work_queue
                    .send(publish)
                    .map_err(|_worker_gone| MqttError::ChannelClosed)?;
            }
            channel.send_packet(Packet::Pubcomp(packet_id))?;
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
            let packet_id = packet_id.expect("alloc'd above");
            let puback_received = channel
                .session()
                .park_publish_ack_waiter(packet_id, AckKind::Puback);
            channel.send_publish(packet)?;
            let acknowledged_id = timeout(DEFAULT_ACK_TIMEOUT, puback_received)
                .await
                .map_err(|_timed_out| {
                    channel.session().cancel_ack_waiter(packet_id);
                    MqttError::Timeout(TimeoutKind::Ack)
                })?
                .map_err(|_sender_dropped| MqttError::ChannelClosed)?;
            Ok(MqttResponse::Published(PublishAck::Acknowledged(acknowledged_id)))
        }
        QoS::ExactlyOnce => {
            let packet_id = packet_id.expect("alloc'd above");
            // Two-phase: PUBREC first, then PUBCOMP after we send PUBREL.
            let pubrec_received = channel
                .session()
                .park_publish_ack_waiter(packet_id, AckKind::Pubrec);
            channel.send_publish(packet)?;
            timeout(DEFAULT_ACK_TIMEOUT, pubrec_received)
                .await
                .map_err(|_timed_out| {
                    channel.session().cancel_ack_waiter(packet_id);
                    MqttError::Timeout(TimeoutKind::Ack)
                })?
                .map_err(|_sender_dropped| MqttError::ChannelClosed)?;

            // PUBREL was sent by the inbound dispatch when PUBREC fired.
            // Now wait for PUBCOMP.
            let pubcomp_received = channel
                .session()
                .park_publish_ack_waiter(packet_id, AckKind::Pubcomp);
            let completed_id = timeout(DEFAULT_ACK_TIMEOUT, pubcomp_received)
                .await
                .map_err(|_timed_out| {
                    channel.session().cancel_ack_waiter(packet_id);
                    MqttError::Timeout(TimeoutKind::Ack)
                })?
                .map_err(|_sender_dropped| MqttError::ChannelClosed)?;
            Ok(MqttResponse::Published(PublishAck::Completed(completed_id)))
        }
    }
}

async fn send_subscribe<W: ConnStream>(
    channel: &MqttChannel<W>,
    filters: Vec<TopicFilter>,
) -> Result<MqttResponse, MqttError> {
    let packet_id = channel.session().allocate_packet_id();
    let suback_received = channel.session().park_suback_waiter(packet_id);
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
    let return_codes = timeout(DEFAULT_ACK_TIMEOUT, suback_received)
        .await
        .map_err(|_timed_out| {
            channel.session().cancel_ack_waiter(packet_id);
            MqttError::Timeout(TimeoutKind::Ack)
        })?
        .map_err(|_sender_dropped| MqttError::ChannelClosed)?;
    Ok(MqttResponse::Subscribed(return_codes))
}

async fn send_unsubscribe<W: ConnStream>(
    channel: &MqttChannel<W>,
    topics: Vec<Arc<str>>,
) -> Result<MqttResponse, MqttError> {
    let packet_id = channel.session().allocate_packet_id();
    let unsuback_received = channel.session().park_unsuback_waiter(packet_id);
    channel.send_packet(Packet::Unsubscribe(UnsubscribePacket {
        packet_id,
        topics,
    }))?;
    timeout(DEFAULT_ACK_TIMEOUT, unsuback_received)
        .await
        .map_err(|_timed_out| {
            channel.session().cancel_ack_waiter(packet_id);
            MqttError::Timeout(TimeoutKind::Ack)
        })?
        .map_err(|_sender_dropped| MqttError::ChannelClosed)?;
    Ok(MqttResponse::Unsubscribed)
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

#[cfg(test)]
mod test;
