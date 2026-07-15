//! `MqttServerProtocol` — server-side MQTT 3.1.1 protocol handler.
//!
//! Each inbound connection produces a fresh `MqttChannel`; `handle_server`
//! runs CONNECT → CONNACK → main select loop → unregister.
//!
//! Sibling of `hotaru_mqtt::MqttClientProtocol`; the symmetric split keeps
//! client / sensor builds free of broker code.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use hotaru_core::app::common::RuntimeConfig;
use hotaru_core::connection::{ConnStream, HotaruRead, HotaruWrite, TransportSpec};
use hotaru_core::protocol::{Channel as _, CtxError, Protocol, ProtocolFlow, ProtocolRole};
use hotaru_core::app::runtime::{Either, RuntimeSpec};
use hotaru_core::url::UrlRoot;
use hotaru_rt_tokio::TokioRuntime;

use crate::traits::TenantId;
use hotaru_mqtt::ack_inbound_publish_pre_chain;
use hotaru_mqtt::channel::MqttChannel;
use hotaru_mqtt::codec::read_packet;
use hotaru_mqtt::context::MqttContext;
use hotaru_mqtt::error::{MqttError, TimeoutKind, Violation};
use hotaru_mqtt::packet::{
    AckPacket, ConnackPacket, ConnackReturnCode, Packet, ProtocolVersion, PublishPacket,
    SubackPacket, incoming_from_packet,
};
use hotaru_mqtt::request::{QoS, TopicFilter, WillMessage};
use hotaru_mqtt::session::BindInfo;
use tracing::{debug, info, warn};

use crate::broker::Broker;
use crate::statics::BROKER_STATICS_KEY;

// ----------------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------------

/// Server-side timeout for the initial CONNECT packet after wire is accepted.
const CONNECT_RECEIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Initial cmd_tx buffer size at `open_channel` time — matches
/// `MqttSafety::max_queued_messages()` default (1000). See the matching
/// constant in `hotaru_mqtt::protocol` for rationale.
const INITIAL_CMD_BUFFER_SIZE: usize = 1000;

/// Sentinel "no deadline" for `tokio::time::timeout` when keep_alive=0
/// disables the read timer (spec §3.1.2.10). 30 days = ~max we ever care
/// about; honest infinity isn't expressible by `Duration` math without
/// risking overflow downstream.
const KEEP_ALIVE_DISABLED_READ_TIMEOUT: Duration = Duration::from_secs(30 * 24 * 60 * 60);

// ----------------------------------------------------------------------------
// MqttServerProtocol
// ----------------------------------------------------------------------------

pub type DefaultMqttTransport = hotaru_io_tokio::TcpTransport;
#[allow(non_camel_case_types)]
pub type MQTT_SERVER = MqttServerProtocol<hotaru_io_tokio::TcpStream, DefaultMqttTransport>;

/// MQTT-server over TLS (gated by `tls` feature). Mirrors core's `MQTTS`.
#[cfg(feature = "tls")]
pub type MqttTlsServerProtocol =
    MqttServerProtocol<hotaru_tls::TlsStream, hotaru_tls::TlsTransport>;

/// `MQTTS_SERVER` alias, enabled by `tls` feature.
#[cfg(feature = "tls")]
#[allow(non_camel_case_types)]
pub type MQTTS_SERVER = MqttTlsServerProtocol;

pub struct MqttServerProtocol<
    W: ConnStream = hotaru_io_tokio::TcpStream,
    TS: TransportSpec<Wire = W> = DefaultMqttTransport,
    Rt: RuntimeSpec = TokioRuntime,
> {
    _w: PhantomData<fn() -> W>,
    _ts: PhantomData<fn() -> TS>,
    _rt: PhantomData<fn() -> Rt>,
}

impl<W: ConnStream, TS: TransportSpec<Wire = W>, Rt: RuntimeSpec> Clone
    for MqttServerProtocol<W, TS, Rt>
{
    fn clone(&self) -> Self {
        Self {
            _w: PhantomData,
            _ts: PhantomData,
            _rt: PhantomData,
        }
    }
}

impl<W: ConnStream, TS: TransportSpec<Wire = W>, Rt: RuntimeSpec> Default
    for MqttServerProtocol<W, TS, Rt>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<W: ConnStream, TS: TransportSpec<Wire = W>, Rt: RuntimeSpec> MqttServerProtocol<W, TS, Rt> {
    pub fn new() -> Self {
        Self {
            _w: PhantomData,
            _ts: PhantomData,
            _rt: PhantomData,
        }
    }
}

impl<W, TS, Rt> Protocol for MqttServerProtocol<W, TS, Rt>
where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
    Rt: RuntimeSpec,
    MqttError: From<<TS as TransportSpec>::IoError>,
    W::ReadHalf: HotaruRead,
    W::WriteHalf: HotaruWrite,
{
    type Wire = W;
    type TS = TS;
    type Channel = MqttChannel<W, Rt>;
    type Stream = ();
    type Message = Packet;
    type Context = MqttContext<TS, Rt>;

    fn name(&self) -> &'static str {
        "mqtt-server"
    }

    fn role(&self) -> ProtocolRole {
        ProtocolRole::Server
    }

    fn default_connection_timeout(&self) -> Option<Duration> {
        None
    }

    fn detect(initial_bytes: &[u8]) -> bool {
        initial_bytes
            .first()
            .map(|b| (b >> 4) == 1)
            .unwrap_or(false)
    }

    fn tokenize_url(
        input: &str,
    ) -> Result<Vec<hotaru_core::url::RawToken>, hotaru_core::url::PatternError> {
        // Closes hotaru #4 on the server side: when a broker host wires
        // `Server::register::<MqttServerProtocol, _>("sensors/+/temp", ...)`,
        // the framework's HTTP URL lexer no longer mangles `+`/`#` into
        // literals. Both client (MqttClientProtocol) and server overrides
        // share the same MQTT-flavored lexer so registered patterns match
        // wire filters identically.
        hotaru_mqtt::topic::tokenize_mqtt_filter(input)
    }

    fn lit_parser<'a>(input: &'a str) -> Vec<&'a str> {
        hotaru_mqtt::topic::split_mqtt_topic(input)
    }

    fn open_channel(
        self,
        reader: <<<Self::TS as TransportSpec>::Wire as ConnStream>::ReadHalf as HotaruRead>::Buffered,
        writer: <<<Self::TS as TransportSpec>::Wire as ConnStream>::WriteHalf as HotaruWrite>::Buffered,
        meta: <<Self::TS as TransportSpec>::Wire as ConnStream>::Meta,
    ) -> Self::Channel {
        MqttChannel::new(
            reader,
            writer,
            &meta,
            ProtocolRole::Server,
            INITIAL_CMD_BUFFER_SIZE,
        )
    }

    async fn handle(
        channel: &Self::Channel,
        runtime: Arc<RuntimeConfig>,
        root: Arc<UrlRoot<Self::Context, Self::TS>>,
    ) -> Result<ProtocolFlow, CtxError<Self>> {
        let result = handle_server(channel, runtime, root).await;
        channel.close();
        result
    }

    async fn acquire_channel(
        &self,
        _runtime: &Arc<RuntimeConfig>,
        _outbound: Arc<<Self::TS as TransportSpec>::Outbound>,
    ) -> Result<Self::Channel, CtxError<Self>> {
        Err(MqttError::Configuration(
            "acquire_channel called on MqttServerProtocol".into(),
        ))
    }

    async fn send(_ctx: Self::Context) -> Result<Self::Context, CtxError<Self>> {
        Err(MqttError::Configuration(
            "MqttServerProtocol does not implement send (outpoint)".into(),
        ))
    }

    fn install_channel(ctx: &mut Self::Context, channel: Self::Channel) {
        ctx.install_channel(channel);
    }
}

// ============================================================================
// handle_server — per-connection session loop
// ============================================================================

async fn handle_server<W, TS, Rt>(
    channel: &MqttChannel<W, Rt>,
    runtime: Arc<RuntimeConfig>,
    root: Arc<UrlRoot<MqttContext<TS, Rt>, TS>>,
) -> Result<ProtocolFlow, MqttError>
where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
    Rt: RuntimeSpec,
    W::ReadHalf: HotaruRead,
{
    let broker = runtime
        .get_static::<Broker<W, Rt>>(BROKER_STATICS_KEY)
        .ok_or_else(|| MqttError::Configuration("Broker not registered".into()))?;

    // P6: idempotent `$SYS/broker/*` initialization on first connection.
    broker.init_sys().await;

    let max_packet_size = broker.safety().max_packet_size();

    let mut reader = channel
        .take_reader()
        .await
        .ok_or_else(|| MqttError::Configuration("reader already taken".into()))?;

    // 1. Read CONNECT with timeout. The version argument only shapes
    //    non-CONNECT frames; CONNECT itself carries its protocol level,
    //    so the pre-handshake default is fine for either client kind.
    let connect_packet = Rt::timeout(
        CONNECT_RECEIVE_TIMEOUT,
        read_packet(&mut reader, max_packet_size, ProtocolVersion::default()),
    )
    .await
    .map_err(|_| MqttError::Timeout(TimeoutKind::ConnectReceive))??;
    let Packet::Connect(connect) = connect_packet else {
        return Err(Violation::ExpectedConnect.into());
    };

    // Negotiate the session's wire version from CONNECT (v5 §3.1.2.2).
    // Must happen before any reply so CONNACK is encoded in-kind.
    let version = connect.version;
    channel.set_protocol_version(version);

    // spec §3.1.3.1: empty client_id requires clean_session=true; broker then
    // assigns a unique identifier. If clean_session=false + empty id,
    // CONNACK 0x02 IdentifierRejected. Checked before resolve/auth so a
    // refused id never reaches downstream policy hooks.
    if connect.client_id.is_empty() && !connect.clean_session {
        warn!(
            target: "hotaru_mqtt_broker",
            "rejecting CONNECT: empty client_id requires clean_session=1"
        );
        let _ = channel.send_packet(Packet::Connack(ConnackPacket {
            properties: Default::default(),
            session_present: false,
            return_code: ConnackReturnCode::IdentifierRejected,
        }));
        return Err(Violation::ConnectionRefused(ConnackReturnCode::IdentifierRejected).into());
    }

    // v5 §4.12 / §3.2.2.2: enhanced authentication is not implemented. A
    // CONNECT carrying an Authentication Method property must be refused
    // with 0x8C (Bad authentication method) rather than silently falling
    // through to password auth with the property ignored. Checked
    // pre-admission alongside the identifier rule: a refused CONNECT
    // never costs a connection slot.
    if connect.properties.authentication_method.is_some() {
        warn!(
            target: "hotaru_mqtt_broker",
            client_id = %connect.client_id,
            "rejecting CONNECT: enhanced authentication (v5 AUTH) not supported"
        );
        let _ = channel.send_packet(Packet::Connack(ConnackPacket {
            properties: Default::default(),
            session_present: false,
            return_code: ConnackReturnCode::BadAuthenticationMethod,
        }));
        return Err(
            Violation::ConnectionRefused(ConnackReturnCode::BadAuthenticationMethod).into(),
        );
    }

    // 2a. Admission control FIRST (SAFETY_PROOF v3 U7): a `TenantResolver`
    //     impl that does DNS / DB lookups would otherwise be exercisable
    //     without occupying a connection slot, opening a DoS amplification
    //     for pre-admission policy hooks. Refuse early when at
    //     `BrokerSafety.max_connections()`. The matching `release_connection`
    //     on every error path below MUST be kept in sync.
    if !broker.try_admit_connection() {
        warn!(
            target: "hotaru_mqtt_broker",
            active = broker.active_connection_count(),
            "rejecting CONNECT: max_connections reached"
        );
        let _ = channel.send_packet(Packet::Connack(ConnackPacket {
            properties: Default::default(),
            session_present: false,
            return_code: ConnackReturnCode::ServerUnavailable,
        }));
        return Err(Violation::ConnectionRefused(ConnackReturnCode::ServerUnavailable).into());
    }

    // 2b. Resolve tenant — runs BEFORE authenticate so the authenticator
    //     can scope per-tenant credentials (D17 / D21). Default
    //     `SingleTenantResolver` returns `None` → single-tenant behavior.
    let tenant: Option<TenantId> = broker.resolve_tenant(&connect, channel.remote_addr()).await;

    // 2c. Authenticate within the resolved tenant scope.
    let auth = broker
        .authenticate(tenant.as_ref(), &connect, channel.remote_addr())
        .await;
    if !auth.accepted {
        warn!(
            target: "hotaru_mqtt_broker",
            client_id = %connect.client_id,
            return_code = ?auth.return_code,
            "authentication rejected"
        );
        let _ = channel.send_packet(Packet::Connack(ConnackPacket {
            properties: Default::default(),
            session_present: false,
            return_code: auth.return_code,
        }));
        // U7: admission slot was reserved above — release it on auth fail.
        broker.release_connection();
        return Err(Violation::ConnectionRefused(auth.return_code).into());
    }

    let client_id: Arc<str> = if connect.client_id.is_empty() {
        let id = format!("hotaru-auto-{}", channel.connection_id());
        Arc::from(id.as_str())
    } else {
        connect.client_id.clone()
    };
    let keep_alive = connect.keep_alive;
    let clean_session = connect.clean_session;
    let will = connect.will.as_ref().map(|w| WillMessage {
        topic: w.topic.clone(),
        payload: w.payload.clone(),
        qos: w.qos,
        retain: w.retain,
        // v5 §3.1.3.2: Will Properties travel onto the will PUBLISH when
        // it fires (Content Type / Response Topic / Correlation Data /
        // Message Expiry / User Properties).
        properties: w.properties.clone(),
    });

    // v5 §3.1.2.11 Receive Maximum: the client's cap on concurrent QoS≥1
    // publishes *we* may have in flight toward it. Effective outbound cap
    // = min(operator's `max_inflight_messages`, client's Receive Maximum);
    // fanout consults `session.max_inflight()` per subscriber. The value 0
    // is a protocol error per spec — clamped to 1 rather than closing.
    // (v3.1.1 clients carry no properties: they get the operator cap.)
    let mut effective_inflight = broker.safety().max_inflight_messages();
    if let Some(rm) = connect.properties.receive_maximum {
        effective_inflight = effective_inflight.min(rm.max(1) as usize);
    }
    channel.session().set_max_inflight(effective_inflight);

    // 3. Register session (broker takes channel clone). `tenant` was
    //    resolved in step 2a; all broker-internal maps key on
    //    `(tenant, client_id)` so cross-tenant fanout / ACL / Will
    //    delivery is structurally constrained.
    let (session_present, connection_id) = broker
        .register_session(
            tenant.clone(),
            client_id.clone(),
            connect.username.clone(),
            channel.clone(),
            will,
            clean_session,
        )
        .await;

    let _ = channel.session().bind.set(BindInfo {
        client_id: client_id.clone(),
        keep_alive,
    });

    info!(
        target: "hotaru_mqtt_broker",
        client_id = %client_id,
        tenant = ?tenant.as_deref(),
        clean_session,
        session_present,
        "CONNECT accepted"
    );

    // 4. Send CONNACK. On a v5 session the acceptance advertises this
    //    broker's limits (§3.2.2.3): Topic Alias Maximum (how many aliases
    //    we will track for this connection) and Receive Maximum (our
    //    inbound QoS-2 stash cap, clamped to the u16 property range).
    let connack_properties = if version == ProtocolVersion::V5 {
        let mut props = hotaru_mqtt::Properties::default();
        let alias_max = broker.safety().topic_alias_maximum();
        if alias_max > 0 {
            props.topic_alias_maximum = Some(alias_max);
        }
        props.receive_maximum =
            Some(broker.safety().receive_maximum_inbound().min(u16::MAX as usize) as u16);
        props
    } else {
        Default::default()
    };
    if let Err(e) = channel.send_packet(Packet::Connack(ConnackPacket {
        properties: connack_properties,
        session_present,
        return_code: ConnackReturnCode::Accepted,
    })) {
        broker
            .unregister_session(&tenant, &client_id, connection_id, false)
            .await;
        broker.release_connection();
        return Err(e);
    }

    // 4b. P7: if a persistent session was resumed, retransmit every
    //     outbound QoS≥1 inflight publish (DUP=1, spec §3.1.2.4 + §4.4).
    //     MUST follow CONNACK (D18-style wire-order — peer expects CONNACK
    //     before any other packet on a fresh connection).
    if session_present {
        debug!(
            target: "hotaru_mqtt_broker",
            client_id = %client_id,
            "retransmitting outbound inflight on resumed session"
        );
        broker.retransmit_inflight(channel);
    }

    // 5. Spawn per-connection fanout coordinator (spec §4.6 FIFO ordering).
    //
    // The read loop submits each inbound publish to this BOUNDED mpsc (audit
    // F8 — previously unbounded; a fast publisher could grow per-connection
    // memory unbounded). Capacity = `MqttSafety.max_queued_messages()`. Full
    // queue → silent drop today (W policy §2); P3 wires the configured
    // `SlowConsumerPolicy` (drop-oldest-QoS0 vs disconnect-laggard).
    //
    // A dedicated worker drains it sequentially, runs the endpoint chain,
    // then calls `broker.publish`. This decouples chain latency from packet
    // read while preserving strict publisher ordering. When `handle_server`
    // returns, `fanout_tx` drops, the worker drains remaining items and
    // exits.
    let (fanout_tx, fanout_rx) =
        async_channel::bounded::<PublishPacket>(broker.safety().max_queued_messages().max(1));
    Rt::spawn_detached(fanout_worker::<W, TS, Rt>(
        fanout_rx,
        channel.clone(),
        broker.clone(),
        tenant.clone(),
        client_id.clone(),
        runtime.clone(),
        root.clone(),
    ));

    // 6. Main select loop. Spec §3.1.2.10: keep_alive=0 disables read timer
    //    (server MUST NOT disconnect for inactivity). 1.5× grace applies
    //    only when keep_alive > 0.
    let read_timeout = if keep_alive == 0 {
        KEEP_ALIVE_DISABLED_READ_TIMEOUT
    } else {
        Duration::from_secs((keep_alive as u64 * 3) / 2)
    };
    let mut graceful = false;
    let mut terminal_error: Option<MqttError> = None;
    let shutdown = channel.shutdown_signal();

    // v5 §3.3.2.3.4: per-connection inbound Topic Alias table. Owned by
    // this read loop (aliases die with the network connection, never with
    // the logical session) and bounded by the advertised Topic Alias
    // Maximum, so its footprint is at most `alias_max` topic strings.
    let alias_max = broker.safety().topic_alias_maximum();
    let mut topic_aliases: BTreeMap<u16, Arc<str>> = BTreeMap::new();

    loop {
        if !channel.is_open() {
            break;
        }
        // Lost-wakeup discipline (see channel.rs): register the shutdown
        // listener before the is_open re-check above ran? The check sits
        // at loop top; re-listen here then re-check once more.
        let closed = shutdown.listen();
        if !channel.is_open() {
            break;
        }
        match Rt::select2(
            Rt::timeout(read_timeout, read_packet(&mut reader, max_packet_size, version)),
            closed,
        )
        .await
        {
            Either::Left(packet) => {
                match packet {
                    Err(_) => break,                              // keep-alive timeout
                    Ok(Err(MqttError::Io(_))) => break,           // wire closed
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
                            &tenant,
                            &client_id,
                            p,
                            &fanout_tx,
                            &mut topic_aliases,
                            alias_max,
                        ).await {
                            terminal_error = Some(e);
                            break;
                        }
                    }
                }
            }
            Either::Right(()) => break,
        }
    }

    // Drop the sender → worker drains queued items, then exits.
    drop(fanout_tx);

    debug!(
        target: "hotaru_mqtt_broker",
        client_id = %client_id,
        tenant = ?tenant.as_deref(),
        graceful,
        "session exiting"
    );
    broker
        .unregister_session(&tenant, &client_id, connection_id, graceful)
        .await;
    broker.release_connection();
    if let Some(e) = terminal_error {
        return Err(e);
    }
    Ok(ProtocolFlow::Close)
}

// ============================================================================
// fanout_worker — per-connection FIFO publish drainer (spec §4.6)
// ============================================================================

async fn fanout_worker<W, TS, Rt>(
    rx: async_channel::Receiver<PublishPacket>,
    channel: MqttChannel<W, Rt>,
    broker: Broker<W, Rt>,
    tenant: Option<TenantId>,
    client_id: Arc<str>,
    runtime: Arc<RuntimeConfig>,
    root: Arc<UrlRoot<MqttContext<TS, Rt>, TS>>,
) where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
    Rt: RuntimeSpec,
{
    while let Ok(publish) = rx.recv().await {
        let fanout_packet = run_server_chain_then_decide_fanout(
            channel.clone(),
            publish,
            runtime.clone(),
            root.clone(),
        )
        .await;
        if let Some(p) = fanout_packet {
            broker.publish(&tenant, &client_id, p).await;
        }
    }
}

/// Resolve (and strip) a v5 Topic Alias on an inbound PUBLISH against the
/// connection's alias table (spec §3.3.2.3.4).
///
/// - alias with a non-empty topic: (re)register the mapping;
/// - alias with an empty topic: substitute the registered topic;
/// - alias of 0, alias above the advertised maximum, or an unregistered
///   alias with an empty topic: protocol error — connection closes;
/// - no alias and an empty topic: `EmptyPublishTopic` (the codec defers
///   this v5 check here, where alias context exists).
///
/// The alias property is always removed: aliases are hop-local and MUST
/// NOT leak into fanout, the retained store, or the QoS-2 stash.
fn resolve_topic_alias(
    publish: &mut PublishPacket,
    table: &mut BTreeMap<u16, Arc<str>>,
    alias_max: u16,
) -> Result<(), MqttError> {
    if let Some(alias) = publish.properties.topic_alias.take() {
        if alias == 0 || alias > alias_max {
            return Err(Violation::TopicAliasNotAccepted.into());
        }
        if publish.topic.is_empty() {
            match table.get(&alias) {
                Some(topic) => publish.topic = topic.clone(),
                None => return Err(Violation::TopicAliasNotAccepted.into()),
            }
        } else {
            table.insert(alias, publish.topic.clone());
        }
    } else if publish.topic.is_empty() {
        return Err(Violation::EmptyPublishTopic.into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_server_inbound<W, Rt>(
    channel: MqttChannel<W, Rt>,
    broker: Broker<W, Rt>,
    tenant: &Option<TenantId>,
    client_id: &Arc<str>,
    packet: Packet,
    fanout_tx: &async_channel::Sender<PublishPacket>,
    topic_aliases: &mut BTreeMap<u16, Arc<str>>,
    alias_max: u16,
) -> Result<(), MqttError>
where
    W: ConnStream,
    Rt: RuntimeSpec,
{
    match packet {
        Packet::Publish(mut publish) => {
            // v5 topic alias FIRST: every later stage (QoS-2 stash, ACL,
            // chain, fanout, retained store) must see the real topic and
            // never the hop-local alias.
            resolve_topic_alias(&mut publish, topic_aliases, alias_max)?;
            // Wildcard/NUL validation was skipped at the codec for the
            // empty-topic alias form — the substituted topic came from a
            // prior validated PUBLISH, so it is already clean.
            // Ack BEFORE chain (O.2). Per-session QoS-2 stash cap from
            // `MqttSafety.receive_maximum_inbound()` (second-audit G2)
            // — overflow surfaces as `ReceiveMaximumExceeded` and
            // propagates here to close the connection fail-closed.
            ack_inbound_publish_pre_chain(
                &channel,
                &publish,
                broker.safety().receive_maximum_inbound(),
            )?;
            // For QoS 2: stashed on the session at ack time; fanout happens when PUBREL arrives.
            if publish.qos == QoS::ExactlyOnce {
                return Ok(());
            }
            // QoS 0 / 1: chain + fanout run on the coordinator worker, in
            // strict arrival order (spec §4.6). Bounded queue (F8): on
            // overflow, apply the broker's `SlowConsumerPolicy`.
            use async_channel::TrySendError;
            let qos_for_policy = publish.qos;
            match fanout_tx.try_send(publish) {
                Ok(_) | Err(TrySendError::Closed(_)) => {}
                Err(TrySendError::Full(_)) => {
                    if broker
                        .broker_safety()
                        .slow_consumer_policy()
                        .should_close_on_overflow(qos_for_policy)
                    {
                        channel.close();
                    }
                }
            }
            Ok(())
        }
        Packet::Subscribe(s) => {
            // F1 hardening: cap filter count per SUBSCRIBE — defends
            // against amplification DoS via 65 535-filter packets which
            // would saturate `subscribe` + `replay_retained_for_subscribe`
            // matching cost.
            let max_filters = broker.safety().max_filters_per_subscribe();
            if s.subscriptions.len() > max_filters {
                return Err(Violation::TooManyFilters {
                    count: s.subscriptions.len(),
                    max: max_filters,
                }
                .into());
            }
            let filters: Vec<TopicFilter> = s
                .subscriptions
                .iter()
                .map(|ts| TopicFilter {
                    filter: ts.topic.clone(),
                    qos: ts.qos,
                })
                .collect();
            let codes = broker.subscribe(tenant, client_id, &filters).await;
            channel.send_packet(Packet::Suback(SubackPacket {
                packet_id: s.packet_id,
                return_codes: codes.clone(),
            }))?;
            // D18 + spec convention: replay retained AFTER SUBACK so the
            // wire order is `SUBACK → retained PUBLISH...`.
            let granted: Vec<(Arc<str>, QoS)> = filters
                .iter()
                .zip(codes.iter())
                .filter_map(|(tf, code)| match code {
                    hotaru_mqtt::request::SubackCode::Granted(q) => Some((tf.filter.clone(), *q)),
                    _ => None,
                })
                .collect();
            broker
                .replay_retained_for_subscribe(tenant, client_id, &granted)
                .await;
            Ok(())
        }
        Packet::Unsubscribe(u) => {
            // F1 hardening (symmetric to SUBSCRIBE).
            let max_filters = broker.safety().max_filters_per_subscribe();
            if u.topics.len() > max_filters {
                return Err(Violation::TooManyFilters {
                    count: u.topics.len(),
                    max: max_filters,
                }
                .into());
            }
            broker.unsubscribe(tenant, client_id, &u.topics).await;
            channel.send_packet(Packet::Unsuback(
                hotaru_mqtt::packet::UnsubackPacket {
                    packet_id: u.packet_id,
                    reason_codes: vec![0x00; u.topics.len()],
                },
            ))?;
            Ok(())
        }
        Packet::Pingreq => {
            channel.send_packet(Packet::Pingresp)?;
            Ok(())
        }
        Packet::Puback(ack) => {
            // A v5 failure reason (0x87 / 0x97 / ...) still terminates the
            // delivery attempt; cleanup is identical to success.
            broker.ack_outbound(tenant, client_id, ack.packet_id).await;
            Ok(())
        }
        Packet::Pubrec(ack) => {
            let id = ack.packet_id;
            if ack.is_success() {
                channel.send_packet(Packet::Pubrel(AckPacket::success(id)))?;
            } else {
                // v5 §4.3.3: failure PUBREC — the subscriber discarded the
                // message. MUST NOT send PUBREL; release the inflight slot.
                broker.ack_outbound(tenant, client_id, id).await;
            }
            Ok(())
        }
        Packet::Pubcomp(ack) => {
            broker.ack_outbound(tenant, client_id, ack.packet_id).await;
            Ok(())
        }
        Packet::Pubrel(ack) => {
            let id = ack.packet_id;
            // QoS 2 phase 2: take the stored publish and submit to coordinator
            // — preserves ordering relative to subsequent QoS 0/1 publishes
            // from this same client.
            let mut found = false;
            if let Some(stored) = channel.session().take_qos2_inbound(id) {
                found = true;
                let publish = PublishPacket {
                    // Forward the publisher's v5 properties through the
                    // QoS 2 release path (stash carries them).
                    properties: stored.properties.clone(),
                    topic: stored.topic.clone(),
                    payload: stored.payload.clone(),
                    dup: false,
                    qos: stored.qos,
                    retain: stored.retain,
                    packet_id: Some(id),
                };
                use async_channel::TrySendError;
                let qos_for_policy = publish.qos;
                match fanout_tx.try_send(publish) {
                    Ok(_) | Err(TrySendError::Closed(_)) => {}
                    Err(TrySendError::Full(_)) => {
                        if broker
                            .broker_safety()
                            .slow_consumer_policy()
                            .should_close_on_overflow(qos_for_policy)
                        {
                            channel.close();
                        }
                    }
                }
            }
            let comp = if found {
                AckPacket::success(id)
            } else if channel.protocol_version() == ProtocolVersion::V5 {
                // v5 §3.6.2.1: no matching QoS-2 stash entry — PUBCOMP
                // 0x92 (Packet Identifier not found).
                AckPacket {
                    packet_id: id,
                    reason_code: 0x92,
                    properties: Default::default(),
                }
            } else {
                // v3.1.1 has no reason codes; bare PUBCOMP as before.
                AckPacket::success(id)
            };
            channel.send_packet(Packet::Pubcomp(comp))?;
            Ok(())
        }
        Packet::Connect(_) => Err(Violation::SessionAlreadyBound.into()),
        _ => Ok(()), // Other inbound types are protocol violations or noise — silent (W §4)
    }
}

/// Server-side: run any matching endpoint chain, return the packet to fan out
/// if the chain didn't suppress it. Sequential (await), unlike client-side
/// which fires-and-forgets, because the chain may mutate the packet before
/// broker fanout (O.4 — chain first, then fanout).
async fn run_server_chain_then_decide_fanout<W, TS, Rt>(
    channel: MqttChannel<W, Rt>,
    publish: PublishPacket,
    _runtime: Arc<RuntimeConfig>,
    root: Arc<UrlRoot<MqttContext<TS, Rt>, TS>>,
) -> Option<PublishPacket>
where
    W: ConnStream,
    TS: TransportSpec<Wire = W>,
    Rt: RuntimeSpec,
{
    let topic = publish.topic.clone();
    let segments: Vec<&str> = topic.split('/').collect();
    let mut cursor = root.walk_cursor(&topic);
    let mut fanout = true;
    let mut current = publish;

    while let Some(node) = cursor.find_next(&segments) {
        let mut ctx = MqttContext::<TS, Rt>::default();
        ctx.set_incoming(incoming_from_packet(&current));
        ctx.install_channel(channel.clone());
        ctx.set_endpoint(node.clone());
        match node.run(ctx).await {
            Ok(out) => {
                if !out.should_propagate() {
                    fanout = false;
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hotaru_mqtt::packet::ProtocolVersion;
    use hotaru_mqtt::Properties;

    fn publish(topic: &str, alias: Option<u16>) -> PublishPacket {
        PublishPacket {
            topic: Arc::from(topic),
            payload: Bytes::from_static(b"x"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
            properties: Properties {
                topic_alias: alias,
                ..Default::default()
            },
        }
    }

    #[test]
    fn topic_alias_register_then_resolve() {
        let mut table = BTreeMap::new();
        // First PUBLISH: topic + alias registers the mapping and strips it.
        let mut p1 = publish("sensors/a/temp", Some(1));
        resolve_topic_alias(&mut p1, &mut table, 16).unwrap();
        assert_eq!(p1.topic.as_ref(), "sensors/a/temp");
        assert_eq!(p1.properties.topic_alias, None, "alias must not leak downstream");
        // Second PUBLISH: empty topic + same alias resolves to the stored topic.
        let mut p2 = publish("", Some(1));
        resolve_topic_alias(&mut p2, &mut table, 16).unwrap();
        assert_eq!(p2.topic.as_ref(), "sensors/a/temp");
        assert_eq!(p2.properties.topic_alias, None);
    }

    #[test]
    fn topic_alias_above_max_rejected() {
        let mut table = BTreeMap::new();
        let mut p = publish("t", Some(99));
        let err = resolve_topic_alias(&mut p, &mut table, 16).unwrap_err();
        assert!(matches!(
            err,
            MqttError::Protocol(Violation::TopicAliasNotAccepted)
        ));
    }

    #[test]
    fn unknown_alias_with_empty_topic_rejected() {
        let mut table = BTreeMap::new();
        let mut p = publish("", Some(2)); // never registered
        let err = resolve_topic_alias(&mut p, &mut table, 16).unwrap_err();
        assert!(matches!(
            err,
            MqttError::Protocol(Violation::TopicAliasNotAccepted)
        ));
    }

    #[test]
    fn empty_topic_without_alias_is_error() {
        let mut table = BTreeMap::new();
        let mut p = publish("", None);
        let err = resolve_topic_alias(&mut p, &mut table, 16).unwrap_err();
        assert!(matches!(
            err,
            MqttError::Protocol(Violation::EmptyPublishTopic)
        ));
    }

    #[test]
    fn plain_publish_untouched() {
        let mut table = BTreeMap::new();
        let mut p = publish("a/b", None);
        resolve_topic_alias(&mut p, &mut table, 16).unwrap();
        assert_eq!(p.topic.as_ref(), "a/b");
        assert!(table.is_empty());
    }
}
