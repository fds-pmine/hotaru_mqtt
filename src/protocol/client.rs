//! The client half of the MQTT protocol flow.
//!
//! Everything reachable only from `handle_client`: the connect handshake, the
//! ping timer, and the inbound dispatch for a connection this process
//! originated. A pure publisher never enters the dispatch arms here — it only
//! sends — while a subscriber lives in them, because the broker pushes PUBLISH
//! frames back over the connection the subscriber itself opened.

use std::sync::Arc;
use std::time::Duration;

use hotaru_core::app::common::RuntimeConfig;
use hotaru_core::connection::{ConnStream, HotaruRead, TransportSpec};
use hotaru_core::protocol::{Channel as _, ProtocolFlow};
use hotaru_core::url::UrlRoot;
use tokio::time::timeout;

use crate::broker::incoming_from_packet;
use crate::channel::MqttChannel;
use crate::client::MqttClientConfig;
use crate::codec::read_packet;
use crate::context::MqttContext;
use crate::error::{MqttError, TimeoutKind, Violation};
use crate::packet::*;
use crate::request::*;
use crate::session::{AckKind, BindInfo};

use super::*;

/// How often a client sends PINGREQ, or `None` when it declared no keep-alive.
///
/// The client's obligation is its own `keep_alive`, not the server's 1.5× grace:
/// pinging on the grace period would be late by construction.
pub(super) fn client_ping_interval(keep_alive: u16) -> Option<Duration> {
    if keep_alive == 0 {
        None
    } else {
        Some(Duration::from_secs(keep_alive as u64))
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

pub(super) async fn handle_client<W, TS>(
    channel: &MqttChannel<W>,
    runtime: Arc<RuntimeConfig>,
    root: Arc<UrlRoot<MqttContext<TS>, TS>>,
) -> Result<ProtocolFlow, MqttError>
where
    W: ConnStream,
    W::ReadHalf: HotaruRead<Error = std::io::Error>,
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
            if let Some(publish) = channel.session().take_qos2_publish(id) {
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

