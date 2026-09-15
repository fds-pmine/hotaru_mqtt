//! The broker half of the MQTT protocol flow.
//!
//! Everything reachable only from `handle_server`: CONNECT admission, the
//! keep-alive policy, the reader loop, and the per-connection chain worker
//! that keeps user endpoint code off that reader (see #67).

use std::sync::Arc;
use std::time::Duration;

use hotaru_core::app::common::RuntimeConfig;
use hotaru_core::connection::{ConnStream, TransportSpec};
use hotaru_core::protocol::{Channel as _, ProtocolFlow};
use hotaru_core::url::UrlRoot;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::broker::{Broker, incoming_from_packet};
use crate::channel::MqttChannel;
use crate::codec::read_packet;
use crate::context::MqttContext;
use crate::error::{MqttError, TimeoutKind, Violation};
use crate::packet::*;
use crate::request::*;
use crate::session::{AckKind, BindInfo};

use super::*;

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
pub(super) fn server_read_deadline(keep_alive: u16) -> Option<Duration> {
    if keep_alive == 0 {
        None
    } else {
        Some(Duration::from_millis(keep_alive as u64 * 1500))
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

// ============================================================================
// handle_server — server-side per-connection session loop
// ============================================================================

pub(super) async fn handle_server<W, TS>(
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
            if let Some(stored) = channel.session().take_qos2_publish(packet_id) {
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

