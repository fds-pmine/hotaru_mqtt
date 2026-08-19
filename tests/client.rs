//! Client-side session tests for `hotaru_mqtt`.
//!
//! `tests/integration.rs` drives the broker and hand-rolls its clients out of
//! raw `codec` calls, so nothing there ever runs `MQTT::client()`. These tests
//! invert that: the code under test is the real client session loop, and the
//! peer is a scripted fake broker sitting on a loopback socket that replies
//! with whatever the case needs.
//!
//! Separate file rather than more of `integration.rs` because the two suites
//! want opposite fixtures — there, the broker is real and the client is a
//! puppet; here it is the other way round.

use std::sync::Arc;
use std::time::Duration;

use hotaru_core::app::common::RuntimeConfig;
use hotaru_core::connection::ConnStream;
use hotaru_core::executable::registry::ProtocolEntryRegistry;
use hotaru_core::executable::{ProtocolEntryBuilder, ProtocolRegistryBuilder};
use hotaru_core::extensions::Locals;
use hotaru_core::protocol::Protocol;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use hotaru_mqtt::{
    CLIENT_CONFIG_STATICS_KEY, ConnackPacket, ConnackReturnCode, MQTT, MqttChannel,
    MqttClientConfig, MqttContext, MqttError, MqttRequest, MqttResponse, Packet,
    PublishAck, PublishPacket, PublishRequest, QoS, SubackCode, SubackPacket,
    TopicFilter, WillMessage, codec,
};

/// Test reads are not exercising the size cap.
const ANY_SIZE: usize = hotaru_mqtt::SPEC_MAX_PACKET_SIZE;

type FakeBroker = (
    BufReader<tokio::net::tcp::OwnedReadHalf>,
    tokio::net::tcp::OwnedWriteHalf,
);

/// Run a real client session against a scripted peer. Returns the peer's end of
/// the socket, so a test writes what the broker would say and reads what the
/// client actually sent.
///
/// `Registry::serve` is deliberately not used: it begins with `fill_buf()` to
/// sniff which protocol is speaking, which is right for an accepted connection
/// and wrong for a dialled one — the client owes the first bytes, so sniffing
/// first deadlocks. `open_channel` + `handle` is the same pair `serve` ends up
/// calling, minus the detection step that does not apply to this direction.
/// The registry is still built, because it is what produces the `UrlRoot` the
/// session loop dispatches inbound publishes through.
async fn start_client(config: MqttClientConfig) -> FakeBroker {
    start_client_with_channel(config).await.0
}

/// As `start_client`, but also hands back the session's `MqttChannel`.
///
/// Outbound sends need it: `Protocol::send` takes a context with a channel
/// installed, and the channel is created inside the session task. Returning a
/// clone is enough — `MqttChannel` is `Clone` and every clone shares one
/// session, which is exactly the sharing the ack slots rely on.
async fn start_client_with_channel(
    config: MqttClientConfig,
) -> (FakeBroker, MqttChannel<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let registry: ProtocolEntryRegistry<hotaru_core::connection::tcp::TcpTransport> =
        ProtocolRegistryBuilder::new()
            .protocol(ProtocolEntryBuilder::new(MQTT::client()))
            .build();
    let root = registry.url::<MQTT>().expect("client entry should be registered");

    let mut statics = Locals::new();
    statics.set(CLIENT_CONFIG_STATICS_KEY, Arc::new(config));
    let runtime = Arc::new(RuntimeConfig::from_parts(
        Default::default(),
        Default::default(),
        statics,
    ));

    let (chan_tx, chan_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (read_half, write_half, meta) = ConnStream::split(stream);
        let channel = MQTT::client().open_channel(BufReader::new(read_half), write_half, meta);
        let _ = chan_tx.send(channel.clone());
        let _ = <MQTT as Protocol>::handle(&channel, runtime, root).await;
    });

    let (stream, _peer) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("client never dialled")
        .unwrap();
    let (r, w) = stream.into_split();
    let channel = chan_rx.await.expect("session task dropped the channel");
    ((BufReader::new(r), w), channel)
}

/// Drive one outbound request the way `run!` would: build a context, install
/// the channel, hand it to `Protocol::send`.
async fn protocol_send(
    channel: &MqttChannel<TcpStream>,
    request: MqttRequest,
) -> Result<MqttResponse, MqttError> {
    let mut ctx: MqttContext = MqttContext::default();
    ctx.request = request;
    <MQTT as Protocol>::install_channel(&mut ctx, channel.clone());
    <MQTT as Protocol>::send(ctx).await.map(|c| c.response)
}

fn publish_request(topic: &str, qos: QoS) -> MqttRequest {
    MqttRequest::Publish(PublishRequest {
        topic: Arc::from(topic),
        payload: bytes::Bytes::from_static(b"payload"),
        qos,
        retain: false,
    })
}

async fn send(writer: &mut tokio::net::tcp::OwnedWriteHalf, packet: &Packet) {
    writer
        .write_all(&codec::encode_packet(packet))
        .await
        .unwrap();
    writer.flush().await.unwrap();
}

async fn recv(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Packet {
    timeout(Duration::from_secs(5), codec::read_packet(reader, ANY_SIZE))
        .await
        .expect("timed out waiting for the client to send something")
        .expect("client sent an undecodable packet")
}

fn accepted() -> Packet {
    Packet::Connack(ConnackPacket {
        session_present: false,
        return_code: ConnackReturnCode::Accepted,
    })
}

/// Drive a session up to "connected": read the CONNECT, answer CONNACK.
async fn handshake(peer: &mut FakeBroker) {
    match recv(&mut peer.0).await {
        Packet::Connect(_) => {}
        other => panic!("expected CONNECT, got {other:?}"),
    }
    send(&mut peer.1, &accepted()).await;
}

// ----------------------------------------------------------------------------
// CONNECT construction
// ----------------------------------------------------------------------------

/// `build_connect` had no coverage, so nothing pinned that a configured field
/// reaches the wire at all.
#[tokio::test]
async fn connect_carries_the_configured_fields() {
    let config = MqttClientConfig::new("cfg-client")
        .clean_session(false)
        .keep_alive(45)
        .with_credentials("user", &b"secret"[..])
        .with_will(WillMessage {
            topic: Arc::from("gone/cfg-client"),
            payload: bytes::Bytes::from_static(b"bye"),
            qos: QoS::AtMostOnce,
            retain: true,
        });
    let mut peer = start_client(config).await;

    match recv(&mut peer.0).await {
        Packet::Connect(c) => {
            assert_eq!("cfg-client", &*c.client_id);
            assert!(!c.clean_session);
            assert_eq!(45, c.keep_alive);
            assert_eq!(Some("user"), c.username.as_deref());
            assert_eq!(Some(&b"secret"[..]), c.password.as_deref());
            let will = c.will.expect("will should have been sent");
            assert_eq!("gone/cfg-client", &*will.topic);
            assert_eq!(&b"bye"[..], &will.payload[..]);
            assert!(will.retain);
        }
        other => panic!("expected CONNECT, got {other:?}"),
    }
}

#[tokio::test]
async fn connect_omits_optional_fields_when_unset() {
    let mut peer = start_client(MqttClientConfig::new("bare")).await;
    match recv(&mut peer.0).await {
        Packet::Connect(c) => {
            assert!(c.clean_session, "clean_session defaults to true");
            assert!(c.username.is_none());
            assert!(c.password.is_none());
            assert!(c.will.is_none());
        }
        other => panic!("expected CONNECT, got {other:?}"),
    }
}

/// A refused CONNACK must end the session rather than proceed into the loop.
#[tokio::test]
async fn a_refused_connack_ends_the_session() {
    let mut peer = start_client(MqttClientConfig::new("refused")).await;
    match recv(&mut peer.0).await {
        Packet::Connect(_) => {}
        other => panic!("expected CONNECT, got {other:?}"),
    }
    send(
        &mut peer.1,
        &Packet::Connack(ConnackPacket {
            session_present: false,
            return_code: ConnackReturnCode::NotAuthorized,
        }),
    )
    .await;

    let mut sink = Vec::new();
    let closed = timeout(
        Duration::from_secs(3),
        tokio::io::AsyncReadExt::read_to_end(&mut peer.0, &mut sink),
    )
    .await;
    assert!(closed.is_ok(), "client stayed connected after a refusal");
}

// ----------------------------------------------------------------------------
// Initial subscription
// ----------------------------------------------------------------------------

/// The configured filters must reach the wire, and the session must go on to
/// its read loop.
///
/// Reaching the loop is the load-bearing half. `handle_client` owns the reader
/// and does not poll it until the loop, so a SUBACK cannot be observed before
/// the loop starts; a startup that waits for one waits forever. `keep_alive=1`
/// makes that visible — a PINGREQ is only ever sent from inside the loop.
#[tokio::test]
async fn initial_subscriptions_are_sent_and_the_loop_starts() {
    let config = MqttClientConfig::new("subber")
        .keep_alive(1)
        .with_initial_subscribe("sensors/+/temp", QoS::AtLeastOnce);
    let mut peer = start_client(config).await;
    handshake(&mut peer).await;

    let packet_id = match recv(&mut peer.0).await {
        Packet::Subscribe(s) => {
            assert_eq!(1, s.subscriptions.len());
            assert_eq!("sensors/+/temp", &*s.subscriptions[0].topic);
            assert_eq!(QoS::AtLeastOnce, s.subscriptions[0].qos);
            s.packet_id
        }
        other => panic!("expected SUBSCRIBE, got {other:?}"),
    };

    send(
        &mut peer.1,
        &Packet::Suback(SubackPacket {
            packet_id,
            return_codes: vec![SubackCode::Granted(QoS::AtLeastOnce)],
        }),
    )
    .await;

    match recv(&mut peer.0).await {
        Packet::Pingreq => {}
        other => panic!("expected PINGREQ once the loop was entered, got {other:?}"),
    }
}

/// A peer that never answers the SUBSCRIBE must not be able to stall the
/// session: startup does not depend on the SUBACK arriving at all.
#[tokio::test]
async fn a_missing_suback_does_not_stall_startup() {
    let config = MqttClientConfig::new("unanswered")
        .keep_alive(1)
        .with_initial_subscribe("a/b", QoS::AtLeastOnce);
    let mut peer = start_client(config).await;
    handshake(&mut peer).await;

    match recv(&mut peer.0).await {
        Packet::Subscribe(_) => {}
        other => panic!("expected SUBSCRIBE, got {other:?}"),
    }
    // No SUBACK is sent. The loop must start regardless.
    match recv(&mut peer.0).await {
        Packet::Pingreq => {}
        other => panic!("expected PINGREQ without a SUBACK, got {other:?}"),
    }
}

#[tokio::test]
async fn no_subscribe_is_sent_when_none_are_configured() {
    let mut peer = start_client(MqttClientConfig::new("quiet").keep_alive(1)).await;
    handshake(&mut peer).await;
    match recv(&mut peer.0).await {
        Packet::Pingreq => {}
        other => panic!("expected PINGREQ with no initial subscriptions, got {other:?}"),
    }
}

// ----------------------------------------------------------------------------
// Inbound dispatch
// ----------------------------------------------------------------------------

#[tokio::test]
async fn inbound_qos1_publish_is_acked() {
    let mut peer = start_client(MqttClientConfig::new("q1")).await;
    handshake(&mut peer).await;

    send(
        &mut peer.1,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("t/1"),
            payload: bytes::Bytes::from_static(b"hello"),
            dup: false,
            qos: QoS::AtLeastOnce,
            retain: false,
            packet_id: Some(21),
        }),
    )
    .await;

    match recv(&mut peer.0).await {
        Packet::Puback(id) => assert_eq!(21, id),
        other => panic!("expected PUBACK, got {other:?}"),
    }
}

/// Inbound QoS 2 is a four-packet handshake and the client owns two of them.
#[tokio::test]
async fn inbound_qos2_publish_completes_the_handshake() {
    let mut peer = start_client(MqttClientConfig::new("q2")).await;
    handshake(&mut peer).await;

    send(
        &mut peer.1,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("t/2"),
            payload: bytes::Bytes::from_static(b"exactly once"),
            dup: false,
            qos: QoS::ExactlyOnce,
            retain: false,
            packet_id: Some(33),
        }),
    )
    .await;
    match recv(&mut peer.0).await {
        Packet::Pubrec(id) => assert_eq!(33, id),
        other => panic!("expected PUBREC, got {other:?}"),
    }

    send(&mut peer.1, &Packet::Pubrel(33)).await;
    match recv(&mut peer.0).await {
        Packet::Pubcomp(id) => assert_eq!(33, id),
        other => panic!("expected PUBCOMP, got {other:?}"),
    }
}

/// Outbound QoS 2 phase 1 seen from the peer: a PUBREC must be answered with
/// PUBREL even when no local waiter is registered for it.
#[tokio::test]
async fn a_pubrec_is_answered_with_pubrel() {
    let mut peer = start_client(MqttClientConfig::new("rec")).await;
    handshake(&mut peer).await;

    send(&mut peer.1, &Packet::Pubrec(77)).await;
    match recv(&mut peer.0).await {
        Packet::Pubrel(id) => assert_eq!(77, id),
        other => panic!("expected PUBREL, got {other:?}"),
    }
}

/// PINGRESP is accepted and must not disturb the loop.
#[tokio::test]
async fn a_pingresp_is_absorbed() {
    let mut peer = start_client(MqttClientConfig::new("ping").keep_alive(1)).await;
    handshake(&mut peer).await;

    match recv(&mut peer.0).await {
        Packet::Pingreq => {}
        other => panic!("expected PINGREQ, got {other:?}"),
    }
    send(&mut peer.1, &Packet::Pingresp).await;
    match recv(&mut peer.0).await {
        Packet::Pingreq => {}
        other => panic!("expected a second PINGREQ, got {other:?}"),
    }
}

/// A DISCONNECT from the peer ends the session.
///
/// The courtesy DISCONNECT the client sends on its way out is best-effort by
/// design (`let _ = channel.send_packet(...)`, W policy §1), and whether it
/// reaches the wire depends on the writer draining before the socket goes —
/// so the assertion is that the session ends, not that a particular byte
/// arrives. Asserting the DISCONNECT is flaky, which is how this was found.
#[tokio::test]
async fn a_broker_disconnect_ends_the_session() {
    let mut peer = start_client(MqttClientConfig::new("bye").keep_alive(1)).await;
    handshake(&mut peer).await;

    send(&mut peer.1, &Packet::Disconnect).await;

    let mut sink = Vec::new();
    let closed = timeout(
        Duration::from_secs(3),
        tokio::io::AsyncReadExt::read_to_end(&mut peer.0, &mut sink),
    )
    .await;
    assert!(
        closed.is_ok(),
        "client kept the session open after the broker said DISCONNECT"
    );
    // Whatever did arrive must not be a PINGREQ: that would mean the loop is
    // still running rather than winding down.
    assert!(
        !sink.windows(2).any(|w| w == [0xC0, 0x00]),
        "client went on pinging after DISCONNECT"
    );
}

// ----------------------------------------------------------------------------
// Outbound: Protocol::send
// ----------------------------------------------------------------------------
//
// These four paths allocate a packet id, park an `AckSlot` in the session, put
// the packet on the wire, and wait. The inbound loop is what wakes them, via
// `fire_ack` / `fire_suback` / `fire_unsuback` — so an outbound send only works
// if the two halves agree on the slot. Nothing here had ever been executed, and
// the matched arms of all three `fire_*` helpers were unreachable in test.
//
// Every case runs the send concurrently with the peer's script, because the
// send does not return until the peer answers. Running them in sequence would
// deadlock the test rather than the code.

/// QoS 0 is fire-and-forget: no id, no slot, no wait.
#[tokio::test]
async fn a_qos0_publish_returns_without_waiting() {
    let (mut peer, channel) = start_client_with_channel(MqttClientConfig::new("q0-out")).await;
    handshake(&mut peer).await;

    let response = timeout(
        Duration::from_secs(2),
        protocol_send(&channel, publish_request("out/0", QoS::AtMostOnce)),
    )
    .await
    .expect("QoS 0 send must not wait for anything")
    .expect("send failed");

    assert!(matches!(response, MqttResponse::Published(PublishAck::Sent)));
    match recv(&mut peer.0).await {
        Packet::Publish(p) => {
            assert_eq!("out/0", &*p.topic);
            assert_eq!(QoS::AtMostOnce, p.qos);
            assert!(p.packet_id.is_none(), "QoS 0 must carry no packet id");
        }
        other => panic!("expected PUBLISH, got {other:?}"),
    }
}

/// QoS 1 parks on `AckSlot::Puback`; the PUBACK arm of `fire_ack` is what
/// releases it.
#[tokio::test]
async fn a_qos1_publish_resolves_when_the_puback_arrives() {
    let (mut peer, channel) = start_client_with_channel(MqttClientConfig::new("q1-out")).await;
    handshake(&mut peer).await;

    let script = async {
        let id = match recv(&mut peer.0).await {
            Packet::Publish(p) => {
                assert_eq!(QoS::AtLeastOnce, p.qos);
                p.packet_id.expect("QoS 1 must carry a packet id")
            }
            other => panic!("expected PUBLISH, got {other:?}"),
        };
        send(&mut peer.1, &Packet::Puback(id)).await;
        id
    };

    let (response, id) = tokio::join!(
        protocol_send(&channel, publish_request("out/1", QoS::AtLeastOnce)),
        script,
    );

    match response.expect("send failed") {
        MqttResponse::Published(PublishAck::Acknowledged(acked)) => assert_eq!(id, acked),
        other => panic!("expected Acknowledged, got {other:?}"),
    }
}

/// QoS 2 is two waits with a client-sent PUBREL between them, so it covers the
/// PUBREC and PUBCOMP arms of `fire_ack` in one pass.
#[tokio::test]
async fn a_qos2_publish_walks_the_whole_handshake() {
    let (mut peer, channel) = start_client_with_channel(MqttClientConfig::new("q2-out")).await;
    handshake(&mut peer).await;

    let script = async {
        let id = match recv(&mut peer.0).await {
            Packet::Publish(p) => {
                assert_eq!(QoS::ExactlyOnce, p.qos);
                p.packet_id.expect("QoS 2 must carry a packet id")
            }
            other => panic!("expected PUBLISH, got {other:?}"),
        };
        send(&mut peer.1, &Packet::Pubrec(id)).await;
        // The client answers PUBREC with PUBREL from its inbound loop.
        match recv(&mut peer.0).await {
            Packet::Pubrel(rel) => assert_eq!(id, rel),
            other => panic!("expected PUBREL, got {other:?}"),
        }
        send(&mut peer.1, &Packet::Pubcomp(id)).await;
        id
    };

    let (response, id) = tokio::join!(
        protocol_send(&channel, publish_request("out/2", QoS::ExactlyOnce)),
        script,
    );

    match response.expect("send failed") {
        MqttResponse::Published(PublishAck::Completed(done)) => assert_eq!(id, done),
        other => panic!("expected Completed, got {other:?}"),
    }
}

/// The granted QoS codes must reach the caller. This is the one place in the
/// crate where a SUBACK's verdict is surfaced rather than dropped — the
/// startup path discards it (see the initial-subscription issue), so without
/// this test nothing pins that the runtime path behaves differently.
#[tokio::test]
async fn subscribe_returns_the_granted_codes() {
    let (mut peer, channel) = start_client_with_channel(MqttClientConfig::new("sub-out")).await;
    handshake(&mut peer).await;

    let script = async {
        match recv(&mut peer.0).await {
            Packet::Subscribe(s) => {
                assert_eq!(2, s.subscriptions.len());
                assert_eq!("ok/topic", &*s.subscriptions[0].topic);
                assert_eq!("denied/topic", &*s.subscriptions[1].topic);
                send(
                    &mut peer.1,
                    &Packet::Suback(SubackPacket {
                        packet_id: s.packet_id,
                        // One granted, one refused — a rejection must survive
                        // the trip back to the caller, not be flattened.
                        return_codes: vec![
                            SubackCode::Granted(QoS::AtLeastOnce),
                            SubackCode::Failure,
                        ],
                    }),
                )
                .await;
            }
            other => panic!("expected SUBSCRIBE, got {other:?}"),
        }
    };

    let request = MqttRequest::Subscribe(vec![
        TopicFilter::new("ok/topic", QoS::AtLeastOnce),
        TopicFilter::new("denied/topic", QoS::AtLeastOnce),
    ]);
    let (response, ()) = tokio::join!(protocol_send(&channel, request), script);

    match response.expect("send failed") {
        MqttResponse::Subscribed(codes) => {
            assert_eq!(2, codes.len());
            assert!(matches!(codes[0], SubackCode::Granted(QoS::AtLeastOnce)));
            assert!(
                matches!(codes[1], SubackCode::Failure),
                "a refused filter must reach the caller as Failure, got {:?}",
                codes[1]
            );
        }
        other => panic!("expected Subscribed, got {other:?}"),
    }
}

#[tokio::test]
async fn unsubscribe_resolves_when_the_unsuback_arrives() {
    let (mut peer, channel) = start_client_with_channel(MqttClientConfig::new("unsub-out")).await;
    handshake(&mut peer).await;

    let script = async {
        match recv(&mut peer.0).await {
            Packet::Unsubscribe(u) => {
                assert_eq!(1, u.topics.len());
                assert_eq!("drop/me", &*u.topics[0]);
                send(&mut peer.1, &Packet::Unsuback(u.packet_id)).await;
            }
            other => panic!("expected UNSUBSCRIBE, got {other:?}"),
        }
    };

    let request = MqttRequest::Unsubscribe(vec![Arc::from("drop/me")]);
    let (response, ()) = tokio::join!(protocol_send(&channel, request), script);
    assert!(matches!(
        response.expect("send failed"),
        MqttResponse::Unsubscribed
    ));
}

/// Two outbound sends in flight at once must not collide: each parks its own
/// slot under its own id, and each must be released by its own ack.
#[tokio::test]
async fn concurrent_sends_get_their_own_acks() {
    let (mut peer, channel) = start_client_with_channel(MqttClientConfig::new("two-out")).await;
    handshake(&mut peer).await;

    let script = async {
        let first = match recv(&mut peer.0).await {
            Packet::Publish(p) => p.packet_id.unwrap(),
            other => panic!("expected PUBLISH, got {other:?}"),
        };
        let second = match recv(&mut peer.0).await {
            Packet::Publish(p) => p.packet_id.unwrap(),
            other => panic!("expected PUBLISH, got {other:?}"),
        };
        assert_ne!(first, second, "two inflight publishes must get distinct ids");
        // Answered out of order on purpose: resolution is by id, not arrival.
        send(&mut peer.1, &Packet::Puback(second)).await;
        send(&mut peer.1, &Packet::Puback(first)).await;
        (first, second)
    };

    let (a, b, (first, second)) = tokio::join!(
        protocol_send(&channel, publish_request("out/a", QoS::AtLeastOnce)),
        protocol_send(&channel, publish_request("out/b", QoS::AtLeastOnce)),
        script,
    );

    let acked = |r: Result<MqttResponse, MqttError>| match r.expect("send failed") {
        MqttResponse::Published(PublishAck::Acknowledged(id)) => id,
        other => panic!("expected Acknowledged, got {other:?}"),
    };
    let mut got = [acked(a), acked(b)];
    got.sort_unstable();
    let mut want = [first, second];
    want.sort_unstable();
    assert_eq!(want, got, "each send must resolve with its own packet id");
}
