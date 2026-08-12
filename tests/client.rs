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
    CLIENT_CONFIG_STATICS_KEY, ConnackPacket, ConnackReturnCode, MQTT, MqttClientConfig,
    Packet, PublishPacket, QoS, WillMessage, codec,
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

    tokio::spawn(async move {
        let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (read_half, write_half, meta) = ConnStream::split(stream);
        let channel = MQTT::client().open_channel(BufReader::new(read_half), write_half, meta);
        let _ = <MQTT as Protocol>::handle(&channel, runtime, root).await;
    });

    let (stream, _peer) = timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("client never dialled")
        .unwrap();
    let (r, w) = stream.into_split();
    (BufReader::new(r), w)
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

