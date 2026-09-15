//! End-to-end integration tests for `hotaru_mqtt`.
//!
//! Each test spins up a broker on a random local port by hand-rolling a
//! TCP accept loop (bypasses `Server::run`'s nested runtime spawn_blocking
//! which is awkward in test contexts). All MQTT traffic flows through real
//! TCP between client connections and the broker's `Protocol::handle` loop.

use std::sync::Arc;
use std::time::Duration;

use hotaru_core::app::common::RuntimeConfig;
use hotaru_core::executable::{ProtocolEntryBuilder, ProtocolRegistryBuilder};
use hotaru_core::executable::registry::ProtocolEntryRegistry;
use hotaru_core::extensions::Locals;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use hotaru_mqtt::{
    BROKER_STATICS_KEY, Broker, ConnackPacket, ConnackReturnCode, ConnectPacket, MQTT, Packet,
    Properties, ProtocolVersion, PublishPacket, QoS, SubackPacket, SubscribePacket,
    TopicSubscription, codec,
};

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/// Spin up a broker on a random port via raw TCP accept loop. Returns the
/// bound port plus the broker handle (for in-process assertions).
async fn start_broker() -> (u16, Broker<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let broker = Broker::<TcpStream>::new();

    // Build a one-protocol registry holding MQTT::server() + the broker statics.
    let registry: ProtocolEntryRegistry<hotaru_core::connection::tcp::TcpTransport> =
        ProtocolRegistryBuilder::new()
            .protocol(ProtocolEntryBuilder::new(MQTT::server()))
            .build();
    let registry = Arc::new(registry);

    let mut statics = Locals::new();
    statics.set(BROKER_STATICS_KEY, broker.clone());
    let runtime = Arc::new(RuntimeConfig::from_parts(
        Default::default(),
        Default::default(),
        statics,
    ));

    // Accept loop.
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let registry = registry.clone();
                    let runtime = runtime.clone();
                    tokio::spawn(async move {
                        registry.serve(runtime, stream).await;
                    });
                }
                Err(_) => break,
            }
        }
    });

    // Brief delay so the spawn-and-accept task is ready to receive.
    tokio::time::sleep(Duration::from_millis(20)).await;

    (port, broker)
}

async fn connect_raw(
    port: u16,
) -> (
    BufReader<tokio::net::tcp::OwnedReadHalf>,
    tokio::net::tcp::OwnedWriteHalf,
) {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (r, w) = stream.into_split();
    (BufReader::new(r), w)
}

async fn send_packet(writer: &mut tokio::net::tcp::OwnedWriteHalf, packet: &Packet) {
    send_packet_version(writer, packet, ProtocolVersion::V311).await;
}

async fn send_packet_version(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    packet: &Packet,
    version: ProtocolVersion,
) {
    let bytes = codec::encode_packet(packet, version).unwrap();
    writer.write_all(&bytes).await.unwrap();
    writer.flush().await.unwrap();
}

async fn read_packet(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Packet {
    read_packet_version(reader, ProtocolVersion::V311).await
}

async fn read_packet_version(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    version: ProtocolVersion,
) -> Packet {
    timeout(Duration::from_secs(5), codec::read_packet(reader, version))
        .await
        .expect("read_packet timeout")
        .expect("read_packet error")
}

fn connect_packet(client_id: &str) -> Packet {
    connect_packet_version(client_id, ProtocolVersion::V311)
}

fn connect_packet_version(client_id: &str, version: ProtocolVersion) -> Packet {
    Packet::Connect(Box::new(ConnectPacket {
        version,
        properties: Default::default(),
        client_id: Arc::from(client_id),
        clean_session: true,
        keep_alive: 60,
        username: None,
        password: None,
        will: None,
    }))
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smoke_lib_constructible() {
    let _broker = Broker::<TcpStream>::new();
    let _config = hotaru_mqtt::MqttClientConfig::new("test-client");
    let _proto = MQTT::server();
    let _proto = MQTT::client();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_returns_connack() {
    let (port, _broker) = start_broker().await;

    let (mut reader, mut writer) = connect_raw(port).await;
    send_packet(&mut writer, &connect_packet("test-client-1")).await;

    match read_packet(&mut reader).await {
        Packet::Connack(ConnackPacket {
            session_present,
            return_code,
            ..
        }) => {
            assert!(!session_present);
            assert_eq!(return_code, ConnackReturnCode::Accepted);
        }
        other => panic!("expected CONNACK, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mqtt5_connect_returns_mqtt5_connack() {
    let (port, _broker) = start_broker().await;
    let (mut reader, mut writer) = connect_raw(port).await;

    let connect = connect_packet_version("mqtt5-client", ProtocolVersion::V5);
    send_packet_version(&mut writer, &connect, ProtocolVersion::V5).await;

    match read_packet_version(&mut reader, ProtocolVersion::V5).await {
        Packet::Connack(ack) => {
            assert_eq!(ack.return_code, ConnackReturnCode::Accepted);
            assert!(ack.properties.is_empty());
        }
        other => panic!("expected MQTT 5 CONNACK, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v311_publish_is_encoded_for_mqtt5_subscriber() {
    let (port, _broker) = start_broker().await;

    let (mut sub_reader, mut sub_writer) = connect_raw(port).await;
    let sub_connect = connect_packet_version("mqtt5-sub", ProtocolVersion::V5);
    send_packet_version(&mut sub_writer, &sub_connect, ProtocolVersion::V5).await;
    let _ = read_packet_version(&mut sub_reader, ProtocolVersion::V5).await;
    send_packet_version(
        &mut sub_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("cross/version"),
                qos: QoS::AtMostOnce,
            }],
        }),
        ProtocolVersion::V5,
    )
    .await;
    let _ = read_packet_version(&mut sub_reader, ProtocolVersion::V5).await;

    let (mut pub_reader, mut pub_writer) = connect_raw(port).await;
    send_packet(&mut pub_writer, &connect_packet("v311-pub")).await;
    let _ = read_packet(&mut pub_reader).await;
    send_packet(
        &mut pub_writer,
        &Packet::Publish(PublishPacket {
            properties: Properties::default(),
            topic: Arc::from("cross/version"),
            payload: bytes::Bytes::from_static(b"mixed"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    match read_packet_version(&mut sub_reader, ProtocolVersion::V5).await {
        Packet::Publish(publish) => {
            assert_eq!(publish.topic.as_ref(), "cross/version");
            assert_eq!(&publish.payload[..], b"mixed");
            assert!(publish.properties.is_empty());
        }
        other => panic!("expected cross-version PUBLISH, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subscribe_returns_suback() {
    let (port, _broker) = start_broker().await;

    let (mut reader, mut writer) = connect_raw(port).await;
    send_packet(&mut writer, &connect_packet("sub-client")).await;
    let _ = read_packet(&mut reader).await;

    let sub = Packet::Subscribe(SubscribePacket {
        packet_id: 7,
        subscriptions: vec![TopicSubscription {
            topic: Arc::from("sensors/+/temp"),
            qos: QoS::AtLeastOnce,
        }],
    });
    send_packet(&mut writer, &sub).await;

    match read_packet(&mut reader).await {
        Packet::Suback(SubackPacket {
            packet_id,
            return_codes,
        }) => {
            assert_eq!(packet_id, 7);
            assert_eq!(return_codes.len(), 1);
            assert!(matches!(
                return_codes[0],
                hotaru_mqtt::SubackCode::Granted(QoS::AtLeastOnce)
            ));
        }
        other => panic!("expected SUBACK, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publish_q0_fanout_to_subscriber() {
    let (port, _broker) = start_broker().await;

    let (mut sub_reader, mut sub_writer) = connect_raw(port).await;
    send_packet(&mut sub_writer, &connect_packet("sub")).await;
    let _ = read_packet(&mut sub_reader).await;
    send_packet(
        &mut sub_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("hello/world"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sub_reader).await;

    let (mut pub_reader, mut pub_writer) = connect_raw(port).await;
    send_packet(&mut pub_writer, &connect_packet("pub")).await;
    let _ = read_packet(&mut pub_reader).await;
    send_packet(
        &mut pub_writer,
        &Packet::Publish(PublishPacket {
            properties: Default::default(),
            topic: Arc::from("hello/world"),
            payload: bytes::Bytes::from_static(b"greetings"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    match read_packet(&mut sub_reader).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "hello/world");
            assert_eq!(&p.payload[..], b"greetings");
            assert_eq!(p.qos, QoS::AtMostOnce);
        }
        other => panic!("expected PUBLISH, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publish_q1_round_trip_with_puback() {
    let (port, _broker) = start_broker().await;

    let (mut sub_reader, mut sub_writer) = connect_raw(port).await;
    send_packet(&mut sub_writer, &connect_packet("sub")).await;
    let _ = read_packet(&mut sub_reader).await;
    send_packet(
        &mut sub_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("q1/topic"),
                qos: QoS::AtLeastOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sub_reader).await;

    let (mut pub_reader, mut pub_writer) = connect_raw(port).await;
    send_packet(&mut pub_writer, &connect_packet("pub")).await;
    let _ = read_packet(&mut pub_reader).await;
    send_packet(
        &mut pub_writer,
        &Packet::Publish(PublishPacket {
            properties: Default::default(),
            topic: Arc::from("q1/topic"),
            payload: bytes::Bytes::from_static(b"q1-payload"),
            dup: false,
            qos: QoS::AtLeastOnce,
            retain: false,
            packet_id: Some(42),
        }),
    )
    .await;

    match read_packet(&mut pub_reader).await {
        Packet::Puback(id) => assert_eq!(id, 42),
        other => panic!("expected PUBACK, got {:?}", other),
    }

    match read_packet(&mut sub_reader).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "q1/topic");
            assert_eq!(&p.payload[..], b"q1-payload");
            assert_eq!(p.qos, QoS::AtLeastOnce);
            assert!(p.packet_id.is_some());
            send_packet(&mut sub_writer, &Packet::Puback(p.packet_id.unwrap())).await;
        }
        other => panic!("expected PUBLISH, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wildcard_plus_matches() {
    let (port, _broker) = start_broker().await;

    let (mut sub_reader, mut sub_writer) = connect_raw(port).await;
    send_packet(&mut sub_writer, &connect_packet("wildsub")).await;
    let _ = read_packet(&mut sub_reader).await;
    send_packet(
        &mut sub_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("a/+/c"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sub_reader).await;

    let (mut pub_reader, mut pub_writer) = connect_raw(port).await;
    send_packet(&mut pub_writer, &connect_packet("wildpub")).await;
    let _ = read_packet(&mut pub_reader).await;
    send_packet(
        &mut pub_writer,
        &Packet::Publish(PublishPacket {
            properties: Default::default(),
            topic: Arc::from("a/b/c"),
            payload: bytes::Bytes::from_static(b"hit"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    match read_packet(&mut sub_reader).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "a/b/c");
            assert_eq!(&p.payload[..], b"hit");
        }
        other => panic!("expected PUBLISH, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unsubscribe_stops_delivery() {
    let (port, _broker) = start_broker().await;

    let (mut sub_reader, mut sub_writer) = connect_raw(port).await;
    send_packet(&mut sub_writer, &connect_packet("unsub-test")).await;
    let _ = read_packet(&mut sub_reader).await;
    send_packet(
        &mut sub_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("u/topic"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sub_reader).await;

    send_packet(
        &mut sub_writer,
        &Packet::Unsubscribe(hotaru_mqtt::UnsubscribePacket {
            packet_id: 2,
            topics: vec![Arc::from("u/topic")],
        }),
    )
    .await;
    match read_packet(&mut sub_reader).await {
        Packet::Unsuback(id) => assert_eq!(id, 2),
        other => panic!("expected UNSUBACK, got {:?}", other),
    }

    let (_, mut pub_writer) = connect_raw(port).await;
    send_packet(&mut pub_writer, &connect_packet("u-pub")).await;
    send_packet(
        &mut pub_writer,
        &Packet::Publish(PublishPacket {
            properties: Default::default(),
            topic: Arc::from("u/topic"),
            payload: bytes::Bytes::from_static(b"should not arrive"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    let waited = timeout(
        Duration::from_millis(300),
        codec::read_packet(&mut sub_reader, ProtocolVersion::V311),
    )
    .await;
    assert!(
        waited.is_err(),
        "subscriber should not receive after UNSUBSCRIBE; got {:?}",
        waited
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pingreq_returns_pingresp() {
    let (port, _broker) = start_broker().await;

    let (mut reader, mut writer) = connect_raw(port).await;
    send_packet(&mut writer, &connect_packet("pinger")).await;
    let _ = read_packet(&mut reader).await;

    send_packet(&mut writer, &Packet::Pingreq).await;
    match read_packet(&mut reader).await {
        Packet::Pingresp => {}
        other => panic!("expected PINGRESP, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn self_fanout_suppression() {
    let (port, _broker) = start_broker().await;

    let (mut reader, mut writer) = connect_raw(port).await;
    send_packet(&mut writer, &connect_packet("self")).await;
    let _ = read_packet(&mut reader).await;
    send_packet(
        &mut writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("self/topic"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut reader).await;

    send_packet(
        &mut writer,
        &Packet::Publish(PublishPacket {
            properties: Default::default(),
            topic: Arc::from("self/topic"),
            payload: bytes::Bytes::from_static(b"echo"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    let waited = timeout(
        Duration::from_millis(300),
        codec::read_packet(&mut reader, ProtocolVersion::V311),
    )
    .await;
    assert!(
        waited.is_err(),
        "self-publish should be suppressed; got {:?}",
        waited
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broker_constructs_cleanly() {
    let _broker = Broker::<TcpStream>::new();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publish_q2_full_handshake() {
    let (port, _broker) = start_broker().await;

    // Subscriber with QoS 2
    let (mut sub_reader, mut sub_writer) = connect_raw(port).await;
    send_packet(&mut sub_writer, &connect_packet("q2-sub")).await;
    let _ = read_packet(&mut sub_reader).await;
    send_packet(
        &mut sub_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("q2/topic"),
                qos: QoS::ExactlyOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sub_reader).await;

    // Publisher sends QoS 2 → expects PUBREC, sends PUBREL, expects PUBCOMP
    let (mut pub_reader, mut pub_writer) = connect_raw(port).await;
    send_packet(&mut pub_writer, &connect_packet("q2-pub")).await;
    let _ = read_packet(&mut pub_reader).await;
    send_packet(
        &mut pub_writer,
        &Packet::Publish(PublishPacket {
            properties: Default::default(),
            topic: Arc::from("q2/topic"),
            payload: bytes::Bytes::from_static(b"q2-payload"),
            dup: false,
            qos: QoS::ExactlyOnce,
            retain: false,
            packet_id: Some(99),
        }),
    )
    .await;

    // Broker should reply PUBREC
    match read_packet(&mut pub_reader).await {
        Packet::Pubrec(id) => assert_eq!(id, 99),
        other => panic!("expected PUBREC, got {:?}", other),
    }

    // Publisher sends PUBREL
    send_packet(&mut pub_writer, &Packet::Pubrel(99)).await;

    // Broker replies PUBCOMP
    match read_packet(&mut pub_reader).await {
        Packet::Pubcomp(id) => assert_eq!(id, 99),
        other => panic!("expected PUBCOMP, got {:?}", other),
    }

    // Subscriber should receive PUBLISH (QoS 2). Order vs PUBCOMP can vary
    // because subscriber's branch is independent; allow either order.
    match read_packet(&mut sub_reader).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "q2/topic");
            assert_eq!(&p.payload[..], b"q2-payload");
            assert_eq!(p.qos, QoS::ExactlyOnce);
            assert!(p.packet_id.is_some());
            // Subscriber sends PUBREC back
            send_packet(&mut sub_writer, &Packet::Pubrec(p.packet_id.unwrap())).await;
            // Broker should send PUBREL
            match read_packet(&mut sub_reader).await {
                Packet::Pubrel(id) => {
                    assert_eq!(id, p.packet_id.unwrap());
                    send_packet(&mut sub_writer, &Packet::Pubcomp(id)).await;
                }
                other => panic!("expected PUBREL, got {:?}", other),
            }
        }
        other => panic!("expected PUBLISH, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wildcard_hash_matches() {
    let (port, _broker) = start_broker().await;

    let (mut sub_reader, mut sub_writer) = connect_raw(port).await;
    send_packet(&mut sub_writer, &connect_packet("hsub")).await;
    let _ = read_packet(&mut sub_reader).await;
    send_packet(
        &mut sub_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("sensors/#"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sub_reader).await;

    let (_, mut pub_writer) = connect_raw(port).await;
    send_packet(&mut pub_writer, &connect_packet("hpub")).await;
    send_packet(
        &mut pub_writer,
        &Packet::Publish(PublishPacket {
            properties: Default::default(),
            topic: Arc::from("sensors/floor/3/temp"),
            payload: bytes::Bytes::from_static(b"deep"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    match read_packet(&mut sub_reader).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "sensors/floor/3/temp");
        }
        other => panic!("expected PUBLISH, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn fanout_to_multiple_subscribers() {
    let (port, _broker) = start_broker().await;

    // Three subscribers
    let mut subs = Vec::new();
    for i in 0..3 {
        let (mut r, mut w) = connect_raw(port).await;
        send_packet(&mut w, &connect_packet(&format!("sub-{}", i))).await;
        let _ = read_packet(&mut r).await;
        send_packet(
            &mut w,
            &Packet::Subscribe(SubscribePacket {
                packet_id: 1,
                subscriptions: vec![TopicSubscription {
                    topic: Arc::from("broadcast/topic"),
                    qos: QoS::AtMostOnce,
                }],
            }),
        )
        .await;
        let _ = read_packet(&mut r).await;
        subs.push((r, w));
    }

    let (_, mut pub_writer) = connect_raw(port).await;
    send_packet(&mut pub_writer, &connect_packet("broadcaster")).await;
    send_packet(
        &mut pub_writer,
        &Packet::Publish(PublishPacket {
            properties: Default::default(),
            topic: Arc::from("broadcast/topic"),
            payload: bytes::Bytes::from_static(b"to all"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    // Each subscriber should receive
    for (i, (mut r, _)) in subs.into_iter().enumerate() {
        match read_packet(&mut r).await {
            Packet::Publish(p) => {
                assert_eq!(p.topic.as_ref(), "broadcast/topic", "sub {}", i);
                assert_eq!(&p.payload[..], b"to all", "sub {}", i);
            }
            other => panic!("sub {}: expected PUBLISH, got {:?}", i, other),
        }
    }
}

// ─── AIoT / cross-protocol tests ─────────────────────────────────────

/// Build a broker on a random port that accepts BOTH HTTP and MQTT
/// (protocol detection picks the right handler per connection). Returns the
/// port + broker handle so the test can also call broker.publish directly
/// (simulating any non-MQTT code path that has a broker handle — e.g. an
/// HTTP endpoint reading it from runtime statics).
async fn start_multi_protocol_broker() -> (u16, Broker<TcpStream>) {
    use hotaru_http::HTTP;
    use hotaru_http::security::safety::HttpSafety;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let broker = Broker::<TcpStream>::new();

    let registry: ProtocolEntryRegistry<hotaru_core::connection::tcp::TcpTransport> =
        ProtocolRegistryBuilder::new()
            .protocol(ProtocolEntryBuilder::new(HTTP::server(HttpSafety::default())))
            .protocol(ProtocolEntryBuilder::new(MQTT::server()))
            .build();
    let registry = Arc::new(registry);

    let mut statics = Locals::new();
    statics.set(BROKER_STATICS_KEY, broker.clone());
    let runtime = Arc::new(RuntimeConfig::from_parts(
        Default::default(),
        Default::default(),
        statics,
    ));

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let registry = registry.clone();
                    let runtime = runtime.clone();
                    tokio::spawn(async move {
                        registry.serve(runtime, stream).await;
                    });
                }
                Err(_) => break,
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    (port, broker)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_protocol_mqtt_works_alongside_http() {
    let (port, _broker) = start_multi_protocol_broker().await;

    // MQTT client connects to the multi-protocol port
    let (mut reader, mut writer) = connect_raw(port).await;
    send_packet(&mut writer, &connect_packet("multi-proto-mqtt")).await;

    // MQTT detection on first byte (0x10) should route to MQTT handler.
    match read_packet(&mut reader).await {
        Packet::Connack(ConnackPacket { return_code, .. }) => {
            assert_eq!(return_code, ConnackReturnCode::Accepted);
        }
        other => panic!("expected CONNACK, got {:?}", other),
    }
}

/// AIoT closed-loop: external code (simulating an HTTP endpoint reading
/// the broker from runtime statics) calls `broker.publish` and MQTT
/// subscribers receive the fanout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_broker_publish_reaches_mqtt_subscriber() {
    let (port, broker) = start_broker().await;

    // MQTT subscriber
    let (mut sub_reader, mut sub_writer) = connect_raw(port).await;
    send_packet(&mut sub_writer, &connect_packet("aiot-sub")).await;
    let _ = read_packet(&mut sub_reader).await;
    send_packet(
        &mut sub_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("aiot/event"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sub_reader).await;

    // External code (NOT an MQTT publisher) calls broker.publish directly.
    // This simulates: an HTTP endpoint receiving a POST, looking up broker
    // from RuntimeConfig statics, and triggering an MQTT publish.
    broker
        .publish(
            &Arc::from("http-bridge"),
            PublishPacket {
                properties: Default::default(),
                topic: Arc::from("aiot/event"),
                payload: bytes::Bytes::from_static(b"from-http"),
                dup: false,
                qos: QoS::AtMostOnce,
                retain: false,
                packet_id: None,
            },
        )
        .await;

    // MQTT subscriber receives the fanout
    match read_packet(&mut sub_reader).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "aiot/event");
            assert_eq!(&p.payload[..], b"from-http");
        }
        other => panic!("expected PUBLISH from external broker.publish, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn will_message_fires_on_abrupt_disconnect() {
    let (port, _broker) = start_broker().await;

    // Subscriber listens for "lwt/topic"
    let (mut sub_reader, mut sub_writer) = connect_raw(port).await;
    send_packet(&mut sub_writer, &connect_packet("lwt-sub")).await;
    let _ = read_packet(&mut sub_reader).await;
    send_packet(
        &mut sub_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("lwt/topic"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sub_reader).await;

    // "Crashing" publisher with a will
    let (mut pub_reader, mut pub_writer) = connect_raw(port).await;
    let will_connect = Packet::Connect(Box::new(ConnectPacket {
        version: ProtocolVersion::V311,
        properties: Default::default(),
        client_id: Arc::from("crash-client"),
        clean_session: true,
        keep_alive: 60,
        username: None,
        password: None,
        will: Some(hotaru_mqtt::WillPacket {
            properties: Default::default(),
            topic: Arc::from("lwt/topic"),
            payload: bytes::Bytes::from_static(b"gone"),
            qos: QoS::AtMostOnce,
            retain: false,
        }),
    }));
    send_packet(&mut pub_writer, &will_connect).await;
    let _ = read_packet(&mut pub_reader).await;

    // Drop the publisher writer/reader abruptly (no DISCONNECT) → broker fires will
    drop(pub_writer);
    drop(pub_reader);

    // Subscriber should receive the will message
    match read_packet(&mut sub_reader).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "lwt/topic");
            assert_eq!(&p.payload[..], b"gone");
        }
        other => panic!("expected will PUBLISH, got {:?}", other),
    }
}
