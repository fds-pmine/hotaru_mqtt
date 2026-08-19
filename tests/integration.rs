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
    BROKER_STATICS_KEY, Broker, ConnackPacket, ConnackReturnCode, ConnectPacket, MQTT,
    MqttSafety, Packet, PublishPacket, QoS, SubackPacket, SubscribePacket,
    TopicSubscription, codec,
};

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/// Spin up a broker on a random port via raw TCP accept loop. Returns the
/// bound port plus the broker handle (for in-process assertions).
async fn start_broker() -> (u16, Broker<TcpStream>) {
    start_broker_with(Broker::<TcpStream>::new()).await
}

async fn start_broker_with(broker: Broker<TcpStream>) -> (u16, Broker<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

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
    let bytes = codec::encode_packet(packet).expect("test packet must encode");
    writer.write_all(&bytes).await.unwrap();
    writer.flush().await.unwrap();
}

/// Test reads are not exercising the size cap, so they use the widest value a
/// conforming packet can declare. `oversize_publish_header_is_refused` is the
/// one test that cares, and it drives the wire directly.
const ANY_SIZE: usize = hotaru_mqtt::SPEC_MAX_PACKET_SIZE;

async fn read_packet(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Packet {
    timeout(Duration::from_secs(5), codec::read_packet(reader, ANY_SIZE))
        .await
        .expect("read_packet timeout")
        .expect("read_packet error")
}

fn connect_packet(client_id: &str) -> Packet {
    Packet::Connect(ConnectPacket {
        client_id: Arc::from(client_id),
        clean_session: true,
        keep_alive: 60,
        username: None,
        password: None,
        will: None,
    })
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
        }) => {
            assert!(!session_present);
            assert_eq!(return_code, ConnackReturnCode::Accepted);
        }
        other => panic!("expected CONNACK, got {:?}", other),
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
            topic: Arc::from("u/topic"),
            payload: bytes::Bytes::from_static(b"should not arrive"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    let waited = timeout(Duration::from_millis(300), codec::read_packet(&mut sub_reader, ANY_SIZE)).await;
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
            topic: Arc::from("self/topic"),
            payload: bytes::Bytes::from_static(b"echo"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    let waited = timeout(Duration::from_millis(300), codec::read_packet(&mut reader, ANY_SIZE)).await;
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
    let will_connect = Packet::Connect(ConnectPacket {
        client_id: Arc::from("crash-client"),
        clean_session: true,
        keep_alive: 60,
        username: None,
        password: None,
        will: Some(hotaru_mqtt::WillPacket {
            topic: Arc::from("lwt/topic"),
            payload: bytes::Bytes::from_static(b"gone"),
            qos: QoS::AtMostOnce,
            retain: false,
        }),
    });
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

// ----------------------------------------------------------------------------
// Wire-layer limits
// ----------------------------------------------------------------------------

/// An unauthenticated peer must not be able to choose the server's allocation
/// size. Five bytes declare a ~256 MiB body; the cap has to bite on the CONNECT
/// read itself, before authentication and before `vec![0u8; remaining]`.
///
/// The assertion is timing-shaped on purpose: without the cap the server
/// allocates and then blocks in `read_exact` waiting for a body that never
/// arrives, so the connection stays open for the full 10s CONNECT_RECEIVE
/// timeout. With the cap it is refused on the header alone and the socket
/// closes immediately.
#[tokio::test]
async fn oversize_declaration_is_refused_before_authentication() {
    let (port, _broker) =
        start_broker_with(Broker::with_safety(MqttSafety::new().with_max_packet_size(1024))).await;
    let (mut reader, mut writer) = connect_raw(port).await;

    // 0x10 = CONNECT, then FF FF FF 7F = the largest 4-byte VBI. No body follows.
    writer.write_all(&[0x10, 0xFF, 0xFF, 0xFF, 0x7F]).await.unwrap();
    writer.flush().await.unwrap();

    let mut sink = Vec::new();
    let closed = timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut sink),
    )
    .await;

    assert!(
        closed.is_ok(),
        "connection still open after 2s: the body was allocated and the read \
is parked waiting for 256 MiB that will never arrive"
    );
    assert!(
        sink.is_empty(),
        "server must not answer a malformed CONNECT, got {sink:?}"
    );
}

/// The same guard on the steady-state loop, i.e. after CONNECT succeeded.
#[tokio::test]
async fn oversize_declaration_is_refused_after_connect() {
    let (port, _broker) =
        start_broker_with(Broker::with_safety(MqttSafety::new().with_max_packet_size(1024))).await;
    let (mut reader, mut writer) = connect_raw(port).await;

    send_packet(&mut writer, &connect_packet("oversize-after-connect")).await;
    match read_packet(&mut reader).await {
        Packet::Connack(ack) => assert_eq!(ConnackReturnCode::Accepted, ack.return_code),
        other => panic!("expected CONNACK, got {other:?}"),
    }

    // 0x30 = PUBLISH with the same oversized declaration.
    writer.write_all(&[0x30, 0xFF, 0xFF, 0xFF, 0x7F]).await.unwrap();
    writer.flush().await.unwrap();

    let mut sink = Vec::new();
    let closed = timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut sink),
    )
    .await;
    assert!(closed.is_ok(), "connection still open after 2s");
}

// ----------------------------------------------------------------------------
// Connection teardown
// ----------------------------------------------------------------------------

/// A malformed packet after CONNECT must still tear the session down.
///
/// The read loop used to `return Err(e)` here, jumping over the
/// `unregister_session` call written below the loop, so the entry stayed in the
/// broker's table with its subscriptions live and its channel `Arc` held.
#[tokio::test]
async fn malformed_packet_after_connect_unregisters_the_session() {
    let (port, broker) = start_broker().await;
    let (mut reader, mut writer) = connect_raw(port).await;

    send_packet(&mut writer, &connect_packet("leaky")).await;
    match read_packet(&mut reader).await {
        Packet::Connack(ack) => assert_eq!(ConnackReturnCode::Accepted, ack.return_code),
        other => panic!("expected CONNACK, got {other:?}"),
    }
    assert_eq!(1, broker.session_count(), "session should be registered");

    // 0xF0 is not a valid MQTT 3.1.1 packet type — the codec refuses it and the
    // read loop takes its error path.
    writer.write_all(&[0xF0, 0x00]).await.unwrap();
    writer.flush().await.unwrap();

    let mut sink = Vec::new();
    let _ = timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut sink),
    )
    .await;
    // The teardown runs after the loop exits; give the task a moment to finish.
    tokio::time::sleep(Duration::from_millis(120)).await;

    assert_eq!(
        0,
        broker.session_count(),
        "malformed packet left the session registered — teardown was skipped"
    );
}

/// The Will is the other half of the same defect, and the more visible one:
/// a Will exists precisely to announce a connection that ended badly, and a
/// malformed packet is exactly that case (MQTT-3.1.2-5).
#[tokio::test]
async fn malformed_packet_after_connect_publishes_the_will() {
    let (port, _broker) = start_broker().await;

    // Subscriber waits on the will topic.
    let (mut sub_reader, mut sub_writer) = connect_raw(port).await;
    send_packet(&mut sub_writer, &connect_packet("will-watcher")).await;
    let _ = read_packet(&mut sub_reader).await;
    send_packet(
        &mut sub_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("gone/#"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sub_reader).await;

    // Publisher connects with a will, then sends garbage.
    let (mut pub_reader, mut pub_writer) = connect_raw(port).await;
    let mut connect = match connect_packet("dies-badly") {
        Packet::Connect(c) => c,
        _ => unreachable!(),
    };
    connect.will = Some(hotaru_mqtt::WillPacket {
        topic: Arc::from("gone/dies-badly"),
        payload: bytes::Bytes::from_static(b"offline"),
        qos: QoS::AtMostOnce,
        retain: false,
    });
    send_packet(&mut pub_writer, &Packet::Connect(connect)).await;
    let _ = read_packet(&mut pub_reader).await;

    pub_writer.write_all(&[0xF0, 0x00]).await.unwrap();
    pub_writer.flush().await.unwrap();

    match read_packet(&mut sub_reader).await {
        Packet::Publish(p) => {
            assert_eq!("gone/dies-badly", &*p.topic);
            assert_eq!(&b"offline"[..], &p.payload[..]);
        }
        other => panic!("expected the will publish, got {other:?}"),
    }
}

// ----------------------------------------------------------------------------
// Connection identity under takeover
// ----------------------------------------------------------------------------

/// MQTT-3.1.4-2: a second CONNECT carrying a client_id that is already
/// connected must close the earlier connection.
///
/// Dropping the map entry does not do that — the earlier `handle_server` holds
/// its own channel clone and reader, and would sit there until keep-alive
/// elapsed, which the client picks and may set to 65535 seconds.
#[tokio::test]
async fn takeover_closes_the_earlier_connection() {
    let (port, broker) = start_broker().await;

    let (mut first_reader, mut first_writer) = connect_raw(port).await;
    send_packet(&mut first_writer, &connect_packet("twins")).await;
    let _ = read_packet(&mut first_reader).await;
    assert_eq!(1, broker.session_count());

    let (mut second_reader, mut second_writer) = connect_raw(port).await;
    send_packet(&mut second_writer, &connect_packet("twins")).await;
    let _ = read_packet(&mut second_reader).await;

    let mut sink = Vec::new();
    let closed = timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_to_end(&mut first_reader, &mut sink),
    )
    .await;
    assert!(
        closed.is_ok(),
        "earlier connection still open 2s after being taken over"
    );
}

/// The earlier connection runs its own teardown after being closed. Removal is
/// keyed on client_id, which by then names the *newer* session, so an
/// unconditional remove deletes the live session and takes its subscriptions
/// with it. The generation guard is what stops that.
#[tokio::test]
async fn earlier_teardown_does_not_evict_the_live_session() {
    let (port, broker) = start_broker().await;

    let (mut first_reader, mut first_writer) = connect_raw(port).await;
    send_packet(&mut first_writer, &connect_packet("twins")).await;
    let _ = read_packet(&mut first_reader).await;

    let (mut second_reader, mut second_writer) = connect_raw(port).await;
    send_packet(&mut second_writer, &connect_packet("twins")).await;
    let _ = read_packet(&mut second_reader).await;

    // Let the earlier connection notice it was closed and finish tearing down.
    let mut sink = Vec::new();
    let _ = timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_to_end(&mut first_reader, &mut sink),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    assert_eq!(
        1,
        broker.session_count(),
        "the earlier connection's teardown deleted the session that replaced it"
    );

    // And the survivor is still functional, not just present in the table.
    send_packet(
        &mut second_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 7,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("after/takeover"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    match read_packet(&mut second_reader).await {
        Packet::Suback(ack) => assert_eq!(7, ack.packet_id),
        other => panic!("expected SUBACK on the surviving session, got {other:?}"),
    }
}

/// A takeover ends the earlier connection non-gracefully by construction, so
/// MQTT-3.1.2-5 requires its Will.
///
/// This is the half that the generation guard silently breaks: once the earlier
/// connection's `unregister_session` no-ops, the Will publishing that lived
/// inside it stops happening, and nothing fails loudly — the connection closes
/// either way and no existing test goes red.
#[tokio::test]
async fn takeover_publishes_the_earlier_connection_will() {
    let (port, _broker) = start_broker().await;

    let (mut watcher_reader, mut watcher_writer) = connect_raw(port).await;
    send_packet(&mut watcher_writer, &connect_packet("will-watcher")).await;
    let _ = read_packet(&mut watcher_reader).await;
    send_packet(
        &mut watcher_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("gone/#"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut watcher_reader).await;

    let (mut first_reader, mut first_writer) = connect_raw(port).await;
    let mut connect = match connect_packet("twins") {
        Packet::Connect(c) => c,
        _ => unreachable!(),
    };
    connect.will = Some(hotaru_mqtt::WillPacket {
        topic: Arc::from("gone/twins"),
        payload: bytes::Bytes::from_static(b"taken over"),
        qos: QoS::AtMostOnce,
        retain: false,
    });
    send_packet(&mut first_writer, &Packet::Connect(connect)).await;
    let _ = read_packet(&mut first_reader).await;

    let (mut second_reader, mut second_writer) = connect_raw(port).await;
    send_packet(&mut second_writer, &connect_packet("twins")).await;
    let _ = read_packet(&mut second_reader).await;

    match read_packet(&mut watcher_reader).await {
        Packet::Publish(p) => {
            assert_eq!("gone/twins", &*p.topic);
            assert_eq!(&b"taken over"[..], &p.payload[..]);
        }
        other => panic!("expected the earlier connection's will, got {other:?}"),
    }
}

/// `subscribe` and `unsubscribe` resolve a session the same by-name way the
/// ack path did, and both are public API. A caller holding a connection_id
/// that has been superseded must not be able to mutate the live session's
/// subscription set — the newer client never asked for that filter and would
/// then receive traffic it did not subscribe to.
///
/// Driven through the broker API rather than over the wire: `close()` on the
/// takeover path makes the earlier read loop exit promptly, so a stale
/// SUBSCRIBE rarely gets dispatched at all. That narrows the window; it does
/// not make the guard unnecessary, and it would make a wire-level test pass
/// for the wrong reason.
#[tokio::test]
async fn a_superseded_connection_id_cannot_touch_the_live_session() {
    let (port, broker) = start_broker().await;

    let (mut reader, mut writer) = connect_raw(port).await;
    send_packet(&mut writer, &connect_packet("twins")).await;
    let _ = read_packet(&mut reader).await;

    let client_id: Arc<str> = Arc::from("twins");
    let filters = vec![hotaru_mqtt::TopicFilter::new("stale/topic", QoS::AtMostOnce)];

    // u64::MAX can never have been issued: ids come from a counter starting at 0.
    let codes = broker.subscribe(&client_id, u64::MAX, &filters).await;
    assert!(
        codes.iter().all(|c| matches!(c, hotaru_mqtt::SubackCode::Failure)),
        "a superseded connection_id was allowed to subscribe: {codes:?}"
    );

    // And nothing was registered: a publish to that filter must not be routed.
    let (mut pub_reader, mut pub_writer) = connect_raw(port).await;
    send_packet(&mut pub_writer, &connect_packet("publisher")).await;
    let _ = read_packet(&mut pub_reader).await;
    send_packet(
        &mut pub_writer,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("stale/topic"),
            payload: bytes::Bytes::from_static(b"should not arrive"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    let waited = timeout(
        Duration::from_millis(400),
        codec::read_packet(&mut reader, ANY_SIZE),
    )
    .await;
    assert!(
        waited.is_err(),
        "the live session received traffic for a filter it never asked for; got {waited:?}"
    );
}

// ----------------------------------------------------------------------------
// keep-alive
// ----------------------------------------------------------------------------

/// A client that declared `keep_alive = 0` asked not to be timed out, so the
/// broker must not disconnect it for saying nothing (spec §3.1.2.10).
///
/// The old code ran `keep_alive.max(1)`, so zero became a one-second deadline —
/// the most aggressive the expression could produce, and the exact opposite of
/// what was requested. A connection that declared "never time me out" was
/// dropped after a second.
#[tokio::test]
async fn a_zero_keep_alive_connection_is_not_dropped_for_being_idle() {
    let (port, broker) = start_broker().await;
    let (mut reader, mut writer) = connect_raw(port).await;

    let mut connect = match connect_packet("patient") {
        Packet::Connect(c) => c,
        _ => unreachable!(),
    };
    connect.keep_alive = 0;
    send_packet(&mut writer, &Packet::Connect(connect)).await;
    match read_packet(&mut reader).await {
        Packet::Connack(ack) => assert_eq!(ConnackReturnCode::Accepted, ack.return_code),
        other => panic!("expected CONNACK, got {other:?}"),
    }

    // Then say nothing. Under the old deadline this connection was gone after
    // one second; two and a half is well past that and well short of flaky.
    let mut sink = Vec::new();
    let closed = timeout(
        Duration::from_millis(2_500),
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut sink),
    )
    .await;
    assert!(
        closed.is_err(),
        "broker disconnected an idle keep_alive=0 client; it read {sink:?}"
    );
    assert_eq!(1, broker.session_count(), "the session should still be live");
}

/// The grace still bites when a keep-alive was actually asked for: a client
/// declaring 1 second and then going quiet is disconnected.
///
/// This is the other half of the same change — turning zero into "no deadline"
/// must not turn every deadline off.
#[tokio::test]
async fn an_idle_connection_with_a_keep_alive_is_still_dropped() {
    let (port, _broker) = start_broker().await;
    let (mut reader, mut writer) = connect_raw(port).await;

    let mut connect = match connect_packet("impatient") {
        Packet::Connect(c) => c,
        _ => unreachable!(),
    };
    connect.keep_alive = 1;
    send_packet(&mut writer, &Packet::Connect(connect)).await;
    let _ = read_packet(&mut reader).await;

    // Deadline is 1.5s; 4s leaves room without being slow.
    let mut sink = Vec::new();
    let closed = timeout(
        Duration::from_secs(4),
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut sink),
    )
    .await;
    assert!(
        closed.is_ok(),
        "broker kept an idle keep_alive=1 connection past its 1.5s grace"
    );
}
