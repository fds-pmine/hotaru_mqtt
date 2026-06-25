//! End-to-end integration tests for `hotaru_mqtt_broker`.
//!
//! Each test spins up a broker on a random local port by hand-rolling a
//! TCP accept loop (bypasses `Server::run`'s nested runtime spawn_blocking
//! which is awkward in test contexts). All MQTT traffic flows through real
//! TCP between client connections and the broker's `Protocol::handle` loop.

use std::sync::Arc;
use std::time::Duration;

use hotaru_core::app::common::RuntimeConfig;
use hotaru_core::executable::registry::ProtocolEntryRegistry;
use hotaru_core::executable::{ProtocolEntryBuilder, ProtocolRegistryBuilder};
use hotaru_core::extensions::Locals;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use hotaru_mqtt::{
    ConnackPacket, ConnackReturnCode, ConnectPacket, Packet, PublishPacket, QoS, SubackPacket,
    SubscribePacket, TopicSubscription, codec,
};
use hotaru_mqtt_broker::{
    AclChecker, AclDecision, BROKER_STATICS_KEY, Broker, BrokerSafety, MQTT_SERVER, TenantId,
    TenantResolver,
};

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/// Spin up a broker on a random port via raw TCP accept loop. Returns the
/// bound port plus the broker handle (for in-process assertions).
async fn start_broker() -> (u16, Broker<TcpStream>) {
    start_broker_with(Broker::<TcpStream>::insecure()).await
}

async fn start_broker_with(broker: Broker<TcpStream>) -> (u16, Broker<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let registry: ProtocolEntryRegistry<hotaru_core::connection::tcp::TcpTransport> =
        ProtocolRegistryBuilder::new()
            .protocol(ProtocolEntryBuilder::new(MQTT_SERVER::new()))
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
    let bytes = codec::encode_packet(packet).expect("encode_packet (test fixture)");
    writer.write_all(&bytes).await.unwrap();
    writer.flush().await.unwrap();
}

async fn read_packet(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Packet {
    timeout(
        Duration::from_secs(5),
        codec::read_packet(reader, usize::MAX),
    )
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

fn connect_packet_persistent(client_id: &str) -> Packet {
    Packet::Connect(ConnectPacket {
        client_id: Arc::from(client_id),
        clean_session: false,
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
    let _broker = Broker::<TcpStream>::insecure();
    let _config = hotaru_mqtt::MqttClientConfig::new("test-client");
    let _server = MQTT_SERVER::new();
    let _client = hotaru_mqtt::MQTT::new();
}

// ──────────────────────────────────────────────────────────────────────
// Stage A P4: TenantResolver wiring — cross-tenant fanout MUST stay
// structurally blocked even with shared `#` subscribers.
// ──────────────────────────────────────────────────────────────────────

/// Tenant resolver that picks the tenant from a `<tenant>:<actual-id>`
/// client_id prefix. Anything without a colon goes to `None` (the
/// single-tenant namespace).
struct PrefixTenantResolver;

#[async_trait::async_trait]
impl TenantResolver for PrefixTenantResolver {
    async fn resolve(
        &self,
        connect: &hotaru_mqtt::ConnectPacket,
        _remote_addr: Option<std::net::SocketAddr>,
    ) -> Option<TenantId> {
        let id = connect.client_id.as_ref();
        id.split_once(':').map(|(t, _)| Arc::from(t))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_tenant_fanout_is_blocked() {
    let broker = Broker::<TcpStream>::insecure().with_tenant_resolver(Arc::new(PrefixTenantResolver));
    let (port, _broker) = start_broker_with(broker).await;

    // Subscriber in tenant `ta`, listening on the wildcard `#`.
    let (mut sub_r, mut sub_w) = connect_raw(port).await;
    send_packet(&mut sub_w, &connect_packet("ta:vacuum-sub")).await;
    let _ = read_packet(&mut sub_r).await; // CONNACK

    send_packet(
        &mut sub_w,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("#"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sub_r).await; // SUBACK

    // Publisher in tenant `tb`, fires a PUBLISH.
    let (_pub_r, mut pub_w) = connect_raw(port).await;
    send_packet(&mut pub_w, &connect_packet("tb:leak-attempt")).await;

    send_packet(
        &mut pub_w,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("secret/cross-tenant"),
            payload: bytes::Bytes::from_static(b"should-not-leak"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    // Subscriber MUST NOT receive — wait briefly for any cross-tenant fanout
    // that would betray the isolation invariant.
    let leaked = timeout(
        Duration::from_millis(300),
        codec::read_packet(&mut sub_r, usize::MAX),
    )
    .await;
    assert!(
        leaked.is_err(),
        "tenant `tb` publish reached tenant `ta` subscriber, audit F6 not enforced: {leaked:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_tenant_fanout_still_works() {
    // Counter-positive control: with PrefixTenantResolver in place, two
    // clients in the SAME tenant DO see each other's traffic.
    let broker = Broker::<TcpStream>::insecure().with_tenant_resolver(Arc::new(PrefixTenantResolver));
    let (port, _broker) = start_broker_with(broker).await;

    let (mut sub_r, mut sub_w) = connect_raw(port).await;
    send_packet(&mut sub_w, &connect_packet("ta:listener")).await;
    let _ = read_packet(&mut sub_r).await;
    send_packet(
        &mut sub_w,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("greet/+"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sub_r).await;

    let (_pub_r, mut pub_w) = connect_raw(port).await;
    send_packet(&mut pub_w, &connect_packet("ta:speaker")).await;
    send_packet(
        &mut pub_w,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("greet/world"),
            payload: bytes::Bytes::from_static(b"hello"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    match read_packet(&mut sub_r).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "greet/world");
            assert_eq!(&p.payload[..], b"hello");
        }
        other => panic!("expected PUBLISH for same-tenant fanout, got {other:?}"),
    }
}

// ──────────────────────────────────────────────────────────────────────
// Stage A P5: retained messages (spec §3.3.1.3 + D19)
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_message_replayed_on_subscribe() {
    let (port, _broker) = start_broker().await;

    // Publisher sends a retained message and disconnects.
    let (_pr, mut pw) = connect_raw(port).await;
    send_packet(&mut pw, &connect_packet("ret-publisher")).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    send_packet(
        &mut pw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("status/online"),
            payload: bytes::Bytes::from_static(b"true"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: true,
            packet_id: None,
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(pw);

    // New subscriber later — should receive the retained message with
    // retain=1 on the wire.
    let (mut sr, mut sw) = connect_raw(port).await;
    send_packet(&mut sw, &connect_packet("ret-subscriber")).await;
    let _ = read_packet(&mut sr).await;
    send_packet(
        &mut sw,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("status/+"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr).await; // SUBACK

    match read_packet(&mut sr).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "status/online");
            assert_eq!(&p.payload[..], b"true");
            assert!(p.retain, "retained replay MUST carry retain=1");
        }
        other => panic!("expected retained PUBLISH, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retained_empty_payload_clears_store() {
    let (port, _broker) = start_broker().await;

    // 1. Store a retained message.
    let (_pr, mut pw) = connect_raw(port).await;
    send_packet(&mut pw, &connect_packet("clearer")).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    send_packet(
        &mut pw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("status/x"),
            payload: bytes::Bytes::from_static(b"v1"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: true,
            packet_id: None,
        }),
    )
    .await;
    // 2. Clear it with empty-payload retain=1.
    send_packet(
        &mut pw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("status/x"),
            payload: bytes::Bytes::new(),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: true,
            packet_id: None,
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(pw);

    // 3. New subscriber should see NO retained replay.
    let (mut sr, mut sw) = connect_raw(port).await;
    send_packet(&mut sw, &connect_packet("listener")).await;
    let _ = read_packet(&mut sr).await;
    send_packet(
        &mut sw,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("status/+"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr).await; // SUBACK

    let leak = timeout(
        Duration::from_millis(200),
        codec::read_packet(&mut sr, usize::MAX),
    )
    .await;
    assert!(
        leak.is_err(),
        "empty-payload retain MUST clear store; got unexpected packet: {leak:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_broker_version_visible_to_subscriber() {
    // P6: `Broker::init_sys` populates `$SYS/broker/version` as a retained
    // message on first connection; subscribers to that literal topic MUST
    // receive it via the normal retained-replay path (D18 ordering).
    let (port, _broker) = start_broker().await;

    // First connect — triggers `init_sys` exactly once.
    let (mut sr, mut sw) = connect_raw(port).await;
    send_packet(&mut sw, &connect_packet("version-probe")).await;
    let _ = read_packet(&mut sr).await; // CONNACK

    send_packet(
        &mut sw,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("$SYS/broker/version"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr).await; // SUBACK

    match read_packet(&mut sr).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "$SYS/broker/version");
            assert!(p.retain, "broker-emitted $SYS MUST replay with retain=1");
            let v = std::str::from_utf8(&p.payload[..]).unwrap();
            assert_eq!(v, env!("CARGO_PKG_VERSION"));
        }
        other => panic!("expected $SYS/broker/version retained replay, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dollar_topic_retain_from_client_is_silently_dropped() {
    let (port, _broker) = start_broker().await;

    // Publisher (a CLIENT) tries to inject a retained on $SYS/poison —
    // broker MUST drop it entirely (no store, no fanout) per D19. The
    // broker's OWN $SYS topics (e.g. $SYS/broker/version) are unaffected
    // because they go through `publish_sys_retained`, not the regular
    // `publish` path.
    let (_pr, mut pw) = connect_raw(port).await;
    send_packet(&mut pw, &connect_packet("syspoison")).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    send_packet(
        &mut pw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("$SYS/poison/attempt"),
            payload: bytes::Bytes::from_static(b"BAD"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: true,
            packet_id: None,
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(pw);

    // Subscriber on `$SYS/poison/+` — literal grant just to that namespace.
    // MUST NOT receive any retained replay because the client's publish
    // was silently dropped.
    let (mut sr, mut sw) = connect_raw(port).await;
    send_packet(&mut sw, &connect_packet("sys-listener")).await;
    let _ = read_packet(&mut sr).await;
    send_packet(
        &mut sw,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("$SYS/poison/+"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr).await; // SUBACK

    let leak = timeout(
        Duration::from_millis(200),
        codec::read_packet(&mut sr, usize::MAX),
    )
    .await;
    assert!(
        leak.is_err(),
        "client-originated $SYS retain MUST be silent-dropped; got unexpected packet: {leak:?}"
    );
}

/// Per-client publish ACL: denies publish on `secret/*` for `blocked-pub`,
/// allows everything else for everyone. Used to pin SAFETY_PROOF §7 G1
/// (retained-store write must not happen on ACL-denied PUBLISH).
struct DenyBlockedPubOnSecretAcl;

#[async_trait::async_trait]
impl AclChecker for DenyBlockedPubOnSecretAcl {
    async fn check_subscribe(
        &self,
        _tenant: Option<&TenantId>,
        _client_id: &Arc<str>,
        _username: Option<&Arc<str>>,
        _filter: &str,
    ) -> AclDecision {
        AclDecision::Allow
    }

    async fn check_publish(
        &self,
        _tenant: Option<&TenantId>,
        client_id: &Arc<str>,
        _username: Option<&Arc<str>>,
        topic: &str,
    ) -> AclDecision {
        if client_id.as_ref() == "blocked-pub" && topic.starts_with("secret/") {
            AclDecision::Deny
        } else {
            AclDecision::Allow
        }
    }
}

/// SAFETY_PROOF §7 G1 regression: a publisher whose `check_publish` is
/// denied MUST NOT be able to modify or delete the retained-store entry
/// for that topic. Prior to the fix, the retained store ran before the
/// ACL gate in `Broker::publish`, so a denied client could overwrite or
/// DoS retained state for topics it had no publish permission on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_denied_publisher_cannot_modify_retained_store() {
    let broker = Broker::<TcpStream>::insecure().with_acl_checker(Arc::new(DenyBlockedPubOnSecretAcl));
    let (port, _broker) = start_broker_with(broker).await;

    // 1. allowed-pub seeds the retained store on `secret/z` with "original".
    let (_ar, mut aw) = connect_raw(port).await;
    send_packet(&mut aw, &connect_packet("allowed-pub")).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    send_packet(
        &mut aw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("secret/z"),
            payload: bytes::Bytes::from_static(b"original"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: true,
            packet_id: None,
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(aw);

    // 2. blocked-pub attempts to overwrite with "MUTATED" — ACL denies.
    let (_br, mut bw) = connect_raw(port).await;
    send_packet(&mut bw, &connect_packet("blocked-pub")).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    send_packet(
        &mut bw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("secret/z"),
            payload: bytes::Bytes::from_static(b"MUTATED"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: true,
            packet_id: None,
        }),
    )
    .await;
    // 3. blocked-pub also tries empty-payload DoS deletion — also denied.
    send_packet(
        &mut bw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("secret/z"),
            payload: bytes::Bytes::new(),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: true,
            packet_id: None,
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(bw);

    // 4. Fresh subscriber on `secret/z` MUST still see "original" — both
    //    the overwrite and the delete attempts must have been ACL-gated
    //    before the retained store could mutate.
    let (mut sr, mut sw) = connect_raw(port).await;
    send_packet(&mut sw, &connect_packet("witness")).await;
    let _ = read_packet(&mut sr).await; // CONNACK
    send_packet(
        &mut sw,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("secret/z"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr).await; // SUBACK

    match read_packet(&mut sr).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "secret/z");
            assert_eq!(
                &p.payload[..],
                b"original",
                "ACL-denied publisher must not be able to overwrite retained"
            );
            assert!(p.retain, "retained replay carries retain=1");
        }
        other => panic!(
            "ACL-denied empty-payload retain must NOT have deleted store; \
             expected retained replay, got {other:?}"
        ),
    }
}

// ──────────────────────────────────────────────────────────────────────
// Stage A P7: SessionStore + reconnect (spec §3.1.2.4 + §3.2.2.2 + §4.4)
// ──────────────────────────────────────────────────────────────────────

/// Persistent session must survive a disconnect/reconnect with
/// `clean_session=false`: the new connection sees CONNACK
/// `session_present=1` and receives PUBLISHes on filters it subscribed
/// to during the previous connection — without re-subscribing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_with_clean_session_false_preserves_subscriptions() {
    let (port, _broker) = start_broker().await;

    // 1. First connection: subscribe with clean_session=false, then drop.
    let (mut sr1, mut sw1) = connect_raw(port).await;
    send_packet(&mut sw1, &connect_packet_persistent("persistent-sub")).await;
    match read_packet(&mut sr1).await {
        Packet::Connack(c) => assert!(
            !c.session_present,
            "first CONNECT of a fresh client_id must report session_present=0"
        ),
        other => panic!("expected CONNACK, got {other:?}"),
    }
    send_packet(
        &mut sw1,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("p7/topic"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr1).await; // SUBACK
    drop(sw1);
    drop(sr1);
    tokio::time::sleep(Duration::from_millis(80)).await;

    // 2. Reconnect with the SAME client_id + clean_session=false: CONNACK
    //    MUST carry session_present=1 (spec §3.2.2.2). DO NOT re-subscribe.
    let (mut sr2, mut sw2) = connect_raw(port).await;
    send_packet(&mut sw2, &connect_packet_persistent("persistent-sub")).await;
    match read_packet(&mut sr2).await {
        Packet::Connack(c) => assert!(
            c.session_present,
            "reconnect of persistent session MUST report session_present=1"
        ),
        other => panic!("expected CONNACK, got {other:?}"),
    }

    // 3. A fresh publisher hits the topic. The persisted subscription
    //    MUST still route to our reconnected client without any new
    //    SUBSCRIBE having been sent.
    let (_pr, mut pw) = connect_raw(port).await;
    send_packet(&mut pw, &connect_packet("p7-publisher")).await;
    let _ = timeout(Duration::from_millis(200), async {
        // drain publisher's CONNACK
    })
    .await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    send_packet(
        &mut pw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("p7/topic"),
            payload: bytes::Bytes::from_static(b"resumed-delivery"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    match read_packet(&mut sr2).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "p7/topic");
            assert_eq!(&p.payload[..], b"resumed-delivery");
        }
        other => panic!("expected PUBLISH on persisted sub, got {other:?}"),
    }
}

/// `clean_session=true` reconnect MUST scrub all prior persistent state:
/// CONNACK reports session_present=0 and the old subscription no longer
/// routes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_with_clean_session_true_resets_state() {
    let (port, _broker) = start_broker().await;

    // 1. First connection: persistent + subscribe.
    let (mut sr1, mut sw1) = connect_raw(port).await;
    send_packet(&mut sw1, &connect_packet_persistent("reset-sub")).await;
    let _ = read_packet(&mut sr1).await; // CONNACK
    send_packet(
        &mut sw1,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("p7/reset"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr1).await; // SUBACK
    drop(sw1);
    drop(sr1);
    tokio::time::sleep(Duration::from_millis(80)).await;

    // 2. Reconnect with clean_session=true: session_present MUST be 0.
    let (mut sr2, mut sw2) = connect_raw(port).await;
    send_packet(&mut sw2, &connect_packet("reset-sub")).await; // clean_session=true
    match read_packet(&mut sr2).await {
        Packet::Connack(c) => assert!(
            !c.session_present,
            "clean_session=true MUST report session_present=0"
        ),
        other => panic!("expected CONNACK, got {other:?}"),
    }

    // 3. Publisher hits the old topic — the old subscription was scrubbed,
    //    so no PUBLISH MUST arrive.
    let (_pr, mut pw) = connect_raw(port).await;
    send_packet(&mut pw, &connect_packet("reset-pub")).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    send_packet(
        &mut pw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("p7/reset"),
            payload: bytes::Bytes::from_static(b"should-not-arrive"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    let leak = timeout(
        Duration::from_millis(250),
        codec::read_packet(&mut sr2, usize::MAX),
    )
    .await;
    assert!(
        leak.is_err(),
        "clean_session=true MUST drop the old subscription; got {leak:?}"
    );
}

/// Outbound QoS≥1 publish that left the broker but was never PUBACKed
/// MUST be redelivered on reconnect with `dup=1` (spec §3.1.2.4 + §4.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_retransmits_unacked_qos1_with_dup() {
    let (port, _broker) = start_broker().await;

    // 1. Persistent subscriber, subscribed at QoS 1.
    let (mut sr1, mut sw1) = connect_raw(port).await;
    send_packet(&mut sw1, &connect_packet_persistent("retransmit-sub")).await;
    let _ = read_packet(&mut sr1).await; // CONNACK
    send_packet(
        &mut sw1,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("p7/inflight"),
                qos: QoS::AtLeastOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr1).await; // SUBACK

    // 2. Publisher sends QoS 1 — broker fans out with QoS 1, stashing
    //    the inflight publish on the subscriber's session.
    let (_pr, mut pw) = connect_raw(port).await;
    send_packet(&mut pw, &connect_packet("retransmit-pub")).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    send_packet(
        &mut pw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("p7/inflight"),
            payload: bytes::Bytes::from_static(b"unacked"),
            dup: false,
            qos: QoS::AtLeastOnce,
            packet_id: Some(42),
            retain: false,
        }),
    )
    .await;

    // 3. Subscriber receives the publish but DOES NOT send PUBACK.
    //    Drop the TCP socket abruptly to simulate network failure.
    match read_packet(&mut sr1).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "p7/inflight");
            assert_eq!(p.qos, QoS::AtLeastOnce);
            assert!(!p.dup, "first delivery has dup=0");
        }
        other => panic!("expected first PUBLISH, got {other:?}"),
    }
    drop(sw1);
    drop(sr1);
    tokio::time::sleep(Duration::from_millis(80)).await;

    // 4. Reconnect persistent. CONNACK session_present=1, then the
    //    broker MUST retransmit the unacked publish with dup=1.
    let (mut sr2, mut sw2) = connect_raw(port).await;
    send_packet(&mut sw2, &connect_packet_persistent("retransmit-sub")).await;
    match read_packet(&mut sr2).await {
        Packet::Connack(c) => assert!(
            c.session_present,
            "reconnect of persistent session MUST report session_present=1"
        ),
        other => panic!("expected CONNACK, got {other:?}"),
    }

    // 5. Broker MUST replay the inflight publish with dup=1, carrying
    //    the broker-side packet_id that was stashed at original delivery.
    match read_packet(&mut sr2).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "p7/inflight");
            assert_eq!(&p.payload[..], b"unacked");
            assert_eq!(p.qos, QoS::AtLeastOnce);
            assert!(p.dup, "retransmitted PUBLISH MUST have dup=1");
            assert!(
                p.packet_id.is_some(),
                "QoS≥1 retransmit MUST carry packet_id"
            );
        }
        other => panic!("expected retransmitted PUBLISH, got {other:?}"),
    }
}

// ──────────────────────────────────────────────────────────────────────
// SAFETY_PROOF v1 G7: enforce max_inflight_messages on outbound fanout
// ──────────────────────────────────────────────────────────────────────

/// Per-subscriber outbound_inflight MUST stop growing once
/// `BrokerSafety.max_inflight_messages()` is reached. Prior to the G7
/// fix the cap was silently ignored and the fallback `allocate_packet_id`
/// would eventually panic — both behaviors are unacceptable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fanout_enforces_max_inflight_messages_per_subscriber() {
    // Cap inflight at 2 for an aggressive test. Use the default
    // SlowConsumerPolicy = DisconnectLaggard so QoS≥1 over-cap closes.
    let broker = Broker::<TcpStream>::insecure()
        .with_broker_safety(BrokerSafety::new().with_max_inflight_messages(2));
    let (port, _broker) = start_broker_with(broker).await;

    // Persistent subscriber at QoS 1 that NEVER sends PUBACK.
    let (mut sr, mut sw) = connect_raw(port).await;
    send_packet(&mut sw, &connect_packet_persistent("g7-sub")).await;
    let _ = read_packet(&mut sr).await; // CONNACK
    send_packet(
        &mut sw,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("g7/topic"),
                qos: QoS::AtLeastOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr).await; // SUBACK

    // Publisher sends 3 QoS 1 publishes; subscriber never acks so the
    // first 2 fill the inflight cap, the 3rd MUST trigger close
    // (DisconnectLaggard), and the broker MUST NOT panic.
    let (mut pr, mut pw) = connect_raw(port).await;
    send_packet(&mut pw, &connect_packet("g7-pub")).await;
    let _ = read_packet(&mut pr).await; // publisher CONNACK
    for i in 0..3 {
        send_packet(
            &mut pw,
            &Packet::Publish(PublishPacket {
                topic: Arc::from("g7/topic"),
                payload: bytes::Bytes::from(format!("msg-{i}").into_bytes()),
                dup: false,
                qos: QoS::AtLeastOnce,
                packet_id: Some(100 + i as u16),
                retain: false,
            }),
        )
        .await;
        // Drain PUBACK so the publisher's writer queue doesn't push back.
        let _ = read_packet(&mut pr).await;
    }

    // Subscriber receives the first 2 publishes (deliveries within the
    // cap), then the channel closes — read MUST surface EOF/error past
    // those 2, not hang or surface a third PUBLISH. Generous timeout
    // because the workspace test runner schedules many tests in parallel.
    let mut delivered = 0;
    for _ in 0..2 {
        match timeout(
            Duration::from_secs(2),
            codec::read_packet(&mut sr, usize::MAX),
        )
        .await
        {
            Ok(Ok(Packet::Publish(_))) => delivered += 1,
            other => panic!("expected PUBLISH ({delivered} so far), got {other:?}"),
        }
    }
    assert_eq!(
        delivered, 2,
        "exactly the cap's worth of PUBLISH should arrive"
    );

    // Past the cap, the channel MUST be closed (DisconnectLaggard).
    let closed = timeout(
        Duration::from_secs(2),
        codec::read_packet(&mut sr, usize::MAX),
    )
    .await;
    assert!(
        matches!(closed, Ok(Err(_)) | Err(_)),
        "subscriber MUST be disconnected once inflight cap is hit; got {closed:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// SAFETY_PROOF v1 G5: ACL-denied Will is dropped at dispatch
// ──────────────────────────────────────────────────────────────────────

/// The Will publish now flows through the ACL-gated
/// `publish_with_source_username` carrying the captured publisher
/// username (G5 structurally closed). This test pins that contract:
/// when an ACL denies publish on the Will topic, the Will MUST NOT
/// reach a subscriber even on abrupt disconnect.
struct DenyPubOnWillTopicAcl;

#[async_trait::async_trait]
impl AclChecker for DenyPubOnWillTopicAcl {
    async fn check_subscribe(
        &self,
        _tenant: Option<&TenantId>,
        _client_id: &Arc<str>,
        _username: Option<&Arc<str>>,
        _filter: &str,
    ) -> AclDecision {
        AclDecision::Allow
    }

    async fn check_publish(
        &self,
        _tenant: Option<&TenantId>,
        _client_id: &Arc<str>,
        _username: Option<&Arc<str>>,
        topic: &str,
    ) -> AclDecision {
        if topic == "g5/forbidden" {
            AclDecision::Deny
        } else {
            AclDecision::Allow
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn will_publish_blocked_by_acl_at_dispatch() {
    let broker = Broker::<TcpStream>::insecure().with_acl_checker(Arc::new(DenyPubOnWillTopicAcl));
    let (port, _broker) = start_broker_with(broker).await;

    // Subscriber on the Will topic.
    let (mut sr, mut sw) = connect_raw(port).await;
    send_packet(&mut sw, &connect_packet("g5-witness")).await;
    let _ = read_packet(&mut sr).await; // CONNACK
    send_packet(
        &mut sw,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("g5/forbidden"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr).await; // SUBACK

    // Will-client connects with a Will on the ACL-denied topic, then
    // abruptly drops the TCP connection (no DISCONNECT) → Will fires.
    let (_wr, mut ww) = connect_raw(port).await;
    let connect_with_will = Packet::Connect(ConnectPacket {
        client_id: Arc::from("g5-will-pub"),
        clean_session: true,
        keep_alive: 60,
        username: Some(Arc::from("alice")),
        password: None,
        will: Some(hotaru_mqtt::WillPacket {
            topic: Arc::from("g5/forbidden"),
            payload: bytes::Bytes::from_static(b"last-words"),
            qos: QoS::AtMostOnce,
            retain: false,
        }),
    });
    send_packet(&mut ww, &connect_with_will).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(ww); // abrupt — broker fires Will

    // Witness MUST NOT receive the Will because ACL denies publish on
    // that topic for the dying client. Give the broker plenty of time.
    let leak = timeout(
        Duration::from_millis(400),
        codec::read_packet(&mut sr, usize::MAX),
    )
    .await;
    assert!(
        leak.is_err(),
        "ACL-denied Will MUST be dropped at dispatch; got {leak:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// SAFETY_PROOF v3 U1: publish_sys_retained MUST also honor max_inflight
// ──────────────────────────────────────────────────────────────────────

/// `publish_sys_retained` is the broker-internal $SYS path; prior to the
/// U1 fix it used the infallible `allocate_packet_id` which would panic
/// at u16 exhaustion when a subscriber never ACKs. Mirror the G7 fix on
/// this path: cap-check + fallible allocator + SlowConsumerPolicy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publish_sys_retained_respects_max_inflight_cap() {
    let broker = Broker::<TcpStream>::insecure()
        .with_broker_safety(BrokerSafety::new().with_max_inflight_messages(2));
    let (port, broker) = start_broker_with(broker).await;

    // Persistent QoS-1 subscriber on $SYS/broker/version that never ACKs.
    let (mut sr, mut sw) = connect_raw(port).await;
    send_packet(&mut sw, &connect_packet_persistent("u1-sys-sub")).await;
    let _ = read_packet(&mut sr).await; // CONNACK
    send_packet(
        &mut sw,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("$SYS/broker/version"),
                qos: QoS::AtLeastOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr).await; // SUBACK
    // init_sys publishes $SYS/broker/version at QoS 0; the
    // subscriber-effective QoS is min(0, sub_qos=1) = QoS 0, so it does
    // NOT touch outbound_inflight. Drain its delivery anyway.
    let _ = read_packet(&mut sr).await;

    // Drive 8 publish_sys_retained calls at QoS 1 (cap=2). The broker
    // MUST NOT panic; outbound_inflight should fill exactly to the cap
    // (2 successful deliveries), then the channel closes.
    for i in 0..8u32 {
        broker
            .publish_sys_retained(
                &None,
                Arc::from("$SYS/broker/version"),
                bytes::Bytes::from(format!("test-{i}").into_bytes()),
                QoS::AtLeastOnce,
            )
            .await;
    }

    let mut delivered = 0;
    for _ in 0..2 {
        match timeout(
            Duration::from_secs(2),
            codec::read_packet(&mut sr, usize::MAX),
        )
        .await
        {
            Ok(Ok(Packet::Publish(p))) => {
                assert_eq!(p.topic.as_ref(), "$SYS/broker/version");
                assert_eq!(p.qos, QoS::AtLeastOnce);
                delivered += 1;
            }
            other => panic!("expected $SYS PUBLISH ({delivered} so far), got {other:?}"),
        }
    }
    assert_eq!(delivered, 2);

    let closed = timeout(
        Duration::from_secs(2),
        codec::read_packet(&mut sr, usize::MAX),
    )
    .await;
    assert!(
        matches!(closed, Ok(Err(_)) | Err(_)),
        "subscriber MUST be disconnected once $SYS inflight cap is hit; got {closed:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// SAFETY_PROOF v3 U2: takeover releases the prior connection's slot
// ──────────────────────────────────────────────────────────────────────

/// Spec §3.1.4-2 — a second CONNECT with the same `client_id` MUST
/// terminate the prior session. Prior to the U2 fix the prior loop kept
/// holding its `active_connections` slot until keep-alive elapsed,
/// allowing a reconnect-loop DoS to pin every connection slot for hours.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn takeover_closes_prior_session_and_releases_slot() {
    // Cap connections at 2 so we can verify the count without spinning
    // up tons of state.
    let broker = Broker::<TcpStream>::insecure().with_broker_safety(
        BrokerSafety::new()
            .with_max_connections(2)
            .with_shutdown_grace_period(Duration::from_millis(500)),
    );
    let (port, broker) = start_broker_with(broker).await;

    let (mut r1, mut w1) = connect_raw(port).await;
    send_packet(&mut w1, &connect_packet("u2-victim")).await;
    let _ = read_packet(&mut r1).await; // CONNACK
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(broker.active_connection_count(), 1);

    // Second CONNECT with same client_id — takeover.
    let (mut r2, mut w2) = connect_raw(port).await;
    send_packet(&mut w2, &connect_packet("u2-victim")).await;
    let _ = read_packet(&mut r2).await; // CONNACK on new
    // Give the prior handle_server loop time to wake on `shutdown` and
    // tear down.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        broker.active_connection_count(),
        1,
        "prior session's slot MUST be released within 200ms of takeover"
    );

    // The first socket should be observable as closed by the broker
    // (reader sees EOF) — though we don't strictly require this for the
    // slot-leak fix.
    let _ = timeout(
        Duration::from_millis(200),
        codec::read_packet(&mut r1, usize::MAX),
    )
    .await;
    drop(w1);
    drop(w2);
}

// ──────────────────────────────────────────────────────────────────────
// SAFETY_PROOF v3 U3: client $-prefixed publishes are dropped (retained
// AND non-retained)
// ──────────────────────────────────────────────────────────────────────

/// Client `retain=0` PUBLISH to `$SYS/broker/version` MUST NOT reach an
/// explicit-literal subscriber. Prior to the U3 fix the guard only fired
/// on `retain=1`, letting a malicious client spoof broker stats to any
/// downstream monitor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_cannot_publish_to_dollar_sys_even_non_retained() {
    let (port, _broker) = start_broker().await;

    // Explicit-literal subscriber on the broker's own version topic.
    let (mut sr, mut sw) = connect_raw(port).await;
    send_packet(&mut sw, &connect_packet("u3-monitor")).await;
    let _ = read_packet(&mut sr).await; // CONNACK
    send_packet(
        &mut sw,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("$SYS/broker/version"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr).await; // SUBACK
    // Drain init_sys's legitimate replay.
    match read_packet(&mut sr).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "$SYS/broker/version");
            assert_eq!(&p.payload[..], env!("CARGO_PKG_VERSION").as_bytes());
        }
        other => panic!("expected init_sys retained replay, got {other:?}"),
    }

    // Malicious client tries to inject retain=0 spoof on the same topic.
    let (_ar, mut aw) = connect_raw(port).await;
    send_packet(&mut aw, &connect_packet("u3-spoofer")).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    send_packet(
        &mut aw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("$SYS/broker/version"),
            payload: bytes::Bytes::from_static(b"0wned"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        }),
    )
    .await;

    // Monitor MUST NOT see the spoofed payload.
    let leak = timeout(
        Duration::from_millis(300),
        codec::read_packet(&mut sr, usize::MAX),
    )
    .await;
    assert!(
        leak.is_err(),
        "client retain=0 publish to $SYS MUST be silent-dropped; got {leak:?}"
    );
}

// ──────────────────────────────────────────────────────────────────────
// Stage A P8: graceful shutdown (D24)
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_drains_active_sessions_within_grace_period() {
    let broker = Broker::<TcpStream>::insecure().with_broker_safety(
        BrokerSafety::new().with_shutdown_grace_period(Duration::from_millis(500)),
    );
    let (port, broker) = start_broker_with(broker).await;

    // Stand up 3 live connections.
    let mut conns = Vec::new();
    for i in 0..3 {
        let (mut r, mut w) = connect_raw(port).await;
        send_packet(&mut w, &connect_packet(&format!("shutdown-{i}"))).await;
        let _ = read_packet(&mut r).await; // CONNACK
        conns.push((r, w));
    }
    // Let registration settle.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(broker.active_connection_count(), 3);

    let report = broker.shutdown().await;

    assert_eq!(report.initial, 3, "initial count should reflect 3 live");
    assert_eq!(
        report.remaining, 0,
        "all sessions MUST drain within grace period: {report:?}"
    );
    assert!(!report.timed_out, "grace period should not have elapsed");

    // The peer-side TCP sockets MUST now read EOF or get closed.
    drop(conns);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broker_drops_connection_on_malformed_subscribe_header() {
    // Stage A P3.A: SUBSCRIBE fixed-header low nibble MUST be 0010 per
    // spec §3.8.1. We hand-craft a SUBSCRIBE with 0000 — `parse_subscribe`
    // surfaces `Violation::SubscribeReservedBits`, `handle_server`
    // propagates the error, and the channel closes.
    let (port, broker) = start_broker().await;
    let (mut reader, mut writer) = connect_raw(port).await;
    send_packet(&mut writer, &connect_packet("malformed-sub")).await;
    let _ = read_packet(&mut reader).await; // CONNACK

    // Hand-crafted SUBSCRIBE wire bytes with reserved bits 0000 (illegal).
    // Layout: fixed header 0x80 (no 0x02), remaining length = 7,
    //         body = packet_id(2) + topic_len(2) + "a/b" + qos(1).
    let bytes: Vec<u8> = vec![
        0x80, // SUBSCRIBE fixed header — should be 0x82
        0x08, // remaining length
        0x00, 0x07, // packet_id = 7
        0x00, 0x03, // topic length
        b'a', b'/', b'b', 0x00, // qos = 0
    ];
    writer.write_all(&bytes).await.unwrap();
    writer.flush().await.unwrap();

    // Broker should close the wire — the next read times out / returns EOF.
    let next = timeout(
        Duration::from_secs(2),
        codec::read_packet(&mut reader, usize::MAX),
    )
    .await;
    match next {
        Err(_) => panic!("broker should have closed the wire, not stayed open"),
        Ok(Ok(other)) => panic!("unexpected packet after malformed SUBSCRIBE: {other:?}"),
        Ok(Err(_)) => {
            // expected: I/O error from peer disconnect
        }
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        broker.active_connection_count(),
        0,
        "malformed post-CONNECT packet MUST unregister the session and release the slot"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broker_rejects_empty_id_with_persistent_session() {
    // Stage A P2.B: spec §3.1.3.1 — empty client_id + clean_session=false
    // must be refused with CONNACK 0x02 IdentifierRejected.
    let (port, _broker) = start_broker().await;

    let (mut reader, mut writer) = connect_raw(port).await;
    let bad_connect = Packet::Connect(ConnectPacket {
        client_id: Arc::from(""),
        clean_session: false,
        keep_alive: 60,
        username: None,
        password: None,
        will: None,
    });
    send_packet(&mut writer, &bad_connect).await;

    match read_packet(&mut reader).await {
        Packet::Connack(ack) => {
            assert_eq!(ack.return_code, ConnackReturnCode::IdentifierRejected);
            assert!(!ack.session_present);
        }
        other => panic!("expected CONNACK IdentifierRejected, got {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broker_rejects_connect_at_max_connections() {
    // Stage A P1.B: BrokerSafety.max_connections enforced before CONNACK.
    let broker =
        Broker::<TcpStream>::insecure().with_broker_safety(BrokerSafety::new().with_max_connections(1));
    let (port, broker) = start_broker_with(broker).await;

    // First CONNECT — should succeed.
    let (mut r1, mut w1) = connect_raw(port).await;
    send_packet(&mut w1, &connect_packet("client-1")).await;
    match read_packet(&mut r1).await {
        Packet::Connack(ack) => {
            assert_eq!(ack.return_code, ConnackReturnCode::Accepted);
        }
        other => panic!("expected CONNACK Accepted, got {:?}", other),
    }
    // Give broker a moment to bump the counter.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(broker.active_connection_count(), 1);

    // Second CONNECT — should be refused with ServerUnavailable.
    let (mut r2, mut w2) = connect_raw(port).await;
    send_packet(&mut w2, &connect_packet("client-2")).await;
    match read_packet(&mut r2).await {
        Packet::Connack(ack) => {
            assert_eq!(ack.return_code, ConnackReturnCode::ServerUnavailable);
        }
        other => panic!("expected CONNACK ServerUnavailable, got {:?}", other),
    }

    // After 2nd refusal, count is still 1.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(broker.active_connection_count(), 1);
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
async fn broker_new_denies_anonymous_connect_by_default() {
    // AS2: `Broker::new()` is fail-closed (DenyAllAuthenticator). A plain
    // CONNECT with no real authenticator installed MUST be refused with
    // NotAuthorized rather than silently accepted.
    let (port, _broker) = start_broker_with(Broker::<TcpStream>::new()).await;

    let (mut reader, mut writer) = connect_raw(port).await;
    send_packet(&mut writer, &connect_packet("denied-by-default")).await;

    match read_packet(&mut reader).await {
        Packet::Connack(ConnackPacket {
            session_present,
            return_code,
        }) => {
            assert!(!session_present);
            assert_eq!(return_code, ConnackReturnCode::NotAuthorized);
        }
        other => panic!("expected CONNACK(NotAuthorized), got {:?}", other),
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

    let waited = timeout(
        Duration::from_millis(300),
        codec::read_packet(&mut sub_reader, usize::MAX),
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
        codec::read_packet(&mut reader, usize::MAX),
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
    let _broker = Broker::<TcpStream>::insecure();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publish_q2_full_handshake() {
    let (port, _broker) = start_broker().await;

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

    match read_packet(&mut pub_reader).await {
        Packet::Pubrec(id) => assert_eq!(id, 99),
        other => panic!("expected PUBREC, got {:?}", other),
    }

    send_packet(&mut pub_writer, &Packet::Pubrel(99)).await;

    match read_packet(&mut pub_reader).await {
        Packet::Pubcomp(id) => assert_eq!(id, 99),
        other => panic!("expected PUBCOMP, got {:?}", other),
    }

    match read_packet(&mut sub_reader).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "q2/topic");
            assert_eq!(&p.payload[..], b"q2-payload");
            assert_eq!(p.qos, QoS::ExactlyOnce);
            assert!(p.packet_id.is_some());
            send_packet(&mut sub_writer, &Packet::Pubrec(p.packet_id.unwrap())).await;
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

/// Build a broker on a random port that accepts BOTH HTTP and MQTT.
async fn start_multi_protocol_broker() -> (u16, Broker<TcpStream>) {
    use hotaru_http::HTTP;
    use hotaru_http::security::safety::HttpSafety;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let broker = Broker::<TcpStream>::insecure();

    let registry: ProtocolEntryRegistry<hotaru_core::connection::tcp::TcpTransport> =
        ProtocolRegistryBuilder::new()
            .protocol(ProtocolEntryBuilder::new(HTTP::server(
                HttpSafety::default(),
            )))
            .protocol(ProtocolEntryBuilder::new(MQTT_SERVER::new()))
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

    let (mut reader, mut writer) = connect_raw(port).await;
    send_packet(&mut writer, &connect_packet("multi-proto-mqtt")).await;

    match read_packet(&mut reader).await {
        Packet::Connack(ConnackPacket { return_code, .. }) => {
            assert_eq!(return_code, ConnackReturnCode::Accepted);
        }
        other => panic!("expected CONNACK, got {:?}", other),
    }
}

/// AIoT closed-loop: external code calls `broker.publish` and MQTT
/// subscribers receive the fanout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_broker_publish_reaches_mqtt_subscriber() {
    let (port, broker) = start_broker().await;

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

    broker
        .publish(
            &None,
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

    match read_packet(&mut sub_reader).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "aiot/event");
            assert_eq!(&p.payload[..], b"from-http");
        }
        other => panic!(
            "expected PUBLISH from external broker.publish, got {:?}",
            other
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn will_message_fires_on_abrupt_disconnect() {
    let (port, _broker) = start_broker().await;

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

    drop(pub_writer);
    drop(pub_reader);

    match read_packet(&mut sub_reader).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "lwt/topic");
            assert_eq!(&p.payload[..], b"gone");
        }
        other => panic!("expected will PUBLISH, got {:?}", other),
    }
}

/// MQTT 3.1.1 §4.6 — when a broker fans out messages from one publisher,
/// subscribers MUST receive them in the order the publisher sent them.
/// Exercises the per-connection FIFO fanout coordinator (P-1.7).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publisher_ordering_preserved_under_load() {
    let (port, _broker) = start_broker().await;

    // Subscriber
    let (mut sub_reader, mut sub_writer) = connect_raw(port).await;
    send_packet(&mut sub_writer, &connect_packet("order-sub")).await;
    let _ = read_packet(&mut sub_reader).await;
    send_packet(
        &mut sub_writer,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("seq/test"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sub_reader).await;

    // Publisher fires N messages with monotonically increasing payloads.
    const N: usize = 50;
    let (_, mut pub_writer) = connect_raw(port).await;
    send_packet(&mut pub_writer, &connect_packet("order-pub")).await;
    for i in 0..N {
        send_packet(
            &mut pub_writer,
            &Packet::Publish(PublishPacket {
                topic: Arc::from("seq/test"),
                payload: bytes::Bytes::from(format!("{}", i)),
                dup: false,
                qos: QoS::AtMostOnce,
                retain: false,
                packet_id: None,
            }),
        )
        .await;
    }

    // Subscriber MUST see them in 0,1,2,...,N-1 order.
    for expected in 0..N {
        match read_packet(&mut sub_reader).await {
            Packet::Publish(p) => {
                let got = std::str::from_utf8(&p.payload)
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                assert_eq!(
                    got, expected,
                    "out-of-order delivery at position {expected}: got {got}"
                );
            }
            other => panic!("expected PUBLISH at position {expected}, got {:?}", other),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// V1 — fanout MUST stash the SUBSCRIBER-shaped (adjusted) packet, not
// the publisher's original
// ──────────────────────────────────────────────────────────────────────

/// V1 regression — broker fanout MUST stash the adjusted PUBLISH (the
/// subscriber-shaped one with `retain=0` per §3.3.1-9 and the broker-
/// allocated subscriber packet_id), not the publisher's original. Prior
/// to the fix `stash_outbound_inflight(id, packet.clone())` retained the
/// publisher's flags, so a reconnect retransmit of an unacked QoS-1
/// `retain=1` publish re-sent it with `retain=1`, violating MQTT-3.3.1-9
/// (current-delivery and its retransmits must carry `retain=0` regardless
/// of how the publisher set it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v1_retransmit_uses_stashed_adjusted_packet_retain_zero() {
    let (port, _broker) = start_broker().await;

    // Persistent subscriber at QoS 1.
    let (mut sr1, mut sw1) = connect_raw(port).await;
    send_packet(&mut sw1, &connect_packet_persistent("v1-sub")).await;
    let _ = read_packet(&mut sr1).await; // CONNACK
    send_packet(
        &mut sw1,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("v1/topic"),
                qos: QoS::AtLeastOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr1).await; // SUBACK

    // Publisher sends QoS-1 retain=1 — the trigger for the original bug.
    let (mut pr, mut pw) = connect_raw(port).await;
    send_packet(&mut pw, &connect_packet("v1-pub")).await;
    let _ = read_packet(&mut pr).await; // CONNACK
    tokio::time::sleep(Duration::from_millis(20)).await;
    send_packet(
        &mut pw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("v1/topic"),
            payload: bytes::Bytes::from_static(b"retained-q1"),
            dup: false,
            qos: QoS::AtLeastOnce,
            packet_id: Some(7),
            retain: true,
        }),
    )
    .await;
    let _ = read_packet(&mut pr).await; // PUBACK

    // First delivery — current-delivery is already retain=0 (existed
    // pre-fix via `adjusted` on the send side). Don't ACK.
    match read_packet(&mut sr1).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "v1/topic");
            assert!(!p.retain, "current delivery MUST be retain=0");
            assert!(!p.dup, "first delivery has dup=0");
        }
        other => panic!("expected first PUBLISH, got {other:?}"),
    }

    // Drop the TCP without PUBACK, reconnect persistent, verify the
    // retransmit also carries retain=0 (the stashed adjusted's flag).
    drop(sw1);
    drop(sr1);
    tokio::time::sleep(Duration::from_millis(80)).await;

    let (mut sr2, mut sw2) = connect_raw(port).await;
    send_packet(&mut sw2, &connect_packet_persistent("v1-sub")).await;
    match read_packet(&mut sr2).await {
        Packet::Connack(c) => assert!(
            c.session_present,
            "persistent reconnect MUST report session_present=1"
        ),
        other => panic!("expected CONNACK, got {other:?}"),
    }

    match read_packet(&mut sr2).await {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "v1/topic");
            assert_eq!(&p.payload[..], b"retained-q1");
            assert_eq!(p.qos, QoS::AtLeastOnce);
            assert!(p.dup, "retransmitted PUBLISH MUST have dup=1");
            assert!(
                !p.retain,
                "V1 — retransmit MUST carry retain=0 (stashed adjusted, \
                 not publisher's original retain=1)"
            );
        }
        other => panic!("expected retransmitted PUBLISH, got {other:?}"),
    }

    drop(pw);
    drop(pr);
    drop(sw2);
    drop(sr2);
}

// ──────────────────────────────────────────────────────────────────────
// V3 — takeover unregister generation race + Will hoist
// ──────────────────────────────────────────────────────────────────────

/// V3 regression #1 — after a takeover, the prior `handle_server` loop's
/// `unregister_session` MUST be a no-op (generation guard). Prior to the
/// fix the prior loop's unguarded `remove(&key)` deleted the NEW session
/// and wiped its subscription / inflight state, so any publish landing
/// on the new session was silently dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v3_takeover_does_not_wipe_new_session_after_prior_unregister() {
    let (port, _broker) = start_broker().await;

    // Connection #1 — takes the slot.
    let (_sr1, mut sw1) = connect_raw(port).await;
    send_packet(&mut sw1, &connect_packet("v3-race-sub")).await;
    // We don't drain sr1's CONNACK — the read half drops naturally.

    // Connection #2 — same client_id. register_session removes prev and
    // closes prev's channel; prev's loop wakes via shutdown notify and
    // (pre-fix) would race with our SUBSCRIBE + the publisher's PUBLISH.
    let (mut sr2, mut sw2) = connect_raw(port).await;
    send_packet(&mut sw2, &connect_packet("v3-race-sub")).await;
    let _ = read_packet(&mut sr2).await; // CONNACK on NEW

    // Subscribe on the NEW session.
    send_packet(
        &mut sw2,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("v3/race/topic"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut sr2).await; // SUBACK

    // Sleep long enough for prev's loop to wake, exit, and call
    // unregister_session. Pre-fix this is when the bug fires: prev's
    // remove(&key) deletes the NEW session entry and the
    // `clean_session=true` cleanup also calls remove_client on the
    // NEW session's subscriptions.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Publisher fires a message — NEW subscriber MUST receive it.
    let (_, mut pw) = connect_raw(port).await;
    send_packet(&mut pw, &connect_packet("v3-race-pub")).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    send_packet(
        &mut pw,
        &Packet::Publish(PublishPacket {
            topic: Arc::from("v3/race/topic"),
            payload: bytes::Bytes::from_static(b"survived"),
            dup: false,
            qos: QoS::AtMostOnce,
            packet_id: None,
            retain: false,
        }),
    )
    .await;

    match timeout(
        Duration::from_secs(2),
        codec::read_packet(&mut sr2, usize::MAX),
    )
    .await
    {
        Ok(Ok(Packet::Publish(p))) => {
            assert_eq!(p.topic.as_ref(), "v3/race/topic");
            assert_eq!(&p.payload[..], b"survived");
        }
        other => panic!(
            "NEW session MUST still be subscribed after prev's late \
             unregister_session — generation guard regressed; got {other:?}"
        ),
    }

    drop(sw1);
    drop(sw2);
    drop(sr2);
    drop(pw);
}

/// V3 regression #2 — takeover closes the prior network connection
/// (spec §3.1.4-2); §3.1.2.5 then requires the Will to fire. Pre-fix
/// the prior loop's unregister_session would fire the Will (correctly)
/// as a side effect of deleting the new session (incorrectly). With
/// the V3 generation guard the prior unregister is a no-op, so the
/// Will dispatch is hoisted into `register_session`'s takeover path.
/// This test pins that the Will still reaches a subscriber.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v3_takeover_fires_prior_session_will() {
    let (port, _broker) = start_broker().await;

    // Will-observer.
    let (mut wr, mut ww) = connect_raw(port).await;
    send_packet(&mut ww, &connect_packet("v3-will-rx")).await;
    let _ = read_packet(&mut wr).await; // CONNACK
    send_packet(
        &mut ww,
        &Packet::Subscribe(SubscribePacket {
            packet_id: 1,
            subscriptions: vec![TopicSubscription {
                topic: Arc::from("v3/will"),
                qos: QoS::AtMostOnce,
            }],
        }),
    )
    .await;
    let _ = read_packet(&mut wr).await; // SUBACK

    // Connection #1 — same client_id `v3-will-victim`, carries a Will.
    let (mut r1, mut w1) = connect_raw(port).await;
    let connect_with_will = Packet::Connect(ConnectPacket {
        client_id: Arc::from("v3-will-victim"),
        clean_session: true,
        keep_alive: 60,
        username: None,
        password: None,
        will: Some(hotaru_mqtt::WillPacket {
            topic: Arc::from("v3/will"),
            payload: bytes::Bytes::from_static(b"taken-over"),
            qos: QoS::AtMostOnce,
            retain: false,
        }),
    });
    send_packet(&mut w1, &connect_with_will).await;
    let _ = read_packet(&mut r1).await; // CONNACK
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Connection #2 — same client_id, takeover. No Will of its own.
    let (mut r2, mut w2) = connect_raw(port).await;
    send_packet(&mut w2, &connect_packet("v3-will-victim")).await;
    let _ = read_packet(&mut r2).await; // CONNACK

    // The Will-observer MUST see the prior session's Will, dispatched
    // from `register_session`'s takeover path (V3 hoist).
    match timeout(
        Duration::from_secs(2),
        codec::read_packet(&mut wr, usize::MAX),
    )
    .await
    {
        Ok(Ok(Packet::Publish(p))) => {
            assert_eq!(p.topic.as_ref(), "v3/will");
            assert_eq!(&p.payload[..], b"taken-over");
        }
        other => panic!(
            "Will MUST fire on takeover-driven close (V3 hoist); got {other:?}"
        ),
    }

    drop(ww);
    drop(wr);
    drop(w1);
    drop(r1);
    drop(w2);
    drop(r2);
}
