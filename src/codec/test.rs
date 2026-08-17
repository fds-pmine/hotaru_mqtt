//! Codec tests: wire round-trips, encoder agreement, and size bounds.

use super::*;

use std::sync::Arc;

use bytes::{Bytes, BytesMut};

use crate::error::{CodecError, MqttError, Violation};
use crate::packet::{
    ConnectPacket, Packet, PublishPacket, SubscribePacket, TopicSubscription,
    UnsubscribePacket, WillPacket,
};
use crate::request::QoS;

/// Round-trip tests are not about the cap, so they use the widest value a
/// conforming packet can declare.
const ANY_SIZE: usize = crate::packet::MQTT_SPEC_MAX_PACKET_SIZE;

#[test]
fn encode_decode_connect_round_trip() {
    let original = ConnectPacket {
        client_id: Arc::from("cid"),
        clean_session: true,
        keep_alive: 60,
        username: None,
        password: None,
        will: None,
    };
    let bytes = encode_packet(&Packet::Connect(original.clone())).expect("fixture packet must encode");
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf, ANY_SIZE).unwrap().unwrap() {
        Packet::Connect(c) => {
            assert_eq!(c.client_id.as_ref(), "cid");
            assert!(c.clean_session);
            assert_eq!(c.keep_alive, 60);
            assert!(c.will.is_none());
        }
        _ => panic!("expected Connect"),
    }
}

#[test]
fn encode_decode_connect_with_will() {
    let original = ConnectPacket {
        client_id: Arc::from("cid"),
        clean_session: false,
        keep_alive: 30,
        username: Some(Arc::from("alice")),
        password: Some(Bytes::from_static(b"secret")),
        will: Some(WillPacket {
            topic: Arc::from("offline"),
            payload: Bytes::from_static(b"bye"),
            qos: QoS::AtLeastOnce,
            retain: true,
        }),
    };
    let bytes = encode_packet(&Packet::Connect(original)).expect("fixture packet must encode");
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf, ANY_SIZE).unwrap().unwrap() {
        Packet::Connect(c) => {
            assert_eq!(c.username.as_ref().unwrap().as_ref(), "alice");
            let p = c.password.as_ref().unwrap();
            assert_eq!(&p[..], b"secret");
            let w = c.will.unwrap();
            assert_eq!(w.topic.as_ref(), "offline");
            assert_eq!(&w.payload[..], b"bye");
            assert_eq!(w.qos, QoS::AtLeastOnce);
            assert!(w.retain);
        }
        _ => panic!("expected Connect"),
    }
}

#[test]
fn encode_decode_publish_qos0() {
    let p = PublishPacket {
        topic: Arc::from("sensors/temp"),
        payload: Bytes::from_static(b"42"),
        dup: false,
        qos: QoS::AtMostOnce,
        retain: false,
        packet_id: None,
    };
    let bytes = encode_packet(&Packet::Publish(p)).expect("fixture packet must encode");
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf, ANY_SIZE).unwrap().unwrap() {
        Packet::Publish(p) => {
            assert_eq!(p.topic.as_ref(), "sensors/temp");
            assert_eq!(&p.payload[..], b"42");
            assert_eq!(p.qos, QoS::AtMostOnce);
            assert!(p.packet_id.is_none());
        }
        _ => panic!("expected Publish"),
    }
}

#[test]
fn encode_decode_publish_qos1() {
    let p = PublishPacket {
        topic: Arc::from("a/b"),
        payload: Bytes::from_static(b"x"),
        dup: false,
        qos: QoS::AtLeastOnce,
        retain: false,
        packet_id: Some(42),
    };
    let bytes = encode_packet(&Packet::Publish(p)).expect("fixture packet must encode");
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf, ANY_SIZE).unwrap().unwrap() {
        Packet::Publish(p) => {
            assert_eq!(p.qos, QoS::AtLeastOnce);
            assert_eq!(p.packet_id, Some(42));
        }
        _ => panic!("expected Publish"),
    }
}

#[test]
fn encode_decode_subscribe_unsubscribe() {
    let s = SubscribePacket {
        packet_id: 7,
        subscriptions: vec![
            TopicSubscription {
                topic: Arc::from("a/+"),
                qos: QoS::AtLeastOnce,
            },
            TopicSubscription {
                topic: Arc::from("b/#"),
                qos: QoS::ExactlyOnce,
            },
        ],
    };
    let bytes = encode_packet(&Packet::Subscribe(s)).expect("fixture packet must encode");
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf, ANY_SIZE).unwrap().unwrap() {
        Packet::Subscribe(s) => {
            assert_eq!(s.packet_id, 7);
            assert_eq!(s.subscriptions.len(), 2);
            assert_eq!(s.subscriptions[0].topic.as_ref(), "a/+");
            assert_eq!(s.subscriptions[1].qos, QoS::ExactlyOnce);
        }
        _ => panic!("expected Subscribe"),
    }

    let u = UnsubscribePacket {
        packet_id: 8,
        topics: vec![Arc::from("a/+"), Arc::from("b/#")],
    };
    let bytes = encode_packet(&Packet::Unsubscribe(u)).expect("fixture packet must encode");
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf, ANY_SIZE).unwrap().unwrap() {
        Packet::Unsubscribe(u) => {
            assert_eq!(u.packet_id, 8);
            assert_eq!(u.topics.len(), 2);
        }
        _ => panic!("expected Unsubscribe"),
    }
}

#[test]
fn pingreq_pingresp_disconnect_unsuback() {
    assert_eq!(encode_packet(&Packet::Pingreq).unwrap(), vec![0xC0, 0x00]);
    assert_eq!(encode_packet(&Packet::Pingresp).unwrap(), vec![0xD0, 0x00]);
    assert_eq!(encode_packet(&Packet::Disconnect).unwrap(), vec![0xE0, 0x00]);
    assert_eq!(
        encode_packet(&Packet::Unsuback(42)).unwrap(),
        vec![0xB0, 0x02, 0x00, 0x2A]
    );
}

/// The same invalid packet must be refused identically by both encoders —
/// the divergence this PR closes is precisely "one path errors, the other
/// silently emits a malformed frame".
#[test]
fn both_encoders_refuse_a_qos1_publish_with_no_packet_id() {
    let invalid = PublishPacket {
        topic: Arc::from("t"),
        payload: Bytes::from_static(b"x"),
        dup: false,
        qos: QoS::AtLeastOnce,
        retain: false,
        packet_id: None,
    };
    assert!(matches!(
        encode_publish(&invalid),
        Err(CodecError::MissingPacketId)
    ));
    // The same packet through write_publish_packet: refused the same way,
    // and not one byte reaches the writer.
    let mut written: Vec<u8> = Vec::new();
    let refused = futures_block_on(write_publish_packet(&mut written, &invalid));
    assert!(matches!(
        refused,
        Err(MqttError::Codec(CodecError::MissingPacketId))
    ));
    assert!(written.is_empty(), "refusal must not leave half a frame");
}

#[test]
fn packet_id_zero_is_refused_on_encode() {
    let invalid = PublishPacket {
        topic: Arc::from("t"),
        payload: Bytes::from_static(b"x"),
        dup: false,
        qos: QoS::ExactlyOnce,
        retain: false,
        packet_id: Some(0),
    };
    assert!(matches!(
        encode_publish(&invalid),
        Err(CodecError::ZeroPacketId)
    ));
}

/// A topic longer than the two-byte length field must be refused, not
/// truncated: `as u16` on 65536 silently gives 0, a frame whose declared
/// topic length disagrees with its bytes.
#[test]
fn an_oversized_topic_is_refused_not_truncated() {
    let huge_topic: String = "a".repeat(u16::MAX as usize + 1);
    let invalid = PublishPacket {
        topic: Arc::from(huge_topic.as_str()),
        payload: Bytes::new(),
        dup: false,
        qos: QoS::AtMostOnce,
        retain: false,
        packet_id: None,
    };
    assert!(matches!(
        encode_publish(&invalid),
        Err(CodecError::TopicTooLong { .. })
    ));
}

/// QoS 0 never carries a packet id; a stray one in the struct is ignored,
/// which is what both encoders already did.
#[test]
fn qos0_with_a_stray_packet_id_still_encodes_without_one() {
    let publish = PublishPacket {
        topic: Arc::from("t"),
        payload: Bytes::from_static(b"x"),
        dup: false,
        qos: QoS::AtMostOnce,
        retain: false,
        packet_id: Some(7),
    };
    let bytes = encode_publish(&publish).expect("QoS 0 must encode");
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf, ANY_SIZE).unwrap().unwrap() {
        Packet::Publish(decoded) => assert_eq!(None, decoded.packet_id),
        other => panic!("expected Publish, got {other:?}"),
    }
}

/// Tiny helper: run one future to completion on the current thread. The
/// writer in these tests is a Vec, which never blocks, so a minimal
/// executor is enough — no tokio runtime needed in a unit test.
fn futures_block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop_raw_waker() -> RawWaker {
        fn no_op(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker { noop_raw_waker() }
        RawWaker::new(std::ptr::null(), &RawWakerVTable::new(clone, no_op, no_op, no_op))
    }
    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut context = Context::from_waker(&waker);
    let mut pinned = Box::pin(future);
    loop {
        if let Poll::Ready(output) = pinned.as_mut().poll(&mut context) {
            return output;
        }
    }
}

#[test]
fn oversize_declaration_is_refused_before_the_body_is_read() {
    // 0x30 = PUBLISH, then FF FF FF 7F = the largest 4-byte VBI: ~256 MiB
    // declared in five bytes. Nothing follows it on the wire.
    let mut buf = BytesMut::from(&[0x30u8, 0xFF, 0xFF, 0xFF, 0x7F][..]);
    let err = decode_packet_from_bytes(&mut buf, 1024).unwrap_err();
    assert!(
        err.to_string().contains("PacketTooLarge"),
        "expected PacketTooLarge, got {err}"
    );
    assert_eq!(5, buf.len(), "buffer must not be consumed on refusal");
}

#[tokio::test]
async fn read_packet_refuses_oversize_before_allocating() {
    // The reader supplies only the fixed header. If the cap were checked
    // after `vec![0u8; remaining]`, this would allocate ~256 MiB first and
    // then block on read_exact; the test would hang rather than fail.
    let mut reader = &[0x30u8, 0xFF, 0xFF, 0xFF, 0x7F][..];
    let err = read_packet(&mut reader, 1024).await.unwrap_err();
    assert!(
        matches!(
            err,
            MqttError::Protocol(Violation::PacketTooLarge { len: 268_435_455, max: 1024 })
        ),
        "expected PacketTooLarge, got {err:?}"
    );
}

#[tokio::test]
async fn packet_exactly_at_the_cap_is_accepted() {
    let publish = Packet::Publish(PublishPacket {
        topic: Arc::from("a"),
        payload: Bytes::from_static(b"hello"),
        dup: false,
        qos: QoS::AtMostOnce,
        retain: false,
        packet_id: None,
    });
    let wire = encode_packet(&publish).expect("fixture packet must encode");
    let body_len = wire.len() - 2; // one-byte fixed header + one-byte VBI
    let mut reader = &wire[..];
    assert!(read_packet(&mut reader, body_len).await.is_ok());
}

#[test]
fn partial_buffer_returns_none() {
    let mut buf = BytesMut::from(&[0x10u8][..]);
    assert!(decode_packet_from_bytes(&mut buf, ANY_SIZE).unwrap().is_none());
    assert_eq!(buf.len(), 1, "buffer must not be consumed on partial");
}
