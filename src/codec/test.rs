//! Codec tests: wire round-trips, encoder agreement, and size bounds.

use super::*;

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
    let bytes = encode_packet(&Packet::Connect(original.clone()));
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf).unwrap().unwrap() {
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
    let bytes = encode_packet(&Packet::Connect(original));
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf).unwrap().unwrap() {
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
    let bytes = encode_packet(&Packet::Publish(p));
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf).unwrap().unwrap() {
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
    let bytes = encode_packet(&Packet::Publish(p));
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf).unwrap().unwrap() {
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
    let bytes = encode_packet(&Packet::Subscribe(s));
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf).unwrap().unwrap() {
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
    let bytes = encode_packet(&Packet::Unsubscribe(u));
    let mut buf = BytesMut::from(&bytes[..]);
    match decode_packet_from_bytes(&mut buf).unwrap().unwrap() {
        Packet::Unsubscribe(u) => {
            assert_eq!(u.packet_id, 8);
            assert_eq!(u.topics.len(), 2);
        }
        _ => panic!("expected Unsubscribe"),
    }
}

#[test]
fn pingreq_pingresp_disconnect_unsuback() {
    assert_eq!(encode_packet(&Packet::Pingreq), vec![0xC0, 0x00]);
    assert_eq!(encode_packet(&Packet::Pingresp), vec![0xD0, 0x00]);
    assert_eq!(encode_packet(&Packet::Disconnect), vec![0xE0, 0x00]);
    assert_eq!(
        encode_packet(&Packet::Unsuback(42)),
        vec![0xB0, 0x02, 0x00, 0x2A]
    );
}

#[test]
fn partial_buffer_returns_none() {
    let mut buf = BytesMut::from(&[0x10u8][..]);
    assert!(decode_packet_from_bytes(&mut buf).unwrap().is_none());
    assert_eq!(buf.len(), 1, "buffer must not be consumed on partial");
}
