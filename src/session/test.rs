//! Session tests: inflight bookkeeping and ack-slot parking.

use super::*;
use bytes::Bytes;

fn publish(id: PacketId) -> PublishPacket {
    PublishPacket {
        topic: Arc::from("t"),
        payload: Bytes::from_static(b"x"),
        dup: false,
        qos: crate::request::QoS::AtLeastOnce,
        retain: false,
        packet_id: Some(id),
    }
}

/// Settling an ack must reach only the session it was called on. Two
/// connections sharing a client_id both exist during a takeover, and they
/// hold the same packet-id space, so a resolver that finds its session by
/// name can clear an inflight entry belonging to the other one — dropping
/// retransmit tracking for a message that was never delivered.
#[test]
fn discharging_an_ack_leaves_other_sessions_alone() {
    let earlier = MqttSession::new();
    let newer = MqttSession::new();
    earlier.outbound_inflight.insert(42, publish(42));
    newer.outbound_inflight.insert(42, publish(42));

    earlier.discharge_outbound_ack(42);

    assert!(earlier.outbound_inflight.get(&42).is_none());
    assert!(
        newer.outbound_inflight.get(&42).is_some(),
        "an ack settled on one session cleared another session's inflight"
    );
}

#[test]
fn discharging_an_unknown_id_is_a_no_op() {
    let session = MqttSession::new();
    session.outbound_inflight.insert(1, publish(1));
    session.discharge_outbound_ack(99);
    assert!(session.outbound_inflight.get(&1).is_some());
}
