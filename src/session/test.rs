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

/// Clearing inflight must reach only the session it was called on. Two
/// connections sharing a client_id both exist during a takeover and share
/// one packet-id space, so a resolver that finds its session by name can
/// clear an entry belonging to the other — dropping retransmit tracking for
/// a message that was never delivered.
#[test]
fn clearing_inflight_leaves_other_sessions_alone() {
    let earlier = MqttSession::new();
    let newer = MqttSession::new();
    earlier.outbound_inflight.insert(42, publish(42));
    newer.outbound_inflight.insert(42, publish(42));

    earlier.clear_outbound_inflight(42);

    assert!(earlier.outbound_inflight.get(&42).is_none());
    assert!(
        newer.outbound_inflight.get(&42).is_some(),
        "clearing one session's inflight reached another session"
    );
}

#[test]
fn clearing_an_unknown_id_is_a_no_op() {
    let session = MqttSession::new();
    session.outbound_inflight.insert(1, publish(1));
    session.clear_outbound_inflight(99);
    assert!(session.outbound_inflight.get(&1).is_some());
}

/// The ack a waiter is parked for is the ack that must wake it.
#[test]
fn a_matching_ack_wakes_the_waiter() {
    let session = MqttSession::new();
    let (sender, receiver) = oneshot::channel();
    session.pending_acks.insert(7, AckSlot::Pubcomp(sender));

    session.wake_ack_waiter(7, AckKind::Pubcomp);

    assert_eq!(Ok(7), receiver.blocking_recv());
    assert!(
        session.pending_acks.get(&7).is_none(),
        "a woken slot should be gone"
    );
}

/// A PUBACK arriving for a slot that is waiting on PUBCOMP must leave that
/// slot alone.
///
/// Removing it would be worse than ignoring the ack. Dropping the sending
/// half of a `oneshot` resolves the receiving half at once with
/// `RecvError`, which the send path reports as `ChannelClosed` — so a flow
/// that is perfectly healthy, and in the QoS 2 case about to complete, gets
/// reported as a disconnection that never happened.
#[test]
fn a_mismatched_ack_leaves_the_waiter_parked() {
    let session = MqttSession::new();
    let (sender, mut receiver) = oneshot::channel();
    session.pending_acks.insert(7, AckSlot::Pubcomp(sender));

    session.wake_ack_waiter(7, AckKind::Puback);

    assert!(
        session.pending_acks.get(&7).is_some(),
        "a Puback must not consume a slot waiting for Pubcomp"
    );
    assert!(
        matches!(receiver.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
        "the waiter must still be waiting, not resolved with an error"
    );

    // And the ack it was actually waiting for still works afterwards.
    session.wake_ack_waiter(7, AckKind::Pubcomp);
    assert_eq!(Ok(7), receiver.blocking_recv());
}

#[test]
fn waking_an_unparked_id_is_a_no_op() {
    let session = MqttSession::new();
    session.wake_ack_waiter(99, AckKind::Puback);
}

/// Parking hands back the receiver that the matching wake fires — the
/// round trip that every outbound send relies on.
#[test]
fn parking_then_waking_delivers_the_suback_codes() {
    let session = MqttSession::new();
    let mut suback_received = session.park_suback_waiter(7);

    session.wake_suback_waiter(7, vec![crate::request::SubackCode::Failure]);

    assert_eq!(
        Ok(vec![crate::request::SubackCode::Failure]),
        suback_received.try_recv().map_err(|_| ())
            .map_err(|_| panic!("waiter was not woken"))
    );
    assert!(session.pending_acks.get(&7).is_none());
}

/// A publish ack must not consume a SUBACK slot, and a SUBACK must not
/// consume a publish slot — the guard works in both directions.
#[test]
fn suback_wake_leaves_a_publish_slot_alone() {
    let session = MqttSession::new();
    let mut pubcomp_received = session.park_publish_ack_waiter(7, AckKind::Pubcomp);

    session.wake_suback_waiter(7, vec![]);
    session.wake_unsuback_waiter(7);

    assert!(session.pending_acks.get(&7).is_some(),
            "a SUBACK/UNSUBACK consumed a publish-flow slot");
    assert!(matches!(
        pubcomp_received.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    // And the ack it is actually waiting for still works.
    session.wake_ack_waiter(7, AckKind::Pubcomp);
    assert_eq!(Ok(7), pubcomp_received.blocking_recv());
}

/// Cancelling (ack timeout) removes the slot so a late ack is a no-op.
#[test]
fn cancelling_a_waiter_empties_the_slot() {
    let session = MqttSession::new();
    let _unsuback_received = session.park_unsuback_waiter(9);
    session.cancel_ack_waiter(9);
    assert!(session.pending_acks.get(&9).is_none());
}

/// SUBACK and UNSUBACK slots share the same map but are not `AckKind`s, so
/// no publish ack may disturb them.
#[test]
fn a_publish_ack_never_touches_a_subscribe_slot() {
    let session = MqttSession::new();
    let (sender, mut receiver) = oneshot::channel();
    session.pending_acks.insert(7, AckSlot::Unsuback(sender));

    for kind in [AckKind::Puback, AckKind::Pubrec, AckKind::Pubcomp] {
        session.wake_ack_waiter(7, kind);
    }

    assert!(session.pending_acks.get(&7).is_some());
    assert!(matches!(
        receiver.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
}
