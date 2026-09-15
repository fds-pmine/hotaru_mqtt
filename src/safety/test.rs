//! `MqttSafety` tests: default and clamping behaviour.

use super::*;

#[test]
fn default_is_below_the_spec_ceiling() {
    let s = MqttSafety::new();
    assert_eq!(1024 * 1024, s.max_packet_size());
    assert!(s.max_packet_size() < SPEC_MAX_PACKET_SIZE);
}

#[test]
fn setter_clamps_to_the_wire_ceiling() {
    let s = MqttSafety::new().with_max_packet_size(usize::MAX);
    assert_eq!(SPEC_MAX_PACKET_SIZE, s.max_packet_size());
}

#[test]
fn setter_accepts_values_under_the_ceiling() {
    let s = MqttSafety::new().with_max_packet_size(4096);
    assert_eq!(4096, s.max_packet_size());
}

#[test]
fn keep_alive_defaults_to_an_hour_and_rejects_the_disabled_form() {
    let s = MqttSafety::new();
    assert_eq!(3600, s.max_keep_alive());
    assert!(
        !s.allows_disabled_keep_alive(),
        "keep_alive = 0 is refused by default, departing from 3.1.2.10 by policy"
    );
}

#[test]
fn keep_alive_ceiling_is_not_clamped() {
    // Unlike the packet-size cap: the operator's number stands as written, so a
    // deployment can raise it to the u16 ceiling.
    let s = MqttSafety::new().with_max_keep_alive(u16::MAX);
    assert_eq!(u16::MAX, s.max_keep_alive());
}

#[test]
fn disabled_keep_alive_can_be_opted_into() {
    let s = MqttSafety::new().allow_disabled_keep_alive();
    assert!(s.allows_disabled_keep_alive());
    // Opting in leaves the ceiling alone — the two knobs are independent.
    assert_eq!(3600, s.max_keep_alive());
}
