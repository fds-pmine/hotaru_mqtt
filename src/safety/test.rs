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
