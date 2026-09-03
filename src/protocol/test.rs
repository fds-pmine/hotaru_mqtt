//! Protocol tests: keep-alive deadline and ping-interval arithmetic.

use std::time::Duration;

use super::client::client_ping_interval;
use super::server::server_read_deadline;

/// Spec §3.1.2.10: `keep_alive = 0` turns the mechanism off, so the server
/// must not disconnect for inactivity. The old `keep_alive.max(1)` turned
/// that request into the most aggressive deadline the code could produce.
#[test]
fn zero_means_no_deadline_on_either_side() {
    assert_eq!(None, server_read_deadline(0));
    assert_eq!(None, client_ping_interval(0));
}

/// The grace is exactly 1.5×, including where integer division used to lose
/// it: `(1 * 3) / 2` was 1 second, i.e. no grace at all.
#[test]
fn the_grace_is_exact_for_odd_values() {
    assert_eq!(Some(Duration::from_millis(1_500)), server_read_deadline(1));
    assert_eq!(Some(Duration::from_millis(4_500)), server_read_deadline(3));
    assert_eq!(Some(Duration::from_millis(7_500)), server_read_deadline(5));
}

#[test]
fn even_values_are_unchanged() {
    assert_eq!(Some(Duration::from_secs(3)), server_read_deadline(2));
    assert_eq!(Some(Duration::from_secs(90)), server_read_deadline(60));
}

/// The largest legal value must stay well inside `u64` milliseconds.
#[test]
fn the_wire_maximum_does_not_overflow() {
    let d = server_read_deadline(u16::MAX).expect("65535 is not zero");
    assert_eq!(Duration::from_millis(65_535 * 1_500), d);
    assert_eq!(98_302_500, d.as_millis());
}

/// A client pings on its own declared interval, not on the server's grace —
/// pinging at 1.5× would be late by construction.
#[test]
fn the_client_pings_on_its_own_interval_not_the_grace() {
    assert_eq!(Some(Duration::from_secs(60)), client_ping_interval(60));
    assert_eq!(Some(Duration::from_secs(1)), client_ping_interval(1));
    assert!(client_ping_interval(60).unwrap() < server_read_deadline(60).unwrap());
}
