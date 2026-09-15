//! Broker tests: topic-filter matching.

use super::*;

#[test]
fn filter_matches_literal() {
    let segs: Vec<&str> = "a/b/c".split('/').collect();
    assert!(filter_matches("a/b/c", &segs));
    assert!(!filter_matches("a/b/d", &segs));
}

#[test]
fn filter_matches_plus() {
    let segs: Vec<&str> = "a/b/c".split('/').collect();
    assert!(filter_matches("a/+/c", &segs));
    assert!(filter_matches("+/+/+", &segs));
    assert!(!filter_matches("a/+/d", &segs));
    assert!(!filter_matches("a/+", &segs));
}

#[test]
fn filter_matches_hash() {
    let segs: Vec<&str> = "a/b/c".split('/').collect();
    assert!(filter_matches("a/#", &segs));
    assert!(filter_matches("#", &segs));
    assert!(filter_matches("a/b/#", &segs));
    assert!(!filter_matches("b/#", &segs));
}

#[test]
fn filter_matches_partial() {
    let segs: Vec<&str> = "a/b".split('/').collect();
    assert!(!filter_matches("a/b/c", &segs));
    assert!(filter_matches("a/b", &segs));
}
