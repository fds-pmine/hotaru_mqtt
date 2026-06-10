//! MQTT topic and filter parsing / validation.
//!
//! Two grammars:
//!
//! - **SUBSCRIBE filter** (per MQTT 3.1.1 §4.7): accepts `+` (single-level
//!   wildcard) and `#` (multi-level wildcard, must be terminal).
//! - **PUBLISH topic** (per §3.3): rejects `+` / `#`; all segments are literal.
//!
//! Both parsers produce `Vec<PathPattern>` compatible with `hotaru_core`'s
//! URL router — `+` maps to `PathPattern::Any`, `#` to `PathPattern::AnyPath`.
//!
//! The reverse map `path_to_wire_filter` converts a registered URL path
//! (HTTP grammar — `<id>` / `<**path>`) back to MQTT wire format (`+` / `#`),
//! used when constructing SUBSCRIBE packets from `endpoint!`-registered paths.

use hotaru_core::url::PathPattern;

use crate::error::{MqttError, Violation};

const MAX_TOPIC_LEN: usize = 65535;

/// Parse a SUBSCRIBE topic filter into `Vec<PathPattern>`.
///
/// Accepts `+` (single-level wildcard) and `#` (multi-level wildcard, must be
/// the terminal segment). Mixed forms like `a+b` or `a/#/b` are rejected.
pub fn parse_subscribe_filter(filter: &str) -> Result<Vec<PathPattern>, MqttError> {
    if filter.is_empty() {
        return Err(Violation::EmptyTopic.into());
    }
    if filter.len() > MAX_TOPIC_LEN {
        return Err(Violation::TopicTooLong.into());
    }

    let segments: Vec<&str> = filter.split('/').collect();
    let last_idx = segments.len() - 1;
    let mut patterns = Vec::with_capacity(segments.len());

    for (i, seg) in segments.iter().enumerate() {
        match *seg {
            "+" => patterns.push(PathPattern::Any),
            "#" => {
                if i != last_idx {
                    return Err(Violation::HashWildcardNotTerminal.into());
                }
                patterns.push(PathPattern::AnyPath);
            }
            s if s.contains('+') || s.contains('#') => {
                return Err(Violation::WildcardMixedWithLiteral.into());
            }
            s => patterns.push(PathPattern::Literal(s.to_string())),
        }
    }
    Ok(patterns)
}

/// Parse a PUBLISH topic into `Vec<PathPattern>` (all literal segments).
///
/// Rejects topics containing `+` or `#`.
pub fn parse_publish_topic(topic: &str) -> Result<Vec<PathPattern>, MqttError> {
    if topic.is_empty() {
        return Err(Violation::EmptyTopic.into());
    }
    if topic.len() > MAX_TOPIC_LEN {
        return Err(Violation::TopicTooLong.into());
    }

    let mut patterns = Vec::new();
    for seg in topic.split('/') {
        if seg.contains('+') || seg.contains('#') {
            return Err(Violation::WildcardInPublishTopic.into());
        }
        patterns.push(PathPattern::Literal(seg.to_string()));
    }
    Ok(patterns)
}

/// Convert a registered `Vec<PathPattern>` back to MQTT wire filter format.
///
/// Mapping:
/// - `Literal(s)` → `s`
/// - `Any` → `"+"`
/// - `Regex(_)` → `"+"` (regex has no MQTT wire equivalent; degrades to single-level)
/// - `AnyPath` → `"#"`
pub fn path_to_wire_filter(path: &[PathPattern]) -> String {
    path.iter()
        .map(|p| match p {
            PathPattern::Literal(s) => s.clone(),
            PathPattern::Any | PathPattern::Regex(_) => "+".to_string(),
            PathPattern::AnyPath => "#".to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Fast validation of SUBSCRIBE filter without allocating `Vec<PathPattern>`.
pub fn validate_subscribe_filter(filter: &str) -> Result<(), MqttError> {
    if filter.is_empty() {
        return Err(Violation::EmptyTopic.into());
    }
    if filter.len() > MAX_TOPIC_LEN {
        return Err(Violation::TopicTooLong.into());
    }
    let segments: Vec<&str> = filter.split('/').collect();
    let last_idx = segments.len() - 1;
    for (i, seg) in segments.iter().enumerate() {
        match *seg {
            "+" => {}
            "#" => {
                if i != last_idx {
                    return Err(Violation::HashWildcardNotTerminal.into());
                }
            }
            s if s.contains('+') || s.contains('#') => {
                return Err(Violation::WildcardMixedWithLiteral.into());
            }
            _ => {}
        }
    }
    Ok(())
}

/// Fast validation of PUBLISH topic without allocating `Vec<PathPattern>`.
pub fn validate_publish_topic(topic: &str) -> Result<(), MqttError> {
    if topic.is_empty() {
        return Err(Violation::EmptyTopic.into());
    }
    if topic.len() > MAX_TOPIC_LEN {
        return Err(Violation::TopicTooLong.into());
    }
    for seg in topic.split('/') {
        if seg.contains('+') || seg.contains('#') {
            return Err(Violation::WildcardInPublishTopic.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_literal() {
        let p = parse_subscribe_filter("sensors/temp").unwrap();
        assert_eq!(
            p,
            vec![
                PathPattern::Literal("sensors".into()),
                PathPattern::Literal("temp".into())
            ]
        );
    }

    #[test]
    fn subscribe_plus() {
        let p = parse_subscribe_filter("sensors/+/temp").unwrap();
        assert_eq!(
            p,
            vec![
                PathPattern::Literal("sensors".into()),
                PathPattern::Any,
                PathPattern::Literal("temp".into())
            ]
        );
    }

    #[test]
    fn subscribe_hash() {
        let p = parse_subscribe_filter("sensors/#").unwrap();
        assert_eq!(
            p,
            vec![PathPattern::Literal("sensors".into()), PathPattern::AnyPath]
        );
    }

    #[test]
    fn subscribe_hash_only() {
        let p = parse_subscribe_filter("#").unwrap();
        assert_eq!(p, vec![PathPattern::AnyPath]);
    }

    #[test]
    fn subscribe_rejects_hash_not_terminal() {
        let e = parse_subscribe_filter("a/#/b").unwrap_err();
        assert!(matches!(
            e,
            MqttError::Protocol(Violation::HashWildcardNotTerminal)
        ));
    }

    #[test]
    fn subscribe_rejects_mixed_wildcard() {
        let e = parse_subscribe_filter("a+b").unwrap_err();
        assert!(matches!(
            e,
            MqttError::Protocol(Violation::WildcardMixedWithLiteral)
        ));
    }

    #[test]
    fn publish_rejects_wildcards() {
        let e = parse_publish_topic("a/+/b").unwrap_err();
        assert!(matches!(
            e,
            MqttError::Protocol(Violation::WildcardInPublishTopic)
        ));
    }

    #[test]
    fn publish_accepts_dollar_sys() {
        let p = parse_publish_topic("$SYS/broker/clients").unwrap();
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn path_to_wire_round_trip() {
        let path = parse_subscribe_filter("sensors/+/temp").unwrap();
        assert_eq!(path_to_wire_filter(&path), "sensors/+/temp");

        let path = parse_subscribe_filter("a/#").unwrap();
        assert_eq!(path_to_wire_filter(&path), "a/#");
    }

    #[test]
    fn validate_fast_path() {
        assert!(validate_subscribe_filter("a/+/b").is_ok());
        assert!(validate_subscribe_filter("a/#/b").is_err());
        assert!(validate_publish_topic("a/b/c").is_ok());
        assert!(validate_publish_topic("a/+").is_err());
    }
}
