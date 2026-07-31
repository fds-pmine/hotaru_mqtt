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

use alloc::{string::{String, ToString}, vec::Vec};
use hotaru_core::url::{PathPattern, PatternError, RawToken, TypeKind};

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

// ----------------------------------------------------------------------------
// Protocol::tokenize_url / lit_parser plumbing (hotaru_core 0.8.3+)
// ----------------------------------------------------------------------------

/// MQTT-flavored `tokenize_url` impl, plugged into [`Protocol::tokenize_url`]
/// override on both `MqttClientProtocol` and `MqttServerProtocol`.
///
/// Emits a `RawToken` stream that, when fed through
/// `hotaru_core::url::tokens_to_patterns`, produces patterns equivalent to
/// `parse_subscribe_filter`:
///
/// - `+` segment → `<_>` (name-only Any) → `PathPattern::Any`
/// - `#` segment → `<**path>` → `PathPattern::AnyPath` (must be terminal)
/// - mixed `+` / `#` with literal in same segment → `UnexpectedToken` error
/// - literal segment → `Literal(segment_string)`
/// - segment separator → `Slash`
///
/// MQTT topic filters have NO leading slash, so the token stream starts
/// directly with the first segment (no leading `Slash` like HTTP would emit).
pub fn tokenize_mqtt_filter(input: &str) -> Result<Vec<RawToken>, PatternError> {
    if input.is_empty() {
        // Spec §4.7.3: zero-length filters are MUST-reject. Surface this
        // via the closest structural variant the framework offers.
        return Err(PatternError::UnexpectedToken {
            at: 0,
            token: RawToken::Literal(String::new()),
        });
    }
    if input.len() > MAX_TOPIC_LEN {
        return Err(PatternError::UnexpectedToken {
            at: input.len(),
            token: RawToken::Literal(String::new()),
        });
    }

    let mut tokens = Vec::new();
    let segments: Vec<&str> = input.split('/').collect();
    let last_idx = segments.len() - 1;
    let mut byte_off: usize = 0;

    for (i, seg) in segments.iter().enumerate() {
        if i > 0 {
            tokens.push(RawToken::Slash);
        }
        match *seg {
            "+" => {
                // <_> — name-only Any. tokens_to_patterns produces
                // PathPattern::Any (parser.rs branch 5 + ok_name_only_any).
                tokens.push(RawToken::AngleStart);
                tokens.push(RawToken::Ident("_".to_string()));
                tokens.push(RawToken::AngleClose);
            }
            "#" => {
                if i != last_idx {
                    // # MUST be terminal (spec §4.7.1.2). Closest framework
                    // error variant is AnyPathMixedWithOtherContent.
                    return Err(PatternError::AnyPathMixedWithOtherContent { at: byte_off });
                }
                tokens.push(RawToken::AngleStart);
                tokens.push(RawToken::Type(TypeKind::Path));
                tokens.push(RawToken::AngleClose);
            }
            s if s.contains('+') || s.contains('#') => {
                return Err(PatternError::UnexpectedToken {
                    at: byte_off,
                    token: RawToken::Literal(s.to_string()),
                });
            }
            s => {
                // Empty literal segment ("a//b") is allowed; tokens_to_patterns
                // emits Literal("") for it, distinguishing "a//b" from "a/b".
                tokens.push(RawToken::Literal(s.to_string()));
            }
        }
        byte_off += seg.len() + 1; // +1 for the consumed `/`
    }

    Ok(tokens)
}

/// MQTT-flavored `lit_parser` impl, plugged into [`Protocol::lit_parser`]
/// override on both `MqttClientProtocol` and `MqttServerProtocol`.
///
/// MQTT topics have no leading `/` (unlike HTTP), so this is a plain
/// `split('/')`. Empty input returns an empty slice so the walker consults
/// the root-endpoint slot (per upstream `Protocol::lit_parser` docstring).
pub fn split_mqtt_topic(input: &str) -> Vec<&str> {
    if input.is_empty() {
        Vec::new()
    } else {
        input.split('/').collect()
    }
}

// ----------------------------------------------------------------------------
// Spec §4.7.2 guard
// ----------------------------------------------------------------------------

/// MQTT 3.1.1 §4.7.2: wildcards (`+` / `#`) in the first segment of a filter
/// MUST NOT match a Topic Name whose first segment begins with `$`. Returns
/// `true` if `topic`'s first segment is dollar-prefixed (i.e. matcher MUST
/// reject wildcard filters in that case).
///
/// Used by:
/// - client-side inbound dispatch before calling `walk_cursor`
/// - any downstream protocol implementation's subscription matcher
/// - any retained-message store implementation's `matching` lookup
///
/// Note: this returns whether the topic *qualifies for* the guard. Callers
/// still need to combine with "filter first segment is a wildcard" to decide
/// whether to skip a match.
pub fn is_dollar_prefixed_first_segment(topic: &str) -> bool {
    topic
        .split('/')
        .next()
        .is_some_and(|seg| seg.starts_with('$'))
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

    // ------------------------------------------------------------------
    // Protocol::tokenize_url / lit_parser override parity (#70 / hotaru #4)
    // ------------------------------------------------------------------

    use hotaru_core::url::tokens_to_patterns;

    fn tokens_then_patterns(filter: &str) -> Vec<PathPattern> {
        let tokens = tokenize_mqtt_filter(filter).expect("tokenize");
        let (pats, _names) = tokens_to_patterns(&tokens).expect("patterns");
        pats
    }

    #[test]
    fn tokenize_literal_parity_with_parse_subscribe_filter() {
        // The token-based path MUST produce the same Vec<PathPattern> the
        // legacy parse_subscribe_filter emits — otherwise endpoint
        // registration via Server::register::<MqttServerProtocol, _>
        // wouldn't match the same wire filters our broker dispatches.
        let viahook = tokens_then_patterns("sensors/temp");
        let legacy = parse_subscribe_filter("sensors/temp").unwrap();
        assert_eq!(viahook, legacy);
    }

    #[test]
    fn tokenize_plus_parity() {
        let viahook = tokens_then_patterns("sensors/+/temp");
        let legacy = parse_subscribe_filter("sensors/+/temp").unwrap();
        assert_eq!(viahook, legacy);
        // and explicit: middle segment is PathPattern::Any
        assert_eq!(viahook[1], PathPattern::Any);
    }

    #[test]
    fn tokenize_hash_parity() {
        let viahook = tokens_then_patterns("sensors/#");
        let legacy = parse_subscribe_filter("sensors/#").unwrap();
        assert_eq!(viahook, legacy);
        assert_eq!(viahook[1], PathPattern::AnyPath);
    }

    #[test]
    fn tokenize_hash_only() {
        let viahook = tokens_then_patterns("#");
        assert_eq!(viahook, vec![PathPattern::AnyPath]);
    }

    #[test]
    fn tokenize_rejects_hash_not_terminal() {
        let err = tokenize_mqtt_filter("a/#/b").unwrap_err();
        assert!(matches!(
            err,
            PatternError::AnyPathMixedWithOtherContent { .. }
        ));
    }

    #[test]
    fn tokenize_rejects_mixed_wildcard() {
        let err = tokenize_mqtt_filter("a+b").unwrap_err();
        assert!(matches!(err, PatternError::UnexpectedToken { .. }));
    }

    #[test]
    fn tokenize_rejects_empty_filter() {
        let err = tokenize_mqtt_filter("").unwrap_err();
        assert!(matches!(err, PatternError::UnexpectedToken { .. }));
    }

    #[test]
    fn tokenize_dollar_prefixed_topic_passes_through() {
        // $SYS/broker/version is a valid PUBLISH topic on the broker side
        // and may also be a valid SUBSCRIBE filter (no leading wildcards).
        // Tokenize MUST accept it — the dollar guard runs separately.
        let pats = tokens_then_patterns("$SYS/broker/version");
        assert_eq!(
            pats,
            vec![
                PathPattern::Literal("$SYS".into()),
                PathPattern::Literal("broker".into()),
                PathPattern::Literal("version".into()),
            ]
        );
    }

    #[test]
    fn split_mqtt_topic_basic() {
        assert_eq!(
            split_mqtt_topic("sensors/temp/1"),
            vec!["sensors", "temp", "1"]
        );
    }

    #[test]
    fn split_mqtt_topic_empty_returns_empty_vec() {
        // Empty input → root-endpoint slot (per Protocol::lit_parser docstring).
        assert_eq!(split_mqtt_topic(""), Vec::<&str>::new());
    }

    #[test]
    fn pattern_and_literal_sides_align() {
        // Mirrors the HTTP override regression in upstream
        // hotaru_http/src/protocol/protocol_impl.rs: when a pattern is
        // registered via tokenize_url, and an incoming literal is split
        // via lit_parser, the two MUST have equal segment count and
        // each pattern MUST match its corresponding literal segment.
        let pats = tokens_then_patterns("sensors/+/temp");
        let segs = split_mqtt_topic("sensors/abc/temp");
        assert_eq!(pats.len(), segs.len(), "arity mismatch");
        for (p, s) in pats.iter().zip(segs.iter()) {
            assert!(
                p.matches(s),
                "pattern {:?} did not match segment {:?}",
                p,
                s
            );
        }
    }

    #[test]
    fn dollar_prefix_detection() {
        assert!(is_dollar_prefixed_first_segment("$SYS/broker/clients"));
        assert!(is_dollar_prefixed_first_segment("$share/group/topic"));
        assert!(is_dollar_prefixed_first_segment("$"));
        assert!(!is_dollar_prefixed_first_segment("sensors/$SYS/x")); // $ not at start
        assert!(!is_dollar_prefixed_first_segment("sensors/temp"));
        assert!(!is_dollar_prefixed_first_segment(""));
        assert!(!is_dollar_prefixed_first_segment("/$SYS")); // first seg is empty
    }
}
