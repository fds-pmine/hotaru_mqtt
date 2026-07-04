//! MQTT 5.0 properties (spec §2.2.2).
//!
//! A property block is a Variable Byte Integer length followed by
//! `(identifier, value)` pairs. Every v5 packet with a variable header
//! carries one (possibly empty) block; CONNECT wills carry a second.
//!
//! Storage policy: all spec-defined properties are parsed into typed
//! fields so a broker can forward PUBLISH properties unaltered
//! (§3.3.2.3 forwarding rules). Validation here is structural only
//! (known id, well-formed value, no illegal duplicates); per-packet
//! allowed-property matrices are enforced by the callers that care
//! (e.g. `codec::parse_publish` rejects `topic_alias` because we never
//! advertise a non-zero Topic Alias Maximum).

use std::sync::Arc;

use bytes::Bytes;

use crate::codec::{read_arc_str, read_bytes, read_u16, write_arc_str, write_bytes};
use crate::error::{CodecError, MqttError, Violation};

// ----------------------------------------------------------------------------
// Property identifiers (spec §2.2.2.2)
// ----------------------------------------------------------------------------

pub(crate) mod id {
    pub const PAYLOAD_FORMAT_INDICATOR: u8 = 0x01;
    pub const MESSAGE_EXPIRY_INTERVAL: u8 = 0x02;
    pub const CONTENT_TYPE: u8 = 0x03;
    pub const RESPONSE_TOPIC: u8 = 0x08;
    pub const CORRELATION_DATA: u8 = 0x09;
    pub const SUBSCRIPTION_IDENTIFIER: u8 = 0x0B;
    pub const SESSION_EXPIRY_INTERVAL: u8 = 0x11;
    pub const ASSIGNED_CLIENT_IDENTIFIER: u8 = 0x12;
    pub const SERVER_KEEP_ALIVE: u8 = 0x13;
    pub const AUTHENTICATION_METHOD: u8 = 0x15;
    pub const AUTHENTICATION_DATA: u8 = 0x16;
    pub const REQUEST_PROBLEM_INFORMATION: u8 = 0x17;
    pub const WILL_DELAY_INTERVAL: u8 = 0x18;
    pub const REQUEST_RESPONSE_INFORMATION: u8 = 0x19;
    pub const RESPONSE_INFORMATION: u8 = 0x1A;
    pub const SERVER_REFERENCE: u8 = 0x1C;
    pub const REASON_STRING: u8 = 0x1F;
    pub const RECEIVE_MAXIMUM: u8 = 0x21;
    pub const TOPIC_ALIAS_MAXIMUM: u8 = 0x22;
    pub const TOPIC_ALIAS: u8 = 0x23;
    pub const MAXIMUM_QOS: u8 = 0x24;
    pub const RETAIN_AVAILABLE: u8 = 0x25;
    pub const USER_PROPERTY: u8 = 0x26;
    pub const MAXIMUM_PACKET_SIZE: u8 = 0x27;
    pub const WILDCARD_SUBSCRIPTION_AVAILABLE: u8 = 0x28;
    pub const SUBSCRIPTION_IDENTIFIER_AVAILABLE: u8 = 0x29;
    pub const SHARED_SUBSCRIPTION_AVAILABLE: u8 = 0x2A;
}

// ----------------------------------------------------------------------------
// Properties
// ----------------------------------------------------------------------------

/// Parsed MQTT 5.0 property block. `Default` is the empty block, which
/// encodes as a single `0x00` length byte — the form every v3-shaped
/// call site gets for free.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Properties {
    pub payload_format_indicator: Option<u8>,
    pub message_expiry_interval: Option<u32>,
    pub content_type: Option<Arc<str>>,
    pub response_topic: Option<Arc<str>>,
    pub correlation_data: Option<Bytes>,
    /// May repeat (broker → client PUBLISH carries one per matched
    /// subscription); spec forbids the value 0.
    pub subscription_identifiers: Vec<u32>,
    pub session_expiry_interval: Option<u32>,
    pub assigned_client_identifier: Option<Arc<str>>,
    pub server_keep_alive: Option<u16>,
    pub authentication_method: Option<Arc<str>>,
    pub authentication_data: Option<Bytes>,
    pub request_problem_information: Option<u8>,
    pub will_delay_interval: Option<u32>,
    pub request_response_information: Option<u8>,
    pub response_information: Option<Arc<str>>,
    pub server_reference: Option<Arc<str>>,
    pub reason_string: Option<Arc<str>>,
    pub receive_maximum: Option<u16>,
    pub topic_alias_maximum: Option<u16>,
    pub topic_alias: Option<u16>,
    pub maximum_qos: Option<u8>,
    pub retain_available: Option<u8>,
    /// May repeat; order preserved (spec §2.2.2.2 User Property).
    pub user_properties: Vec<(Arc<str>, Arc<str>)>,
    pub maximum_packet_size: Option<u32>,
    pub wildcard_subscription_available: Option<u8>,
    pub subscription_identifier_available: Option<u8>,
    pub shared_subscription_available: Option<u8>,
}

impl Properties {
    /// True when the block encodes as just the `0x00` length byte.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    // ------------------------------------------------------------------
    // Decode
    // ------------------------------------------------------------------

    /// Parse one property block at `cursor`, advancing it past the block.
    pub(crate) fn parse(body: &[u8], cursor: &mut usize) -> Result<Self, MqttError> {
        let len = read_vbi(body, cursor)?;
        let end = cursor
            .checked_add(len)
            .ok_or(CodecError::MalformedLength)?;
        if end > body.len() {
            return Err(CodecError::UnexpectedEof.into());
        }

        let mut props = Self::default();
        // Duplicate tracking: all ids are < 64, so one u64 bitmask works.
        // User Property and Subscription Identifier are allowed to repeat.
        let mut seen: u64 = 0;

        while *cursor < end {
            let pid = body[*cursor];
            *cursor += 1;
            let repeatable = matches!(pid, id::USER_PROPERTY | id::SUBSCRIPTION_IDENTIFIER);
            if !repeatable {
                let bit = 1u64 << (pid & 0x3F);
                if seen & bit != 0 {
                    return Err(Violation::DuplicateProperty(pid).into());
                }
                seen |= bit;
            }
            match pid {
                id::PAYLOAD_FORMAT_INDICATOR => {
                    props.payload_format_indicator = Some(read_u8(body, cursor)?)
                }
                id::MESSAGE_EXPIRY_INTERVAL => {
                    props.message_expiry_interval = Some(read_u32(body, cursor)?)
                }
                id::CONTENT_TYPE => props.content_type = Some(read_arc_str(body, cursor)?),
                id::RESPONSE_TOPIC => props.response_topic = Some(read_arc_str(body, cursor)?),
                id::CORRELATION_DATA => props.correlation_data = Some(read_bytes(body, cursor)?),
                id::SUBSCRIPTION_IDENTIFIER => {
                    let v = read_vbi(body, cursor)?;
                    if v == 0 {
                        return Err(Violation::MalformedProperty(pid).into());
                    }
                    props.subscription_identifiers.push(v as u32);
                }
                id::SESSION_EXPIRY_INTERVAL => {
                    props.session_expiry_interval = Some(read_u32(body, cursor)?)
                }
                id::ASSIGNED_CLIENT_IDENTIFIER => {
                    props.assigned_client_identifier = Some(read_arc_str(body, cursor)?)
                }
                id::SERVER_KEEP_ALIVE => props.server_keep_alive = Some(read_u16(body, cursor)?),
                id::AUTHENTICATION_METHOD => {
                    props.authentication_method = Some(read_arc_str(body, cursor)?)
                }
                id::AUTHENTICATION_DATA => {
                    props.authentication_data = Some(read_bytes(body, cursor)?)
                }
                id::REQUEST_PROBLEM_INFORMATION => {
                    props.request_problem_information = Some(read_u8(body, cursor)?)
                }
                id::WILL_DELAY_INTERVAL => {
                    props.will_delay_interval = Some(read_u32(body, cursor)?)
                }
                id::REQUEST_RESPONSE_INFORMATION => {
                    props.request_response_information = Some(read_u8(body, cursor)?)
                }
                id::RESPONSE_INFORMATION => {
                    props.response_information = Some(read_arc_str(body, cursor)?)
                }
                id::SERVER_REFERENCE => props.server_reference = Some(read_arc_str(body, cursor)?),
                id::REASON_STRING => props.reason_string = Some(read_arc_str(body, cursor)?),
                id::RECEIVE_MAXIMUM => props.receive_maximum = Some(read_u16(body, cursor)?),
                id::TOPIC_ALIAS_MAXIMUM => {
                    props.topic_alias_maximum = Some(read_u16(body, cursor)?)
                }
                id::TOPIC_ALIAS => props.topic_alias = Some(read_u16(body, cursor)?),
                id::MAXIMUM_QOS => props.maximum_qos = Some(read_u8(body, cursor)?),
                id::RETAIN_AVAILABLE => props.retain_available = Some(read_u8(body, cursor)?),
                id::USER_PROPERTY => {
                    let k = read_arc_str(body, cursor)?;
                    let v = read_arc_str(body, cursor)?;
                    props.user_properties.push((k, v));
                }
                id::MAXIMUM_PACKET_SIZE => {
                    props.maximum_packet_size = Some(read_u32(body, cursor)?)
                }
                id::WILDCARD_SUBSCRIPTION_AVAILABLE => {
                    props.wildcard_subscription_available = Some(read_u8(body, cursor)?)
                }
                id::SUBSCRIPTION_IDENTIFIER_AVAILABLE => {
                    props.subscription_identifier_available = Some(read_u8(body, cursor)?)
                }
                id::SHARED_SUBSCRIPTION_AVAILABLE => {
                    props.shared_subscription_available = Some(read_u8(body, cursor)?)
                }
                other => return Err(Violation::UnknownProperty(other).into()),
            }
        }
        if *cursor != end {
            // A value read overran the declared block length.
            return Err(CodecError::MalformedLength.into());
        }
        Ok(props)
    }

    // ------------------------------------------------------------------
    // Encode
    // ------------------------------------------------------------------

    /// Append this block (VBI length + fields) to `out`.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), MqttError> {
        let mut buf = Vec::new();
        if let Some(v) = self.payload_format_indicator {
            buf.push(id::PAYLOAD_FORMAT_INDICATOR);
            buf.push(v);
        }
        if let Some(v) = self.message_expiry_interval {
            buf.push(id::MESSAGE_EXPIRY_INTERVAL);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        if let Some(v) = &self.content_type {
            buf.push(id::CONTENT_TYPE);
            write_arc_str(&mut buf, v, "prop.content_type")?;
        }
        if let Some(v) = &self.response_topic {
            buf.push(id::RESPONSE_TOPIC);
            write_arc_str(&mut buf, v, "prop.response_topic")?;
        }
        if let Some(v) = &self.correlation_data {
            buf.push(id::CORRELATION_DATA);
            write_bytes(&mut buf, v, "prop.correlation_data")?;
        }
        for v in &self.subscription_identifiers {
            buf.push(id::SUBSCRIPTION_IDENTIFIER);
            write_vbi(&mut buf, *v as usize);
        }
        if let Some(v) = self.session_expiry_interval {
            buf.push(id::SESSION_EXPIRY_INTERVAL);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        if let Some(v) = &self.assigned_client_identifier {
            buf.push(id::ASSIGNED_CLIENT_IDENTIFIER);
            write_arc_str(&mut buf, v, "prop.assigned_client_identifier")?;
        }
        if let Some(v) = self.server_keep_alive {
            buf.push(id::SERVER_KEEP_ALIVE);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        if let Some(v) = &self.authentication_method {
            buf.push(id::AUTHENTICATION_METHOD);
            write_arc_str(&mut buf, v, "prop.authentication_method")?;
        }
        if let Some(v) = &self.authentication_data {
            buf.push(id::AUTHENTICATION_DATA);
            write_bytes(&mut buf, v, "prop.authentication_data")?;
        }
        if let Some(v) = self.request_problem_information {
            buf.push(id::REQUEST_PROBLEM_INFORMATION);
            buf.push(v);
        }
        if let Some(v) = self.will_delay_interval {
            buf.push(id::WILL_DELAY_INTERVAL);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        if let Some(v) = self.request_response_information {
            buf.push(id::REQUEST_RESPONSE_INFORMATION);
            buf.push(v);
        }
        if let Some(v) = &self.response_information {
            buf.push(id::RESPONSE_INFORMATION);
            write_arc_str(&mut buf, v, "prop.response_information")?;
        }
        if let Some(v) = &self.server_reference {
            buf.push(id::SERVER_REFERENCE);
            write_arc_str(&mut buf, v, "prop.server_reference")?;
        }
        if let Some(v) = &self.reason_string {
            buf.push(id::REASON_STRING);
            write_arc_str(&mut buf, v, "prop.reason_string")?;
        }
        if let Some(v) = self.receive_maximum {
            buf.push(id::RECEIVE_MAXIMUM);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        if let Some(v) = self.topic_alias_maximum {
            buf.push(id::TOPIC_ALIAS_MAXIMUM);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        if let Some(v) = self.topic_alias {
            buf.push(id::TOPIC_ALIAS);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        if let Some(v) = self.maximum_qos {
            buf.push(id::MAXIMUM_QOS);
            buf.push(v);
        }
        if let Some(v) = self.retain_available {
            buf.push(id::RETAIN_AVAILABLE);
            buf.push(v);
        }
        for (k, v) in &self.user_properties {
            buf.push(id::USER_PROPERTY);
            write_arc_str(&mut buf, k, "prop.user_property.key")?;
            write_arc_str(&mut buf, v, "prop.user_property.value")?;
        }
        if let Some(v) = self.maximum_packet_size {
            buf.push(id::MAXIMUM_PACKET_SIZE);
            buf.extend_from_slice(&v.to_be_bytes());
        }
        if let Some(v) = self.wildcard_subscription_available {
            buf.push(id::WILDCARD_SUBSCRIPTION_AVAILABLE);
            buf.push(v);
        }
        if let Some(v) = self.subscription_identifier_available {
            buf.push(id::SUBSCRIPTION_IDENTIFIER_AVAILABLE);
            buf.push(v);
        }
        if let Some(v) = self.shared_subscription_available {
            buf.push(id::SHARED_SUBSCRIPTION_AVAILABLE);
            buf.push(v);
        }

        write_vbi(out, buf.len());
        out.extend_from_slice(&buf);
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Scalar readers / VBI
// ----------------------------------------------------------------------------

fn read_u8(body: &[u8], cursor: &mut usize) -> Result<u8, MqttError> {
    if *cursor >= body.len() {
        return Err(CodecError::UnexpectedEof.into());
    }
    let v = body[*cursor];
    *cursor += 1;
    Ok(v)
}

fn read_u32(body: &[u8], cursor: &mut usize) -> Result<u32, MqttError> {
    if *cursor + 4 > body.len() {
        return Err(CodecError::UnexpectedEof.into());
    }
    let v = u32::from_be_bytes([
        body[*cursor],
        body[*cursor + 1],
        body[*cursor + 2],
        body[*cursor + 3],
    ]);
    *cursor += 4;
    Ok(v)
}

/// Read a Variable Byte Integer at `cursor` (spec §1.5.5, max 4 bytes).
pub(crate) fn read_vbi(body: &[u8], cursor: &mut usize) -> Result<usize, MqttError> {
    let mut result = 0usize;
    let mut multiplier = 1usize;
    for i in 0..4 {
        if *cursor >= body.len() {
            return Err(CodecError::UnexpectedEof.into());
        }
        let byte = body[*cursor];
        *cursor += 1;
        result += (byte & 0x7F) as usize * multiplier;
        multiplier *= 128;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        if i == 3 {
            return Err(CodecError::MalformedLength.into());
        }
    }
    unreachable!()
}

/// Append a Variable Byte Integer (spec §1.5.5).
pub(crate) fn write_vbi(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(props: &Properties) -> Properties {
        let mut buf = Vec::new();
        props.encode(&mut buf).unwrap();
        let mut cursor = 0usize;
        let parsed = Properties::parse(&buf, &mut cursor).unwrap();
        assert_eq!(cursor, buf.len(), "cursor must land on block end");
        parsed
    }

    #[test]
    fn empty_block_is_single_zero_byte() {
        let props = Properties::default();
        let mut buf = Vec::new();
        props.encode(&mut buf).unwrap();
        assert_eq!(buf, vec![0x00]);
        assert!(roundtrip(&props).is_empty());
    }

    #[test]
    fn full_roundtrip() {
        let props = Properties {
            payload_format_indicator: Some(1),
            message_expiry_interval: Some(300),
            content_type: Some(Arc::from("application/json")),
            response_topic: Some(Arc::from("reply/here")),
            correlation_data: Some(Bytes::from_static(b"corr")),
            subscription_identifiers: vec![1, 268_435_455],
            session_expiry_interval: Some(0xFFFF_FFFF),
            receive_maximum: Some(20),
            topic_alias_maximum: Some(0),
            user_properties: vec![
                (Arc::from("k1"), Arc::from("v1")),
                (Arc::from("k1"), Arc::from("v2")), // duplicate keys legal
            ],
            maximum_packet_size: Some(1024),
            ..Default::default()
        };
        assert_eq!(roundtrip(&props), props);
    }

    #[test]
    fn duplicate_scalar_property_rejected() {
        // Two SESSION_EXPIRY_INTERVAL entries.
        let mut buf = Vec::new();
        let mut body = Vec::new();
        for _ in 0..2 {
            body.push(id::SESSION_EXPIRY_INTERVAL);
            body.extend_from_slice(&10u32.to_be_bytes());
        }
        write_vbi(&mut buf, body.len());
        buf.extend_from_slice(&body);
        let mut cursor = 0;
        let err = Properties::parse(&buf, &mut cursor).unwrap_err();
        match err {
            MqttError::Protocol(Violation::DuplicateProperty(pid)) => {
                assert_eq!(pid, id::SESSION_EXPIRY_INTERVAL)
            }
            other => panic!("expected DuplicateProperty, got {other:?}"),
        }
    }

    #[test]
    fn unknown_property_rejected() {
        let buf = vec![0x02, 0x7F, 0x00]; // len=2, id=0x7F (undefined)
        let mut cursor = 0;
        let err = Properties::parse(&buf, &mut cursor).unwrap_err();
        match err {
            MqttError::Protocol(Violation::UnknownProperty(0x7F)) => {}
            other => panic!("expected UnknownProperty, got {other:?}"),
        }
    }

    #[test]
    fn zero_subscription_identifier_rejected() {
        let buf = vec![0x02, id::SUBSCRIPTION_IDENTIFIER, 0x00];
        let mut cursor = 0;
        let err = Properties::parse(&buf, &mut cursor).unwrap_err();
        match err {
            MqttError::Protocol(Violation::MalformedProperty(pid)) => {
                assert_eq!(pid, id::SUBSCRIPTION_IDENTIFIER)
            }
            other => panic!("expected MalformedProperty, got {other:?}"),
        }
    }

    #[test]
    fn value_overrunning_block_length_rejected() {
        // Block claims len=2 but CONTENT_TYPE string needs more.
        let buf = vec![0x02, id::CONTENT_TYPE, 0x00];
        let mut cursor = 0;
        assert!(Properties::parse(&buf, &mut cursor).is_err());
    }
}
