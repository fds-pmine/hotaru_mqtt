//! MQTT 5 property blocks (specification section 2.2.2).
//!
//! A block starts with a Variable Byte Integer containing the byte length of
//! the properties which follow. This module owns the identifier table and the
//! structural/value validation shared by future packet-specific codecs.

use std::sync::Arc;

use bytes::Bytes;

use crate::{CodecError, MqttError, Violation};

pub(crate) const MAX_VARIABLE_BYTE_INTEGER: usize = 268_435_455;

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

/// Typed representation of an MQTT 5 property block.
///
/// `Default` represents an empty block. User Properties and Subscription
/// Identifiers preserve their wire order because those identifiers may repeat.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Properties {
    pub payload_format_indicator: Option<u8>,
    pub message_expiry_interval: Option<u32>,
    pub content_type: Option<Arc<str>>,
    pub response_topic: Option<Arc<str>>,
    pub correlation_data: Option<Bytes>,
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
    pub user_properties: Vec<(Arc<str>, Arc<str>)>,
    pub maximum_packet_size: Option<u32>,
    pub wildcard_subscription_available: Option<u8>,
    pub subscription_identifier_available: Option<u8>,
    pub shared_subscription_available: Option<u8>,
}

#[allow(dead_code)] // Wired into packet codecs by the follow-up version-threading change.
impl Properties {
    /// Whether this block contains no properties.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Decode one length-prefixed property block and advance `cursor`.
    pub(crate) fn parse(body: &[u8], cursor: &mut usize) -> Result<Self, MqttError> {
        let property_length = read_vbi(body, cursor)?;
        let end = cursor
            .checked_add(property_length)
            .ok_or(CodecError::MalformedLength)?;
        if end > body.len() {
            return Err(CodecError::UnexpectedEof.into());
        }

        // Restrict every scalar read to the declared property block. Without
        // this slice, a malformed value could consume bytes from the payload.
        let property_body = &body[*cursor..end];
        let mut property_cursor = 0;
        let mut properties = Self::default();
        let mut seen = 0u64;

        while property_cursor < property_body.len() {
            let property_id = read_u8(property_body, &mut property_cursor)?;
            let repeatable = matches!(property_id, id::USER_PROPERTY | id::SUBSCRIPTION_IDENTIFIER);
            if !repeatable {
                let bit = 1u64
                    .checked_shl(property_id.into())
                    .ok_or(Violation::UnknownProperty(property_id))?;
                if seen & bit != 0 {
                    return Err(Violation::DuplicateProperty(property_id).into());
                }
                seen |= bit;
            }

            match property_id {
                id::PAYLOAD_FORMAT_INDICATOR => {
                    properties.payload_format_indicator =
                        Some(read_u8(property_body, &mut property_cursor)?);
                }
                id::MESSAGE_EXPIRY_INTERVAL => {
                    properties.message_expiry_interval =
                        Some(read_u32(property_body, &mut property_cursor)?);
                }
                id::CONTENT_TYPE => {
                    properties.content_type =
                        Some(read_string(property_body, &mut property_cursor)?);
                }
                id::RESPONSE_TOPIC => {
                    properties.response_topic =
                        Some(read_string(property_body, &mut property_cursor)?);
                }
                id::CORRELATION_DATA => {
                    properties.correlation_data =
                        Some(read_binary(property_body, &mut property_cursor)?);
                }
                id::SUBSCRIPTION_IDENTIFIER => {
                    properties
                        .subscription_identifiers
                        .push(read_vbi(property_body, &mut property_cursor)? as u32);
                }
                id::SESSION_EXPIRY_INTERVAL => {
                    properties.session_expiry_interval =
                        Some(read_u32(property_body, &mut property_cursor)?);
                }
                id::ASSIGNED_CLIENT_IDENTIFIER => {
                    properties.assigned_client_identifier =
                        Some(read_string(property_body, &mut property_cursor)?);
                }
                id::SERVER_KEEP_ALIVE => {
                    properties.server_keep_alive =
                        Some(read_u16(property_body, &mut property_cursor)?);
                }
                id::AUTHENTICATION_METHOD => {
                    properties.authentication_method =
                        Some(read_string(property_body, &mut property_cursor)?);
                }
                id::AUTHENTICATION_DATA => {
                    properties.authentication_data =
                        Some(read_binary(property_body, &mut property_cursor)?);
                }
                id::REQUEST_PROBLEM_INFORMATION => {
                    properties.request_problem_information =
                        Some(read_u8(property_body, &mut property_cursor)?);
                }
                id::WILL_DELAY_INTERVAL => {
                    properties.will_delay_interval =
                        Some(read_u32(property_body, &mut property_cursor)?);
                }
                id::REQUEST_RESPONSE_INFORMATION => {
                    properties.request_response_information =
                        Some(read_u8(property_body, &mut property_cursor)?);
                }
                id::RESPONSE_INFORMATION => {
                    properties.response_information =
                        Some(read_string(property_body, &mut property_cursor)?);
                }
                id::SERVER_REFERENCE => {
                    properties.server_reference =
                        Some(read_string(property_body, &mut property_cursor)?);
                }
                id::REASON_STRING => {
                    properties.reason_string =
                        Some(read_string(property_body, &mut property_cursor)?);
                }
                id::RECEIVE_MAXIMUM => {
                    properties.receive_maximum =
                        Some(read_u16(property_body, &mut property_cursor)?);
                }
                id::TOPIC_ALIAS_MAXIMUM => {
                    properties.topic_alias_maximum =
                        Some(read_u16(property_body, &mut property_cursor)?);
                }
                id::TOPIC_ALIAS => {
                    properties.topic_alias = Some(read_u16(property_body, &mut property_cursor)?);
                }
                id::MAXIMUM_QOS => {
                    properties.maximum_qos = Some(read_u8(property_body, &mut property_cursor)?);
                }
                id::RETAIN_AVAILABLE => {
                    properties.retain_available =
                        Some(read_u8(property_body, &mut property_cursor)?);
                }
                id::USER_PROPERTY => {
                    let key = read_string(property_body, &mut property_cursor)?;
                    let value = read_string(property_body, &mut property_cursor)?;
                    properties.user_properties.push((key, value));
                }
                id::MAXIMUM_PACKET_SIZE => {
                    properties.maximum_packet_size =
                        Some(read_u32(property_body, &mut property_cursor)?);
                }
                id::WILDCARD_SUBSCRIPTION_AVAILABLE => {
                    properties.wildcard_subscription_available =
                        Some(read_u8(property_body, &mut property_cursor)?);
                }
                id::SUBSCRIPTION_IDENTIFIER_AVAILABLE => {
                    properties.subscription_identifier_available =
                        Some(read_u8(property_body, &mut property_cursor)?);
                }
                id::SHARED_SUBSCRIPTION_AVAILABLE => {
                    properties.shared_subscription_available =
                        Some(read_u8(property_body, &mut property_cursor)?);
                }
                other => return Err(Violation::UnknownProperty(other).into()),
            }
        }

        properties.validate_values()?;
        *cursor = end;
        Ok(properties)
    }

    /// Encode this property block, including its Variable Byte Integer length.
    pub(crate) fn encode(&self, output: &mut Vec<u8>) -> Result<(), MqttError> {
        self.validate_values()?;
        let mut body = Vec::new();
        self.encode_values(&mut body)?;
        write_vbi(output, body.len())?;
        output.extend_from_slice(&body);
        Ok(())
    }

    fn validate_values(&self) -> Result<(), MqttError> {
        for (property_id, value) in [
            (id::PAYLOAD_FORMAT_INDICATOR, self.payload_format_indicator),
            (
                id::REQUEST_PROBLEM_INFORMATION,
                self.request_problem_information,
            ),
            (
                id::REQUEST_RESPONSE_INFORMATION,
                self.request_response_information,
            ),
            (id::MAXIMUM_QOS, self.maximum_qos),
            (id::RETAIN_AVAILABLE, self.retain_available),
            (
                id::WILDCARD_SUBSCRIPTION_AVAILABLE,
                self.wildcard_subscription_available,
            ),
            (
                id::SUBSCRIPTION_IDENTIFIER_AVAILABLE,
                self.subscription_identifier_available,
            ),
            (
                id::SHARED_SUBSCRIPTION_AVAILABLE,
                self.shared_subscription_available,
            ),
        ] {
            if value.is_some_and(|value| value > 1) {
                return Err(Violation::MalformedProperty(property_id).into());
            }
        }
        if self.receive_maximum == Some(0) {
            return Err(Violation::MalformedProperty(id::RECEIVE_MAXIMUM).into());
        }
        if self.topic_alias == Some(0) {
            return Err(Violation::MalformedProperty(id::TOPIC_ALIAS).into());
        }
        if self.maximum_packet_size == Some(0) {
            return Err(Violation::MalformedProperty(id::MAXIMUM_PACKET_SIZE).into());
        }
        if self
            .subscription_identifiers
            .iter()
            .any(|&value| value == 0 || value as usize > MAX_VARIABLE_BYTE_INTEGER)
        {
            return Err(Violation::MalformedProperty(id::SUBSCRIPTION_IDENTIFIER).into());
        }
        if self.authentication_data.is_some() && self.authentication_method.is_none() {
            return Err(Violation::MalformedProperty(id::AUTHENTICATION_DATA).into());
        }
        if let Some(response_topic) = &self.response_topic {
            crate::topic::validate_publish_topic(response_topic)?;
        }
        Ok(())
    }

    fn encode_values(&self, body: &mut Vec<u8>) -> Result<(), MqttError> {
        macro_rules! byte_property {
            ($field:ident, $id:expr) => {
                if let Some(value) = self.$field {
                    body.extend_from_slice(&[$id, value]);
                }
            };
        }
        macro_rules! two_byte_property {
            ($field:ident, $id:expr) => {
                if let Some(value) = self.$field {
                    body.push($id);
                    body.extend_from_slice(&value.to_be_bytes());
                }
            };
        }
        macro_rules! four_byte_property {
            ($field:ident, $id:expr) => {
                if let Some(value) = self.$field {
                    body.push($id);
                    body.extend_from_slice(&value.to_be_bytes());
                }
            };
        }
        macro_rules! string_property {
            ($field:ident, $id:expr) => {
                if let Some(value) = &self.$field {
                    body.push($id);
                    write_string(body, value, concat!("property.", stringify!($field)))?;
                }
            };
        }
        macro_rules! binary_property {
            ($field:ident, $id:expr) => {
                if let Some(value) = &self.$field {
                    body.push($id);
                    write_binary(body, value, concat!("property.", stringify!($field)))?;
                }
            };
        }

        byte_property!(payload_format_indicator, id::PAYLOAD_FORMAT_INDICATOR);
        four_byte_property!(message_expiry_interval, id::MESSAGE_EXPIRY_INTERVAL);
        string_property!(content_type, id::CONTENT_TYPE);
        string_property!(response_topic, id::RESPONSE_TOPIC);
        binary_property!(correlation_data, id::CORRELATION_DATA);
        for &value in &self.subscription_identifiers {
            body.push(id::SUBSCRIPTION_IDENTIFIER);
            write_vbi(body, value as usize)?;
        }
        four_byte_property!(session_expiry_interval, id::SESSION_EXPIRY_INTERVAL);
        string_property!(assigned_client_identifier, id::ASSIGNED_CLIENT_IDENTIFIER);
        two_byte_property!(server_keep_alive, id::SERVER_KEEP_ALIVE);
        string_property!(authentication_method, id::AUTHENTICATION_METHOD);
        binary_property!(authentication_data, id::AUTHENTICATION_DATA);
        byte_property!(request_problem_information, id::REQUEST_PROBLEM_INFORMATION);
        four_byte_property!(will_delay_interval, id::WILL_DELAY_INTERVAL);
        byte_property!(
            request_response_information,
            id::REQUEST_RESPONSE_INFORMATION
        );
        string_property!(response_information, id::RESPONSE_INFORMATION);
        string_property!(server_reference, id::SERVER_REFERENCE);
        string_property!(reason_string, id::REASON_STRING);
        two_byte_property!(receive_maximum, id::RECEIVE_MAXIMUM);
        two_byte_property!(topic_alias_maximum, id::TOPIC_ALIAS_MAXIMUM);
        two_byte_property!(topic_alias, id::TOPIC_ALIAS);
        byte_property!(maximum_qos, id::MAXIMUM_QOS);
        byte_property!(retain_available, id::RETAIN_AVAILABLE);
        for (key, value) in &self.user_properties {
            body.push(id::USER_PROPERTY);
            write_string(body, key, "property.user_property.key")?;
            write_string(body, value, "property.user_property.value")?;
        }
        four_byte_property!(maximum_packet_size, id::MAXIMUM_PACKET_SIZE);
        byte_property!(
            wildcard_subscription_available,
            id::WILDCARD_SUBSCRIPTION_AVAILABLE
        );
        byte_property!(
            subscription_identifier_available,
            id::SUBSCRIPTION_IDENTIFIER_AVAILABLE
        );
        byte_property!(
            shared_subscription_available,
            id::SHARED_SUBSCRIPTION_AVAILABLE
        );
        Ok(())
    }
}

#[allow(dead_code)] // Used by the follow-up MQTT 5 packet codec.
pub(crate) fn read_vbi(input: &[u8], cursor: &mut usize) -> Result<usize, MqttError> {
    let mut value = 0usize;
    let mut multiplier = 1usize;
    for byte_index in 0..4 {
        let byte = read_u8(input, cursor)?;
        value += (byte & 0x7F) as usize * multiplier;
        if byte & 0x80 == 0 {
            let minimum = if byte_index == 0 {
                0
            } else {
                1usize << (7 * byte_index)
            };
            if value < minimum {
                return Err(CodecError::MalformedLength.into());
            }
            return Ok(value);
        }
        multiplier *= 128;
    }
    Err(CodecError::MalformedLength.into())
}

#[allow(dead_code)] // Used by the follow-up MQTT 5 packet codec.
pub(crate) fn write_vbi(output: &mut Vec<u8>, mut value: usize) -> Result<(), MqttError> {
    if value > MAX_VARIABLE_BYTE_INTEGER {
        return Err(CodecError::VariableByteIntegerOutOfRange { value }.into());
    }
    loop {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return Ok(());
        }
    }
}

fn read_u8(input: &[u8], cursor: &mut usize) -> Result<u8, MqttError> {
    let value = input
        .get(*cursor)
        .copied()
        .ok_or(CodecError::UnexpectedEof)?;
    *cursor += 1;
    Ok(value)
}

fn read_u16(input: &[u8], cursor: &mut usize) -> Result<u16, MqttError> {
    let bytes = read_array::<2>(input, cursor)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(input: &[u8], cursor: &mut usize) -> Result<u32, MqttError> {
    let bytes = read_array::<4>(input, cursor)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_array<const N: usize>(input: &[u8], cursor: &mut usize) -> Result<[u8; N], MqttError> {
    let end = cursor.checked_add(N).ok_or(CodecError::UnexpectedEof)?;
    let bytes = input.get(*cursor..end).ok_or(CodecError::UnexpectedEof)?;
    *cursor = end;
    Ok(bytes
        .try_into()
        .expect("slice length is fixed by the range"))
}

fn read_string(input: &[u8], cursor: &mut usize) -> Result<Arc<str>, MqttError> {
    let bytes = read_prefixed_bytes(input, cursor)?;
    let value = std::str::from_utf8(bytes).map_err(|_| CodecError::InvalidUtf8)?;
    validate_string(value)?;
    Ok(Arc::from(value))
}

fn read_binary(input: &[u8], cursor: &mut usize) -> Result<Bytes, MqttError> {
    Ok(Bytes::copy_from_slice(read_prefixed_bytes(input, cursor)?))
}

fn read_prefixed_bytes<'a>(input: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], MqttError> {
    let length = read_u16(input, cursor)? as usize;
    let end = cursor
        .checked_add(length)
        .ok_or(CodecError::UnexpectedEof)?;
    let bytes = input.get(*cursor..end).ok_or(CodecError::UnexpectedEof)?;
    *cursor = end;
    Ok(bytes)
}

fn write_string(output: &mut Vec<u8>, value: &str, kind: &'static str) -> Result<(), MqttError> {
    validate_string(value)?;
    write_prefixed_bytes(output, value.as_bytes(), kind)
}

fn write_binary(output: &mut Vec<u8>, value: &[u8], kind: &'static str) -> Result<(), MqttError> {
    write_prefixed_bytes(output, value, kind)
}

fn write_prefixed_bytes(
    output: &mut Vec<u8>,
    value: &[u8],
    kind: &'static str,
) -> Result<(), MqttError> {
    let length = u16::try_from(value.len()).map_err(|_| CodecError::FieldTooLong {
        kind,
        len: value.len(),
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn validate_string(value: &str) -> Result<(), MqttError> {
    if value.contains('\0') {
        return Err(Violation::Utf8NullCharacter.into());
    }
    Ok(())
}

#[cfg(test)]
mod test;
