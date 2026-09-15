//! Packet-body parsers: wire bytes -> `Packet`.


use bytes::Bytes;

use crate::error::{CodecError, MqttError, Violation};
use crate::packet::{
    ConnackPacket, ConnackReturnCode, ConnectFlags, ConnectPacket, FixedHeaderFlags, Packet,
    PacketType, PublishPacket, SubackPacket, SubscribePacket, TopicSubscription,
    UnsubscribePacket, WillPacket,
};
use crate::request::{QoS, SubackCode};

use super::primitives::{read_arc_str, read_bytes, read_u16};

pub(super) fn parse_packet(
    first: u8,
    packet_type: PacketType,
    remaining: usize,
    body: &[u8],
) -> Result<Packet, MqttError> {
    match packet_type {
        PacketType::Connect => parse_connect(body),
        PacketType::Connack => parse_connack(body),
        PacketType::Publish => parse_publish(first, body),
        PacketType::Puback | PacketType::Pubrec | PacketType::Pubrel | PacketType::Pubcomp => {
            parse_ack_packet(first, packet_type, remaining, body)
        }
        PacketType::Subscribe => parse_subscribe(body),
        PacketType::Suback => parse_suback(body),
        PacketType::Unsubscribe => parse_unsubscribe(body),
        PacketType::Unsuback => parse_unsuback(remaining, body),
        PacketType::Pingreq => {
            require_empty_body(remaining)?;
            Ok(Packet::Pingreq)
        }
        PacketType::Pingresp => {
            require_empty_body(remaining)?;
            Ok(Packet::Pingresp)
        }
        PacketType::Disconnect => {
            require_empty_body(remaining)?;
            Ok(Packet::Disconnect)
        }
    }
}

pub(super) fn require_empty_body(remaining: usize) -> Result<(), MqttError> {
    if remaining != 0 {
        return Err(CodecError::PayloadTooLong {
            len: remaining,
            max: 0,
        }
        .into());
    }
    Ok(())
}

pub(super) fn parse_connect(body: &[u8]) -> Result<Packet, MqttError> {
    if body.len() < 10 {
        return Err(CodecError::UnexpectedEof.into());
    }
    // Protocol name + level + flags + keep_alive
    let proto_name_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if proto_name_len != 4 || &body[2..6] != b"MQTT" {
        return Err(Violation::InvalidProtocolName.into());
    }
    let level = body[6];
    if level != 0x04 {
        return Err(Violation::UnsupportedProtocolLevel(level).into());
    }
    let flags_byte = body[7];
    let connect_flags = ConnectFlags::from_bits_truncate(flags_byte);
    let keep_alive = u16::from_be_bytes([body[8], body[9]]);

    let mut cursor = 10usize;
    let client_id = read_arc_str(body, &mut cursor)?;

    let will = if connect_flags.contains(ConnectFlags::WillFlag) {
        let topic = read_arc_str(body, &mut cursor)?;
        let payload = read_bytes(body, &mut cursor)?;
        let will_qos_bits = (flags_byte & ConnectFlags::WillQoSMask.bits()) >> 3;
        let qos = QoS::from_u8(will_qos_bits).ok_or(CodecError::QosInvalid(will_qos_bits))?;
        let retain = connect_flags.contains(ConnectFlags::WillRetain);
        Some(WillPacket {
            topic,
            payload,
            qos,
            retain,
        })
    } else {
        None
    };

    let username = if connect_flags.contains(ConnectFlags::Username) {
        Some(read_arc_str(body, &mut cursor)?)
    } else {
        None
    };

    let password = if connect_flags.contains(ConnectFlags::Password) {
        Some(read_bytes(body, &mut cursor)?)
    } else {
        None
    };

    Ok(Packet::Connect(ConnectPacket {
        client_id,
        clean_session: connect_flags.contains(ConnectFlags::CleanSession),
        keep_alive,
        username,
        password,
        will,
    }))
}

pub(super) fn parse_connack(body: &[u8]) -> Result<Packet, MqttError> {
    if body.len() < 2 {
        return Err(CodecError::UnexpectedEof.into());
    }
    let session_present = (body[0] & 0x01) != 0;
    let return_code = ConnackReturnCode::try_from(body[1])
        .map_err(|_| MqttError::Codec(CodecError::InvalidPacketType(body[1])))?;
    Ok(Packet::Connack(ConnackPacket {
        session_present,
        return_code,
    }))
}

pub(super) fn parse_publish(first: u8, body: &[u8]) -> Result<Packet, MqttError> {
    if body.len() < 2 {
        return Err(CodecError::UnexpectedEof.into());
    }
    let raw_flags = first & 0x0F;
    let header_flags = FixedHeaderFlags::from_bits(raw_flags)
        .ok_or(CodecError::ReservedFlagSet)?;
    let dup = header_flags.contains(FixedHeaderFlags::Dup);
    let retain = header_flags.contains(FixedHeaderFlags::Retain);
    let qos_bits = (header_flags.bits() & FixedHeaderFlags::QoS.bits()) >> 1;
    let qos = QoS::from_u8(qos_bits).ok_or(CodecError::QosInvalid(qos_bits))?;

    let mut cursor = 0usize;
    let topic = read_arc_str(body, &mut cursor)?;

    let packet_id = if qos != QoS::AtMostOnce {
        Some(read_u16(body, &mut cursor)?)
    } else {
        None
    };

    // Payload is the remainder. Move into Bytes (O(1) from Vec<u8>).
    let payload = Bytes::from(body[cursor..].to_vec());

    Ok(Packet::Publish(PublishPacket {
        topic,
        payload,
        dup,
        qos,
        retain,
        packet_id,
    }))
}

pub(super) fn parse_ack_packet(
    first: u8,
    packet_type: PacketType,
    remaining: usize,
    body: &[u8],
) -> Result<Packet, MqttError> {
    if remaining != 2 {
        return Err(CodecError::PayloadTooLong {
            len: remaining,
            max: 2,
        }
        .into());
    }
    let flags = first & 0x0F;
    let expected = if packet_type == PacketType::Pubrel { 0x02 } else { 0x00 };
    if flags != expected {
        return Err(CodecError::ReservedFlagSet.into());
    }
    let id = u16::from_be_bytes([body[0], body[1]]);
    Ok(match packet_type {
        PacketType::Puback => Packet::Puback(id),
        PacketType::Pubrec => Packet::Pubrec(id),
        PacketType::Pubrel => Packet::Pubrel(id),
        _ => Packet::Pubcomp(id),
    })
}

pub(super) fn parse_subscribe(body: &[u8]) -> Result<Packet, MqttError> {
    if body.len() < 5 {
        return Err(CodecError::UnexpectedEof.into());
    }
    let mut cursor = 0usize;
    let packet_id = read_u16(body, &mut cursor)?;
    let mut subscriptions = Vec::new();
    while cursor < body.len() {
        let topic = read_arc_str(body, &mut cursor)?;
        if cursor >= body.len() {
            return Err(CodecError::UnexpectedEof.into());
        }
        let qos_bits = body[cursor];
        cursor += 1;
        let qos = QoS::from_u8(qos_bits).ok_or(CodecError::QosInvalid(qos_bits))?;
        subscriptions.push(TopicSubscription { topic, qos });
    }
    Ok(Packet::Subscribe(SubscribePacket {
        packet_id,
        subscriptions,
    }))
}

pub(super) fn parse_suback(body: &[u8]) -> Result<Packet, MqttError> {
    if body.len() < 3 {
        return Err(CodecError::UnexpectedEof.into());
    }
    let packet_id = u16::from_be_bytes([body[0], body[1]]);
    let return_codes = body[2..]
        .iter()
        .map(|&b| SubackCode::from_u8(b).ok_or(CodecError::InvalidPacketType(b)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Packet::Suback(SubackPacket {
        packet_id,
        return_codes,
    }))
}

pub(super) fn parse_unsubscribe(body: &[u8]) -> Result<Packet, MqttError> {
    if body.len() < 4 {
        return Err(CodecError::UnexpectedEof.into());
    }
    let mut cursor = 0usize;
    let packet_id = read_u16(body, &mut cursor)?;
    let mut topics = Vec::new();
    while cursor < body.len() {
        topics.push(read_arc_str(body, &mut cursor)?);
    }
    Ok(Packet::Unsubscribe(UnsubscribePacket {
        packet_id,
        topics,
    }))
}

pub(super) fn parse_unsuback(remaining: usize, body: &[u8]) -> Result<Packet, MqttError> {
    if remaining != 2 {
        return Err(CodecError::PayloadTooLong {
            len: remaining,
            max: 2,
        }
        .into());
    }
    Ok(Packet::Unsuback(u16::from_be_bytes([body[0], body[1]])))
}
