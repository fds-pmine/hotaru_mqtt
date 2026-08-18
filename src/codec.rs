//! Version-aware MQTT 3.1.1 and MQTT 5 wire codec.
//!
//! Decode path constructs `Arc<str>` (topic / client_id) and `Bytes`
//! (payload / password) directly from read buffers — no `String::from_utf8`
//! copies, just `Arc::from(String)` and `Bytes::from(Vec<u8>)` (both O(1)).
//!
//! Encode path writes through `write_all(&payload[..])` — `Bytes` derefs to
//! `&[u8]` with zero overhead.

use std::error::Error;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use hotaru_core::protocol::Message;

use crate::error::{CodecError, MqttError, Violation};
use crate::packet::{
    ConnackPacket, ConnackReturnCode, ConnectFlags, ConnectPacket, FixedHeaderFlags, Packet,
    PacketType, ProtocolVersion, PublishPacket, SubackPacket, SubscribePacket, TopicSubscription,
    UnsubscribePacket, WillPacket,
};
use crate::properties::Properties;
use crate::request::{QoS, SubackCode};

// ============================================================================
// Public encode/decode API
// ============================================================================

/// Read one complete MQTT packet from the async reader. Used by handle_*
/// loops that own the reader directly (single-take pattern).
pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    version: ProtocolVersion,
) -> Result<Packet, MqttError> {
    let mut header_byte = [0u8; 1];
    reader.read_exact(&mut header_byte).await?;
    let first = header_byte[0];

    let raw_type = first >> 4;
    let packet_type =
        PacketType::try_from(raw_type).map_err(|_| CodecError::InvalidPacketType(raw_type))?;

    let remaining = read_remaining_length(reader).await?;
    let mut body = vec![0u8; remaining];
    reader.read_exact(&mut body).await?;

    parse_packet(first, packet_type, remaining, &body, version)
}

/// Try to decode one MQTT packet from a buffer. Returns `Ok(None)` if more
/// bytes are needed. On success consumes the packet bytes from the buffer.
pub fn decode_packet_from_bytes(
    buf: &mut BytesMut,
    version: ProtocolVersion,
) -> Result<Option<Packet>, Box<dyn Error + Send + Sync>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let first = buf[0];
    let raw_type = first >> 4;
    let packet_type = PacketType::try_from(raw_type)
        .map_err(|_| MqttError::Codec(CodecError::InvalidPacketType(raw_type)))?;

    let (remaining, rl_bytes) = match decode_remaining_length_from_slice(&buf[1..])? {
        Some(v) => v,
        None => return Ok(None),
    };

    let header_len = 1 + rl_bytes;
    let total = header_len + remaining;
    if buf.len() < total {
        return Ok(None);
    }

    let packet_bytes = buf.split_to(total);
    let body = &packet_bytes[header_len..];
    let packet = parse_packet(first, packet_type, remaining, body, version)
        .map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })?;
    Ok(Some(packet))
}

/// Encode any packet into a fresh `Vec<u8>`. Convenience for tests and the
/// `Message::encode` trait impl. Hot paths use `write_packet` /
/// `write_publish_packet` directly to avoid the intermediate Vec.
pub fn encode_packet(packet: &Packet, version: ProtocolVersion) -> Result<Vec<u8>, MqttError> {
    match packet {
        // CONNECT carries its own version and establishes the connection version.
        Packet::Connect(c) => encode_connect(c),
        Packet::Connack(c) => encode_connack(c, version),
        Packet::Publish(p) => encode_publish(p, version),
        Packet::Puback(id) => Ok(vec![0x40, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8]),
        Packet::Pubrec(id) => Ok(vec![0x50, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8]),
        Packet::Pubrel(id) => Ok(vec![0x62, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8]),
        Packet::Pubcomp(id) => Ok(vec![0x70, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8]),
        Packet::Subscribe(s) => encode_subscribe(s, version),
        Packet::Suback(s) => encode_suback(s, version),
        Packet::Unsubscribe(u) => encode_unsubscribe(u, version),
        Packet::Unsuback(id) => Ok(vec![0xB0, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8]),
        Packet::Pingreq => Ok(vec![0xC0, 0x00]),
        Packet::Pingresp => Ok(vec![0xD0, 0x00]),
        Packet::Disconnect => Ok(vec![0xE0, 0x00]),
    }
}

/// Write a packet to an async writer. Used by the writer actor for control
/// packets.
pub async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &Packet,
    version: ProtocolVersion,
) -> Result<(), MqttError> {
    let buf = encode_packet(packet, version)?;
    writer.write_all(&buf).await?;
    Ok(())
}

/// Optimized write path for PUBLISH: writes the header in one syscall, then
/// the payload `Bytes` directly with `write_all(&payload[..])` — no copy
/// from `Bytes` to intermediate buffer.
pub async fn write_publish_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &PublishPacket,
    version: ProtocolVersion,
) -> Result<(), MqttError> {
    // Build header + variable header into a small buffer; payload streamed
    // separately from the Bytes directly.
    let topic_bytes = packet.topic.as_bytes();
    let mut var_header_len = 2 + topic_bytes.len();
    if packet.qos != QoS::AtMostOnce {
        var_header_len += 2;
    }
    let mut properties = Vec::new();
    if version == ProtocolVersion::V5 {
        packet.properties.encode(&mut properties)?;
        var_header_len += properties.len();
    }
    let body_len = var_header_len + packet.payload.len();

    let mut header = Vec::with_capacity(1 + 4 + var_header_len);
    let flags = pack_publish_flags(packet);
    header.push(((PacketType::Publish as u8) << 4) | flags);
    header.extend(encode_remaining_length(body_len));
    header.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
    header.extend_from_slice(topic_bytes);
    if packet.qos != QoS::AtMostOnce {
        let id = packet
            .packet_id
            .ok_or_else(|| MqttError::Codec(CodecError::PayloadTooLong { len: 0, max: 0 }))?;
        header.extend_from_slice(&id.to_be_bytes());
    }
    header.extend_from_slice(&properties);

    writer.write_all(&header).await?;
    writer.write_all(&packet.payload[..]).await?;
    Ok(())
}

// ============================================================================
// Internal: remaining length
// ============================================================================

async fn read_remaining_length<R: AsyncRead + Unpin>(reader: &mut R) -> Result<usize, MqttError> {
    let mut result = 0usize;
    let mut multiplier = 1usize;
    for i in 0..4 {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await?;
        result += (byte[0] & 0x7F) as usize * multiplier;
        multiplier *= 128;
        if byte[0] & 0x80 == 0 {
            return Ok(result);
        }
        if i == 3 {
            return Err(CodecError::MalformedLength.into());
        }
    }
    unreachable!()
}

fn decode_remaining_length_from_slice(
    data: &[u8],
) -> Result<Option<(usize, usize)>, MqttError> {
    let mut result = 0usize;
    let mut multiplier = 1usize;
    for (i, &byte) in data.iter().enumerate() {
        result += (byte & 0x7F) as usize * multiplier;
        multiplier *= 128;
        if byte & 0x80 == 0 {
            return Ok(Some((result, i + 1)));
        }
        if i >= 3 {
            return Err(CodecError::MalformedLength.into());
        }
    }
    Ok(None)
}

fn encode_remaining_length(mut value: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
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
    out
}

// ============================================================================
// Internal: packet parsers (decode body → Packet)
// ============================================================================

fn parse_packet(
    first: u8,
    packet_type: PacketType,
    remaining: usize,
    body: &[u8],
    version: ProtocolVersion,
) -> Result<Packet, MqttError> {
    match packet_type {
        PacketType::Connect => parse_connect(body),
        PacketType::Connack => parse_connack(body, version),
        PacketType::Publish => parse_publish(first, body, version),
        PacketType::Puback | PacketType::Pubrec | PacketType::Pubrel | PacketType::Pubcomp => {
            parse_ack_packet(first, packet_type, remaining, body, version)
        }
        PacketType::Subscribe => parse_subscribe(body, version),
        PacketType::Suback => parse_suback(body, version),
        PacketType::Unsubscribe => parse_unsubscribe(body, version),
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
            if version == ProtocolVersion::V311 {
                require_empty_body(remaining)?;
            } else if !body.is_empty() {
                let mut cursor = 1;
                if body.len() > 1 {
                    let _ = Properties::parse(body, &mut cursor)?;
                }
                if cursor != body.len() {
                    return Err(CodecError::PayloadTooLong {
                        len: body.len() - cursor,
                        max: 0,
                    }
                    .into());
                }
            }
            Ok(Packet::Disconnect)
        }
    }
}

fn require_empty_body(remaining: usize) -> Result<(), MqttError> {
    if remaining != 0 {
        return Err(CodecError::PayloadTooLong {
            len: remaining,
            max: 0,
        }
        .into());
    }
    Ok(())
}

fn parse_connect(body: &[u8]) -> Result<Packet, MqttError> {
    if body.len() < 10 {
        return Err(CodecError::UnexpectedEof.into());
    }
    // Protocol name + level + flags + keep_alive
    let proto_name_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if proto_name_len != 4 || &body[2..6] != b"MQTT" {
        return Err(Violation::InvalidProtocolName.into());
    }
    let level = body[6];
    let version =
        ProtocolVersion::from_level(level).ok_or(Violation::UnsupportedProtocolLevel(level))?;
    let flags_byte = body[7];
    let connect_flags = ConnectFlags::from_bits_truncate(flags_byte);
    let keep_alive = u16::from_be_bytes([body[8], body[9]]);

    let mut cursor = 10usize;
    let properties = if version == ProtocolVersion::V5 {
        Properties::parse(body, &mut cursor)?
    } else {
        Properties::default()
    };
    let client_id = read_arc_str(body, &mut cursor)?;

    let will = if connect_flags.contains(ConnectFlags::WillFlag) {
        let properties = if version == ProtocolVersion::V5 {
            Properties::parse(body, &mut cursor)?
        } else {
            Properties::default()
        };
        let topic = read_arc_str(body, &mut cursor)?;
        let payload = read_bytes(body, &mut cursor)?;
        let will_qos_bits = (flags_byte & ConnectFlags::WillQoSMask.bits()) >> 3;
        let qos = QoS::from_u8(will_qos_bits).ok_or(CodecError::QosInvalid(will_qos_bits))?;
        let retain = connect_flags.contains(ConnectFlags::WillRetain);
        Some(WillPacket {
            properties,
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

    Ok(Packet::Connect(Box::new(ConnectPacket {
        version,
        properties,
        client_id,
        clean_session: connect_flags.contains(ConnectFlags::CleanSession),
        keep_alive,
        username,
        password,
        will,
    })))
}

fn parse_connack(body: &[u8], version: ProtocolVersion) -> Result<Packet, MqttError> {
    if body.len() < 2 {
        return Err(CodecError::UnexpectedEof.into());
    }
    let session_present = (body[0] & 0x01) != 0;
    let return_code = match version {
        ProtocolVersion::V311 => ConnackReturnCode::try_from(body[1]),
        ProtocolVersion::V5 => ConnackReturnCode::from_v5_reason(body[1]).ok_or(()),
    }
    .map_err(|_| MqttError::Codec(CodecError::InvalidPacketType(body[1])))?;
    let mut cursor = 2;
    let properties = if version == ProtocolVersion::V5 {
        Properties::parse(body, &mut cursor)?
    } else {
        Properties::default()
    };
    if cursor != body.len() {
        return Err(CodecError::PayloadTooLong {
            len: body.len() - cursor,
            max: 0,
        }
        .into());
    }
    Ok(Packet::Connack(ConnackPacket {
        properties,
        session_present,
        return_code,
    }))
}

fn parse_publish(first: u8, body: &[u8], version: ProtocolVersion) -> Result<Packet, MqttError> {
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
    let properties = if version == ProtocolVersion::V5 {
        Properties::parse(body, &mut cursor)?
    } else {
        Properties::default()
    };

    // Payload is the remainder. Move into Bytes (O(1) from Vec<u8>).
    let payload = Bytes::from(body[cursor..].to_vec());

    Ok(Packet::Publish(PublishPacket {
        properties,
        topic,
        payload,
        dup,
        qos,
        retain,
        packet_id,
    }))
}

fn parse_ack_packet(
    first: u8,
    packet_type: PacketType,
    remaining: usize,
    body: &[u8],
    version: ProtocolVersion,
) -> Result<Packet, MqttError> {
    if remaining < 2 || (version == ProtocolVersion::V311 && remaining != 2) {
        return Err(CodecError::PayloadTooLong {
            len: remaining,
            max: if version == ProtocolVersion::V311 {
                2
            } else {
                usize::MAX
            },
        }
        .into());
    }
    let flags = first & 0x0F;
    let expected = if packet_type == PacketType::Pubrel { 0x02 } else { 0x00 };
    if flags != expected {
        return Err(CodecError::ReservedFlagSet.into());
    }
    let id = u16::from_be_bytes([body[0], body[1]]);
    if version == ProtocolVersion::V5 && remaining > 2 {
        let mut cursor = 3;
        if remaining > 3 {
            let _ = Properties::parse(body, &mut cursor)?;
        }
        if cursor != body.len() {
            return Err(CodecError::PayloadTooLong {
                len: body.len() - cursor,
                max: 0,
            }
            .into());
        }
    }
    Ok(match packet_type {
        PacketType::Puback => Packet::Puback(id),
        PacketType::Pubrec => Packet::Pubrec(id),
        PacketType::Pubrel => Packet::Pubrel(id),
        _ => Packet::Pubcomp(id),
    })
}

fn parse_subscribe(body: &[u8], version: ProtocolVersion) -> Result<Packet, MqttError> {
    if body.len() < 5 {
        return Err(CodecError::UnexpectedEof.into());
    }
    let mut cursor = 0usize;
    let packet_id = read_u16(body, &mut cursor)?;
    if version == ProtocolVersion::V5 {
        let _ = Properties::parse(body, &mut cursor)?;
    }
    let mut subscriptions = Vec::new();
    while cursor < body.len() {
        let topic = read_arc_str(body, &mut cursor)?;
        if cursor >= body.len() {
            return Err(CodecError::UnexpectedEof.into());
        }
        let options = body[cursor];
        cursor += 1;
        if (version == ProtocolVersion::V311 && options > 2)
            || (version == ProtocolVersion::V5
                && (options & 0xC0 != 0 || (options >> 4) & 0x03 == 0x03))
        {
            return Err(CodecError::ReservedFlagSet.into());
        }
        let qos_bits = options & 0x03;
        let qos = QoS::from_u8(qos_bits).ok_or(CodecError::QosInvalid(qos_bits))?;
        subscriptions.push(TopicSubscription { topic, qos });
    }
    Ok(Packet::Subscribe(SubscribePacket {
        packet_id,
        subscriptions,
    }))
}

fn parse_suback(body: &[u8], version: ProtocolVersion) -> Result<Packet, MqttError> {
    if body.len() < 3 {
        return Err(CodecError::UnexpectedEof.into());
    }
    let mut cursor = 0;
    let packet_id = read_u16(body, &mut cursor)?;
    if version == ProtocolVersion::V5 {
        let _ = Properties::parse(body, &mut cursor)?;
    }
    let return_codes = body[cursor..]
        .iter()
        .map(|&b| match SubackCode::from_u8(b) {
            Some(code) => Ok(code),
            None if version == ProtocolVersion::V5 && b >= 0x80 => Ok(SubackCode::Failure),
            None => Err(CodecError::InvalidPacketType(b)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Packet::Suback(SubackPacket {
        packet_id,
        return_codes,
    }))
}

fn parse_unsubscribe(body: &[u8], version: ProtocolVersion) -> Result<Packet, MqttError> {
    if body.len() < 4 {
        return Err(CodecError::UnexpectedEof.into());
    }
    let mut cursor = 0usize;
    let packet_id = read_u16(body, &mut cursor)?;
    if version == ProtocolVersion::V5 {
        let _ = Properties::parse(body, &mut cursor)?;
    }
    let mut topics = Vec::new();
    while cursor < body.len() {
        topics.push(read_arc_str(body, &mut cursor)?);
    }
    Ok(Packet::Unsubscribe(UnsubscribePacket {
        packet_id,
        topics,
    }))
}

fn parse_unsuback(remaining: usize, body: &[u8]) -> Result<Packet, MqttError> {
    if remaining != 2 {
        return Err(CodecError::PayloadTooLong {
            len: remaining,
            max: 2,
        }
        .into());
    }
    Ok(Packet::Unsuback(u16::from_be_bytes([body[0], body[1]])))
}

// ============================================================================
// Internal: packet encoders (Packet → Vec<u8>)
// ============================================================================

fn encode_connect(conn: &ConnectPacket) -> Result<Vec<u8>, MqttError> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T']);
    body.push(conn.version.level());
    let mut flags = 0u8;
    if conn.clean_session {
        flags |= ConnectFlags::CleanSession.bits();
    }
    if let Some(will) = &conn.will {
        flags |= ConnectFlags::WillFlag.bits();
        flags |= (will.qos.as_u8() << 3) & ConnectFlags::WillQoSMask.bits();
        if will.retain {
            flags |= ConnectFlags::WillRetain.bits();
        }
    }
    if conn.username.is_some() {
        flags |= ConnectFlags::Username.bits();
    }
    if conn.password.is_some() {
        flags |= ConnectFlags::Password.bits();
    }
    body.push(flags);
    body.extend_from_slice(&conn.keep_alive.to_be_bytes());
    if conn.version == ProtocolVersion::V5 {
        conn.properties.encode(&mut body)?;
    }
    write_arc_str(&mut body, &conn.client_id);
    if let Some(will) = &conn.will {
        if conn.version == ProtocolVersion::V5 {
            will.properties.encode(&mut body)?;
        }
        write_arc_str(&mut body, &will.topic);
        write_bytes(&mut body, &will.payload);
    }
    if let Some(username) = &conn.username {
        write_arc_str(&mut body, username);
    }
    if let Some(password) = &conn.password {
        write_bytes(&mut body, password);
    }
    let mut buf = vec![(PacketType::Connect as u8) << 4];
    buf.extend(encode_remaining_length(body.len()));
    buf.extend(body);
    Ok(buf)
}

fn encode_connack(ack: &ConnackPacket, version: ProtocolVersion) -> Result<Vec<u8>, MqttError> {
    if version == ProtocolVersion::V311 {
        return Ok(vec![
            (PacketType::Connack as u8) << 4,
            0x02,
            if ack.session_present { 0x01 } else { 0x00 },
            ack.return_code.as_u8(),
        ]);
    }

    let mut body = vec![
        if ack.session_present { 0x01 } else { 0x00 },
        ack.return_code.to_v5_reason(),
    ];
    ack.properties.encode(&mut body)?;
    let mut packet = vec![(PacketType::Connack as u8) << 4];
    packet.extend(encode_remaining_length(body.len()));
    packet.extend(body);
    Ok(packet)
}

fn encode_publish(p: &PublishPacket, version: ProtocolVersion) -> Result<Vec<u8>, MqttError> {
    let topic_bytes = p.topic.as_bytes();
    let mut body = Vec::with_capacity(2 + topic_bytes.len() + 2 + p.payload.len());
    body.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(topic_bytes);
    if p.qos != QoS::AtMostOnce
        && let Some(id) = p.packet_id
    {
        body.extend_from_slice(&id.to_be_bytes());
    }
    if version == ProtocolVersion::V5 {
        p.properties.encode(&mut body)?;
    }
    body.extend_from_slice(&p.payload[..]);

    let flags = pack_publish_flags(p);
    let mut buf = vec![((PacketType::Publish as u8) << 4) | flags];
    buf.extend(encode_remaining_length(body.len()));
    buf.extend(body);
    Ok(buf)
}

fn encode_subscribe(s: &SubscribePacket, version: ProtocolVersion) -> Result<Vec<u8>, MqttError> {
    let mut body = Vec::new();
    body.extend_from_slice(&s.packet_id.to_be_bytes());
    if version == ProtocolVersion::V5 {
        Properties::default().encode(&mut body)?;
    }
    for sub in &s.subscriptions {
        write_arc_str(&mut body, &sub.topic);
        body.push(sub.qos.as_u8());
    }
    let mut buf = vec![((PacketType::Subscribe as u8) << 4) | 0x02];
    buf.extend(encode_remaining_length(body.len()));
    buf.extend(body);
    Ok(buf)
}

fn encode_suback(s: &SubackPacket, version: ProtocolVersion) -> Result<Vec<u8>, MqttError> {
    let mut body = Vec::with_capacity(2 + s.return_codes.len());
    body.extend_from_slice(&s.packet_id.to_be_bytes());
    if version == ProtocolVersion::V5 {
        Properties::default().encode(&mut body)?;
    }
    for code in &s.return_codes {
        body.push(code.as_u8());
    }
    let mut buf = vec![(PacketType::Suback as u8) << 4];
    buf.extend(encode_remaining_length(body.len()));
    buf.extend(body);
    Ok(buf)
}

fn encode_unsubscribe(
    u: &UnsubscribePacket,
    version: ProtocolVersion,
) -> Result<Vec<u8>, MqttError> {
    let mut body = Vec::new();
    body.extend_from_slice(&u.packet_id.to_be_bytes());
    if version == ProtocolVersion::V5 {
        Properties::default().encode(&mut body)?;
    }
    for topic in &u.topics {
        write_arc_str(&mut body, topic);
    }
    let mut buf = vec![((PacketType::Unsubscribe as u8) << 4) | 0x02];
    buf.extend(encode_remaining_length(body.len()));
    buf.extend(body);
    Ok(buf)
}

fn pack_publish_flags(p: &PublishPacket) -> u8 {
    let mut flags = 0u8;
    if p.dup {
        flags |= FixedHeaderFlags::Dup.bits();
    }
    if p.retain {
        flags |= FixedHeaderFlags::Retain.bits();
    }
    flags |= (p.qos.as_u8() << 1) & FixedHeaderFlags::QoS.bits();
    flags
}

// ============================================================================
// Helpers: read/write length-prefixed strings / bytes
// ============================================================================

fn read_u16(body: &[u8], cursor: &mut usize) -> Result<u16, MqttError> {
    if *cursor + 2 > body.len() {
        return Err(CodecError::UnexpectedEof.into());
    }
    let v = u16::from_be_bytes([body[*cursor], body[*cursor + 1]]);
    *cursor += 2;
    Ok(v)
}

fn read_arc_str(body: &[u8], cursor: &mut usize) -> Result<Arc<str>, MqttError> {
    let len = read_u16(body, cursor)? as usize;
    if *cursor + len > body.len() {
        return Err(CodecError::UnexpectedEof.into());
    }
    let bytes = &body[*cursor..*cursor + len];
    let s = std::str::from_utf8(bytes).map_err(|_| CodecError::InvalidUtf8)?;
    let result: Arc<str> = Arc::from(s);
    *cursor += len;
    Ok(result)
}

fn read_bytes(body: &[u8], cursor: &mut usize) -> Result<Bytes, MqttError> {
    let len = read_u16(body, cursor)? as usize;
    if *cursor + len > body.len() {
        return Err(CodecError::UnexpectedEof.into());
    }
    let v = body[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(Bytes::from(v))
}

fn write_arc_str(out: &mut Vec<u8>, s: &Arc<str>) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
}

fn write_bytes(out: &mut Vec<u8>, b: &Bytes) {
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(&b[..]);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_v311(packet: &Packet) -> Vec<u8> {
        encode_packet(packet, ProtocolVersion::V311).unwrap()
    }

    fn decode_v311(buf: &mut BytesMut) -> Result<Option<Packet>, Box<dyn Error + Send + Sync>> {
        decode_packet_from_bytes(buf, ProtocolVersion::V311)
    }

    #[test]
    fn encode_decode_connect_round_trip() {
        let original = ConnectPacket {
            version: ProtocolVersion::V311,
            properties: Default::default(),
            client_id: Arc::from("cid"),
            clean_session: true,
            keep_alive: 60,
            username: None,
            password: None,
            will: None,
        };
        let bytes = encode_v311(&Packet::Connect(Box::new(original.clone())));
        let mut buf = BytesMut::from(&bytes[..]);
        match decode_v311(&mut buf).unwrap().unwrap() {
            Packet::Connect(c) => {
                assert_eq!(c.client_id.as_ref(), "cid");
                assert!(c.clean_session);
                assert_eq!(c.keep_alive, 60);
                assert!(c.will.is_none());
            }
            _ => panic!("expected Connect"),
        }
    }

    #[test]
    fn encode_decode_connect_with_will() {
        let original = ConnectPacket {
            version: ProtocolVersion::V311,
            properties: Default::default(),
            client_id: Arc::from("cid"),
            clean_session: false,
            keep_alive: 30,
            username: Some(Arc::from("alice")),
            password: Some(Bytes::from_static(b"secret")),
            will: Some(WillPacket {
                properties: Default::default(),
                topic: Arc::from("offline"),
                payload: Bytes::from_static(b"bye"),
                qos: QoS::AtLeastOnce,
                retain: true,
            }),
        };
        let bytes = encode_v311(&Packet::Connect(Box::new(original)));
        let mut buf = BytesMut::from(&bytes[..]);
        match decode_v311(&mut buf).unwrap().unwrap() {
            Packet::Connect(c) => {
                assert_eq!(c.username.as_ref().unwrap().as_ref(), "alice");
                let p = c.password.as_ref().unwrap();
                assert_eq!(&p[..], b"secret");
                let w = c.will.unwrap();
                assert_eq!(w.topic.as_ref(), "offline");
                assert_eq!(&w.payload[..], b"bye");
                assert_eq!(w.qos, QoS::AtLeastOnce);
                assert!(w.retain);
            }
            _ => panic!("expected Connect"),
        }
    }

    #[test]
    fn encode_decode_publish_qos0() {
        let p = PublishPacket {
            properties: Default::default(),
            topic: Arc::from("sensors/temp"),
            payload: Bytes::from_static(b"42"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        };
        let bytes = encode_v311(&Packet::Publish(p));
        let mut buf = BytesMut::from(&bytes[..]);
        match decode_v311(&mut buf).unwrap().unwrap() {
            Packet::Publish(p) => {
                assert_eq!(p.topic.as_ref(), "sensors/temp");
                assert_eq!(&p.payload[..], b"42");
                assert_eq!(p.qos, QoS::AtMostOnce);
                assert!(p.packet_id.is_none());
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn encode_decode_publish_qos1() {
        let p = PublishPacket {
            properties: Default::default(),
            topic: Arc::from("a/b"),
            payload: Bytes::from_static(b"x"),
            dup: false,
            qos: QoS::AtLeastOnce,
            retain: false,
            packet_id: Some(42),
        };
        let bytes = encode_v311(&Packet::Publish(p));
        let mut buf = BytesMut::from(&bytes[..]);
        match decode_v311(&mut buf).unwrap().unwrap() {
            Packet::Publish(p) => {
                assert_eq!(p.qos, QoS::AtLeastOnce);
                assert_eq!(p.packet_id, Some(42));
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn encode_decode_subscribe_unsubscribe() {
        let s = SubscribePacket {
            packet_id: 7,
            subscriptions: vec![
                TopicSubscription {
                    topic: Arc::from("a/+"),
                    qos: QoS::AtLeastOnce,
                },
                TopicSubscription {
                    topic: Arc::from("b/#"),
                    qos: QoS::ExactlyOnce,
                },
            ],
        };
        let bytes = encode_v311(&Packet::Subscribe(s));
        let mut buf = BytesMut::from(&bytes[..]);
        match decode_v311(&mut buf).unwrap().unwrap() {
            Packet::Subscribe(s) => {
                assert_eq!(s.packet_id, 7);
                assert_eq!(s.subscriptions.len(), 2);
                assert_eq!(s.subscriptions[0].topic.as_ref(), "a/+");
                assert_eq!(s.subscriptions[1].qos, QoS::ExactlyOnce);
            }
            _ => panic!("expected Subscribe"),
        }

        let u = UnsubscribePacket {
            packet_id: 8,
            topics: vec![Arc::from("a/+"), Arc::from("b/#")],
        };
        let bytes = encode_v311(&Packet::Unsubscribe(u));
        let mut buf = BytesMut::from(&bytes[..]);
        match decode_v311(&mut buf).unwrap().unwrap() {
            Packet::Unsubscribe(u) => {
                assert_eq!(u.packet_id, 8);
                assert_eq!(u.topics.len(), 2);
            }
            _ => panic!("expected Unsubscribe"),
        }
    }

    #[test]
    fn pingreq_pingresp_disconnect_unsuback() {
        assert_eq!(encode_v311(&Packet::Pingreq), vec![0xC0, 0x00]);
        assert_eq!(encode_v311(&Packet::Pingresp), vec![0xD0, 0x00]);
        assert_eq!(encode_v311(&Packet::Disconnect), vec![0xE0, 0x00]);
        assert_eq!(
            encode_v311(&Packet::Unsuback(42)),
            vec![0xB0, 0x02, 0x00, 0x2A]
        );
    }

    #[test]
    fn partial_buffer_returns_none() {
        let mut buf = BytesMut::from(&[0x10u8][..]);
        assert!(decode_v311(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 1, "buffer must not be consumed on partial");
    }
}

// ----------------------------------------------------------------------------
// Message impl — connects Packet to hotaru_core's protocol Message trait
//
// Lives here rather than in `packet` so the data definitions stay free of any
// dependency on the codec: `codec -> packet` is the intended direction.
// ----------------------------------------------------------------------------

impl Message for Packet {
    type BytesMut = BytesMut;

    fn encode(&self, buf: &mut Self::BytesMut) -> Result<(), Box<dyn Error + Send + Sync>> {
        let version = match self {
            Packet::Connect(connect) => connect.version,
            _ => ProtocolVersion::default(),
        };
        buf.extend_from_slice(&encode_packet(self, version)?);
        Ok(())
    }

    fn decode(buf: &mut Self::BytesMut) -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        decode_packet_from_bytes(buf, ProtocolVersion::default())
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn protocol_version_defaults_to_v311() {
        assert_eq!(ProtocolVersion::default(), ProtocolVersion::V311);
        assert_eq!(ProtocolVersion::V311.level(), 4);
        assert_eq!(ProtocolVersion::V5.level(), 5);
        assert_eq!(ProtocolVersion::from_level(4), Some(ProtocolVersion::V311));
        assert_eq!(ProtocolVersion::from_level(5), Some(ProtocolVersion::V5));
        assert_eq!(ProtocolVersion::from_level(3), None);
    }

    #[test]
    fn v311_connect_wire_stays_byte_identical() {
        let connect = Packet::Connect(Box::new(ConnectPacket {
            version: ProtocolVersion::V311,
            properties: Default::default(),
            client_id: Arc::from("cid"),
            clean_session: true,
            keep_alive: 60,
            username: None,
            password: None,
            will: None,
        }));

        assert_eq!(
            encode_packet(&connect, ProtocolVersion::V311).unwrap(),
            vec![
                0x10, 0x0f, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x03,
                b'c', b'i', b'd',
            ]
        );
    }

    #[test]
    fn mqtt5_connect_round_trip_uses_packet_version() {
        let properties = Properties {
            session_expiry_interval: Some(30),
            ..Default::default()
        };
        let connect = Packet::Connect(Box::new(ConnectPacket {
            version: ProtocolVersion::V5,
            properties,
            client_id: Arc::from("v5"),
            clean_session: true,
            keep_alive: 10,
            username: None,
            password: None,
            will: None,
        }));

        let bytes = encode_packet(&connect, ProtocolVersion::V311).unwrap();
        assert_eq!(bytes[8], 5, "CONNECT must advertise its own version");
        let mut buffer = BytesMut::from(&bytes[..]);
        match decode_packet_from_bytes(&mut buffer, ProtocolVersion::V311)
            .unwrap()
            .unwrap()
        {
            Packet::Connect(decoded) => {
                assert_eq!(decoded.version, ProtocolVersion::V5);
                assert_eq!(decoded.properties.session_expiry_interval, Some(30));
            }
            other => panic!("expected CONNECT, got {:?}", other),
        }
    }

    #[test]
    fn mqtt5_publish_properties_round_trip() {
        let properties = Properties {
            content_type: Some(Arc::from("text/plain")),
            user_properties: vec![(Arc::from("source"), Arc::from("test"))],
            ..Default::default()
        };
        let publish = Packet::Publish(PublishPacket {
            properties,
            topic: Arc::from("v5/topic"),
            payload: Bytes::from_static(b"payload"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        });

        let bytes = encode_packet(&publish, ProtocolVersion::V5).unwrap();
        let mut buffer = BytesMut::from(&bytes[..]);
        match decode_packet_from_bytes(&mut buffer, ProtocolVersion::V5)
            .unwrap()
            .unwrap()
        {
            Packet::Publish(decoded) => {
                assert_eq!(
                    decoded.properties.content_type.as_deref(),
                    Some("text/plain")
                );
                assert_eq!(decoded.properties.user_properties.len(), 1);
                assert_eq!(&decoded.payload[..], b"payload");
            }
            other => panic!("expected PUBLISH, got {:?}", other),
        }
    }
}
