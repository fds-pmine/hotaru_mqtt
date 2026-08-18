//! MQTT 3.1.1 wire codec.
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
    PacketType, PublishPacket, SubackPacket, SubscribePacket, TopicSubscription,
    UnsubscribePacket, WillPacket,
};
use crate::request::{QoS, SubackCode};

// ============================================================================
// Public encode/decode API
// ============================================================================

/// Read one complete MQTT packet from the async reader. Used by handle_*
/// loops that own the reader directly (single-take pattern).
pub async fn read_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Packet, MqttError> {
    let mut header_byte = [0u8; 1];
    reader.read_exact(&mut header_byte).await?;
    let first = header_byte[0];

    let raw_type = first >> 4;
    let packet_type =
        PacketType::try_from(raw_type).map_err(|_| CodecError::InvalidPacketType(raw_type))?;

    let remaining = read_remaining_length(reader).await?;
    let mut body = vec![0u8; remaining];
    reader.read_exact(&mut body).await?;

    parse_packet(first, packet_type, remaining, &body)
}

/// Try to decode one MQTT packet from a buffer. Returns `Ok(None)` if more
/// bytes are needed. On success consumes the packet bytes from the buffer.
pub fn decode_packet_from_bytes(
    buf: &mut BytesMut,
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
    let packet = parse_packet(first, packet_type, remaining, body)
        .map_err(|e| -> Box<dyn Error + Send + Sync> { Box::new(e) })?;
    Ok(Some(packet))
}

/// Encode any packet into a fresh `Vec<u8>`. Convenience for tests and the
/// `Message::encode` trait impl. Hot paths use `write_packet` /
/// `write_publish_packet` directly to avoid the intermediate Vec.
pub fn encode_packet(packet: &Packet) -> Vec<u8> {
    match packet {
        Packet::Connect(c) => encode_connect(c),
        Packet::Connack(c) => encode_connack(c),
        Packet::Publish(p) => encode_publish(p),
        Packet::Puback(id) => vec![0x40, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8],
        Packet::Pubrec(id) => vec![0x50, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8],
        Packet::Pubrel(id) => vec![0x62, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8],
        Packet::Pubcomp(id) => vec![0x70, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8],
        Packet::Subscribe(s) => encode_subscribe(s),
        Packet::Suback(s) => encode_suback(s),
        Packet::Unsubscribe(u) => encode_unsubscribe(u),
        Packet::Unsuback(id) => vec![0xB0, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8],
        Packet::Pingreq => vec![0xC0, 0x00],
        Packet::Pingresp => vec![0xD0, 0x00],
        Packet::Disconnect => vec![0xE0, 0x00],
    }
}

/// Write a packet to an async writer. Used by the writer actor for control
/// packets.
pub async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &Packet,
) -> Result<(), MqttError> {
    let buf = encode_packet(packet);
    writer.write_all(&buf).await?;
    Ok(())
}

/// Optimized write path for PUBLISH: writes the header in one syscall, then
/// the payload `Bytes` directly with `write_all(&payload[..])` — no copy
/// from `Bytes` to intermediate buffer.
pub async fn write_publish_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    packet: &PublishPacket,
) -> Result<(), MqttError> {
    // Build header + variable header into a small buffer; payload streamed
    // separately from the Bytes directly.
    let topic_bytes = packet.topic.as_bytes();
    let mut var_header_len = 2 + topic_bytes.len();
    if packet.qos != QoS::AtMostOnce {
        var_header_len += 2;
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

fn parse_connack(body: &[u8]) -> Result<Packet, MqttError> {
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

fn parse_publish(first: u8, body: &[u8]) -> Result<Packet, MqttError> {
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

fn parse_ack_packet(
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

fn parse_subscribe(body: &[u8]) -> Result<Packet, MqttError> {
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

fn parse_suback(body: &[u8]) -> Result<Packet, MqttError> {
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

fn parse_unsubscribe(body: &[u8]) -> Result<Packet, MqttError> {
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

fn encode_connect(conn: &ConnectPacket) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T']);
    body.push(0x04);
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
    write_arc_str(&mut body, &conn.client_id);
    if let Some(will) = &conn.will {
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
    buf
}

fn encode_connack(ack: &ConnackPacket) -> Vec<u8> {
    vec![
        (PacketType::Connack as u8) << 4,
        0x02,
        if ack.session_present { 0x01 } else { 0x00 },
        ack.return_code.as_u8(),
    ]
}

fn encode_publish(p: &PublishPacket) -> Vec<u8> {
    let topic_bytes = p.topic.as_bytes();
    let mut body = Vec::with_capacity(2 + topic_bytes.len() + 2 + p.payload.len());
    body.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(topic_bytes);
    if p.qos != QoS::AtMostOnce
        && let Some(id) = p.packet_id
    {
        body.extend_from_slice(&id.to_be_bytes());
    }
    body.extend_from_slice(&p.payload[..]);

    let flags = pack_publish_flags(p);
    let mut buf = vec![((PacketType::Publish as u8) << 4) | flags];
    buf.extend(encode_remaining_length(body.len()));
    buf.extend(body);
    buf
}

fn encode_subscribe(s: &SubscribePacket) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&s.packet_id.to_be_bytes());
    for sub in &s.subscriptions {
        write_arc_str(&mut body, &sub.topic);
        body.push(sub.qos.as_u8());
    }
    let mut buf = vec![((PacketType::Subscribe as u8) << 4) | 0x02];
    buf.extend(encode_remaining_length(body.len()));
    buf.extend(body);
    buf
}

fn encode_suback(s: &SubackPacket) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + s.return_codes.len());
    body.extend_from_slice(&s.packet_id.to_be_bytes());
    for code in &s.return_codes {
        body.push(code.as_u8());
    }
    let mut buf = vec![(PacketType::Suback as u8) << 4];
    buf.extend(encode_remaining_length(body.len()));
    buf.extend(body);
    buf
}

fn encode_unsubscribe(u: &UnsubscribePacket) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&u.packet_id.to_be_bytes());
    for topic in &u.topics {
        write_arc_str(&mut body, topic);
    }
    let mut buf = vec![((PacketType::Unsubscribe as u8) << 4) | 0x02];
    buf.extend(encode_remaining_length(body.len()));
    buf.extend(body);
    buf
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

// ----------------------------------------------------------------------------
// Message impl — connects Packet to hotaru_core's protocol Message trait
//
// Lives here rather than in `packet` so the data definitions stay free of any
// dependency on the codec: `codec -> packet` is the intended direction.
// ----------------------------------------------------------------------------

impl Message for Packet {
    type BytesMut = BytesMut;

    fn encode(&self, buf: &mut Self::BytesMut) -> Result<(), Box<dyn Error + Send + Sync>> {
        buf.extend_from_slice(&encode_packet(self));
        Ok(())
    }

    fn decode(buf: &mut Self::BytesMut) -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        decode_packet_from_bytes(buf)
    }
}

#[cfg(test)]
mod test;
