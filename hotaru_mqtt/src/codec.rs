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
use zeroize::Zeroizing;

use crate::error::{CodecError, MqttError, Violation};
use crate::packet::{
    ConnackPacket, ConnackReturnCode, ConnectFlags, ConnectPacket, FixedHeaderFlags, Packet,
    PacketType, PublishPacket, SubackPacket, SubscribePacket, TopicSubscription, UnsubscribePacket,
    WillPacket,
};
use crate::request::{QoS, SubackCode};

// ============================================================================
// Public encode/decode API
// ============================================================================

/// Read one complete MQTT packet from the async reader. Used by handle_*
/// loops that own the reader directly (single-take pattern).
///
/// `max_size` caps the declared remaining length BEFORE allocation — over-
/// large frames are rejected without `vec![0u8; remaining]` ever running,
/// so a malicious peer cannot OOM the process by declaring a 256 MiB body.
/// Pass `usize::MAX` to disable (spec hard cap of 268_435_455 still applies
/// via `read_remaining_length`).
pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_size: usize,
) -> Result<Packet, MqttError> {
    let mut header_byte = [0u8; 1];
    reader.read_exact(&mut header_byte).await?;
    let first = header_byte[0];

    let raw_type = first >> 4;
    let packet_type =
        PacketType::try_from(raw_type).map_err(|_| CodecError::InvalidPacketType(raw_type))?;

    let remaining = read_remaining_length(reader).await?;
    if remaining > max_size {
        return Err(Violation::PacketTooLarge {
            len: remaining,
            max: max_size,
        }
        .into());
    }
    let mut body = vec![0u8; remaining];
    reader.read_exact(&mut body).await?;

    parse_packet(first, packet_type, remaining, &body)
}

/// Try to decode one MQTT packet from a buffer. Returns `Ok(None)` if more
/// bytes are needed. On success consumes the packet bytes from the buffer.
///
/// `max_size` caps the declared remaining length BEFORE the parser
/// touches `body` — passes 268_435_455 (spec hard cap) keeps the prior
/// behavior; callers wanting a tighter `MqttSafety.max_packet_size()`
/// budget pass that. Symmetric to [`read_packet`] (M2 close, second
/// audit).
pub fn decode_packet_from_bytes(
    buf: &mut BytesMut,
    max_size: usize,
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

    if remaining > max_size {
        return Err(Box::new(MqttError::from(Violation::PacketTooLarge {
            len: remaining,
            max: max_size,
        })));
    }

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
///
/// Returns [`CodecError::FieldTooLong`] when any length-prefixed string or
/// bytes field exceeds the u16 wire encoding (second-audit F2 — prior
/// `as u16` truncation was silently corrupting framing).
pub fn encode_packet(packet: &Packet) -> Result<Vec<u8>, MqttError> {
    match packet {
        Packet::Connect(c) => encode_connect(c),
        Packet::Connack(c) => Ok(encode_connack(c)),
        Packet::Publish(p) => encode_publish(p),
        Packet::Puback(id) => Ok(vec![0x40, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8]),
        Packet::Pubrec(id) => Ok(vec![0x50, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8]),
        Packet::Pubrel(id) => Ok(vec![0x62, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8]),
        Packet::Pubcomp(id) => Ok(vec![0x70, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8]),
        Packet::Subscribe(s) => encode_subscribe(s),
        Packet::Suback(s) => Ok(encode_suback(s)),
        Packet::Unsubscribe(u) => encode_unsubscribe(u),
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
) -> Result<(), MqttError> {
    let buf = encode_packet(packet)?;
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

    let topic_len = u16_or_err(topic_bytes.len(), "publish.topic")?;
    let mut header = Vec::with_capacity(1 + 4 + var_header_len);
    let flags = pack_publish_flags(packet);
    header.push(((PacketType::Publish as u8) << 4) | flags);
    header.extend(encode_remaining_length(body_len));
    header.extend_from_slice(&topic_len.to_be_bytes());
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

fn decode_remaining_length_from_slice(data: &[u8]) -> Result<Option<(usize, usize)>, MqttError> {
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
        PacketType::Subscribe => {
            // spec §3.8.1: SUBSCRIBE reserved bits MUST be 0010.
            if first & 0x0F != 0x02 {
                return Err(Violation::SubscribeReservedBits.into());
            }
            parse_subscribe(body)
        }
        PacketType::Suback => parse_suback(body),
        PacketType::Unsubscribe => {
            // spec §3.10.1: UNSUBSCRIBE reserved bits MUST be 0010.
            if first & 0x0F != 0x02 {
                return Err(Violation::UnsubscribeReservedBits.into());
            }
            parse_unsubscribe(body)
        }
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
    // spec §3.1.2.3: reserved bit (bit 0) MUST be 0.
    if flags_byte & ConnectFlags::Reserved.bits() != 0 {
        return Err(Violation::ReservedHeaderBits.into());
    }
    let connect_flags = ConnectFlags::from_bits_truncate(flags_byte);
    let keep_alive = u16::from_be_bytes([body[8], body[9]]);

    let will_flag = connect_flags.contains(ConnectFlags::WillFlag);
    let will_qos_bits = (flags_byte & ConnectFlags::WillQoSMask.bits()) >> 3;
    let will_retain = connect_flags.contains(ConnectFlags::WillRetain);
    if !will_flag {
        // spec §3.1.2.6-7: Will QoS and Will Retain MUST be 0 when Will Flag = 0.
        if will_qos_bits != 0 || will_retain {
            return Err(Violation::ReservedHeaderBits.into());
        }
    }

    let username_flag = connect_flags.contains(ConnectFlags::Username);
    let password_flag = connect_flags.contains(ConnectFlags::Password);
    // spec §3.1.2.9: Password Flag MUST be 0 if Username Flag = 0.
    if !username_flag && password_flag {
        return Err(Violation::ReservedHeaderBits.into());
    }

    let mut cursor = 10usize;
    let client_id = read_arc_str(body, &mut cursor)?;

    let will = if will_flag {
        let topic = read_arc_str(body, &mut cursor)?;
        let payload = read_bytes(body, &mut cursor)?;
        let qos = QoS::from_u8(will_qos_bits).ok_or(CodecError::QosInvalid(will_qos_bits))?;
        Some(WillPacket {
            topic,
            payload,
            qos,
            retain: will_retain,
        })
    } else {
        None
    };

    let username = if username_flag {
        Some(read_arc_str(body, &mut cursor)?)
    } else {
        None
    };

    // SAFETY_PROOF v5 §7 F1 / #69: copy the wire bytes into an owned, zeroized
    // buffer instead of holding a `Bytes` view. The wire arena is still alive
    // until `parse_connect` returns, but our long-lived copy is `Zeroizing<Vec<u8>>`
    // — guaranteed wiped at packet-drop. `read_bytes`' internal `Vec` allocated
    // for the slice is dropped here without an explicit wipe; the wire arena
    // is the residual window addressed by the future wipeable wire allocator.
    let password = if password_flag {
        Some(Zeroizing::new(read_bytes(body, &mut cursor)?.to_vec()))
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
    // spec §3.2.2.1: bits 1-7 of the CONNACK first byte are reserved and MUST be 0.
    if body[0] & 0xFE != 0 {
        return Err(Violation::ConnackReservedBits.into());
    }
    let session_present = (body[0] & 0x01) != 0;
    let return_code = ConnackReturnCode::try_from(body[1])
        .map_err(|_| MqttError::Codec(CodecError::InvalidPacketType(body[1])))?;
    // spec §3.2.2.2: SessionPresent MUST be 0 if ReturnCode != Accepted.
    if session_present && return_code != ConnackReturnCode::Accepted {
        return Err(Violation::SessionPresentWithError.into());
    }
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
    let header_flags = FixedHeaderFlags::from_bits(raw_flags).ok_or(CodecError::ReservedFlagSet)?;
    let dup = header_flags.contains(FixedHeaderFlags::Dup);
    let retain = header_flags.contains(FixedHeaderFlags::Retain);
    let qos_bits = (header_flags.bits() & FixedHeaderFlags::QoS.bits()) >> 1;
    let qos = QoS::from_u8(qos_bits).ok_or(CodecError::QosInvalid(qos_bits))?;

    // spec §3.3.1.1: DUP MUST be 0 for QoS 0.
    if dup && qos == QoS::AtMostOnce {
        return Err(Violation::DupSetOnQos0.into());
    }

    let mut cursor = 0usize;
    let topic = read_arc_str(body, &mut cursor)?;

    // spec §3.3.2.1: topic name MUST be at least 1 char.
    if topic.is_empty() {
        return Err(Violation::EmptyPublishTopic.into());
    }
    // spec §3.3.2.1 + §4.7.1.1: PUBLISH topic name MUST NOT contain
    // wildcards. Reuses the canonical validator so client and server
    // share one rule (§1.4).
    crate::topic::validate_publish_topic(topic.as_ref())?;

    let packet_id = if qos != QoS::AtMostOnce {
        let id = read_u16(body, &mut cursor)?;
        // spec §2.3.1: packet_id MUST be non-zero for QoS > 0.
        if id == 0 {
            return Err(Violation::PacketIdZero.into());
        }
        Some(id)
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
    let expected = if packet_type == PacketType::Pubrel {
        0x02
    } else {
        0x00
    };
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
    Ok(Packet::Unsubscribe(UnsubscribePacket { packet_id, topics }))
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
    write_arc_str(&mut body, &conn.client_id, "client_id")?;
    if let Some(will) = &conn.will {
        write_arc_str(&mut body, &will.topic, "will.topic")?;
        write_bytes(&mut body, &will.payload, "will.payload")?;
    }
    if let Some(username) = &conn.username {
        write_arc_str(&mut body, username, "username")?;
    }
    if let Some(password) = &conn.password {
        // `Zeroizing<Vec<u8>>` derefs to `[u8]`. Wire-bound bytes get
        // staged in `body: Vec<u8>` — that buffer is NOT zeroized; the
        // encode-side residency is the same wire-arena window addressed
        // by the future wipeable wire allocator.
        write_bytes(&mut body, password.as_slice(), "password")?;
    }
    let mut buf = vec![(PacketType::Connect as u8) << 4];
    buf.extend(encode_remaining_length(body.len()));
    buf.extend(body);
    Ok(buf)
}

fn encode_connack(ack: &ConnackPacket) -> Vec<u8> {
    vec![
        (PacketType::Connack as u8) << 4,
        0x02,
        if ack.session_present { 0x01 } else { 0x00 },
        ack.return_code.as_u8(),
    ]
}

fn encode_publish(p: &PublishPacket) -> Result<Vec<u8>, MqttError> {
    let topic_bytes = p.topic.as_bytes();
    let topic_len = u16_or_err(topic_bytes.len(), "publish.topic")?;
    let mut body = Vec::with_capacity(2 + topic_bytes.len() + 2 + p.payload.len());
    body.extend_from_slice(&topic_len.to_be_bytes());
    body.extend_from_slice(topic_bytes);
    if p.qos != QoS::AtMostOnce {
        // SAFETY_PROOF v6 F5: spec §3.3.2.2 — a QoS ≥ 1 PUBLISH MUST carry
        // a non-zero packet identifier. The previous `if let Some(id)`
        // silently emitted a malformed frame (truncated wire body) when
        // a caller built a PublishPacket directly with `packet_id = None`
        // (or with zero). Fail closed here so the bug surfaces at the
        // encode boundary instead of being interpreted by a remote peer.
        let id = p.packet_id.ok_or(CodecError::QosRequiresPacketId)?;
        if id == 0 {
            return Err(CodecError::QosRequiresPacketId.into());
        }
        body.extend_from_slice(&id.to_be_bytes());
    }
    body.extend_from_slice(&p.payload[..]);

    let flags = pack_publish_flags(p);
    let mut buf = vec![((PacketType::Publish as u8) << 4) | flags];
    buf.extend(encode_remaining_length(body.len()));
    buf.extend(body);
    Ok(buf)
}

fn encode_subscribe(s: &SubscribePacket) -> Result<Vec<u8>, MqttError> {
    let mut body = Vec::new();
    body.extend_from_slice(&s.packet_id.to_be_bytes());
    for sub in &s.subscriptions {
        write_arc_str(&mut body, &sub.topic, "subscribe.filter")?;
        body.push(sub.qos.as_u8());
    }
    let mut buf = vec![((PacketType::Subscribe as u8) << 4) | 0x02];
    buf.extend(encode_remaining_length(body.len()));
    buf.extend(body);
    Ok(buf)
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

fn encode_unsubscribe(u: &UnsubscribePacket) -> Result<Vec<u8>, MqttError> {
    let mut body = Vec::new();
    body.extend_from_slice(&u.packet_id.to_be_bytes());
    for topic in &u.topics {
        write_arc_str(&mut body, topic, "unsubscribe.filter")?;
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
    // spec §1.5.3: MQTT UTF-8 strings MUST NOT contain U+0000.
    if s.contains('\0') {
        return Err(Violation::Utf8NullCharacter.into());
    }
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

fn write_arc_str(out: &mut Vec<u8>, s: &Arc<str>, kind: &'static str) -> Result<(), MqttError> {
    let b = s.as_bytes();
    let len = u16_or_err(b.len(), kind)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn write_bytes(out: &mut Vec<u8>, b: &[u8], kind: &'static str) -> Result<(), MqttError> {
    let len = u16_or_err(b.len(), kind)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn u16_or_err(len: usize, kind: &'static str) -> Result<u16, MqttError> {
    if len > u16::MAX as usize {
        return Err(CodecError::FieldTooLong { kind, len }.into());
    }
    Ok(len as u16)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_connect_round_trip() {
        let original = ConnectPacket {
            client_id: Arc::from("cid"),
            clean_session: true,
            keep_alive: 60,
            username: None,
            password: None,
            will: None,
        };
        let bytes = encode_packet(&Packet::Connect(original.clone())).unwrap();
        let mut buf = BytesMut::from(&bytes[..]);
        match decode_packet_from_bytes(&mut buf, usize::MAX)
            .unwrap()
            .unwrap()
        {
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
            client_id: Arc::from("cid"),
            clean_session: false,
            keep_alive: 30,
            username: Some(Arc::from("alice")),
            password: Some(Zeroizing::new(b"secret".to_vec())),
            will: Some(WillPacket {
                topic: Arc::from("offline"),
                payload: Bytes::from_static(b"bye"),
                qos: QoS::AtLeastOnce,
                retain: true,
            }),
        };
        let bytes = encode_packet(&Packet::Connect(original)).unwrap();
        let mut buf = BytesMut::from(&bytes[..]);
        match decode_packet_from_bytes(&mut buf, usize::MAX)
            .unwrap()
            .unwrap()
        {
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
            topic: Arc::from("sensors/temp"),
            payload: Bytes::from_static(b"42"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        };
        let bytes = encode_packet(&Packet::Publish(p)).unwrap();
        let mut buf = BytesMut::from(&bytes[..]);
        match decode_packet_from_bytes(&mut buf, usize::MAX)
            .unwrap()
            .unwrap()
        {
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
            topic: Arc::from("a/b"),
            payload: Bytes::from_static(b"x"),
            dup: false,
            qos: QoS::AtLeastOnce,
            retain: false,
            packet_id: Some(42),
        };
        let bytes = encode_packet(&Packet::Publish(p)).unwrap();
        let mut buf = BytesMut::from(&bytes[..]);
        match decode_packet_from_bytes(&mut buf, usize::MAX)
            .unwrap()
            .unwrap()
        {
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
        let bytes = encode_packet(&Packet::Subscribe(s)).unwrap();
        let mut buf = BytesMut::from(&bytes[..]);
        match decode_packet_from_bytes(&mut buf, usize::MAX)
            .unwrap()
            .unwrap()
        {
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
        let bytes = encode_packet(&Packet::Unsubscribe(u)).unwrap();
        let mut buf = BytesMut::from(&bytes[..]);
        match decode_packet_from_bytes(&mut buf, usize::MAX)
            .unwrap()
            .unwrap()
        {
            Packet::Unsubscribe(u) => {
                assert_eq!(u.packet_id, 8);
                assert_eq!(u.topics.len(), 2);
            }
            _ => panic!("expected Unsubscribe"),
        }
    }

    #[test]
    fn pingreq_pingresp_disconnect_unsuback() {
        assert_eq!(encode_packet(&Packet::Pingreq).unwrap(), vec![0xC0, 0x00]);
        assert_eq!(encode_packet(&Packet::Pingresp).unwrap(), vec![0xD0, 0x00]);
        assert_eq!(
            encode_packet(&Packet::Disconnect).unwrap(),
            vec![0xE0, 0x00]
        );
        assert_eq!(
            encode_packet(&Packet::Unsuback(42)).unwrap(),
            vec![0xB0, 0x02, 0x00, 0x2A]
        );
    }

    /// F2 regression — encode MUST surface an error rather than silently
    /// truncate a >65 535-byte length-prefixed field.
    #[test]
    fn encode_rejects_oversize_topic() {
        let oversize: Arc<str> = Arc::from("x".repeat(65_536).as_str());
        let publish = PublishPacket {
            topic: oversize,
            payload: Bytes::new(),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        };
        let err = encode_packet(&Packet::Publish(publish)).unwrap_err();
        assert!(
            matches!(
                err,
                MqttError::Codec(CodecError::FieldTooLong { kind, .. })
                    if kind == "publish.topic"
            ),
            "expected FieldTooLong{{kind=publish.topic}}, got {err:?}"
        );
    }

    #[test]
    fn partial_buffer_returns_none() {
        let mut buf = BytesMut::from(&[0x10u8][..]);
        assert!(
            decode_packet_from_bytes(&mut buf, usize::MAX)
                .unwrap()
                .is_none()
        );
        assert_eq!(buf.len(), 1, "buffer must not be consumed on partial");
    }

    // ── Stage A P1.A: strict codec hardening ──────────────────────────

    /// Build a PUBLISH frame on the wire with explicit fixed-header flags.
    /// Bypasses the encode path (which would refuse invalid combos).
    fn build_publish_wire(
        flags: u8,
        topic: &[u8],
        packet_id: Option<u16>,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        body.extend_from_slice(topic);
        if let Some(id) = packet_id {
            body.extend_from_slice(&id.to_be_bytes());
        }
        body.extend_from_slice(payload);
        let mut frame = vec![0x30 | (flags & 0x0F)];
        frame.extend(encode_remaining_length(body.len()));
        frame.extend(body);
        frame
    }

    fn must_violation(err: MqttError) -> Violation {
        match err {
            MqttError::Protocol(v) => v,
            other => panic!("expected MqttError::Protocol, got {:?}", other),
        }
    }

    #[test]
    fn publish_with_dup_set_on_qos0_rejected() {
        // Flags = DUP(1) | QoS=0 | RETAIN=0 → 0b1000 = 0x8
        let wire = build_publish_wire(0x08, b"a", None, b"x");
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("DUP+QoS0 must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::DupSetOnQos0);
    }

    #[test]
    fn publish_packet_id_zero_rejected() {
        // Flags = QoS=1 → 0b0010 = 0x2; packet_id = 0
        let wire = build_publish_wire(0x02, b"a", Some(0), b"x");
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("packet_id=0 on QoS>0 must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::PacketIdZero);
    }

    #[test]
    fn publish_empty_topic_rejected() {
        // QoS=0, zero-length topic
        let wire = build_publish_wire(0x00, b"", None, b"x");
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("empty topic must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::EmptyPublishTopic);
    }

    #[test]
    fn connack_reserved_bits_rejected() {
        // first byte = 0x02 (any bit besides 0 set) — illegal per §3.2.2.1
        let wire = [0x20, 0x02, 0x02, 0x00];
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("CONNACK reserved bits must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::ConnackReservedBits);
    }

    #[test]
    fn connack_session_present_with_non_accepted_rejected() {
        // SessionPresent=1 + return_code=5 (NotAuthorized) — illegal per §3.2.2.2
        let wire = [0x20, 0x02, 0x01, 0x05];
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("SessionPresent + error code must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::SessionPresentWithError);
    }

    #[test]
    fn publish_wildcard_in_topic_rejected() {
        // spec §3.3.2.1: PUBLISH topic name MUST NOT contain `+` or `#`.
        let wire = build_publish_wire(0x00, b"a/+/b", None, b"x");
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("wildcard topic must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::WildcardInPublishTopic);
    }

    /// Build a SUBSCRIBE wire frame with explicit fixed-header low nibble.
    fn build_subscribe_wire(reserved_bits: u8, topic: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&7u16.to_be_bytes()); // packet_id
        body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        body.extend_from_slice(topic);
        body.push(0x00); // QoS=0
        let mut frame = vec![0x80 | (reserved_bits & 0x0F)];
        frame.extend(encode_remaining_length(body.len()));
        frame.extend(body);
        frame
    }

    fn build_unsubscribe_wire(reserved_bits: u8, topic: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&7u16.to_be_bytes());
        body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        body.extend_from_slice(topic);
        let mut frame = vec![0xA0 | (reserved_bits & 0x0F)];
        frame.extend(encode_remaining_length(body.len()));
        frame.extend(body);
        frame
    }

    #[test]
    fn subscribe_reserved_bits_must_be_0010() {
        // spec §3.8.1 — only 0010 is legal for the low nibble.
        let wire = build_subscribe_wire(0x00, b"a/b");
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("SUBSCRIBE low-nibble 0000 must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::SubscribeReservedBits);

        // 0010 is the spec-required value — must succeed.
        let wire_ok = build_subscribe_wire(0x02, b"a/b");
        let mut buf_ok = BytesMut::from(&wire_ok[..]);
        assert!(decode_packet_from_bytes(&mut buf_ok, usize::MAX).is_ok());
    }

    #[test]
    fn unsubscribe_reserved_bits_must_be_0010() {
        let wire = build_unsubscribe_wire(0x04, b"a/b");
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("UNSUBSCRIBE non-0010 must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::UnsubscribeReservedBits);
    }

    #[test]
    fn utf8_null_in_topic_rejected() {
        // PUBLISH QoS=0 with topic "a\0b" — UTF-8 valid but spec-forbidden.
        let wire = build_publish_wire(0x00, b"a\0b", None, b"x");
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("U+0000 in UTF-8 string must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::Utf8NullCharacter);
    }

    // ── Stage A P2.B: CONNECT strict validation ──────────────────────

    /// Build a CONNECT frame with explicit raw flags byte.
    /// Bypasses the encode path so we can synthesize illegal combinations.
    fn build_connect_wire(flags: u8, client_id: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T']);
        body.push(0x04); // protocol level
        body.push(flags);
        body.extend_from_slice(&60u16.to_be_bytes()); // keep_alive
        body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        body.extend_from_slice(client_id);
        let mut frame = vec![0x10];
        frame.extend(encode_remaining_length(body.len()));
        frame.extend(body);
        frame
    }

    #[test]
    fn connect_reserved_bit_rejected() {
        // flags = 0x01 (reserved bit set, no other flags)
        let wire = build_connect_wire(0x01, b"cid");
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("reserved bit must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::ReservedHeaderBits);
    }

    #[test]
    fn connect_will_qos_set_without_will_flag_rejected() {
        // flags = 0x18 = WillQoSMask(0b0001_1000) without WillFlag(0b0000_0100)
        let wire = build_connect_wire(0x18, b"cid");
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("will QoS without will flag must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::ReservedHeaderBits);
    }

    #[test]
    fn connect_will_retain_without_will_flag_rejected() {
        // flags = 0x20 = WillRetain without WillFlag
        let wire = build_connect_wire(0x20, b"cid");
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("will retain without will flag must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::ReservedHeaderBits);
    }

    #[test]
    fn connect_password_flag_without_username_flag_rejected() {
        // flags = 0x40 = Password without Username
        let wire = build_connect_wire(0x40, b"cid");
        let mut buf = BytesMut::from(&wire[..]);
        let err = decode_packet_from_bytes(&mut buf, usize::MAX)
            .expect_err("password without username must be rejected")
            .downcast::<MqttError>()
            .unwrap();
        assert_eq!(must_violation(*err), Violation::ReservedHeaderBits);
    }

    #[tokio::test]
    async fn read_packet_rejects_oversize_before_alloc() {
        // 5-byte declared body but max_size = 4 → reject without allocating.
        let mut wire = vec![0x30, 0x05];
        wire.extend_from_slice(&[0u8; 5]);
        let mut reader = &wire[..];
        let err = read_packet(&mut reader, 4)
            .await
            .expect_err("oversize must be rejected");
        match must_violation(err) {
            Violation::PacketTooLarge { len, max } => {
                assert_eq!(len, 5);
                assert_eq!(max, 4);
            }
            other => panic!("expected PacketTooLarge, got {:?}", other),
        }
    }

    // SAFETY_PROOF v6 F5 — encode_publish must reject QoS ≥ 1 PUBLISH that
    // lacks a non-zero packet identifier. Spec §3.3.2.2 says the identifier
    // is MUST-have; emitting a malformed frame would be silently confusing.

    fn must_codec_error(err: MqttError) -> CodecError {
        match err {
            MqttError::Codec(c) => c,
            other => panic!("expected CodecError, got {:?}", other),
        }
    }

    #[test]
    fn encode_publish_rejects_qos1_without_packet_id() {
        let pkt = Packet::Publish(PublishPacket {
            topic: Arc::from("sensors/temp"),
            payload: bytes::Bytes::from_static(b"21"),
            dup: false,
            qos: QoS::AtLeastOnce,
            retain: false,
            packet_id: None,
        });
        let err = encode_packet(&pkt).expect_err("QoS1 without pkt-id must fail");
        assert!(matches!(
            must_codec_error(err),
            CodecError::QosRequiresPacketId
        ));
    }

    #[test]
    fn encode_publish_rejects_qos2_with_zero_packet_id() {
        let pkt = Packet::Publish(PublishPacket {
            topic: Arc::from("sensors/temp"),
            payload: bytes::Bytes::from_static(b"21"),
            dup: false,
            qos: QoS::ExactlyOnce,
            retain: false,
            packet_id: Some(0),
        });
        let err = encode_packet(&pkt).expect_err("QoS2 with pkt-id 0 must fail");
        assert!(matches!(
            must_codec_error(err),
            CodecError::QosRequiresPacketId
        ));
    }

    #[test]
    fn encode_publish_qos0_still_accepts_none_packet_id() {
        // QoS 0 deliberately has no packet identifier (spec §3.3.2.2).
        // F5 must NOT regress that path.
        let pkt = Packet::Publish(PublishPacket {
            topic: Arc::from("sensors/temp"),
            payload: bytes::Bytes::from_static(b"21"),
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            packet_id: None,
        });
        let bytes = encode_packet(&pkt).expect("QoS0 + None must encode fine");
        assert!(!bytes.is_empty());
    }
}
