//! MQTT 3.1.1 wire codec.
//!
//! Decode path constructs `Arc<str>` (topic / client_id) and `Bytes`
//! (payload / password) directly from read buffers — no `String::from_utf8`
//! copies, just `Arc::from(String)` and `Bytes::from(Vec<u8>)` (both O(1)).
//!
//! Encode path writes through `write_all(&payload[..])` — `Bytes` derefs to
//! `&[u8]` with zero overhead.


use bytes::BytesMut;
use hotaru_core::connection::{HotaruRead, HotaruWrite};

use hotaru_core::protocol::Message;

use crate::error::{CodecError, MqttError, Violation};
use crate::packet::{
    MQTT_SPEC_MAX_PACKET_SIZE, Packet, PacketType, PublishPacket,
};
use crate::safety::MqttSafety;

mod decode;
mod encode;
mod primitives;
mod varint;

#[cfg(test)]
mod test;


use decode::parse_packet;
use encode::{validate_publish_for_encode, encode_connack, encode_connect, encode_publish, encode_suback,
    encode_subscribe, encode_unsubscribe, pack_publish_flags};
use varint::{decode_remaining_length_from_slice, encode_remaining_length,
    read_remaining_length};

// ============================================================================
// Public encode/decode API
// ============================================================================

/// Read one complete MQTT packet from the async reader. Used by handle_*
/// loops that own the reader directly (single-take pattern).
///
/// `max_size` bounds the declared remaining-length. The check sits between
/// decoding that length and allocating the body, so an oversized declaration
/// costs one fixed header and no heap — the peer never gets to pick an
/// allocation size. Callers pass the value from their `MqttSafety`.
pub async fn read_packet<R: HotaruRead<Error = std::io::Error> + Unpin + Send>(
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
    // Must stay above `vec![0u8; remaining]`. Moving it below would restore
    // the exact defect it exists to close.
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
/// `max_size` carries the same meaning as in [`read_packet`]. The buffered
/// path needs its own check: without it, framing this way would be a way
/// around the cap rather than a second place enforcing it.
pub fn decode_packet_from_bytes(
    buf: &mut BytesMut,
    max_size: usize,
) -> Result<Option<Packet>, MqttError> {
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

    // Before the `buf.len() < total` wait: an oversized declaration must fail
    // now, not sit here holding the connection open until the bytes arrive.
    if remaining > max_size {
        return Err(MqttError::Protocol(Violation::PacketTooLarge {
            len: remaining,
            max: max_size,
        }));
    }

    let header_len = 1 + rl_bytes;
    let total = header_len + remaining;
    if buf.len() < total {
        return Ok(None);
    }

    let packet_bytes = buf.split_to(total);
    let body = &packet_bytes[header_len..];
    let packet = parse_packet(first, packet_type, remaining, body)?;
    Ok(Some(packet))
}

/// Encode any packet into a fresh `Vec<u8>`. Convenience for tests and the
/// `Message::encode` trait impl. Hot paths use `write_packet` /
/// `write_publish_packet` directly to avoid the intermediate Vec.
///
/// Fallible because PUBLISH is: an invalid `PublishPacket` (QoS >= 1 with no
/// packet id, id 0, oversized topic or body) is refused rather than silently
/// emitted malformed. Every other variant cannot fail and simply wraps in Ok.
pub fn encode_packet(packet: &Packet) -> Result<Vec<u8>, CodecError> {
    let bytes = match packet {
        Packet::Connect(connect) => encode_connect(connect),
        Packet::Connack(connack) => encode_connack(connack),
        Packet::Publish(publish) => return encode_publish(publish),
        Packet::Puback(id) => vec![0x40, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8],
        Packet::Pubrec(id) => vec![0x50, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8],
        Packet::Pubrel(id) => vec![0x62, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8],
        Packet::Pubcomp(id) => vec![0x70, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8],
        Packet::Subscribe(subscribe) => encode_subscribe(subscribe),
        Packet::Suback(suback) => encode_suback(suback),
        Packet::Unsubscribe(unsubscribe) => encode_unsubscribe(unsubscribe),
        Packet::Unsuback(id) => vec![0xB0, 0x02, (*id >> 8) as u8, (*id & 0xFF) as u8],
        Packet::Pingreq => vec![0xC0, 0x00],
        Packet::Pingresp => vec![0xD0, 0x00],
        Packet::Disconnect => vec![0xE0, 0x00],
    };
    Ok(bytes)
}

/// Write a packet to an async writer. Used by the writer actor for control
/// packets.
pub async fn write_packet<W: HotaruWrite<Error = std::io::Error> + Unpin + Send>(
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
pub async fn write_publish_packet<W: HotaruWrite<Error = std::io::Error> + Unpin + Send>(
    writer: &mut W,
    packet: &PublishPacket,
) -> Result<(), MqttError> {
    // Validate before committing a single byte: refusing after a partial
    // write would leave half a frame on the wire.
    let packet_id = validate_publish_for_encode(packet).map_err(MqttError::Codec)?;

    // Build header + variable header into a small buffer; payload streamed
    // separately from the Bytes directly.
    let topic_bytes = packet.topic.as_bytes();
    let mut var_header_len = 2 + topic_bytes.len();
    if packet_id.is_some() {
        var_header_len += 2;
    }
    let body_len = var_header_len + packet.payload.len();
    if body_len > MQTT_SPEC_MAX_PACKET_SIZE {
        return Err(MqttError::Codec(CodecError::BodyTooLong {
            len: body_len,
            max: MQTT_SPEC_MAX_PACKET_SIZE,
        }));
    }

    let mut header = Vec::with_capacity(1 + 4 + var_header_len);
    let flags = pack_publish_flags(packet);
    header.push(((PacketType::Publish as u8) << 4) | flags);
    header.extend(encode_remaining_length(body_len));
    header.extend_from_slice(&(topic_bytes.len() as u16).to_be_bytes());
    header.extend_from_slice(topic_bytes);
    if let Some(packet_id) = packet_id {
        header.extend_from_slice(&packet_id.to_be_bytes());
    }

    writer.write_all(&header).await?;
    writer.write_all(&packet.payload[..]).await?;
    Ok(())
}

// ----------------------------------------------------------------------------
// Message impl — connects Packet to hotaru_core's protocol Message trait
//
// Lives here rather than in `packet` so the data definitions stay free of any
// dependency on the codec: `codec -> packet` is the intended direction.
// ----------------------------------------------------------------------------

impl Message for Packet {
    type BytesMut = BytesMut;
    /// 0.8.5's `Message` names its error instead of boxing it. `Infallible`
    /// is for impls that cannot fail; a wire codec is the opposite of that.
    type Error = MqttError;

    fn encode(&self, buf: &mut Self::BytesMut) -> Result<(), Self::Error> {
        buf.extend_from_slice(&encode_packet(self).map_err(MqttError::Codec)?);
        Ok(())
    }

    /// The framework's `Message::decode` signature carries no configuration,
    /// so there is no per-connection `MqttSafety` to read here. It applies the
    /// default cap rather than the spec ceiling: this path is not reachable
    /// with an operator's chosen value, and defaulting to "whatever the wire
    /// format can express" would leave a 256 MiB hole beside a 1 MiB door.
    fn decode(buf: &mut Self::BytesMut) -> Result<Option<Self>, Self::Error> {
        decode_packet_from_bytes(buf, MqttSafety::new().max_packet_size())
    }
}
