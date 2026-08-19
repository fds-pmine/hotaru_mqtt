//! Packet encoders: `Packet` -> wire bytes.



use crate::packet::{
    ConnackPacket, ConnectFlags, ConnectPacket, FixedHeaderFlags,
    PacketType, PublishPacket, SubackPacket, SubscribePacket,
    UnsubscribePacket,
};
use crate::request::QoS;

use super::primitives::{write_arc_str, write_bytes};
use super::varint::encode_remaining_length;

pub(super) fn encode_connect(conn: &ConnectPacket) -> Vec<u8> {
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

pub(super) fn encode_connack(ack: &ConnackPacket) -> Vec<u8> {
    vec![
        (PacketType::Connack as u8) << 4,
        0x02,
        if ack.session_present { 0x01 } else { 0x00 },
        ack.return_code.as_u8(),
    ]
}

pub(super) fn encode_publish(p: &PublishPacket) -> Vec<u8> {
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

pub(super) fn encode_subscribe(s: &SubscribePacket) -> Vec<u8> {
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

pub(super) fn encode_suback(s: &SubackPacket) -> Vec<u8> {
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

pub(super) fn encode_unsubscribe(u: &UnsubscribePacket) -> Vec<u8> {
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

pub(super) fn pack_publish_flags(p: &PublishPacket) -> u8 {
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
