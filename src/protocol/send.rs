//! The outbound send path, shared by both roles.
//!
//! `Protocol::send` lands in `send_impl` no matter which role opened the
//! connection: a broker publishing to a subscriber and a client publishing to
//! a broker run the same ack bookkeeping over the same session tables. One
//! copy rather than two is what #64 and #80 were about — divergent
//! implementations of this path are how the ack-routing defects arose.

use std::sync::Arc;

use hotaru_core::connection::{ConnStream, TransportSpec};
use tokio::time::timeout;

use crate::channel::MqttChannel;
use crate::context::MqttContext;
use crate::error::{MqttError, TimeoutKind};
use crate::packet::*;
use crate::request::*;
use crate::session::AckKind;

use super::*;

// ============================================================================
// Protocol::send — outpoint outbound execution
// ============================================================================

pub(super) async fn send_impl<TS>(mut ctx: MqttContext<TS>) -> Result<MqttContext<TS>, MqttError>
where
    TS: TransportSpec,
{
    let channel = ctx
        .channel()
        .cloned()
        .ok_or(MqttError::NotConnected("no channel installed in ctx".into()))?;

    let request = std::mem::replace(
        &mut ctx.request,
        MqttRequest::Publish(PublishRequest::default()),
    );

    let response = match request {
        MqttRequest::Publish(req) => send_publish(&channel, req).await?,
        MqttRequest::Subscribe(filters) => send_subscribe(&channel, filters).await?,
        MqttRequest::Unsubscribe(topics) => send_unsubscribe(&channel, topics).await?,
    };

    ctx.response = response;
    Ok(ctx)
}

async fn send_publish<W: ConnStream>(
    channel: &MqttChannel<W>,
    req: PublishRequest,
) -> Result<MqttResponse, MqttError> {
    let packet_id = if req.qos != QoS::AtMostOnce {
        Some(channel.session().allocate_packet_id())
    } else {
        None
    };

    let packet = PublishPacket {
        topic: req.topic,
        payload: req.payload,
        dup: false,
        qos: req.qos,
        retain: req.retain,
        packet_id,
    };

    match req.qos {
        QoS::AtMostOnce => {
            channel.send_publish(packet)?;
            Ok(MqttResponse::Published(PublishAck::Sent))
        }
        QoS::AtLeastOnce => {
            let packet_id = packet_id.expect("alloc'd above");
            let puback_received = channel
                .session()
                .park_publish_ack_waiter(packet_id, AckKind::Puback);
            channel.send_publish(packet)?;
            let acknowledged_id = timeout(DEFAULT_ACK_TIMEOUT, puback_received)
                .await
                .map_err(|_timed_out| {
                    channel.session().cancel_ack_waiter(packet_id);
                    MqttError::Timeout(TimeoutKind::Ack)
                })?
                .map_err(|_sender_dropped| MqttError::ChannelClosed)?;
            Ok(MqttResponse::Published(PublishAck::Acknowledged(acknowledged_id)))
        }
        QoS::ExactlyOnce => {
            let packet_id = packet_id.expect("alloc'd above");
            // Two-phase: PUBREC first, then PUBCOMP after we send PUBREL.
            let pubrec_received = channel
                .session()
                .park_publish_ack_waiter(packet_id, AckKind::Pubrec);
            channel.send_publish(packet)?;
            timeout(DEFAULT_ACK_TIMEOUT, pubrec_received)
                .await
                .map_err(|_timed_out| {
                    channel.session().cancel_ack_waiter(packet_id);
                    MqttError::Timeout(TimeoutKind::Ack)
                })?
                .map_err(|_sender_dropped| MqttError::ChannelClosed)?;

            // PUBREL was sent by the inbound dispatch when PUBREC fired.
            // Now wait for PUBCOMP.
            let pubcomp_received = channel
                .session()
                .park_publish_ack_waiter(packet_id, AckKind::Pubcomp);
            let completed_id = timeout(DEFAULT_ACK_TIMEOUT, pubcomp_received)
                .await
                .map_err(|_timed_out| {
                    channel.session().cancel_ack_waiter(packet_id);
                    MqttError::Timeout(TimeoutKind::Ack)
                })?
                .map_err(|_sender_dropped| MqttError::ChannelClosed)?;
            Ok(MqttResponse::Published(PublishAck::Completed(completed_id)))
        }
    }
}

async fn send_subscribe<W: ConnStream>(
    channel: &MqttChannel<W>,
    filters: Vec<TopicFilter>,
) -> Result<MqttResponse, MqttError> {
    let packet_id = channel.session().allocate_packet_id();
    let suback_received = channel.session().park_suback_waiter(packet_id);
    let subs: Vec<TopicSubscription> = filters
        .into_iter()
        .map(|f| TopicSubscription {
            topic: f.filter,
            qos: f.qos,
        })
        .collect();
    channel.send_packet(Packet::Subscribe(SubscribePacket {
        packet_id,
        subscriptions: subs,
    }))?;
    let return_codes = timeout(DEFAULT_ACK_TIMEOUT, suback_received)
        .await
        .map_err(|_timed_out| {
            channel.session().cancel_ack_waiter(packet_id);
            MqttError::Timeout(TimeoutKind::Ack)
        })?
        .map_err(|_sender_dropped| MqttError::ChannelClosed)?;
    Ok(MqttResponse::Subscribed(return_codes))
}

async fn send_unsubscribe<W: ConnStream>(
    channel: &MqttChannel<W>,
    topics: Vec<Arc<str>>,
) -> Result<MqttResponse, MqttError> {
    let packet_id = channel.session().allocate_packet_id();
    let unsuback_received = channel.session().park_unsuback_waiter(packet_id);
    channel.send_packet(Packet::Unsubscribe(UnsubscribePacket {
        packet_id,
        topics,
    }))?;
    timeout(DEFAULT_ACK_TIMEOUT, unsuback_received)
        .await
        .map_err(|_timed_out| {
            channel.session().cancel_ack_waiter(packet_id);
            MqttError::Timeout(TimeoutKind::Ack)
        })?
        .map_err(|_sender_dropped| MqttError::ChannelClosed)?;
    Ok(MqttResponse::Unsubscribed)
}

