//! `MqttChannel` — Arc-backed cheap-clone handle to one MQTT connection.
//!
//! Internal layout per BCH design:
//! - `reader`: single-take `Arc<Mutex<Option<...>>>`; handle_*_loop owns it
//! - `cmd_tx`: writer actor input — pub(crate) so broker can fanout directly
//! - `session`: `Arc<MqttSession>` — logical state, may outlive channel (M phase)
//! - `open` / `shutdown`: lifecycle signals
//!
//! All wire writes flow through the writer actor via `cmd_tx`. Reader is owned
//! by whoever takes it first (typically the `Protocol::handle` loop).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hotaru_core::connection::{ConnMeta, ConnStream};
use hotaru_core::protocol::{Channel, ProtocolRole};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, Notify, mpsc};

use crate::codec::{write_packet, write_publish_packet};
use crate::error::MqttError;
use crate::packet::{Packet, PublishPacket};
use crate::session::MqttSession;

// ----------------------------------------------------------------------------
// Connection-id global counter (Q decision: u64 + AtomicU64)
// ----------------------------------------------------------------------------

static CONNECTION_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_connection_id() -> u64 {
    CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ----------------------------------------------------------------------------
// Writer commands
// ----------------------------------------------------------------------------

/// Commands accepted by the writer actor. All wire writes for one channel
/// flow through this single queue, eliminating the global writer mutex.
#[derive(Debug)]
pub enum WriteCmd {
    Packet(Packet),
    Publish(PublishPacket),
    Flush,
    Shutdown,
}

// ----------------------------------------------------------------------------
// MqttChannel
// ----------------------------------------------------------------------------

pub struct MqttChannel<W: ConnStream> {
    // ── Physical wire ───────────────────────────────────────────
    reader: Arc<Mutex<Option<BufReader<W::ReadHalf>>>>,
    /// Writer actor's input. `pub(crate)` so `Broker::publish` can directly
    /// fanout `WriteCmd::Publish(...)` to subscriber channels (G simplification).
    pub(crate) cmd_tx: mpsc::UnboundedSender<WriteCmd>,

    // ── Connection metadata ─────────────────────────────────────
    connection_id: u64,
    role: ProtocolRole,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,

    // ── Logical session (may outlive channel under clean_session=false) ──
    session: Arc<MqttSession>,

    // ── Lifecycle signals ───────────────────────────────────────
    open: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
}

impl<W: ConnStream> Clone for MqttChannel<W> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            cmd_tx: self.cmd_tx.clone(),
            connection_id: self.connection_id,
            role: self.role,
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            session: self.session.clone(),
            open: self.open.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
}

impl<W: ConnStream> Channel for MqttChannel<W> {
    fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    fn close(&self) {
        // Idempotent — first caller flips the flag and signals.
        if !self.open.swap(false, Ordering::AcqRel) {
            return;
        }
        // Notify writer actor to exit (drains in-flight commands first).
        self.shutdown.notify_waiters();
        // MVP: tear down session inflight on channel close. M phase
        // (clean_session=false) will skip this so session can rebind.
        self.session.abandon();
    }
}

impl<W: ConnStream> MqttChannel<W> {
    /// Construct a new channel, spawn its writer actor, and stash the reader
    /// for `take_reader`. Called from `MqttProtocol::open_channel`.
    pub(crate) fn new(
        reader: BufReader<W::ReadHalf>,
        writer: W::WriteHalf,
        meta: &W::Meta,
        role: ProtocolRole,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let open = Arc::new(AtomicBool::new(true));
        let shutdown = Arc::new(Notify::new());
        let session = MqttSession::new();

        // Spawn the writer actor — single owner of W::WriteHalf.
        tokio::spawn(writer_actor::<W>(
            writer,
            cmd_rx,
            shutdown.clone(),
            open.clone(),
        ));

        Self {
            reader: Arc::new(Mutex::new(Some(reader))),
            cmd_tx,
            connection_id: next_connection_id(),
            role,
            local_addr: meta.local_addr(),
            remote_addr: meta.remote_addr(),
            session,
            open,
            shutdown,
        }
    }

    /// Take ownership of the reader. Returns `None` on subsequent calls.
    ///
    /// Called once by the `Protocol::handle` loop at startup. Channel clones
    /// (e.g. broker-held copies) cannot read — they only push commands.
    pub async fn take_reader(&self) -> Option<BufReader<W::ReadHalf>> {
        self.reader.lock().await.take()
    }

    pub fn session(&self) -> &Arc<MqttSession> {
        &self.session
    }

    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }

    pub fn role(&self) -> ProtocolRole {
        self.role
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    pub fn client_id(&self) -> Option<Arc<str>> {
        self.session.bind().client_id()
    }

    pub fn keep_alive(&self) -> Option<u16> {
        self.session.bind().keep_alive()
    }

    /// Send a control packet through the writer actor. Returns
    /// `MqttError::ChannelClosed` if the actor has exited.
    pub fn send_packet(&self, packet: Packet) -> Result<(), MqttError> {
        self.cmd_tx
            .send(WriteCmd::Packet(packet))
            .map_err(|_| MqttError::ChannelClosed)
    }

    /// Send a PUBLISH through the writer actor (optimized path).
    pub fn send_publish(&self, packet: PublishPacket) -> Result<(), MqttError> {
        self.cmd_tx
            .send(WriteCmd::Publish(packet))
            .map_err(|_| MqttError::ChannelClosed)
    }

    /// Shared `Notify` that fires on `close()`. `handle_*` loops `.await`
    /// `notified()` on this to break early.
    pub(crate) fn shutdown_signal(&self) -> Arc<Notify> {
        self.shutdown.clone()
    }
}

// ----------------------------------------------------------------------------
// Writer actor task
// ----------------------------------------------------------------------------

async fn writer_actor<W: ConnStream>(
    mut writer: W::WriteHalf,
    mut cmd_rx: mpsc::UnboundedReceiver<WriteCmd>,
    shutdown: Arc<Notify>,
    open: Arc<AtomicBool>,
) {
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(WriteCmd::Packet(p)) => {
                        if write_packet(&mut writer, &p).await.is_err() { break; }
                    }
                    Some(WriteCmd::Publish(p)) => {
                        if write_publish_packet(&mut writer, &p).await.is_err() { break; }
                    }
                    Some(WriteCmd::Flush) => {
                        let _ = writer.flush().await;  // W policy §1: shutdown-ish path
                    }
                    Some(WriteCmd::Shutdown) | None => break,
                }
            }
            _ = shutdown.notified() => break,
        }
    }
    // Mark channel closed (idempotent with Channel::close).
    open.store(false, Ordering::Release);
    let _ = writer.shutdown().await;   // W policy §1: shutdown path
}
