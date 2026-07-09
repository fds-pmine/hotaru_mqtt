//! `MqttChannel` — Arc-backed cheap-clone handle to one MQTT connection.
//!
//! Internal layout per BCH design:
//! - `reader`: single-take `Arc<Mutex<Option<...>>>`; handle_*_loop owns it
//! - `cmd_tx`: writer actor input — drained via the public `send_cmd` /
//!   `send_packet` / `send_publish` helpers; one queue per connection
//! - `session`: `Arc<MqttSession>` — logical state, may outlive channel (M phase)
//! - `open` / `shutdown`: lifecycle signals
//!
//! All wire writes flow through the writer actor via `cmd_tx`. Reader is owned
//! by whoever takes it first (typically the `Protocol::handle` loop).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use event_listener::Event;
use hotaru_core::app::runtime::{AsyncMutexCap, Either, RuntimeSpec};
use hotaru_core::connection::{ConnMeta, ConnStream, HotaruRead, HotaruWrite};
use hotaru_core::protocol::{Channel, ProtocolRole};
use hotaru_rt_tokio::TokioRuntime;

use crate::codec::{write_packet, write_publish_packet};
use crate::error::MqttError;
use crate::packet::{Packet, ProtocolVersion, PublishPacket};
use crate::session::MqttSession;

// ----------------------------------------------------------------------------
// Connection-id global counter (Q decision: u64 + AtomicU64)
// ----------------------------------------------------------------------------

static CONNECTION_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn next_connection_id() -> u64 {
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

pub struct MqttChannel<W: ConnStream, Rt: RuntimeSpec = TokioRuntime> {
    // ── Physical wire ───────────────────────────────────────────
    reader: Arc<Rt::AsyncMutex<Option<<W::ReadHalf as HotaruRead>::Buffered>>>,
    /// Writer actor's input — **bounded** (capacity from caller's `MqttSafety`).
    /// `pub(crate)`; downstream protocol implementations drive it via the
    /// public `send_cmd` / `send_packet` / `send_publish` methods, never
    /// touch the sender directly. Full queue → `MqttError::Backpressure`
    /// (P1.B); slow-consumer policy that translates that into drop-vs-
    /// disconnect lives in `hotaru_mqtt_broker` and gets wired in P3.
    pub(crate) cmd_tx: async_channel::Sender<WriteCmd>,

    // ── Connection metadata ─────────────────────────────────────
    connection_id: u64,
    role: ProtocolRole,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,

    // ── Logical session (may outlive channel under clean_session=false) ──
    session: Arc<MqttSession>,

    // ── Negotiated protocol version ─────────────────────────────
    /// Wire protocol level for this connection (4 = v3.1.1, 5 = v5).
    /// Shared with the writer actor so encodes always match the version
    /// set during the CONNECT handshake. Defaults to v3.1.1.
    version: Arc<AtomicU8>,

    // ── Lifecycle signals ───────────────────────────────────────
    open: Arc<AtomicBool>,
    /// Close broadcast. `event_listener::Event` replaces `tokio::sync::Notify`:
    /// executor-independent, same register-then-notify discipline. Every
    /// wait site pairs `listen()` with an `open` re-check to close the
    /// lost-wakeup window (close() flips `open` before notifying).
    shutdown: Arc<Event>,
}

impl<W: ConnStream, Rt: RuntimeSpec> Clone for MqttChannel<W, Rt> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            cmd_tx: self.cmd_tx.clone(),
            connection_id: self.connection_id,
            role: self.role,
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            session: self.session.clone(),
            version: self.version.clone(),
            open: self.open.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
}

impl<W: ConnStream, Rt: RuntimeSpec> Channel for MqttChannel<W, Rt> {
    fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    fn close(&self) {
        // Idempotent — first caller flips the flag and signals.
        if !self.open.swap(false, Ordering::AcqRel) {
            return;
        }
        // Notify writer actor to exit (drains in-flight commands first).
        self.shutdown.notify(usize::MAX);
        // MVP: tear down session inflight on channel close. M phase
        // (clean_session=false) will skip this so session can rebind.
        self.session.abandon();
    }
}

impl<W: ConnStream, Rt: RuntimeSpec> MqttChannel<W, Rt> {
    /// Construct a new channel, spawn its writer actor, and stash the reader
    /// for `take_reader`. Called from `Protocol::open_channel` implementations
    /// in any downstream protocol crate, client or server.
    ///
    /// `cmd_buffer_size` bounds the writer actor's input queue
    /// (`MqttSafety.max_queued_messages()`). A producer overrunning it gets
    /// `MqttError::Backpressure`.
    pub fn new(
        reader: <W::ReadHalf as HotaruRead>::Buffered,
        writer: <W::WriteHalf as HotaruWrite>::Buffered,
        meta: &W::Meta,
        role: ProtocolRole,
        cmd_buffer_size: usize,
    ) -> Self
    where
        W::WriteHalf: HotaruWrite,
    {
        let (cmd_tx, cmd_rx) = async_channel::bounded(cmd_buffer_size.max(1));
        let open = Arc::new(AtomicBool::new(true));
        let shutdown = Arc::new(Event::new());
        let session = MqttSession::new();
        let version = Arc::new(AtomicU8::new(ProtocolVersion::default().level()));

        // Spawn the writer actor — single owner of W::WriteHalf. Spawned
        // through the runtime spec, never a concrete executor.
        Rt::spawn_detached(writer_actor::<W, Rt>(
            writer,
            cmd_rx,
            shutdown.clone(),
            open.clone(),
            version.clone(),
        ));

        Self {
            reader: Arc::new(Rt::AsyncMutex::new(Some(reader))),
            cmd_tx,
            connection_id: next_connection_id(),
            role,
            local_addr: meta.local_addr(),
            remote_addr: meta.remote_addr(),
            session,
            version,
            open,
            shutdown,
        }
    }

    /// Record the protocol version negotiated on CONNECT. Client side sets
    /// this from its config before sending CONNECT; broker side sets it
    /// from the parsed CONNECT before replying CONNACK. The writer actor
    /// picks it up on the next encode.
    pub fn set_protocol_version(&self, version: ProtocolVersion) {
        self.version.store(version.level(), Ordering::Release);
    }

    /// The protocol version negotiated for this connection.
    pub fn protocol_version(&self) -> ProtocolVersion {
        ProtocolVersion::from_level(self.version.load(Ordering::Acquire)).unwrap_or_default()
    }

    /// Take ownership of the reader. Returns `None` on subsequent calls.
    ///
    /// Called once by the `Protocol::handle` loop at startup. Channel clones
    /// held elsewhere cannot read — they only push commands.
    pub async fn take_reader(&self) -> Option<<W::ReadHalf as HotaruRead>::Buffered> {
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
        self.session.bind.client_id()
    }

    pub fn keep_alive(&self) -> Option<u16> {
        self.session.bind.keep_alive()
    }

    /// Send a control packet through the writer actor. Non-blocking:
    /// returns `MqttError::Backpressure` on queue-full, `MqttError::ChannelClosed`
    /// if the actor has exited.
    pub fn send_packet(&self, packet: Packet) -> Result<(), MqttError> {
        self.try_send(WriteCmd::Packet(packet))
    }

    /// Send a PUBLISH through the writer actor (optimized path). Non-blocking.
    pub fn send_publish(&self, packet: PublishPacket) -> Result<(), MqttError> {
        self.try_send(WriteCmd::Publish(packet))
    }

    /// Send any `WriteCmd` through the writer actor. General-purpose entry
    /// point for downstream protocol implementations that need to push commands
    /// the specialized `send_packet` / `send_publish` helpers don't cover
    /// (e.g. `Flush`, `Shutdown`). Non-blocking.
    pub fn send_cmd(&self, cmd: WriteCmd) -> Result<(), MqttError> {
        self.try_send(cmd)
    }

    fn try_send(&self, cmd: WriteCmd) -> Result<(), MqttError> {
        use async_channel::TrySendError;
        match self.cmd_tx.try_send(cmd) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(MqttError::Backpressure),
            Err(TrySendError::Closed(_)) => Err(MqttError::ChannelClosed),
        }
    }

    /// Shared close `Event` that fires on `close()`. `handle_*` loops
    /// `listen().await` on this to break early (always re-checking
    /// `is_open` after `listen()` to avoid the lost-wakeup window).
    /// Exposed `pub` so downstream dispatchers can react to shutdown.
    pub fn shutdown_signal(&self) -> Arc<Event> {
        self.shutdown.clone()
    }
}

// ----------------------------------------------------------------------------
// Writer actor task
// ----------------------------------------------------------------------------

async fn writer_actor<W: ConnStream, Rt: RuntimeSpec>(
    mut writer: <W::WriteHalf as HotaruWrite>::Buffered,
    cmd_rx: async_channel::Receiver<WriteCmd>,
    shutdown: Arc<Event>,
    open: Arc<AtomicBool>,
    version: Arc<AtomicU8>,
) where
    W::WriteHalf: HotaruWrite,
{
    loop {
        let ver = ProtocolVersion::from_level(version.load(Ordering::Acquire)).unwrap_or_default();
        // Register the listener BEFORE re-checking `open`: close() flips
        // `open` first and notifies second, so either we observe the flag
        // here or the listener catches the notification — no lost wakeup.
        let closed = shutdown.listen();
        if !open.load(Ordering::Acquire) {
            drain_queued::<W, Rt>(&mut writer, &cmd_rx, ver).await;
            break;
        }
        match Rt::select2(cmd_rx.recv(), closed).await {
            Either::Left(cmd) => {
                match cmd {
                    // 0.8.3: the write half is the transport's Buffered form
                    // (`into_buf_write`), so bytes sit in the buffer until
                    // flushed. Flush after each packet to keep the pre-0.8.3
                    // unbuffered-write semantics (acks must hit the wire now).
                    Ok(WriteCmd::Packet(p)) => {
                        if write_packet(&mut writer, &p, ver).await.is_err() { break; }
                        if writer.flush().await.is_err() { break; }
                    }
                    Ok(WriteCmd::Publish(p)) => {
                        if write_publish_packet(&mut writer, &p, ver).await.is_err() { break; }
                        if writer.flush().await.is_err() { break; }
                    }
                    Ok(WriteCmd::Flush) => {
                        let _ = writer.flush().await;  // W policy §1: shutdown-ish path
                    }
                    // Err(_) = every sender dropped — same end-of-stream
                    // semantics as tokio's `recv() == None`.
                    Ok(WriteCmd::Shutdown) | Err(_) => break,
                }
            }
            Either::Right(()) => {
                // close() contract: "drains in-flight commands first".
                // The refusal path (send CONNACK-refused, then close())
                // depends on this — commands queued before the close
                // still reach the wire.
                drain_queued::<W, Rt>(&mut writer, &cmd_rx, ver).await;
                break;
            }
        }
    }
    // Mark channel closed (idempotent with Channel::close).
    open.store(false, Ordering::Release);
    let _ = writer.shutdown().await; // W policy §1: shutdown path
}

/// Best-effort drain of commands already queued at close() time. Stops on
/// the first write error or an explicit `Shutdown` command; never blocks
/// (only `try_recv`, so nothing enqueued after this point is honoured).
async fn drain_queued<W: ConnStream, Rt: RuntimeSpec>(
    writer: &mut <W::WriteHalf as HotaruWrite>::Buffered,
    cmd_rx: &async_channel::Receiver<WriteCmd>,
    ver: ProtocolVersion,
) where
    W::WriteHalf: HotaruWrite,
{
    while let Ok(cmd) = cmd_rx.try_recv() {
        match cmd {
            WriteCmd::Packet(p) => {
                if write_packet(writer, &p, ver).await.is_err() { return; }
                if writer.flush().await.is_err() { return; }
            }
            WriteCmd::Publish(p) => {
                if write_publish_packet(writer, &p, ver).await.is_err() { return; }
                if writer.flush().await.is_err() { return; }
            }
            WriteCmd::Flush => {
                let _ = writer.flush().await;
            }
            WriteCmd::Shutdown => return,
        }
    }
}
