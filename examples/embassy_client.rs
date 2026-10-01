//! Minimal MQTT 3.1.1 client on `hotaru_rt_embassy`, using this crate's
//! public wire codec.
//!
//! Against a broker (default `127.0.0.1:1883`):
//!
//! ```text
//! cargo run --example embassy_client --features embassy-example -- 127.0.0.1:1883
//! ```
//!
//! Without a broker, against the scripted peer at the bottom of this file:
//!
//! ```text
//! cargo run --example embassy_client --features embassy-example -- --self-test
//! ```
//!
//! The client sends CONNECT, waits for CONNACK, sends one QoS 1 PUBLISH, waits
//! for PUBACK, sends DISCONNECT, and exits. It drives the codec directly rather
//! than the Tokio-based `MqttProtocol` session. The runtime setup mirrors the
//! `runtime_tutorial` and `app_tutorial` examples in `hotaru_rt_embassy`; on a
//! board, keep it and swap the desktop socket for the board's network driver.

use std::error::Error;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use hotaru_core::app::runtime::RuntimeSpec;
use hotaru_mqtt::{
    Bytes, BytesMut, ConnackReturnCode, ConnectPacket, MqttError, Packet, PublishPacket, QoS, codec,
};

type ClientResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PACKET_SIZE: usize = 64 * 1024;
const TOPIC: &str = "hotaru/embassy-example";
const PAYLOAD: &[u8] = b"hello from Embassy";

// One runtime type, its static storage, and a pool of Embassy worker tasks.
hotaru_rt_embassy::define_runtime_worker_pool!(
    pub ClientRuntime,
    worker_count = 1,
    job_queue_capacity = 1,
);

#[embassy_executor::main]
async fn main(spawner: embassy_executor::Spawner) {
    // Initialize before calling any Hotaru API that spawns a task.
    ClientRuntime::init(spawner);
    let result = run().await;
    match &result {
        Ok(()) => println!("embassy_client: CONNECT/CONNACK and QoS 1 PUBLISH/PUBACK completed"),
        Err(error) => eprintln!("embassy_client: {error}"),
    }
    // The std Embassy executor keeps running after the entry task returns.
    std::process::exit(i32::from(result.is_err()));
}

async fn run() -> ClientResult<()> {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| "127.0.0.1:1883".into());
    if args.next().is_some() {
        return Err("usage: embassy_client [HOST:PORT | --self-test]".into());
    }
    let (address, peer) = if target == "--self-test" {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        (
            address,
            Some(std::thread::spawn(move || scripted_peer(listener))),
        )
    } else {
        (target.parse::<SocketAddr>()?, None)
    };
    // Blocking socket with timeouts: the std Embassy executor is single-threaded,
    // so a blocked read also parks the runtime's timers; the socket timeout is
    // the deadline here.
    // ponytail: fine for one short desktop exchange; sustained traffic or more
    // than one task needs an async network driver (embassy-net) instead.
    let stream = TcpStream::connect_timeout(&address, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    // The MQTT exchange runs as a Hotaru job on an Embassy worker; `spawn`
    // returns a join handle that yields the job's result.
    let result = ClientRuntime::spawn(async move { session(stream) }).await?;
    if let Some(peer) = peer {
        peer.join().map_err(|_| "scripted peer panicked")??;
    }
    result
}

fn session(mut stream: TcpStream) -> ClientResult<()> {
    let mut incoming = BytesMut::new();
    send(
        &mut stream,
        Packet::Connect(ConnectPacket {
            client_id: "embassy-example".into(),
            clean_session: true,
            keep_alive: 15,
            username: None,
            password: None,
            will: None,
        }),
    )?;
    match receive(&mut stream, &mut incoming)? {
        Packet::Connack(ack) if ack.return_code == ConnackReturnCode::Accepted => {
            println!("CONNACK: accepted, session_present={}", ack.session_present)
        }
        other => return Err(format!("expected an accepting CONNACK, got {other:?}").into()),
    }
    send(
        &mut stream,
        Packet::Publish(PublishPacket {
            topic: TOPIC.into(),
            payload: Bytes::from_static(PAYLOAD),
            dup: false,
            qos: QoS::AtLeastOnce,
            retain: false,
            packet_id: Some(1),
        }),
    )?;
    match receive(&mut stream, &mut incoming)? {
        Packet::Puback(1) => println!("PUBACK: packet id 1 acknowledged"),
        other => return Err(format!("expected PUBACK for packet id 1, got {other:?}").into()),
    }
    send(&mut stream, Packet::Disconnect)
}

fn send(stream: &mut TcpStream, packet: Packet) -> ClientResult<()> {
    let bytes = codec::encode_packet(&packet).map_err(MqttError::Codec)?;
    Ok(stream.write_all(&bytes)?)
}

fn receive(stream: &mut TcpStream, incoming: &mut BytesMut) -> ClientResult<Packet> {
    let mut buffer = [0; 512];
    loop {
        if let Some(packet) = codec::decode_packet_from_bytes(incoming, MAX_PACKET_SIZE)? {
            return Ok(packet);
        }
        match stream.read(&mut buffer)? {
            0 => return Err("peer closed the connection".into()),
            read => incoming.extend_from_slice(&buffer[..read]),
        }
    }
}

// `--self-test` peer: checks the client's exact CONNECT, PUBLISH, and DISCONNECT
// frames and answers with fixed CONNACK and PUBACK bytes. Plain OS thread; the
// client side always runs on Embassy.
fn scripted_peer(listener: TcpListener) -> ClientResult<()> {
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    let exchange: [(&[u8], &[u8]); 3] = [
        (
            b"\x10\x1b\x00\x04MQTT\x04\x02\x00\x0f\x00\x0fembassy-example",
            b"\x20\x02\x00\x00",
        ),
        (
            b"\x32\x2c\x00\x16hotaru/embassy-example\x00\x01hello from Embassy",
            b"\x40\x02\x00\x01",
        ),
        (b"\xe0\x00", b""),
    ];
    for (expected, reply) in exchange {
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received)?;
        if received != expected {
            return Err(format!("unexpected frame from client: {received:02x?}").into());
        }
        stream.write_all(reply)?;
    }
    Ok(())
}
