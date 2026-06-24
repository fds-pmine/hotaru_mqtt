//! mosquitto_pub / mosquitto_sub interop regression — 5 hard-constraint
//! scenarios from `HANDOFF_STATUS.md §8.2` that MUST NOT regress per phase.
//!
//! Tests spawn the real Eclipse mosquitto CLI clients against the in-process
//! `Broker` + `MqttServerProtocol` and assert message flow. Skipped (with a
//! stderr note) when mosquitto is not installed — local-only by default; CI
//! gating is via `MOSQUITTO_INTEROP=1`.

use std::sync::Arc;
use std::time::Duration;

use hotaru_core::app::common::RuntimeConfig;
use hotaru_core::executable::registry::ProtocolEntryRegistry;
use hotaru_core::executable::{ProtocolEntryBuilder, ProtocolRegistryBuilder};
use hotaru_core::extensions::Locals;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::time::timeout;

use hotaru_mqtt_broker::{BROKER_STATICS_KEY, Broker, MQTT_SERVER};

// ----------------------------------------------------------------------------
// Broker boot — same shape as integration.rs::start_broker
// ----------------------------------------------------------------------------

async fn start_broker() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let broker = Broker::<TcpStream>::insecure();

    let registry: ProtocolEntryRegistry<hotaru_core::connection::tcp::TcpTransport> =
        ProtocolRegistryBuilder::new()
            .protocol(ProtocolEntryBuilder::new(MQTT_SERVER::new()))
            .build();
    let registry = Arc::new(registry);

    let mut statics = Locals::new();
    statics.set(BROKER_STATICS_KEY, broker.clone());
    let runtime = Arc::new(RuntimeConfig::from_parts(
        Default::default(),
        Default::default(),
        statics,
    ));

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let registry = registry.clone();
                    let runtime = runtime.clone();
                    tokio::spawn(async move {
                        registry.serve(runtime, stream).await;
                    });
                }
                Err(_) => break,
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    port
}

// ----------------------------------------------------------------------------
// mosquitto presence detection
// ----------------------------------------------------------------------------

async fn mosquitto_available() -> bool {
    // mosquitto_pub --help exits 0 when installed.
    Command::new("mosquitto_pub")
        .arg("--help")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

macro_rules! skip_if_no_mosquitto {
    () => {
        if !mosquitto_available().await {
            eprintln!(
                "[skip] mosquitto_pub / mosquitto_sub not in PATH — install Eclipse mosquitto CLI to run interop"
            );
            return;
        }
    };
}

// ----------------------------------------------------------------------------
// Subprocess helpers
// ----------------------------------------------------------------------------

/// Spawn `mosquitto_sub -t <filter> -C 1 -W 5 -q <qos>` with stdout piped.
/// Returns the child handle; caller calls `wait_with_output` to collect.
fn spawn_sub(port: u16, filter: &str, qos: u8) -> tokio::process::Child {
    Command::new("mosquitto_sub")
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-t",
            filter,
            "-C",
            "1",
            "-W",
            "5",
            "-q",
            &qos.to_string(),
            "-i",
            &format!("interop-sub-{}", rand_suffix()),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mosquitto_sub")
}

/// Fire one `mosquitto_pub -t <topic> -m <payload> -q <qos>` to the broker.
async fn run_pub(port: u16, topic: &str, payload: &str, qos: u8) {
    let status = Command::new("mosquitto_pub")
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-t",
            topic,
            "-m",
            payload,
            "-q",
            &qos.to_string(),
            "-i",
            &format!("interop-pub-{}", rand_suffix()),
        ])
        .status()
        .await
        .expect("spawn mosquitto_pub");
    assert!(status.success(), "mosquitto_pub failed: {:?}", status);
}

/// Crude unique-ish suffix without pulling in the `rand` crate — process id
/// XOR nanos is plenty for a test client_id.
fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("{:x}", nanos ^ std::process::id() as u64)
}

/// Run a single pub/sub exchange and assert the subscriber receives the
/// expected payload on its stdout.
async fn assert_pubsub(port: u16, topic: &str, filter: &str, payload: &str, qos: u8) {
    let sub = spawn_sub(port, filter, qos);

    // Give the subscriber a beat to CONNECT/SUBSCRIBE before publish fires.
    tokio::time::sleep(Duration::from_millis(400)).await;

    run_pub(port, topic, payload, qos).await;

    let out = timeout(Duration::from_secs(8), sub.wait_with_output())
        .await
        .expect("mosquitto_sub wall-clock timeout")
        .expect("mosquitto_sub join");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains(payload),
        "mosquitto_sub did not receive payload {payload:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
}

// ============================================================================
// 5 hard-constraint scenarios
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mosquitto_qos0_fanout() {
    skip_if_no_mosquitto!();
    let port = start_broker().await;
    assert_pubsub(port, "interop/q0", "interop/q0", "hello-q0", 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mosquitto_qos1_fanout() {
    skip_if_no_mosquitto!();
    let port = start_broker().await;
    assert_pubsub(port, "interop/q1", "interop/q1", "hello-q1", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mosquitto_qos2_fanout() {
    skip_if_no_mosquitto!();
    let port = start_broker().await;
    assert_pubsub(port, "interop/q2", "interop/q2", "hello-q2", 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mosquitto_wildcard_plus() {
    skip_if_no_mosquitto!();
    let port = start_broker().await;
    assert_pubsub(port, "sensors/floor1/temp", "sensors/+/temp", "23.4", 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mosquitto_wildcard_hash() {
    skip_if_no_mosquitto!();
    let port = start_broker().await;
    assert_pubsub(port, "sensors/floor3/2/temp", "sensors/#", "deep-match", 0).await;
}

// ============================================================================
// Bonus — multi-subscriber fanout via mosquitto
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn mosquitto_multi_subscriber_fanout() {
    skip_if_no_mosquitto!();
    let port = start_broker().await;

    let mut subs = Vec::with_capacity(3);
    for _ in 0..3 {
        subs.push(spawn_sub(port, "broadcast/topic", 0));
    }

    tokio::time::sleep(Duration::from_millis(400)).await;

    run_pub(port, "broadcast/topic", "to-all", 0).await;

    for (i, sub) in subs.into_iter().enumerate() {
        let out = timeout(Duration::from_secs(8), sub.wait_with_output())
            .await
            .unwrap_or_else(|_| panic!("sub {i} timeout"))
            .unwrap_or_else(|e| panic!("sub {i} join: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stdout.contains("to-all"),
            "sub {i} missed broadcast\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
}
