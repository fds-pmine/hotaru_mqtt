# hotaru_mqtt

[![Crates.io](https://img.shields.io/crates/v/hotaru_mqtt.svg)](https://crates.io/crates/hotaru_mqtt)
[![Docs.rs](https://docs.rs/hotaru_mqtt/badge.svg)](https://docs.rs/hotaru_mqtt)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)

MQTT 3.1.1 protocol implementation for the [Hotaru](https://github.com/hotaru/hotaru) framework, split across two crates so client / sensor deployments don't pay the broker's compile and runtime cost.

| Crate                 | Role                                                              |
| --------------------- | ----------------------------------------------------------------- |
| `hotaru_mqtt`         | Wire codec, session state, `MqttClientProtocol`, `MqttContext`.   |
| `hotaru_mqtt_broker`  | `Broker`, `MqttServerProtocol`, auth / ACL / tenant / retained traits. Depends on `hotaru_mqtt`. |

A sensor that only needs to PUBLISH / SUBSCRIBE depends on `hotaru_mqtt` alone. A broker host pulls in `hotaru_mqtt_broker`.

> **Status:** pre-1.0 (currently `0.8.3-rc1`). Tracks the `hotaru_core` release cadence; the public API may shift between minor versions. See [`MQTT_PRODUCTION_PLAN.md`](MQTT_PRODUCTION_PLAN.md) for the path to mosquitto-grade Stage A.

## Features

- **MQTT 3.1.1 wire codec** — CONNECT / PUBLISH / SUBSCRIBE / UNSUBSCRIBE / PINGREQ / DISCONNECT + every ack.
- **Broker** with hand-rolled topic-filter matching (spec §4.7.2 `$`-prefix guard), per-subscriber fanout via `MqttChannel`, last-will, self-fanout suppression, multi-protocol coexistence (HTTP + MQTT on one port).
- **Per-connection FIFO fanout coordinator** on the server side and **per-endpoint FIFO dispatcher** on the client side — preserves spec §4.6 publisher ordering under chain latency.
- **Pluggable hooks** — `Authenticator`, `AclChecker`, `TenantResolver`, `RetainedStore`, `SessionStore`. Default impls accept-all / allow-all / single-tenant for tests and dev.
- **Client session** with clean-session toggle, keep-alive, last-will, credentials, initial subscriptions, fallback inbound handler.
- **QoS 0 / 1 / 2** with packet-id tracking via `MqttSession` / `AckSlot`.
- **Zero-copy payloads** on `bytes::Bytes`.
- **Async**, built on Tokio.

## Install

Client / sensor:

```toml
[dependencies]
hotaru_mqtt = "0.8"
hotaru_core = "0.8"
tokio       = { version = "1.28", features = ["full"] }
```

Broker host (pulls `hotaru_mqtt` transitively):

```toml
[dependencies]
hotaru_mqtt_broker = "0.8"
hotaru_core        = "0.8"
tokio              = { version = "1.28", features = ["full"] }
```

## Broker

Register `MQTT_SERVER::new()` as a protocol entry and stash the `Broker` in runtime statics under `BROKER_STATICS_KEY`. The protocol handler reads it from there on each accepted connection.

```rust
use std::sync::Arc;
use hotaru_core::app::common::RuntimeConfig;
use hotaru_core::executable::{ProtocolEntryBuilder, ProtocolRegistryBuilder};
use hotaru_core::extensions::Locals;
use hotaru_mqtt_broker::{BROKER_STATICS_KEY, Broker, MQTT_SERVER};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let broker = Broker::<TcpStream>::new();

    let registry = Arc::new(
        ProtocolRegistryBuilder::new()
            .protocol(ProtocolEntryBuilder::new(MQTT_SERVER::new()))
            .build(),
    );

    let mut statics = Locals::new();
    statics.set(BROKER_STATICS_KEY, broker.clone());
    let runtime = Arc::new(RuntimeConfig::from_parts(
        Default::default(),
        Default::default(),
        statics,
    ));

    let listener = TcpListener::bind("0.0.0.0:1883").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let registry = registry.clone();
        let runtime  = runtime.clone();
        tokio::spawn(async move { registry.serve(runtime, stream).await; });
    }
}
```

Swap the default authenticator out with `Broker::with_authenticator(Arc::new(MyAuth))` to gate CONNECT against your own credential store. Implement `AclChecker` / `TenantResolver` / `RetainedStore` / `SessionStore` for the rest of the policy surface.

## Client

A client session is configured with `MqttClientConfig`, registered into runtime statics under `CLIENT_CONFIG_STATICS_KEY`, and driven by `MQTT::new()`.

```rust
use hotaru_mqtt::{CLIENT_CONFIG_STATICS_KEY, MQTT, MqttClientConfig, QoS};

let config = MqttClientConfig::new("device-42")
    .clean_session(true)
    .keep_alive(60)
    .with_credentials("user", "secret")
    .with_initial_subscribe("sensors/+/temp", QoS::AtLeastOnce);

// Register `config` under CLIENT_CONFIG_STATICS_KEY in your RuntimeConfig
// statics, then run MQTT::new() as a protocol entry against the connection
// to your broker. See hotaru_mqtt_broker/tests/integration.rs for the
// raw-TCP wiring used by the test suite.
```

## Tests

```sh
cargo test --workspace
```

Runs:

- **Core unit tests** — codec round-trips, topic parsing / validation (incl. `$`-prefix detection).
- **Broker unit tests** — filter-match cases including `$`-prefix wildcard guard (spec §4.7.2).
- **Broker integration tests** — raw-TCP end-to-end through `MqttServerProtocol`: QoS 0 / 1 / 2 fanout, wildcards `+` / `#`, self-fanout suppression, last-will, multi-protocol (MQTT + HTTP on one port), spec §4.6 publisher-ordering regression.
- **mosquitto interop** — six scenarios driven by real Eclipse `mosquitto_pub` / `mosquitto_sub` subprocesses. Skipped with a stderr note when mosquitto isn't installed.

## Module layout

### `hotaru_mqtt` (core)

| Module      | Responsibility                                                                  |
| ----------- | ------------------------------------------------------------------------------- |
| `protocol`  | `MqttClientProtocol`, `MQTT` alias, per-endpoint FIFO `EndpointDispatcher`.     |
| `codec`     | MQTT 3.1.1 wire encode / decode.                                                |
| `packet`    | Strongly-typed CONNECT / PUBLISH / SUBSCRIBE / … packet structs.                |
| `channel`   | `MqttChannel<W>` + `WriteCmd` for the per-connection write actor.               |
| `context`   | `MqttContext` carried through request handling.                                 |
| `request`   | `MqttRequest` / `MqttResponse`, QoS, topic filters, will, creds.                |
| `session`   | `MqttSession`, packet-id tracking, `AckSlot`, `tenant_id` slot.                 |
| `client`    | `MqttClientConfig` builder.                                                     |
| `topic`     | Topic / filter parsing + `is_dollar_prefixed_first_segment` helper.             |
| `error`     | `MqttError`, `CodecError`, `Violation`, `TimeoutKind`.                          |
| `transport` | Transport trait glue for `hotaru_core::connection`.                             |

### `hotaru_mqtt_broker` (broker)

| Module      | Responsibility                                                                  |
| ----------- | ------------------------------------------------------------------------------- |
| `broker`    | `Broker`, `SubscriberEntry`, `RetainedMessage`, filter matching with `$` guard. |
| `protocol`  | `MqttServerProtocol`, `MQTT_SERVER` alias, per-connection FIFO fanout worker.   |
| `traits`    | `Authenticator`, `AclChecker`, `TenantResolver`, `RetainedStore`, `SessionStore`. |
| `defaults`  | `AcceptAllAuthenticator`, `AllowAllAclChecker`, `SingleTenantResolver`.         |
| `safety`    | `BrokerSafety` resource limits + `SlowConsumerPolicy`.                          |
| `statics`   | `BROKER_STATICS_KEY` runtime statics constant.                                  |

## Design docs

- [`MQTT_AOI_DESIGN.md`](MQTT_AOI_DESIGN.md) — outpoint / endpoint shape, inbound dispatch, topic matching.
- [`MQTT_PRODUCTION_PLAN.md`](MQTT_PRODUCTION_PLAN.md) — Stage A P0–P8 path to mosquitto-grade production.
- [`MQTT_SPEC_GAPS.md`](MQTT_SPEC_GAPS.md) — severity-ranked audit of spec gaps remaining.
- [`MQTT_FRAMEWORK_TRACE.md`](MQTT_FRAMEWORK_TRACE.md) — deep trace of the Hotaru dispatch pipeline.
- [`HANDOFF_STATUS.md`](HANDOFF_STATUS.md) — current state + next-up plan for continued work.

## License

Licensed under [MIT](https://opensource.org/licenses/MIT)
