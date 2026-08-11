# hotaru_mqtt

[![Crates.io](https://img.shields.io/crates/v/hotaru_mqtt.svg)](https://crates.io/crates/hotaru_mqtt)
[![Docs.rs](https://docs.rs/hotaru_mqtt/badge.svg)](https://docs.rs/hotaru_mqtt)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)

MQTT 3.1.1 broker and client for the [Hotaru](https://github.com/hotaru/hotaru) framework.

`hotaru_mqtt` plugs into `hotaru_core`'s protocol/runtime model and gives you both sides of an MQTT 3.1.1 deployment in one crate: a server-side `Broker` for cross-connection fanout, and a client session driven by `MqttClientConfig`. Wire framing, session state, topic matching, and QoS 0/1/2 flows are all handled internally.

> **Status:** pre-1.0 (currently `0.8.2`). The crate tracks the `hotaru_core` release cadence and the public API may shift between minor versions.

## Features

- MQTT 3.1.1 wire codec (CONNECT, PUBLISH, SUBSCRIBE, UNSUBSCRIBE, PINGREQ, DISCONNECT and their acks).
- Broker with hand-rolled topic-filter matching and per-subscriber fanout via `MqttChannel`.
- Pluggable authentication through the `Authenticator` trait (`AcceptAllAuthenticator` by default).
- Client session with clean-session toggle, keep-alive, last-will, credentials, and initial subscriptions.
- QoS 0 / 1 / 2 with packet-id tracking via `MqttSession` / `AckSlot`.
- Zero-copy payload handling on `bytes::Bytes`.
- Async, built on Tokio (`io-util`, `macros`, `net`, `rt`, `sync`, `time`).

## Install

```toml
[dependencies]
hotaru_mqtt = "0.8"
hotaru_core = "0.8"
tokio       = { version = "1.28", features = ["full"] }
```

## Broker

Register `MQTT::server()` as a protocol entry and stash the `Broker` in runtime statics under `BROKER_STATICS_KEY`. The protocol handler reads it from there on each accepted connection.

```rust
use std::sync::Arc;
use hotaru_core::app::common::RuntimeConfig;
use hotaru_core::executable::{ProtocolEntryBuilder, ProtocolRegistryBuilder};
use hotaru_core::extensions::Locals;
use hotaru_mqtt::{BROKER_STATICS_KEY, Broker, MQTT};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let broker = Broker::<TcpStream>::new();

    let registry = Arc::new(
        ProtocolRegistryBuilder::new()
            .protocol(ProtocolEntryBuilder::new(MQTT::server()))
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

Swap the default authenticator out with `Broker::with_authenticator(Arc::new(MyAuth))` to gate CONNECT against your own credential store.

## Client

A client session is configured with `MqttClientConfig`, registered into runtime statics under `CLIENT_CONFIG_STATICS_KEY`, and driven by `MQTT::client()`.

```rust
use std::sync::Arc;
use hotaru_mqtt::{
    CLIENT_CONFIG_STATICS_KEY, MQTT, MqttClientConfig, QoS,
};

let config = MqttClientConfig::new("device-42")
    .clean_session(true)
    .keep_alive(60)
    .with_credentials("user", "secret")
    .with_initial_subscribe("sensors/+/temp", QoS::AtLeastOnce);

// Register `config` under CLIENT_CONFIG_STATICS_KEY in your RuntimeConfig
// statics, then run MQTT::client() as a protocol entry against the connection
// to your broker. See tests/integration.rs for the wiring.
```

## Examples & tests

End-to-end examples live in [`tests/integration.rs`](tests/integration.rs), which exercises the broker and client against real TCP loopback connections. Run them with:

```sh
cargo test
```

## Internal layout

These are internal modules, not addressable paths. Everything supported is
re-exported at the crate root; `codec` is the one module you can name, for
low-level wire encode/decode.

| Module      | Responsibility                                                   |
| ----------- | ---------------------------------------------------------------- |
| `broker`    | Server-side fanout, subscriber registry, `Authenticator` hook.   |
| `client`    | `MqttClientConfig` builder for client-session startup.           |
| `protocol`  | `MqttProtocol`, `MQTT::server()` / `MQTT::client()` entry points.|
| `codec`     | MQTT 3.1.1 wire encode / decode.                                 |
| `packet`    | Strongly-typed CONNECT / PUBLISH / SUBSCRIBE / … packet structs. |
| `channel`   | `MqttChannel<W>` + `WriteCmd` for the per-connection write loop. |
| `context`   | `MqttContext` carried through request handling.                  |
| `request`   | `MqttRequest` / `MqttResponse`, QoS, topic filters, will, creds. |
| `session`   | `MqttSession`, packet-id tracking, `AckSlot`.                    |
| `topic`     | Topic / filter parsing and validation.                           |
| `error`     | `MqttError`, `CodecError`, `Violation`, `TimeoutKind`.           |

Custom transports are supplied through the protocol's type parameters,
`MqttProtocol<W, TS>`, rather than through a dedicated module.

## License

Licensed under [MIT](https://opensource.org/licenses/MIT)
