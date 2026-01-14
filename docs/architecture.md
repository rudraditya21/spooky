# Spooky Architecture (Codex)

## Overview

The new spooky build terminates QUIC at the edge with `quiche`, translates HTTP/3 streams into HTTP/2 requests, and steers them across a pool of upstream connections. Configuration stays declarative in `config.yaml`, so swapping balancing policies or upstream weights never requires a recompile. The architecture keeps the control plane (config + telemetry) away from the hot data path, which stays fully async and zero-copy where possible.

## High-Level Design

```
┌─────────────────┐    ┌─────────────────────┐    ┌────────────────────┐
│ HTTP/3 Client   │ ──▶│ Spooky (QUIC edge)  │ ──▶│ HTTP/2 Backends    │
└─────────────────┘    └─────────────────────┘    └────────────────────┘
         │                      │                          │
         ▼                      ▼                          ▼
┌─────────────────┐    ┌─────────────────────┐    ┌────────────────────┐
│ QUIC Listener   │    │ Stream Router       │    │ HTTP/2 Connection  │
│ (`edge/`)       │    │ (`bridge/`)         │    │ Pool (`transport/`)│
└─────────────────┘    └─────────────────────┘    └────────────────────┘
```

## Components

1. **QUIC Edge Listener** — Listens on UDP, handles TLS 1.3, ALPN, and manages the lifecycle of HTTP/3 streams.
2. **Stream Router** — Maps HTTP/3 stream IDs to logical requests, enforces per-stream flow control, and tags metadata needed by the balancer.
3. **Policy-Driven Balancer** — Applies the algorithm declared in config (RR, EWMA, consistent hashing, fallback) and emits routing decisions plus retry guidance.
4. **HTTP/2 Connection Pool** — Maintains warm H2 sessions to each upstream, multiplexes routed requests, and handles backpressure + retries.
5. **Telemetry + Control Plane** — Ships metrics (loss, RTT, 5xx, retry counts) and watches config updates; reloads policies without tearing down listener sockets.

### Source Layout

| Path | Responsibility | Current Notes |
| --- | --- | --- |
| `src/main.rs` | CLI + bootstrap | Parses flags, loads YAML config, initializes logging, spawns the listener loop. |
| `src/config` | Config structs/defaults/validator | Ensures TLS paths, backend IDs, and load-balancing mode are sane before boot. |
| `src/edge` | QUIC listener built on `quiche` | Binds UDP socket, configures TLS. `poll()` is currently a stub awaiting packet handling. |
| `src/bridge` | HTTP/3 header normalization | Converts QPACK-decoded headers (`quiche::h3::NameValue`) into `http::Request<()>` for reuse by the H2 client. |
| `src/transport` | HTTP/2 client wrapper (`hyper`) | Creates HTTP/2-only clients to reach existing infrastructure. Integration pending. |
| `src/lb` | Load-balancing trait + algorithms | `Random` exists as a placeholder; other strategies/health integration will extend this module. |
| `src/utils` | TLS helpers | Loads DER cert/key pairs and shared crypto helpers used by both the edge and the sample server. |

## Flow

1. QUIC packets land at the edge and are absorbed by the listener.
2. When a stream is promoted to a request, the router turns it into a normalized envelope (headers, body, tracing context).
3. The balancer chooses an upstream channel and annotates the envelope with the target backend + timeout budget.
4. The HTTP/2 pool forwards the request, keeps track of EOStream or errors, and pushes responses back into the original stream in-order.
5. Telemetry sidecars observe each step and push signals for config reloads or circuit-breaking.

## Markdown Diagram

```
┌────────────────────────────────────────────────────────────────┐
│                            spooky                               │
├──────────────────────────────┬──────────────────────────────────┤
│          Data Plane          │          Control Plane           │
│                              │                                  │
│  ┌──────────────┐            │      ┌──────────────────┐        │
│  │ QUIC Listener│◄──────┐    │      │ Config Watcher   │        │
│  └──────┬───────┘       │    │      └──────┬───────────┘        │
│         │HTTP/3 Streams │    │             │ hot-reload         │
│  ┌──────▼───────┐       │    │      ┌──────▼───────────┐        │
│  │ Stream Router│───────┼────┼────► │ Policy Balancer  │        │
│  └──────┬───────┘       │    │      └──────┬───────────┘        │
│         │ envelopes     │    │             │ decisions          │
│  ┌──────▼────────┐      │    │      ┌──────▼───────────┐        │
│  │ HTTP/2 Pool   │──────┼────┼────► │ Telemetry + Trcs │        │
│  └──────┬────────┘      │    │      └────────┬─────────┘        │
│         │ responses     │    │               │ metrics          │
│  ┌──────▼─────┐   ┌─────▼────┐│               │                  │
│  │HTTP/3 Resp │◄──│Backends  ││◄──────────────┘                  │
│  └────────────┘   └──────────┘│                                  │
└───────────────────────────────┴──────────────────────────────────┘
```

The diagram keeps the boundary between the data plane (left) and control plane (right) explicit, showing how config updates and telemetry feedback loop into balancing decisions without blocking the packet path.

## Request Pipeline Details

1. **Connection Establishment** – `edge::QUICListener` accepts UDP packets, drives the `quiche` handshake, and instantiates HTTP/3 sessions.
2. **Request Reception** – HTTP/3 headers flow through QPACK decoding; `bridge::h3_to_h2` maps pseudo-headers into a canonical `http::Request`.
3. **Backend Selection** – `lb::LoadBalancer` picks a backend based on config and future health data; the selection is attached to the in-flight request.
4. **Forwarding & Streaming** – `transport::H2Client` maintains HTTP/2 sessions, streaming request bodies upstream and relaying responses downstream.
5. **Telemetry & Control** – Metrics, errors, and state changes feed into the control plane (config watcher, circuit-breaker policies, optional hot reload).

## State & Concurrency

```rust
struct AppState {
    config: Arc<RwLock<Config>>,
    lb: Arc<dyn LoadBalancer>,
    backends: Arc<BackendPool>,   // future module
}
```

- **Listener task**: awaits UDP packets, hands them to `quiche`, and schedules connection workers on Tokio.
- **Connection tasks**: multiplex HTTP/3 streams, request scheduling, and error propagation.
- **Background tasks (planned)**: health checks, metrics exporters, configuration watchers, TLS rotation.

Shared data uses `Arc` + lock-free structures when possible; write-heavy items (config) sit behind `RwLock` to keep the hot path non-blocking.

## Error Handling & Recovery

```rust
enum ProxyError {
    Config(ConfigError),
    Transport(TransportError),
    Backend(BackendError),
    Protocol(ProtocolError),
}
```

- **Config / bootstrap errors** abort startup before sockets open.
- **Transport/protocol errors** drop the affected stream or connection but keep the listener alive.
- **Backend errors** are surfaced to the balancer, which can retry elsewhere or mark a node unhealthy once health checks land.

This layered recovery keeps the UDP listener resilient even when individual streams fail, and it mirrors how production L7 proxies isolate faults today.
