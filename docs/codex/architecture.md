# Spooky Architecture (Codex)

## Overview

The new spooky build terminates QUIC at the edge with `quiche`, translates HTTP/3 streams into HTTP/2 requests, and steers them across a pool of upstream connections. Configuration stays declarative in `config.yaml`, so swapping balancing policies or upstream weights never requires a recompile. The architecture keeps the control plane (config + telemetry) away from the hot data path, which stays fully async and zero-copy where possible.

## Components

1. **QUIC Edge Listener** — Listens on UDP, handles TLS 1.3, ALPN, and manages the lifecycle of HTTP/3 streams.
2. **Stream Router** — Maps HTTP/3 stream IDs to logical requests, enforces per-stream flow control, and tags metadata needed by the balancer.
3. **Policy-Driven Balancer** — Applies the algorithm declared in config (RR, EWMA, consistent hashing, fallback) and emits routing decisions plus retry guidance.
4. **HTTP/2 Connection Pool** — Maintains warm H2 sessions to each upstream, multiplexes routed requests, and handles backpressure + retries.
5. **Telemetry + Control Plane** — Ships metrics (loss, RTT, 5xx, retry counts) and watches config updates; reloads policies without tearing down listener sockets.

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
