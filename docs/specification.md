# Spooky HTTP/3 Load Balancer

## Overview

Spooky is an in-progress HTTP/3 edge proxy written in Rust. The long-term goal is to terminate QUIC at the edge, translate HTTP/3 streams into HTTP/2 requests, and steer them across configurable backends. The current codebase contains the scaffolding (CLI, YAML configuration, TLS bootstrap, modules for bridging to HTTP/2) but the request forwarding logic is not yet wired up.

## Current Capabilities

- **CLI + configuration** – `clap`-based argument parsing with a `--config` flag, YAML loader/validator, and log-level controls.
- **TLS bootstrap** – DER/PKCS#8 loader (`utils::tls`) plus `quiche` listener configuration in `src/edge`.
- **QUIC listener stub** – `edge::QUICListener` binds a UDP socket via `quiche` and prepares HTTP/3 settings; the `poll()` loop is still a placeholder.
- **Random balancer placeholder** – `lb::Random` exists but does not yet conform to a finalized trait signature.
- **HTTP/3 → HTTP/2 bridge pieces** – `bridge::h3_to_h2` and `transport::H2Client` modules exist, waiting to be connected to the listener.
- **Sample HTTP/3 server** – `bins/server.rs` uses Quinn/H3 for local testing and experimentation.

## Features Still Under Construction

- End-to-end request forwarding between HTTP/3 clients and HTTP/2 backends.
- Additional load-balancing algorithms (round-robin, weight-aware, least connections, etc.).
- Backend health checking, circuit breakers, and metrics/telemetry.
- Graceful shutdown, connection pooling, and runtime configuration reload.
- Production-ready documentation (quickstarts, tutorials, operations guides).

## Dependency & License Snapshot

| Dependency | License | Commercial Use | Notes |
|------------|---------|----------------|-------|
| `quiche` | BSD-2-Clause | ✅ Yes | QUIC + HTTP/3 implementation |
| `tokio` | MIT | ✅ Yes | Async runtime |
| `serde` | Apache-2.0/MIT | ✅ Yes | Serialization |
| `serde_yaml` | MIT | ✅ Yes | YAML support |
| `clap` | Apache-2.0/MIT | ✅ Yes | CLI parsing |
| `rustls-pki-types` | Apache-2.0/ISC | ✅ Yes | TLS certificate types |
| `bytes` | MIT | ✅ Yes | Byte utilities |
| `rand` | Apache-2.0/MIT | ✅ Yes | Random number generation |
| `log` | Apache-2.0/MIT | ✅ Yes | Logging |
| `env_logger` | Apache-2.0/MIT | ✅ Yes | Logger implementation |

All dependencies remain permissively licensed, so commercial and closed-source builds are permitted. No copyleft licenses are present.

## Runtime Requirements

- Rust 1.70+
- Linux/macOS/Windows
- Network access for QUIC UDP

## Quick Start

```bash
# Clone repository
git clone <repo-url>
cd spooky

# Build
cargo build --release

# Run with config
./target/release/spooky --config ./config/config.yaml
```
