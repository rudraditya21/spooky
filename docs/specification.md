# Spooky HTTP/3 Load Balancer

## Overview

**Spooky** is a high-performance HTTP/3 load balancer written in Rust. It distributes incoming HTTP/3 requests across multiple backend servers, supporting modern web protocols with enterprise-grade features.

## Core Features

- HTTP/3 protocol support (QUIC transport)
- Load balancing algorithms (random, round-robin, least connections)
- TLS 1.3 encryption
- Backend health monitoring
- Metrics collection
- Configuration via YAML

## Commercial License Analysis

### Dependencies

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

### License Compatibility

All dependencies are compatible with commercial use. No GPL licenses or copyleft restrictions. All dependencies use permissive licenses (Apache-2.0, MIT, ISC) that allow:

- Commercial software development
- Proprietary software
- SaaS offerings
- Closed-source derivatives

## Requirements

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
