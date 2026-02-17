# Spooky

<img 
    src="./spooky.png"
    style="display:block;margin:auto;"
    width="240"
    height="240"
/>

**HTTP/3 load balancer in Rust: terminate QUIC at the edge, serve HTTP/2 backends**

Spooky bridges HTTP/3 clients to HTTP/2 backends. It terminates QUIC connections, converts streams to HTTP/2 requests, and routes them across upstream servers.

---

## Why Spooky?

“Your SaaS API runs behind HTTP/2.
You want HTTP/3 for mobile performance.
Rewriting backend fleet is risky.
Deploy Spooky at edge.
Done.”


HTTP/3 is real, but most backends still speak HTTP/2. Spooky lets you deploy HTTP/3 at the edge without rewriting your entire infrastructure. Built in Rust for performance, safety, and async-first design.

---

## Current Status

**Work in progress.** Core architecture is complete (QUIC termination, stream conversion, modular routing). Request forwarding and load balancing are being wired up.

## Features (Implemented)

- CLI with YAML configuration
- TLS 1.3 with custom certificates
- QUIC listener (quiche-based) (quiche uses BoringSSL and builds it via cmake)
- Modular architecture (edge/bridge/transport)
- Random load balancing (placeholder)
- Health check scaffolding

## Dependencies

```sh
# also install rust

sudo apt update
sudo apt install -y cmake build-essential pkg-config
```

## Quick Start

```bash
# Build
cargo build

# Run spooky with config (QUIC listener starts but forwarding is stubbed)
cargo run -p spooky -- --config ./config/config.yaml
```

## Configuration

[Sample Config File](./config/config.sample.yaml)

```yaml
listen:
    protocol: http3
    port: 9889
    address: "0.0.0.0"
    tls:
        cert: "/path/to/cert.pem" 
        key: "/path/to/key.pem" 

backends:
    -   id: "backend1"
        address: "10.0.1.100:8080"
        weight: 100  # server can have /metric route for weight-based balancing
        health_check:
            path: "/health"
            interval: 5000

load_balancing:
    type: random  # random, round-robin, consistent-hash

log:
  level: info
```

Generate certificates: [Generate](docs/strong-cert.md))

## Testing

```bash
# Full workspace test suite
cargo test

# LB integration tests (requires UDP/TCP sockets)
cargo test -p spooky-edge --test lb_integration

# Multi-node manual LB scripts
./scripts/lb-round-robin.sh
./scripts/lb-consistent-hash.sh
./scripts/lb-random.sh
```

## Architecture

- **Edge** (`crates/edge/`): QUIC listener with quiche
- **Bridge** (`crates/bridge/`): HTTP/3 → HTTP/2 conversion
- **Transport** (`crates/transport/`): HTTP/2 client for backends

See: [docs/architecture.md](docs/architecture.md)

## Development

- [Development Guide](docs/development.md)
- [Roadmap](docs/roadmap.md)
- [References](docs/references.md)

## License

ELv2 - see [LICENSE.md](LICENSE.md)
