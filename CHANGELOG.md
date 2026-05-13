# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Packaging layout cleanup: Debian assets moved under `packaging/deb/` (`make-deb.sh`, systemd unit, default config).
- Installation and Docker docs updated to match current packaging paths and runtime behavior.

## [0.1.0-beta] - 2026-05-12

Initial release of Spooky HTTP/3 edge proxy and load balancer.

### Core Features

**Protocol Support**
- HTTP/3 termination using quiche (RFC 9114)
- QUIC transport (RFC 9000)
- HTTP/2 backend connectivity (RFC 9113)
- TLS 1.3 with certificate chain loading (RFC 8446)
- TLS bootstrap ingress for HTTP/1.1 + HTTP/2 compatibility and Alt-Svc upgrade flow

**Routing and Load Balancing**
- Upstream pool architecture with per-upstream configuration
- Route matching based on path prefix and host headers with longest-match selection
- Method-aware route matching support (`route.method`)
- Multiple load balancing algorithms: random, round-robin, consistent hashing (64 replicas), least-connections, latency-aware, sticky-cid
- Configurable load-balancing key sourcing (`load_balancing.key`)
- Backend weight configuration for weighted load balancing

**Health Management**
- Active health checking with HTTP probes
- Configurable interval, timeout, failure/success thresholds, and cooldown
- Automatic backend removal and recovery

**Connection Management**
- Connection ID-based routing for QUIC packets
- Prefix matching for Short packets with extended DCIDs
- Peer-based fallback for connection migration scenarios
- Version negotiation packet handling
- Proper 0-RTT handling to prevent crypto failures
- Config-driven graceful shutdown drain timeout

**Ingress and Resilience**
- Sharded ingress dispatch — per-worker UDP sockets for parallel packet processing
- Global route-queue cap with `503 + Retry-After` shedding under overload
- LB fallback, health probe, and streaming timeout semantics
- Panic handling hardened for worker and control-plane tasks

**Bootstrap (HTTP/1.1 + HTTP/2 TCP Path)**
- Dual ingress: QUIC/HTTP3 and TCP/TLS bootstrap for browser compatibility
- Bootstrap path enforces LB strategy and health-aware backend resolution (parity with QUIC path)
- Bootstrap route-resolution parity with QUIC path (host/path/method decision flow)
- Bootstrap path enforces QUIC request policy pipeline (method/path/header policies)
- Bootstrap path enforces downstream mTLS policy
- Bootstrap header sanitization and RFC 7239-compliant IPv6 normalization in `Forwarded`
- Bootstrap connection limiter and per-connection timeout guard
- Bootstrap backend request/response streaming support with deterministic unsupported-upgrade behavior for WebSocket

**Configuration**
- YAML-based configuration with comprehensive validation at startup
- Per-upstream load balancing strategy and embedded routing rules
- Packet shard ingress controls
- `performance.control_plane_threads` applied to startup runtime configuration
- Upstream TLS verification enforced by default; cleartext backends require explicit opt-in
- Downstream mTLS support via `listen.tls.client_auth.*`

**Observability**
- Structured JSON logging with standard and spooky-themed log levels
- Request/response metrics: total requests, successes, failures, timeouts
- Backend selection and health transition logging
- QUIC connection error classification and deduplication

**Control API**
- Bearer token authentication with constant-time comparison
- Metrics endpoint, health and ready probes
- TLS-enabled control-plane listener path support and startup hardening

**Operational**
- Debian package with systemd unit, system user/group, and config at `/etc/spooky/config.yaml`
- Docker packaging with compose bootstrap and operator smoke-test scripts
- CLI with `--config` flag
- Streaming request/response handling with bounded queues and hard body caps
- Deterministic cap-breach behavior via HTTP errors (`413`/`503`) under pressure
- Concurrent connection handling (10,000+ connections tested)
- Per-backend concurrency limiting (64 max in-flight requests)

### Known Limitations

1. No dynamic backend discovery (service discovery remains static config-driven).
2. No configuration hot reload (restart-based config apply model).
3. Project is pre-GA and still requires extended soak/failure-mode hardening for broad production rollout.

See [roadmap](docs/roadmap.md) for planned improvements.

---

## Version Numbering

- **Major version** (X.0.0): Breaking changes to configuration or API
- **Minor version** (0.X.0): New features, non-breaking changes
- **Patch version** (0.0.X): Bug fixes, documentation updates

## Contributing

See [contributing guide](CONTRIBUTING.md) for development guidelines.

## License

Elastic License 2.0 (ELv2) — see [LICENSE.md](LICENSE.md)
