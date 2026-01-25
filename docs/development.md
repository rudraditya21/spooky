# Development Guide

This document combines the internal and LLM-oriented development notes into a single source of truth. It reflects the current (work-in-progress) shape of the repository rather than the aspirational proxy module that was removed.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Rust toolchain | `rustup` with Rust 1.70+ |
| Cargo | ships with Rust; needed for builds/tests |
| OpenSSL / LibreSSL | required for local certificate generation |
| curl with HTTP/3 (optional) | useful for smoke tests |

```bash
# Install/upgrade toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustc --version
cargo --version
```

## Project Setup

```bash
git clone <repo-url>
cd spooky
cargo fetch # pre-download deps
```

### Build & Test

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Lint / basic checks
cargo check
cargo clippy

# Unit tests (none yet, but keep the habit)
cargo test
```

## Repository Layout

```
spooky/
├── Cargo.toml
├── config/
│   ├── config.yaml          # default runtime config
│   └── config.sample.yaml
├── docs/                    # architecture, roadmap, internal notes
├── spooky/                  # main application crate
│   └── src/                 # CLI + process bootstrap
├── crates/
│   ├── config/              # serde models, defaults, validation
│   ├── edge/                # QUIC listener built on quiche
│   ├── bridge/              # HTTP/3 headers → HTTP/2 request helper
│   ├── transport/           # HTTP/2 client wrapper (unused yet)
│   ├── lb/                  # Random balancer placeholder
│   └── utils/               # TLS helpers
└── certs/                   # DO NOT COMMIT real keys; regenerate locally
```

### Module Overview

| Module | Status | Notes |
| --- | --- | --- |
| `spooky/src/main.rs` | ✅ | CLI parsing via `clap`, config loading, logger init, spins `spooky_edge::QUICListener` loop. |
| `crates/config` | ✅ | YAML structures, defaults, and validator. `health_check.interval` expects a numeric millisecond value. |
| `crates/edge` | 🚧 | Binds QUIC socket via `quiche` but `poll()` is still a stub; no packets handled yet. |
| `crates/lb` | 🚧 | Random picker skeleton; trait signatures mismatched and not wired into the listener. |
| `crates/bridge` | 🧩 | Converts HTTP/3 headers into an `http::Request<()>`. Needs integration once streams are plumbed through. |
| `crates/transport` | 🧩 | HTTP/2 client built on `hyper`. Not yet invoked. |
| `crates/utils` | ✅ | Loads DER-formatted cert/key pairs for TLS helpers. |

## Development Workflow

1. Create a feature branch (`git checkout -b feature/<name>`).
2. Build and run `cargo check` frequently; the project is unstable and easy to break.
3. Keep documentation aligned with the actual modules—avoid referencing the removed `proxy/` tree.
4. Run tests (even if empty) before opening a PR to ensure dependencies still compile.
5. Update this file or the architecture doc when modules move or new subsystems appear.

### Coding Standards

- 4-space indentation, `rustfmt` defaults.
- `snake_case` for modules/functions, `PascalCase` for types.
- Prefer small, focused modules; add doc comments (`//!`) for new subsystems.
- Log via `log` macros; avoid `println!` except in throwaway binaries/tests.

## Current Implementation Status

**Finished / Working**
- CLI + configuration loader/validator
- env_logger-based logging setup
- TLS loading helper (DER + PKCS#8)

**Partially Implemented**
- QUIC listener (`spooky_edge::QUICListener`) – socket + TLS configuration done, IO loop missing
- Load balancer trait/random picker – compiles only after API reconciliation
- Documentation: high-level architecture reflects the quiche plan but still mentions future pieces

**Not Yet Started**
- HTTP/3 request handling, forwarding into HTTP/2
- Health checking / metrics / observability
- Additional balancers, connection pooling, graceful shutdown, hot reload

## Testing & Debugging Tips

- Use `RUST_LOG=debug` when running binaries to surface validator/log output.
- `cargo run -p spooky -- --config ./config/config.yaml` uses the default config path; point it at temp configs while the YAML schema churns.
- For HTTP/3 clients, `curl --http3` plus `--cacert certs/ca-cert.pem` is the easiest compatibility check once the listener handles traffic.

## Certificate Hygiene

The repo currently contains sample keys for convenience, but long term every developer should:
1. Run `make certs-clean certs-ca` to generate fresh material.
2. Keep only `san.conf` + documentation under version control.
3. Point `config.yaml` at the DER outputs under `certs/`.

Expect this workflow to change once the TLS story is hardened; track updates in `docs/strong-cert.md`.
