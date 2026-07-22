# Public API Surface Inventory

Phase 2 inventory for `refactor/public-api-and-visibility-hardening`.

Scope:
- crate `lib.rs` façades
- top-level `mod.rs` files that currently fan out public surface area
- current re-exports and compatibility paths that look broader than the canonical entrypoints

This document is a baseline audit. It does not change visibility yet.

## `spooky-edge`

### Primary façades
- `crates/edge/src/lib.rs`
- `crates/edge/src/quic_listener/mod.rs`
- `crates/edge/src/runtime/mod.rs`
- `crates/edge/src/routing/mod.rs`
- `crates/edge/src/resilience/mod.rs`
- `crates/edge/src/watchdog/mod.rs`

### Current public surface
- `pub mod benchmark`
- `pub mod body`
- `pub mod cid_radix`
- `pub mod constants`
- `pub mod hash`
- `pub mod metrics`
- `pub mod quic_listener`
- `pub mod resilience`
- `pub mod routing`
- `pub mod runtime`
- `pub mod watchdog`
- `pub use body::ChannelBody`
- `pub use hash::{stable_hash_socket_addr, stable_hash64}`
- `pub use metrics::{HealthFailureReason, Metrics, OverloadShedReason, RouteOutcome}`
- `pub use quic_listener::configure_async_runtime`
- `quic_listener/mod.rs` also publicly exposes:
  - `pub mod workers`
  - `pub use runtime_state::ListenerWorkerRuntimeState`
  - `pub use workers::{ListenerWorkerGroupConfig, spawn_listener_worker_group}`

### Likely canonical entrypoints
- `configure_async_runtime`
- listener worker startup types/functions if they are intentionally crate-external
- `Metrics`
- top-level stable hashing helpers if consumed outside `edge`
- `ChannelBody`

### Likely leakage / visibility review targets
- crate-wide public exposure of `runtime`, `routing`, `resilience`, and `watchdog`
- public `benchmark` module
- public `constants` and `cid_radix`
- public `ListenerWorkerRuntimeState`
- `quic_listener` as a large mixed façade instead of a narrow service entrypoint
- top-level `routing` and `resilience` submodules are all `pub mod`, which currently exposes internal policy/mechanics as crate API
- top-level `watchdog` submodules are all `pub mod`, including service/state/time internals

## `spooky-config`

### Primary façades
- `crates/config/src/lib.rs`
- `crates/config/src/runtime/policies/mod.rs`

### Current public surface
- `pub mod backend_endpoint`
- `pub mod config`
- `pub mod default`
- `pub mod loader`
- `pub mod runtime`
- `pub mod validator`
- `runtime/policies/mod.rs` publicly re-exports canonical runtime policy/output types:
  - admission policies
  - auth policies
  - backend policies
  - load-balancing policies
  - resilience policies
  - timeout policies
  - transport policies
  - watchdog policies
- `runtime/policies/mod.rs` also defines and exports:
  - `RuntimeRouteHostPattern`
  - `RuntimeRouteMatchPolicy`
  - `RuntimeBackendTransportKind`
  - `RuntimeUpstreamTransportPolicy`
  - `RuntimePolicySet`
  - `RuntimeListenerPolicySet`
  - `RuntimeUpstreamPolicySet`

### Likely canonical entrypoints
- raw config types under `config`
- loader entrypoints
- validated runtime config/output types under `runtime`
- backend endpoint shape if used cross-crate

### Likely leakage / visibility review targets
- `default` and `validator` as top-level public modules may be broader than needed
- some `runtime/policies/mod.rs` structs may be intermediate interpreter outputs rather than stable consumer-facing API
- route-match normalization types may belong under `runtime` but not necessarily as crate-public guarantees

## `spooky-bridge`

### Primary façade
- `crates/bridge/src/lib.rs`

### Current public surface
- `pub mod h3_to_h1`
- `pub mod h3_to_h2`
- `pub mod request`
- `pub mod response`
- `pub mod websocket`
- `pub use spooky_errors::BridgeError`

### Likely canonical entrypoints
- `request`
- `response`
- `websocket`
- `BridgeError`

### Likely leakage / visibility review targets
- public `h3_to_h1` and `h3_to_h2` modules look implementation-shaped, not policy-surface-shaped
- host/forwarded/header internals are already private; the remaining cleanup target is protocol-specific request builder exposure

## `spooky-errors`

### Primary façade
- `crates/errors/src/lib.rs`

### Current public surface
- `pub mod bridge`
- `pub mod pool`
- `pub mod proxy`
- `pub mod retry`
- `pub mod upstream`
- `pub use bridge::BridgeError`
- `pub use pool::PoolError`
- `pub use proxy::{ClassifiedUpstreamProxyError, ProxyError, UpstreamProxyErrorKind, classify_upstream_proxy_error, classify_upstream_send_error}`
- `pub use retry::{HedgeOutcomeTelemetryReason, HedgePolicyDecision, HedgePolicyDenialReason, HedgePolicyFacts, HedgePrimaryState, HedgeTriggerTelemetryReason, RetryAttemptTelemetryReason, RetryPolicyDecision, RetryPolicyDenialReason, RetryPolicyFacts, UpstreamRetryReason, UpstreamRetryability, UpstreamTerminalErrorKind, classify_retryability, evaluate_hedge_policy, evaluate_retry_policy, is_idempotent_method, is_retryable}`
- `pub use spooky_lb::alternate_backend::{AlternateBackendChoice, AlternateBackendDecision, AlternateBackendFailureReason, AlternateBackendSelectionMode}`
- `pub use upstream::{UpstreamErrorCategory, UpstreamErrorClassification, UpstreamHealthFailureMapping, UpstreamTlsReason, classify_upstream_error_detail}`

### Likely canonical entrypoints
- `ProxyError`
- `PoolError`
- bridge/pool/proxy/upstream shared classifiers
- retry/hedge policy result types if `errors` is intentionally the shared policy surface

### Likely leakage / visibility review targets
- crate re-export of `spooky_lb::alternate_backend::*` crosses ownership boundaries and looks like a compatibility path
- both `pub mod retry` and large `pub use retry::*` surface may be redundant
- crate-level surface mixes true error types with policy evaluators and LB-owned types

## `spooky-lb`

### Primary façades
- `crates/lb/src/lib.rs`
- `crates/lb/src/algorithms/mod.rs`

### Current public surface
- `pub mod algorithms`
- `pub mod alternate_backend`
- `pub mod backend`
- `pub mod backend_pool`
- `pub mod hash`
- `pub mod health`
- `pub mod load_balancing`
- `pub mod upstream_pool`
- `algorithms/mod.rs` publicly exposes:
  - `consistent_hash`
  - `latency_aware`
  - `least_connections`
  - `random`
  - `round_robin`
  - `sticky_cid`

### Likely canonical entrypoints
- `upstream_pool`
- `load_balancing`
- `alternate_backend`
- `health`

### Likely leakage / visibility review targets
- direct public exposure of individual algorithm modules
- `backend` and `backend_pool` may be internal substrate rather than consumer API
- `hash` may be implementation detail unless deliberately shared

## `spooky-transport`

### Primary façade
- `crates/transport/src/lib.rs`

### Current public surface
- private modules:
  - `client_rotation`
  - `h1_client`
  - `h1_pool`
  - `h2_client`
  - `h2_pool`
  - `transport_pool`
- public re-exports from `transport_pool`:
  - `ConnectObservation`
  - `ConnectObserver`
  - `SharedDnsResolver`
  - `TlsClientConfig`
  - `TransportClientRotation`
  - `UpstreamTransportPool`

### Likely canonical entrypoints
- `UpstreamTransportPool`
- `TlsClientConfig`
- `SharedDnsResolver`
- connection observation hooks if used by `edge`

### Likely leakage / visibility review targets
- `TransportClientRotation` may still be more internal than desired after transport abstraction cleanup
- confirm `ConnectObservation` / `ConnectObserver` are intentionally public and not just cross-crate plumbing

## Cross-crate leakage patterns to address next

### 1. Whole-subsystem public modules
Current examples:
- `edge::runtime`
- `edge::routing`
- `edge::resilience`
- `edge::watchdog`
- `lb::algorithms`

These make internal organization look like external API.

### 2. Compatibility re-exports that blur ownership
Current examples:
- `errors` re-exporting `spooky_lb::alternate_backend::*`
- `edge::quic_listener` re-exporting worker/runtime-state details directly

These are the first candidates to replace with narrower canonical entrypoints.

### 3. Implementation-shaped public modules
Current examples:
- `bridge::h3_to_h1`
- `bridge::h3_to_h2`
- individual LB algorithm modules

These expose transport/protocol detail instead of domain contracts.

### 4. Façades that are still too broad
Current examples:
- `edge::quic_listener`
- `config::runtime::policies`

These should stay façades, but the next step should make their outward surfaces more intentional.

## Proposed hardening order

1. `edge`
2. `config`
3. `bridge`
4. `errors`
5. `lb`
6. `transport`

Reason:
- `edge` and `config` currently define the broadest visible internal surface.
- `bridge`, `errors`, `lb`, and `transport` mostly need narrowing and ownership cleanup, not structural discovery.
