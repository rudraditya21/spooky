# Spooky Development Roadmap

The goal is to turn spooky into a production-ready HTTP/3 load balancer that terminates QUIC, balances HTTP/3 streams across HTTP/2 backends, and stays observable under pressure. The roadmap below lays out the phases, timelines, and deliverables so the work stays predictable.

| Phase | Name | Duration | Key Deliverables |
| --- | --- | --- | --- |
| 0 | Foundation & Scope | Week 0 | Requirements, guardrails, architecture baseline |
| 1 | QUIC Edge Prototype | Weeks 1–2 | QUIC listener, stream envelopes, baseline telemetry |
| 2 | Stream Router & Policy Core | Weeks 3–4 | Router, policy engine, config hot-reload |
| 3 | HTTP/2 Upstream Plane | Weeks 5–7 | Connection pools, backpressure, retries |
| 4 | Observability & Control | Weeks 8–9 | Metrics, tracing, control endpoints |
| 5 | Hardening & Chaos | Weeks 10–11 | Soak tests, chaos harness, regression suite |
| 6 | Launch & Enablement | Week 12 | Docs, packaging, narrative alignment |

---

## Phase 0 — Foundation & Scope (Week 0)

**Objectives**

- Confirm the problem statement and success metrics (latency, throughput, error budgets).
- Audit existing claims in README/features to understand mandatory functionality.
- Finalize architectural boundaries and non-negotiables (QUIC termination, load balancing policies, observability expectations).

**Deliverables**

- Requirements doc pairing functional + non-functional goals.
- Risk register noting unknowns (e.g., quiche constraints, UDP limits in target environments).
- Architecture baseline (already started in `docs/codex/architecture.md`).

---

## Phase 1 — QUIC Edge Prototype (Weeks 1–2)

**Objectives**

- Implement the `quiche`-backed QUIC listener with TLS 1.3 and ALPN configured via `config.yaml`.
- Normalize HTTP/3 streams into envelopes the rest of the system can consume (headers, body cursor, trace context).
- Emit baseline telemetry (connections, RTT, loss, handshake failures) to validate the transport layer.

**Deliverables**

- Running binary that accepts HTTP/3 requests and surfaces normalized envelopes through logs/tests.
- Configurable TLS/ALPN support validated with sample certificates.
- Metrics hooks for QUIC health (exported through a temporary endpoint or logs).

---

## Phase 2 — Stream Router & Policy Core (Weeks 3–4)

**Objectives**

- Build the stream router that tracks stream lifecycle, enforces per-stream flow control, and tags idempotency hints.
- Implement the policy engine supporting round-robin, weight-based, IP hash, and EWMA, backed by `config.yaml`.
- Wire up config hot-reloads so load-balancing policies and weights update without restarting the listener.

**Deliverables**

- Router module with tests covering out-of-order stream completion and backpressure scenarios.
- Policy engine with deterministic routing verified via unit tests and property tests where applicable.
- Config watcher that reloads policies safely (with rollback on validation errors).

---

## Phase 3 — HTTP/2 Upstream Plane (Weeks 5–7)

**Objectives**

- Implement HTTP/2 connection pools with health checks, warm-up, and graceful degradation logic.
- Map router envelopes onto upstream sessions, respecting HTTP/2 flow control and prioritization.
- Handle retries with idempotency tagging; ensure non-idempotent requests surface failures immediately rather than silently replaying.

**Deliverables**

- Pool manager with health monitoring and automatic ejection/rejoin of unhealthy backends.
- Backpressure mechanism coupling QUIC flow control with HTTP/2 windows to avoid runaway buffering.
- End-to-end demo: HTTP/3 client → spooky → multiple HTTP/2 backends with policy selection and response streaming.

---

## Phase 4 — Observability & Control Plane (Weeks 8–9)

**Objectives**

- Expose structured metrics for QUIC (loss, RTT, congestion), load balancing (per-policy distribution, pending queue depth), and upstream health.
- Integrate tracing spans/payloads so individual streams can be followed end-to-end.
- Provide administrative surfaces: `/metrics`, `/health`, and a control endpoint for safe config reloads/feature toggles.

**Deliverables**

- Metrics exporter (Prometheus or similar) plus dashboards for operators.
- Tracing integration (e.g., OpenTelemetry) with documented context propagation.
- Control-plane APIs/scripts for config reloads and policy validation.

---

## Phase 5 — Hardening & Chaos (Weeks 10–11)

**Objectives**

- Stress-test under packet loss, reordering, and connection migration scenarios; capture mitigations for each failure.
- Run soak tests to confirm no leaks or performance regressions over multi-day runs.
- Build a regression suite covering critical paths (QUIC admission, routing, retries, observability).

**Deliverables**

- Chaos harness/scripts that can be rerun before releases.
- Documentation of failure modes, detection signals, and remediation playbooks.
- Automated CI jobs running regression suites and reporting on latency/error budgets.

---

## Phase 6 — Launch & Enablement (Week 12)

**Objectives**

- Polish public-facing artifacts: README, architecture doc, development plan, and sample configurations.
- Package binaries/containers with reproducible builds and signing where needed.
- Craft the narrative for talks, proposals, and onboarding docs—why spooky exists, how it works, how to operate it.

**Deliverables**

- Tagged release (v1.0.0) with changelog and artifacts.
- Operator guide describing deployment, monitoring, and troubleshooting.
- Slide/paper-ready story that aligns technical outcomes with reviewer/operator expectations.

---

## Ongoing Workstreams (Parallel to Phases)

- **Security:** Regular TLS/certificate rotation testing, QUIC fuzzing, dependency audits.
- **Documentation:** Keep codex docs, architecture diagrams, and usage examples fresh as features land.
- **Community/Feedback:** Collect operator feedback, triage issues, and prioritize incremental improvements post-launch.
