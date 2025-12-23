# HTTP/3 / QUIC Load Balancer – Development Roadmap

This document describes the phased development plan for a production-grade HTTP/3 (QUIC) L7 load balancer implemented in Rust using Quinn, h3, h3-quinn, and rustls.

The roadmap is based on the current implementation state and extends it toward a production-ready, industry-standard system. Each phase defines objectives, concrete deliverables, and the algorithms or mechanisms involved.

---

## Phase 1: Foundation (Completed)

**Status**: Completed  
**Duration**: 2–3 weeks

### Objectives
- Establish project structure and module boundaries
- Select and integrate core dependencies
- Implement configuration system and defaults
- Provide CLI entry point and logging initialization

### Deliverables
- Compilable Rust project with clean module layout
- YAML configuration loading with defaults
- Configuration validation
- CLI interface (`spooky`)
- Logging via `env_logger` with configurable log level

### Notes
- This phase is considered frozen.
- Architectural invariants established here should not change without a design review.

---

## Phase 2: HTTP/3 Proxy Core

**Status**: In progress  
**Duration**: 4–5 weeks

This phase transitions the system from a functional prototype to a structurally correct HTTP/3 L7 proxy.

---

### 2.1 QUIC and HTTP/3 Listener

**Status**: Completed

#### Deliverables
- QUIC endpoint initialization using Quinn
- TLS configuration using rustls
- ALPN configured for `h3`
- HTTP/3 server connection handling using `h3` and `h3-quinn`
- Accept loop for incoming QUIC connections

#### Invariants
- QUIC is terminated at the load balancer
- HTTP/3 is always handled at Layer 7
- No protocol pass-through mode

---

### 2.2 Request Processing and Proxying

**Status**: Completed

#### Deliverables
- Full HTTP/3 request handling
- Streaming of request and response bodies
- Header propagation between client and backend
- Proper error mapping (e.g., 502, 503)

#### Known Limitations
- Backend QUIC client connections are currently created per request

---

### 2.3 Backend Connection Reuse and Pooling

**Status**: Required (Critical)

This is a mandatory step for production readiness.

#### Objectives
- Eliminate per-request QUIC client creation
- Enable stream multiplexing over persistent backend connections
- Reduce handshake latency and resource usage

#### Deliverables
- Shared QUIC client endpoint per load balancer instance
- Persistent QUIC connections per backend
- Backend connection pool abstraction
- Stream acquisition and release per request
- Idle connection reaping

#### Algorithms / Mechanisms
- Round-robin stream allocation within a backend
- Maximum concurrent streams per connection
- Connection health tracking

---

### 2.4 Load Balancing Algorithms (Baseline)

**Status**: Partial

#### Implemented
- Random backend selection

#### To Add
- Round-robin
- Weighted round-robin
- Least-connections

#### Notes
- These algorithms operate independently of health logic
- Backend selection must be abstracted behind a strategy interface

---

### 2.5 Graceful Lifecycle Management

**Status**: Planned

#### Deliverables
- Signal handling (SIGINT, SIGTERM)
- Stop accepting new connections on shutdown
- Drain active streams
- Enforced shutdown timeout

#### Mechanisms
- Atomic accept-state flag
- Connection draining timers

---

## Phase 3: Reliability, Health, and Observability

**Status**: In progress  
**Duration**: 4–6 weeks

This phase focuses on making the system operable under failure and load.

---

### 3.1 Structured Error Handling

#### Objectives
- Remove `unwrap` and `expect` from runtime paths
- Introduce a unified error model

#### Deliverables
- Error taxonomy:
  - Client errors
  - Backend errors
  - Internal errors
- Retry eligibility classification
- Centralized error reporting

---

### 3.2 Backend Health Monitoring

#### Active Health Checks
- Periodic HTTP/3 health probes
- Configurable interval and timeout

#### Passive Health Checks
Triggered by:
- Request timeouts
- QUIC stream resets
- Consecutive 5xx responses

#### Health State Machine
```

Healthy → Degraded → Unhealthy → Recovering → Healthy

```

#### Algorithms
- Failure threshold (N failures within T seconds)
- Exponential backoff for recovery attempts

---

### 3.3 Circuit Breakers

#### Scope
- Per-backend circuit breakers

#### States
```

Closed → Open → Half-Open → Closed

```

#### Algorithms
- Hystrix-style circuit breaker
- Limited trial requests in half-open state

---

### 3.4 Observability

#### Metrics
- Requests per second
- Request latency (P50, P90, P99)
- Backend latency
- QUIC handshake latency
- Active connections
- Stream resets

Metrics should be exposed in Prometheus format.

#### Logging
Structured logs including:
- Request ID
- Backend ID
- Retry count
- Error category

#### Tracing
- OpenTelemetry integration
- Span per request
- Trace context propagation

---

## Phase 4: Advanced Load Balancing and Traffic Control

**Status**: Planned  
**Duration**: 3–4 weeks

---

### 4.1 Advanced Load Balancing Algorithms

#### Algorithms
- Least-latency (EWMA)
- Power-of-two choices (P2C)
- Consistent hashing (Rendezvous hashing)

#### Data Tracked
- Backend inflight requests
- Rolling latency metrics
- Error rates

---

### 4.2 Session Persistence

#### Use Cases
- Sticky sessions
- Cache affinity

#### Strategies
- Source IP hash
- Header or cookie-based hashing

---

### 4.3 Dynamic Backend Management

#### Deliverables
- Runtime backend enable/disable
- Dynamic weight updates
- Canary deployment support

#### Mechanisms
- Versioned configuration objects
- RCU-style configuration swap

---

## Phase 5: Enterprise and Scale Features

**Status**: Planned  
**Duration**: 4–6 weeks

---

### 5.1 Rate Limiting and Abuse Protection

#### Algorithms
- Token bucket
- Leaky bucket

#### Scope
- Per-IP
- Per-CID
- Per-backend

---

### 5.2 Authentication and Authorization (Optional)

- mTLS
- API key validation
- JWT verification (gateway mode)

---

### 5.3 High Availability and Scaling

#### Features
- Stateless load balancer instances
- Anycast-friendly behavior
- Externalized or shared health state (optional)

---

### 5.4 Performance Hardening

#### Areas
- Async fairness audits
- Lock contention reduction
- Memory growth analysis

#### Optional (Advanced)
- eBPF UDP fast path
- io_uring-based I/O
- Kernel bypass techniques
