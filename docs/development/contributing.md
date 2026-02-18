# Contributing to Spooky

This guide provides comprehensive information for contributing to Spooky, an HTTP/3-to-HTTP/2 gateway. Follow these guidelines to ensure your contributions integrate smoothly with the codebase.

## Development Setup

### Prerequisites

Install the following tools before beginning development:

- Rust 1.85 or later via [rustup](https://rustup.rs/) (edition 2024 support required)
- Git version control
- A Unix-like development environment (Linux, macOS, or WSL2 on Windows)
- Working knowledge of async Rust and HTTP protocol specifications

### Initial Setup

Clone and build the project:

```bash
git clone https://github.com/nishujangra/spooky.git
cd spooky
cargo build
```

Verify the installation:

```bash
cargo test
cargo run -- --config config/config.yaml
```

The first command runs the test suite. The second starts Spooky with the sample configuration.

### Development Tools

Install recommended tooling for efficient development:

```bash
# Format checker
rustup component add rustfmt

# Linter
rustup component add clippy

# Code coverage (optional)
cargo install cargo-tarpaulin
```

Run these tools before committing:

```bash
cargo fmt --check      # Verify formatting
cargo clippy           # Check for common mistakes
cargo test             # Run test suite
```

## Code Structure and Organization

### Architecture Overview

Spooky follows a modular crate-based architecture:

```
spooky/
├── Cargo.toml              # Workspace definition
├── spooky/                 # Main binary crate
│   ├── src/main.rs        # Entry point and initialization
│   └── Cargo.toml
├── crates/
│   ├── config/            # Configuration parsing and validation
│   │   ├── src/
│   │   │   ├── lib.rs      # Public configuration API
│   │   │   ├── config.rs   # Configuration data structures
│   │   │   ├── loader.rs   # YAML loading and parsing
│   │   │   ├── validator.rs # Configuration validation
│   │   │   └── default.rs  # Default value definitions
│   │   └── Cargo.toml
│   ├── edge/              # QUIC/HTTP/3 listener and request handling
│   │   ├── src/
│   │   │   ├── lib.rs         # Edge server implementation
│   │   │   └── quic_listener.rs # Main QUIC listener logic
│   │   └── Cargo.toml
│   ├── bridge/            # Protocol conversion layer
│   │   ├── src/
│   │   │   ├── lib.rs       # Bridge module exports
│   │   │   └── h3_to_h2.rs  # HTTP/3 to HTTP/2 conversion
│   │   └── Cargo.toml
│   ├── transport/         # HTTP/2 client and connection management
│   │   ├── src/
│   │   │   ├── lib.rs      # Transport module exports
│   │   │   ├── h2_client.rs # HTTP/2 client implementation
│   │   │   └── h2_pool.rs   # HTTP/2 connection pooling
│   │   └── Cargo.toml
│   ├── lb/                # Load balancing algorithms
│   │   ├── src/
│   │   │   └── lib.rs      # All load balancing implementations
│   │   └── Cargo.toml
│   ├── utils/             # Shared utilities and helpers
│   │   ├── src/
│   │   │   ├── lib.rs      # Utils module exports
│   │   │   ├── logger.rs   # Logging configuration
│   │   │   └── tls.rs      # TLS utilities
│   │   └── Cargo.toml
│   └── errors/            # Error types and handling
│       ├── src/
│       │   └── lib.rs      # Error definitions
│       └── Cargo.toml
├── config/                # Sample configuration files
└── scripts/               # Development and deployment scripts
```

### Module Responsibilities

**config**: Handles YAML/TOML parsing, validates configuration parameters, and provides a strongly-typed configuration API.

**edge**: Implements the QUIC/HTTP/3 server that accepts incoming client connections. Manages TLS handshakes and QUIC stream multiplexing.

**bridge**: Converts between HTTP/3 and HTTP/2 representations. Handles header mapping, stream semantics differences, and error translation.

**transport**: Maintains HTTP/2 connections to backend servers. Implements connection pooling, health checks, and request forwarding.

**lb**: Provides load balancing algorithms for selecting backend servers. Supports random selection, round-robin, and consistent hashing.

**utils**: Contains cross-cutting concerns like logging, metrics collection, and error handling utilities.

### Adding New Features

When implementing new features:

1. Identify the appropriate crate for your changes
2. Create new modules for substantial additions
3. Update the crate's `lib.rs` to export new public APIs
4. Add integration points in the main binary if needed
5. Update configuration parsing if new settings are required

## Testing Requirements

### Unit Tests

Write unit tests for all public functions and core logic. Place tests in the same file as the implementation:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configuration_parsing() {
        let config = parse_config("port: 443").unwrap();
        assert_eq!(config.port, 443);
    }

    #[tokio::test]
    async fn test_backend_selection() {
        let lb = LoadBalancer::new(Algorithm::RoundRobin);
        let backend = lb.select_backend(&request).await.unwrap();
        assert!(backend.is_available());
    }
}
```

### Integration Tests

Create integration tests in the `tests/` directory at the crate level:

```rust
// crates/edge/tests/integration_test.rs
use edge::QuicServer;
use tokio::runtime::Runtime;

#[test]
fn test_full_request_lifecycle() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let server = QuicServer::new(config).await.unwrap();
        let response = send_h3_request(&server).await.unwrap();
        assert_eq!(response.status(), 200);
    });
}
```

### Test Coverage

Maintain high test coverage for critical paths:

- Configuration parsing: 100%
- Load balancing algorithms: 100%
- Protocol conversion logic: 95%+
- Error handling paths: 90%+

Run coverage analysis:

```bash
cargo tarpaulin --workspace --out Html
```

### Test Data and Mocking

Use test fixtures for complex scenarios:

```rust
#[cfg(test)]
mod test_helpers {
    use crate::*;

    pub fn mock_backend() -> Backend {
        Backend::new("127.0.0.1:8080")
            .with_health_check(false)
            .with_timeout(Duration::from_secs(1))
    }

    pub fn sample_request() -> Request {
        Request::builder()
            .uri("https://example.com/")
            .body(Body::empty())
            .unwrap()
    }
}
```

### Performance Benchmarks

Add benchmarks for performance-critical code using Criterion:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_load_balancer(c: &mut Criterion) {
    let lb = LoadBalancer::new(Algorithm::Random);
    c.bench_function("select_backend", |b| {
        b.iter(|| lb.select_backend(black_box(&request)))
    });
}

criterion_group!(benches, benchmark_load_balancer);
criterion_main!(benches);
```

## Pull Request Process

### Branch Strategy

Create feature branches from the main branch:

```bash
git checkout -b username/feature-name
```

Use descriptive branch names:
- `username/upstream-pools` for features
- `username/fix-quic-retry` for bug fixes
- `username/refactor-connection-pool` for refactoring

### Commit Standards

Write clear, atomic commits:

```bash
# Good commit messages
fix: upstream pool route matching ordering
feat: quic integration with new config of upstream pools
refactor: simplify connection state management
docs: update configuration guide for TLS settings

# Avoid vague messages
fix: bug
update: code
misc: changes
```

Follow the conventional commits format:
- `feat:` for new features
- `fix:` for bug fixes
- `refactor:` for code restructuring
- `docs:` for documentation
- `test:` for test additions
- `perf:` for performance improvements

### Pre-submission Checklist

Before opening a pull request:

1. Run the full test suite: `cargo test --workspace`
2. Check formatting: `cargo fmt --check`
3. Run clippy: `cargo clippy --workspace -- -D warnings`
4. Verify the binary builds: `cargo build --release`
5. Test with sample configuration: `cargo run -- --config config/config.yaml`
6. Update documentation for user-facing changes
7. Add changelog entries for notable changes

### Creating the Pull Request

Push your branch and create a PR:

```bash
git push origin username/feature-name
```

In the PR description:

1. **Summary**: Describe what the PR does and why
2. **Changes**: List modified components and key changes
3. **Testing**: Explain how you tested the changes
4. **Related Issues**: Link to relevant issue numbers

Example PR template:

```markdown
## Summary
Implements upstream connection pooling to reduce connection overhead.

## Changes
- Added connection pool manager in transport crate
- Modified bridge to reuse existing connections
- Added configuration options for pool size limits

## Testing
- Added unit tests for pool lifecycle management
- Integration test verifying connection reuse
- Manual testing with 10k requests showing 40% latency improvement

## Related Issues
Fixes #123
```

### Review Process

1. Automated checks must pass (CI/CD pipeline)
2. At least one maintainer approval required
3. Address review feedback with new commits
4. Maintainer will merge once approved

Do not force-push after receiving reviews. Append fixup commits to preserve review context.

## Code Style and Conventions

### Rust Formatting

Follow standard Rust formatting enforced by `rustfmt`. Key conventions:

```rust
// Use explicit types for public APIs
pub fn create_server(config: ServerConfig) -> Result<Server, Error> {
    // Implementation
}

// Prefer descriptive names over abbreviations
let backend_connection = pool.acquire().await?;  // Good
let conn = pool.get().await?;                    // Avoid

// Use Result for fallible operations
async fn send_request(req: Request) -> Result<Response, TransportError> {
    let backend = select_backend(&req).await?;
    transport::send(backend, req).await
}
```

### Error Handling

Use `thiserror` for error definitions:

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(#[from] std::io::Error),

    #[error("backend {backend} timed out after {timeout:?}")]
    Timeout {
        backend: String,
        timeout: Duration,
    },

    #[error("invalid response: {0}")]
    InvalidResponse(String),
}
```

Propagate errors with context:

```rust
backend.send_request(req)
    .await
    .map_err(|e| TransportError::BackendUnavailable {
        backend: backend.address().to_string(),
        source: e,
    })?
```

### Async Patterns

Follow tokio best practices:

```rust
// Spawn background tasks for independent work
tokio::spawn(async move {
    health_checker.run().await;
});

// Use select for concurrent operations
tokio::select! {
    result = backend.send(req) => handle_response(result),
    _ = timeout => handle_timeout(),
}

// Prefer bounded channels for backpressure
let (tx, rx) = mpsc::channel::<Request>(100);
```

Avoid blocking operations in async contexts:

```rust
// Bad: blocks the async runtime
let data = std::fs::read("file.txt").unwrap();

// Good: use async I/O
let data = tokio::fs::read("file.txt").await?;

// Acceptable: use spawn_blocking for unavoidable blocking
let data = tokio::task::spawn_blocking(|| {
    expensive_computation()
}).await?;
```

### Documentation Standards

Document all public APIs:

```rust
/// Manages connections to backend HTTP/2 servers.
///
/// The connection pool maintains a configurable number of persistent
/// connections to each backend, reducing connection establishment overhead.
///
/// # Examples
///
/// ```
/// use spooky_transport::ConnectionPool;
///
/// let pool = ConnectionPool::builder()
///     .max_connections(10)
///     .idle_timeout(Duration::from_secs(30))
///     .build();
///
/// let conn = pool.acquire("backend1.example.com").await?;
/// ```
pub struct ConnectionPool {
    // Private fields
}

impl ConnectionPool {
    /// Acquires a connection to the specified backend.
    ///
    /// Returns an existing idle connection if available, or creates a new
    /// connection if under the pool limit. Waits for an available connection
    /// if the pool is at capacity.
    ///
    /// # Errors
    ///
    /// Returns `TransportError::ConnectionFailed` if unable to establish
    /// a connection to the backend.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub async fn acquire(&self, backend: &str) -> Result<Connection, TransportError> {
        // Implementation
    }
}
```

### Naming Conventions

Use clear, descriptive names:

```rust
// Modules: snake_case
mod connection_pool;
mod load_balancer;

// Types: PascalCase
struct ConnectionPool;
enum LoadBalancingAlgorithm;

// Functions and variables: snake_case
fn select_backend() -> Backend;
let backend_address = "127.0.0.1:8080";

// Constants: SCREAMING_SNAKE_CASE
const MAX_CONNECTIONS: usize = 100;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
```

## Debugging Techniques

### Logging

Spooky uses the `log` crate for structured logging:

```rust
use log::{debug, info, warn, error};

async fn handle_request(req: Request) -> Result<Response, Error> {
    debug!("handling request for {:?}", req.uri);

    let backend = select_backend(&req).await
        .map_err(|e| {
            error!("backend selection failed: {}", e);
            e
        })?;

    info!(backend = %backend.address(), "forwarding request");
    backend.send(req).await
}
```

Set log levels via environment variable:

```bash
RUST_LOG=spooky=debug,spooky_transport=trace cargo run
```

### QUIC-Specific Debugging

Enable QUIC protocol debugging:

```bash
RUST_LOG=quiche=debug,spooky_edge=info cargo run -- --config config/config.yaml
```

Capture QUIC packets with tcpdump:

```bash
sudo tcpdump -i any -w quic.pcap 'udp port 443'
```

Analyze with Wireshark (ensure QUIC keys are logged):

```bash
export SSLKEYLOGFILE=./quic-keys.log
cargo run -- --config config/config.yaml
```

### Performance Profiling

Profile CPU usage with `perf`:

```bash
cargo build --release
perf record --call-graph=dwarf ./target/release/spooky --config config/config.yaml
perf report
```

Profile memory allocations:

```bash
cargo install cargo-instruments
cargo instruments --release --template Allocations --bin spooky
```

Use `tokio-console` for async task inspection:

```toml
# Add to Cargo.toml
[dependencies]
console-subscriber = "0.1"
```

```rust
// In main.rs
#[tokio::main]
async fn main() {
    console_subscriber::init();
    // Rest of initialization
}
```

Run with console:

```bash
tokio-console
```

### Common Issues

**Issue**: High latency under load

**Debug approach**:
1. Check connection pool exhaustion: Look for "waiting for connection" logs
2. Profile hot paths: Use `perf` to identify bottlenecks
3. Check backend health: Verify backend response times
4. Review async task spawning: Ensure tasks aren't blocking

**Issue**: QUIC connection failures

**Debug approach**:
1. Verify UDP port accessibility: `nc -u -l 443`
2. Check certificate validity: Inspect TLS handshake logs
3. Review QUIC version negotiation: Enable quiche debug logs
4. Test with different QUIC implementations: Use quiche or ngtcp2 clients

**Issue**: Memory growth

**Debug approach**:
1. Profile allocations with `cargo instruments`
2. Check for connection leaks: Review pool metrics
3. Verify stream cleanup: Ensure HTTP/3 streams close properly
4. Look for unbounded channels: Review channel buffer sizes

### Testing Locally

Test with sample configuration:

```bash
cargo run -- --config config/config.yaml
```

Send test requests:

```bash
# HTTP/3 request using curl (requires HTTP/3 support)
curl --http3 https://localhost:443/

# HTTP/3 request using custom client
cargo run --bin h3_client -- https://localhost:443/
```

Test load balancing:

```bash
# Start multiple backend servers (manually or use available scripts)
# Example: Start two HTTP/2 backends on different ports
cargo run --bin h2_backend -- --port 8080 &
cargo run --bin h2_backend -- --port 8081 &

# Send requests and verify distribution
for i in {1..100}; do
    curl --http3 https://localhost:443/ &
done
wait
```

### CI/CD Pipeline

Pull requests automatically run:
- `cargo test --workspace` - All tests
- `cargo clippy --workspace -- -D warnings` - Linting
- `cargo fmt --check` - Formatting verification
- `cargo build --release` - Release build

View results in the GitHub Actions tab of your PR.

## Additional Resources

- [Rust Async Book](https://rust-lang.github.io/async-book/)
- [QUIC Specification (RFC 9000)](https://www.rfc-editor.org/rfc/rfc9000.html)
- [HTTP/3 Specification (RFC 9114)](https://www.rfc-editor.org/rfc/rfc9114.html)
- [tokio Documentation](https://tokio.rs/)
- [quiche QUIC Implementation](https://github.com/cloudflare/quiche)

For questions or discussions, open an issue on GitHub or join the project's communication channels.