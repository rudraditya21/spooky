# References

This is the list of references we have taken to build this project.

## Protocol RFCs

1. [RFC 9114 HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
2. [RFC 9000 QUIC: A UDP-based Multiplexed and secure transport](https://www.rfc-editor.org/rfc/rfc9000.html)

## Core Dependencies
1. [quiche](https://crates.io/crates/quiche/0.24.6) - QUIC + HTTP/3 implementation
2. [tokio](https://crates.io/crates/tokio) - Async runtime
3. [serde](https://crates.io/crates/serde) - Serialization framework
4. [serde_yaml](https://crates.io/crates/serde_yaml/0.9.34) - YAML serialization
5. [clap](https://crates.io/crates/clap) - Command line argument parser
6. [rustls-pki-types](https://crates.io/crates/rustls-pki-types) - TLS certificate types
7. [http](https://crates.io/crates/http/1.3.1) - HTTP types and traits
8. [bytes](https://crates.io/crates/bytes) - Byte utilities
9. [rand](https://crates.io/crates/rand) - Random number generation
10. [log](https://crates.io/crates/log/0.4.28) - Logging facade
11. [env_logger](https://crates.io/crates/env_logger/0.11.3) - Environment-based logger

## Documentations
1. [serde_yaml Documentation](https://docs.rs/serde_yaml/) - YAML serialization in Rust
2. [quiche Documentation](https://docs.rs/quiche/) - QUIC + HTTP/3 implementation
3. [tokio Documentation](https://docs.rs/tokio/) - Asynchronous runtime for Rust
4. [clap Documentation](https://docs.rs/clap/) - Command line argument parser
5. [HTTP/3 Implementation in Rust: Performance Tuning for Global Web Services](http://markaicode.com/http3-rust-implementation-performance-tuning/)

## Load Balancing Algorithms
1. [Load Balancing Algorithms](https://kemptechnologies.com/load-balancer/load-balancing-algorithms-techniques/)
2. [Consistent Hashing](https://en.wikipedia.org/wiki/Consistent_hashing)
3. [Least Connections Algorithm](https://www.nginx.com/resources/glossary/least-connections-load-balancing/)
