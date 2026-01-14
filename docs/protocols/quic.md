# QUIC: A UDP-Based Multiplexed and Secure Transport

QUIC is a secure, connection-oriented transport protocol built on UDP. It integrates TLS 1.3 for encryption and combines cryptographic and transport negotiation in a single handshake, enabling fast setup and even 0-RTT data transmission. Communication happens through QUIC packets (containing frames) and streams (bidirectional or unidirectional) with flow control via a credit-based system. It ensures reliable delivery, loss recovery, and congestion control. QUIC also supports client-driven connection migration using connection identifiers, making it resilient to network changes (like NAT rebinding). Connections can be closed gracefully, via timeout, errors, or stateless termination.

**NOTE**: QUIC is a name, not an acronym

## Terms


