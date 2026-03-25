# Shard Protocol Roadmap

This document outlines the current status of the Shard protocol and the planned milestones for the **v1.0.0 (Production Ready)** release.

## Phase 1: Foundation and Security (Completed - v0.1.1)
- [x] **Core Protocol**: Zero-copy frame implementation using `zerocopy`.
- [x] **AEAD Cryptography**: ChaCha20-Poly1305 for integrity and confidentiality.
- [x] **KDR (Key Derivation & Rotation)**: Per-packet session key derivation via HKDF-SHA256.
- [x] **Anti-Replay**: 64-bit monotonic sequence ID validation and temporal drift windowing.
- [x] **Multi-Platform SDK**: Native Rust and FFI (C-ABI) support.
- [x] **Project Panama**: High-performance integration for Java 21+.
- [x] **Shard CLI**: Management, key generation, and testing utility.

---

## Phase 2: Robustness and Resilience (In Progress)
*Focus: Attack mitigation and delivery reliability.*

- [ ] **Perfect Forward Secrecy (PFS)**: Optional Diffie-Hellman (X25519) key exchange to protect historical traffic.
- [ ] **Reliability Layer**:
    - [ ] Acknowledgment (ACK) system.
    - [ ] Automatic retransmission of dropped packets.
    - [ ] Receiver-side packet reordering.
- [ ] **Anti-DoS Protection**:
    - [ ] Pre-validation mechanisms (Cookies/Tokens) prior to HKDF execution.
    - [ ] Integrated Rate Limiting per IP/Subnet within the SDK.
- [ ] **MTU Path Discovery**: Dynamic payload adjustment based on network path constraints.

---

## Phase 3: Ecosystem and Tooling (Planned)
*Focus: Adoption and monitoring capabilities.*
- [ ] **Java Native Wrapper**: A high-level library providing a clean, idiomatic Java API. 
    - [ ] Compatibility bridge for Java 21 (Preview) and Java 22+ (Stable).
    - [ ] Automatic native library loading (OS-aware extraction).
- [ ] **Language Bindings**:
    - [ ] TypeScript/Node.js (via N-API or WASM-bridge).
    - [ ] Python (via PyO3).

- [ ] **Observability**:
    - [ ] Prometheus metrics exporter (packets/sec, auth failures, latency).
    - [ ] Structured logging compatible with OpenTelemetry.
- [ ] **Shard Proxy**: Lightweight load balancer for distributing Shard traffic across multiple endpoints.

---

## Phase 4: v1.0.0 Stabilization
- [ ] **Security Audit**: External review of cryptographic primitives and state machine.
- [ ] **Formal Specification (RFC)**: Final technical documentation with formal protocol grammar.
- [ ] **Comparative Benchmarks**: Stress testing against gRPC/UDP and TLS/TCP.
- [ ] **Deployment Guides**: Integration wikis for IoT, Gaming, and Infrastructure Ops.

---

## Contribution
To contribute to any of these milestones, please open an Issue or a Pull Request. Shard aims to become the standard for secure, lightweight command transport.
