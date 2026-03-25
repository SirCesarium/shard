# Shard Protocol Roadmap

This document outlines the strategic milestones for Shard, transitioning from the v1.x stateless foundation to the **Shard 2.0 stateful architecture**.

## Phase 1: Stateless Foundation (Completed - v0.1.3)
- [x] **Zero-Copy Core**: High-efficiency frame implementation using `zerocopy`.
- [x] **AEAD Cryptography**: ChaCha20-Poly1305 for authenticated encryption.
- [x] **KDR (Key Derivation)**: Initial HKDF-SHA256 session key implementation.
- [x] **Anti-Replay v1**: Monotonic sequence validation with temporal windowing.
- [x] **Persistent CLI**: Advanced session management and DNS support.
- [x] **FFI Bridge**: Initial Project Panama compatibility for Java 21+.

---

## Phase 2: Shard 2.0 - The Handshake Era (In Progress)
*Focus: Perfect Forward Secrecy (PFS) and Stateful Session Management.*

- [ ] **X25519 Integration**: Implement Elliptic Curve Diffie-Hellman (ECDH) for ephemeral key exchange.
- [ ] **Handshake Protocol**: Implement `Handshake Init` and `Handshake Response` frame types.
- [ ] **Stateful SDK**:
    - [ ] Client-side session negotiation state machine.
    - [ ] Server-side session table for concurrent peer tracking.
- [ ] **Absolute Replay Protection**: Eliminate temporal windowing requirements by tracking exact last-received sequence IDs per session.
- [ ] **Automatic Key Rotation**: Periodic re-handshaking logic based on time or packet count.

---

## Phase 3: Reliability and Resilience
*Focus: Guaranteed delivery and advanced network hardening.*

- [ ] **Reliability Layer**:
    - [ ] Acknowledgment (ACK) system for guaranteed delivery.
    - [ ] Selective retransmission of dropped packets.
    - [ ] Packet reordering buffer at the receiver.
- [ ] **Anti-DoS Protection**:
    - [ ] Pre-computation validation (Stateless Cookies) to prevent HKDF exhaustion attacks.
    - [ ] SDK-integrated Rate Limiting per peer Identity.
- [ ] **MTU Path Discovery**: Dynamic payload fragmentation management.

---

## Phase 4: Ecosystem and Tooling
*Focus: Broad adoption and high-level abstractions.*

- [ ] **Java Native Wrapper**:
    - [ ] Clean, idiomatic Java API for Plugin developers.
    - [ ] Automatic OS-aware native library extraction.
    - [ ] Compatibility layer for Java 21 (Preview) and Java 22+.
- [ ] **Language Bindings**:
    - [ ] TypeScript/Node.js (via N-API).
    - [ ] Python (via PyO3).
- [ ] **Observability**:
    - [ ] OpenTelemetry integration for distributed tracing.
    - [ ] Prometheus metrics exporter for server health monitoring.

---

## Phase 5: v1.0.0 Final Stabilization
- [ ] **Third-Party Security Audit**: Formal review of the Shard 2.0 handshake and crypto implementation.
- [ ] **Standardization (RFC)**: Finalizing the formal protocol grammar and byte-level specification.
- [ ] **Global Benchmarks**: Comprehensive performance analysis against gRPC, WireGuard, and TLS 1.3.

---

## Contribution
To contribute to Shard 2.0, please consult the `SPEC.md` and open an Issue or Pull Request. Shard aims to be the fastest and most secure transport for command-based systems.
