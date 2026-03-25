# Shard Core

Foundational protocol implementation for the Shard ecosystem. This crate provides the byte-level definitions, cryptographic primitives, and state validation logic that power the Shard protocol v2.0.

## Technical Architecture

`shard-core` is designed for zero-trust environments where minimal overhead and high integrity are paramount.

- **Zero-Copy Parsing:** Utilizes the `zerocopy` crate to cast raw UDP datagrams directly into Rust structs, achieving near-zero latency in frame processing (~1.5ns parsing overhead).
- **Hardened Cryptography (Shard 2.0):**
  - **Key Exchange:** X25519 (ECDH) for ephemeral session key establishment.
  - **AEAD:** Implements ChaCha20-Poly1305 for authenticated encryption.
  - **KDR (Key Derivation):** Uses HKDF-SHA256 to derive unique session keys from ECDH shared secrets and a Master PSK.
- **Strict Validation:**
  - **Monotonic ID:** 64-bit sequence ID validation per stateful session.
  - **Handshake Authentication:** The entire 1-RTT handshake is encrypted and authenticated using the Master PSK.
  - **Silent Drop Policy:** Explicitly avoids sending error responses for unauthenticated packets to minimize the attack surface.

## MTU Compliance
All frames are hard-capped at 1024 bytes to ensure atomic delivery over standard Ethernet MTUs and prevent IP fragmentation.

## Usage

This is a low-level crate. Most users should prefer `shard-sdk`.

```rust
use shard_core::frame::ShardFrame;

// Example: Parse a raw buffer into a Shard Frame
let frame = ShardFrame::from_bytes(raw_udp_payload)?;
```

## License
MIT License.
