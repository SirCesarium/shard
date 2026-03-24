# Shard Core

Foundational protocol implementation for the Shard ecosystem. This crate provides the byte-level definitions, cryptographic primitives, and state validation logic that power the Shard protocol.

## Technical Architecture

`shard-core` is designed for zero-trust environments where minimal overhead and high integrity are paramount.

- **Zero-Copy Parsing:** Utilizes the `zerocopy` crate to cast raw UDP datagrams directly into Rust structs, achieving near-zero latency in frame processing (~1.5ns parsing overhead).
- **Hardened Cryptography:**
  - **AEAD:** Implements ChaCha20-Poly1305 for authenticated encryption.
  - **KDR (Key Derivation & Rotation):** Uses HKDF-SHA256 to derive unique per-packet session keys from a Master PSK and Sequence ID.
- **Strict Validation:**
  - **Anti-Replay:** 64-bit monotonic sequence ID validation.
  - **Temporal Window:** ±5000ms drift validation to prevent delayed replay attacks.
- **Silent Drop Policy:** Explicitly avoids sending error responses for unauthenticated packets to minimize the attack surface against port scanning.

## MTU Compliance
All frames are hard-capped at 1024 bytes to ensure atomic delivery over standard Ethernet MTUs and prevent IP fragmentation.

## Usage

This is a low-level crate. Most users should prefer `shard-sdk`.

```rust
use shard_core::frame::ShardFrame;
use zerocopy::FromBytes;

// Example: Parse a raw buffer into a Shard Frame
let frame = ShardFrame::from_bytes(raw_udp_payload)?;
```

## License
MIT License.
