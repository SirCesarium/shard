# Shard

[![CI](https://github.com/SirCesarium/shard/actions/workflows/ci.yml/badge.svg)](https://github.com/SirCesarium/shard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Shard is a high-performance, hardened application-layer protocol for secure, low-latency binary data transport over UDP. Designed for zero-trust environments, it prioritizes minimal overhead, resistance to fragmentation, and cryptographic integrity.

## Technical Overview

- **Authenticated Encryption:** Implements ChaCha20-Poly1305 (AEAD) for all packets, ensuring both confidentiality and authenticity.
- **Stateless Monotonicity:** Sequence IDs are initialized via high-precision Unix nanoseconds to ensure monotonicity across restarts without the need for persistent state.
- **Anti-Replay Mechanism:** Strict 64-bit sequence validation combined with a ±5000ms temporal drift window.
- **Silent Drop Policy:** Minimizes attack surface by silently discarding unauthenticated packets, preventing service discovery via port scanning.
- **MTU Compliance:** Hard-capped 1024-byte payloads to ensure atomic delivery and prevent IP fragmentation.
- **Zero-Copy Parsing:** Built using the `zerocopy` crate for high-efficiency, memory-safe frame processing.

## Project Structure

The project is managed as a Cargo workspace:

- **shard-core:** Foundational protocol implementation including frame parsing, cryptographic primitives, and state validation.
- **shard-sdk:** High-level asynchronous ShardServer and ShardClient implementations for Rust applications.
- **shard-cli:** Command-line interface for session management, key generation, and remote command execution.

## Getting Started

### Prerequisites

The project requires the Rust toolchain (v1.75 or later).

### Installation

Clone the repository and build using the release profile:

```bash
git clone https://github.com/SirCesarium/shard.git
cd shard
cargo build --release
```

### Command Line Interface

1. **Generate a Master PSK:**
   ```bash
   shard keygen
   ```

2. **Initialize a Listening Server:**
   ```bash
   shard listen --port 3000 --key <BASE64_KEY>
   ```

3. **Transmit an Encrypted Command:**
   ```bash
   shard send "system:reboot" --to 127.0.0.1:3000 --key <BASE64_KEY>
   ```

## Security and Specification

Shard utilizes a Key Derivation & Rotation (KDR) scheme via HKDF-SHA256. Every packet employs a unique session key derived from the Master PSK and the current Sequence ID.

Detailed technical documentation is available in the following documents:
- **Security Model:** Detailed analysis and pentesting instructions in [SECURITY.md](SECURITY.md).
- **Protocol Specification:** Byte-level definitions and state transitions in [SPEC.md](SPEC.md).

## Verification

The core protocol is verified with a comprehensive suite of unit and integration tests:

```bash
cargo test --workspace
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
