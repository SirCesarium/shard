# Shard CLI

The `shard` command-line tool is a management and testing utility for the Shard protocol ecosystem.

## Installation

```bash
cargo install shard-cli
```
*Binary name: `shard`*

## The Concept of Sessions

Unlike traditional TCP sessions, Shard is **stateless** yet **monotonic**. 

### How it works:
- **Statelessness:** The server does not need to store persistent session state to disk.
- **Monotonicity:** To prevent replay attacks, every packet must have a higher Sequence ID than the last one received.
- **The Solution:** The `shard` CLI initializes its starting Sequence ID using high-precision **Unix nanoseconds**. This ensures that even if you stop and restart the CLI, the next packet will always have a significantly higher Sequence ID, satisfying the server's anti-replay checks without requiring a database.

---

## Commands & Usage

### 1. Key Generation
Generate a cryptographically secure 32-byte Master Pre-Shared Key (PSK) encoded in Base64.
```bash
shard keygen
```

### 2. Listening (Server Mode)
Start a secure listener. It will silently drop any packet that doesn't pass the AEAD integrity check, effectively making your server invisible to port scanners.
```bash
shard listen --port 3000 --key <BASE64_KEY>
```
- `--port`: The UDP port to bind to.
- `--key`: The 32-byte Master PSK (Base64).

### 3. Sending (Client Mode)
Send an encrypted command or payload to a remote Shard server.
```bash
shard send "system:status" --to 127.0.0.1:3000 --key <BASE64_KEY>
```
- `--to`: Target `IP:PORT`.
- `--key`: The Master PSK (must match the server's key).

## Features
- **Zero-Trust Defaults:** No response is sent unless the packet is fully authenticated.
- **Hardened Security:** Implements ChaCha20-Poly1305 and HKDF key rotation per packet.
- **Modern Aesthetics:** Rich CLI feedback powered by `miette` and `clap`.

## License
MIT License.
