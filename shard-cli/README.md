# Shard CLI

The `shard` command-line tool is a management and testing utility for the Shard protocol ecosystem.

## Installation

```bash
cargo install shard-cli
```
*Binary name: `shard`*

## Sessions and Persistence

Shard 2.0 CLI supports persistent, named sessions and **stateful handshakes**. Unlike simple UDP relays, every connection now performs an X25519 key exchange to establish a unique session key with **Perfect Forward Secrecy (PFS)**.

Sessions are stored in `~/.shard/config.toml` (or `%USERPROFILE%\.shard\config.toml` on Windows).

### How it works (Shard 2.0):
- **Handshake:** When you run `shard send`, the CLI first performs a 1-RTT handshake with the server.
- **PFS:** Even if your Master PSK is compromised in the future, past captured traffic remains secure.
- **DNS Support:** Domain names (e.g., `localhost:3000`) are resolved automatically.
- **Absolute Replay Protection:** The stateful nature allows the server to reject any packet with a sequence ID lower or equal to the last one seen, with no time window limitations.

---

## Commands & Usage

### 1. Key Generation
Generate a cryptographically secure 32-byte Master Pre-Shared Key (PSK) encoded in Base64.
```bash
shard keygen
```

### 2. Session Management
Create and switch between multiple remote targets easily.

- **Create a new session (Secure):**
  ```bash
  export MY_PROD_KEY="AAAAA..."
  shard session new prod-server --to example.com:3000 --key env:MY_PROD_KEY
  ```
- **List all sessions:**
  ```bash
  shard session list
  ```
- **Switch to a different session:**
  ```bash
  shard session use dev-server
  ```
- **Logout (clear active session):**
  ```bash
  shard logout
  ```

### 3. Listening (Server Mode)
Start a secure listener.
```bash
shard listen --port 3000
```

### 4. Sending (Client Mode)
Send an encrypted command or payload.
```bash
shard send "system:status"
```
*You can always override the session by providing `--to` or `--key` explicitly.*

## Features
- **Zero-Trust Defaults:** No response is sent unless the packet is fully authenticated.
- **Hardened Security:** Implements ChaCha20-Poly1305 and HKDF key rotation per packet.
- **Modern Aesthetics:** Rich CLI feedback powered by `miette` and `clap`.

## License
MIT License.
