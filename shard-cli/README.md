# Shard CLI

The `shard` command-line tool is a management and testing utility for the Shard protocol ecosystem.

## Installation

```bash
cargo install shard-cli
```
*Binary name: `shard`*

## Sessions and Persistence

Shard CLI supports persistent, named sessions. Unlike simple environment variables, sessions are stored in `~/.shard/config.toml` (or `%USERPROFILE%\.shard\config.toml` on Windows) and remain available across terminal restarts and reboots.

### Key Security and Environment Variables
Storing keys in plain text in the configuration file is discouraged. Shard CLI supports an `env:` prefix to reference environment variables safely.

- **Direct Key:** `shard session new prod --key AAAAAA...` (Stores key in plain text on disk).
- **Secure Reference:** `shard session new prod --key env:MY_KEY` (Only stores the variable name; the key is read from memory at runtime).

### DNS and Domain Support
You can use domain names (e.g., `localhost:3000` or `server.example.com:5000`) instead of raw IP addresses. The CLI performs automatic DNS resolution before transmission.

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
