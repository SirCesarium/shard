# Shard CLI

The `shard` command-line interface is a versatile tool for managing, testing, and interacting with Shard 2.0 endpoints. It supports persistent session management, encrypted command delivery, and a bi-directional interactive shell.

## Installation

### From Source
```bash
cargo install --path shard-cli
```
*Note: The installed binary name is `shard`.*

## Command Reference

### `shard keygen`
Generates a cryptographically secure 32-byte Master Pre-Shared Key (PSK) encoded in Base64.
- **Output:** A random string to be used as your shared secret.

### `shard listen`
Starts a Shard 2.0 server to receive and respond to encrypted commands.
- `--port, -p`: The UDP port to bind (default: random).
- `--key, -k`: The Master PSK (Base64) or an `env:VAR` reference.
- **Auto-Response:** In listen mode, the CLI will automatically acknowledge received text commands.

### `shard send <MESSAGE>`
Performs a 1-RTT handshake, sends a single encrypted message, and waits for a response.
- `--to, -t`: Target address (`IP:PORT` or `domain:PORT`).
- `--key, -k`: The Master PSK.
- **Exit Code:** Returns 0 on success, non-zero on handshake or protocol error.

### `shard shell`
Opens an interactive stateful shell. Performs the X25519 handshake once and keeps the session alive.
- `--to, -t`: Target address.
- `--key, -k`: The Master PSK.
- **Features:**
    - Command history (Arrow Up/Down).
    - In-place line editing.
    - Real-time server response visualization.

---

## Session Management

Shard allows you to save remote targets so you don't have to re-enter keys and addresses.

### `shard session new <NAME>`
Creates and activates a new named profile.
```bash
shard session new prod --to mc.example.com:3000 --key env:PROD_KEY
```

### `shard session list`
Displays all saved sessions and marks the currently active one.

### `shard session use <NAME>`
Switches the active session to the specified profile.

### `shard logout`
Deactivates the current session without deleting your saved profiles.

---

## Security Best Practices

### Avoiding Plain-Text Keys
Shard CLI encourages the use of environment variables to keep your Master PSK off the disk.
1. `export SHARD_KEY="your-base64-key"`
2. `shard session new dev --key env:SHARD_KEY`

This stores only the string `"env:SHARD_KEY"` in your config file.

### Configuration File Location
- **Linux/macOS:** `~/.shard/config.toml`
- **Windows:** `%USERPROFILE%\.shard\config.toml`

The file is protected by standard OS file permissions.

## Troubleshooting

- **`Handshake Timed Out`**: Ensure the server is reachable and the UDP port is open in your firewall.
- **`CryptoError`**: Ensure the Master PSK matches exactly on both the client and the server.
- **`Timestamp Drift`**: Ensure your system clock is synchronized (max allowed drift: 5 seconds).

## License
MIT License.
