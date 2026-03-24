# Shard Security Model

Shard is designed for high-performance, secure command delivery over UDP. This document outlines the security mechanisms implemented and how to verify them.

## 1. Security Architecture

### 1.1 Authenticated Encryption (AEAD)
Shard uses **ChaCha20-Poly1305** for every packet. This provides:
- **Confidentiality:** The payload is encrypted and unreadable without the Master PSK.
- **Integrity & Authenticity:** Any modification to the ciphertext or header (AAD) will cause the packet to be rejected.

### 1.2 Anti-Replay Mechanism
Shard prevents replay attacks using a monotonic 64-bit `SEQUENCE_ID`. 
- Every packet must have an ID strictly greater than the last successfully processed one.
- **Stateless Monotonicity:** The client uses high-precision Unix timestamps (nanoseconds) as the initial `SEQUENCE_ID` to ensure monotonicity across restarts without disk persistence.

### 1.3 Silent Drop Policy
To minimize attack surface and prevent side-channel analysis:
- Packets failing the **AEAD integrity check** are dropped silently.
- The server does not respond to authentication failures, making it appear as a "stealth" or "filtered" port to scanners.

### 1.4 Temporal Windowing
Packets with a timestamp drift greater than **±5000ms** are rejected to mitigate long-term replay attempts and clock-sync-related issues.

---

## 2. Security Testing (Pentesting)

We provide a suite of tools in the `tools/` directory to verify these protections. These scripts require **Python 3**, **Scapy**, and **root** privileges.

### Prerequisites
```bash
# On Arch Linux
sudo pacman -S python-scapy
```

### 2.1 Testing Anti-Replay
1. Start the server: `shard listen --port 3000 --key <BASE64_KEY>`
2. Start the tool: `sudo python3 tools/replay_attack.py --port 3000`
3. Send a message: `shard send "Secret" --to 127.0.0.1:3000 --key <BASE64_KEY>`
4. **Verification:** The script will capture the packet and attempt to replay it. The server must ignore the replayed packet.

### 2.2 Testing Integrity (Bit-Flipping)
1. Start the server and the tool: `sudo python3 tools/integrity_attack.py --port 3000`
2. Send a message with `shard send`.
3. **Verification:** The script will flip a bit in the encrypted payload. The server must perform a **Silent Drop**.

### 2.3 Testing Parser Robustness (Fuzzing)
1. Start the server.
2. Run the fuzzer: `sudo python3 tools/malformed_packet.py --port 3000`
3. **Verification:** The server must handle malformed headers and size mismatches without crashing (panicking).
