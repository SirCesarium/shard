# Shard Protocol Specification (v1.1)

**Shard** is a high-performance, hardened application-layer protocol for secure, low-latency binary data transport over UDP. It is designed for zero-trust environments where minimal overhead, resistance to fragmentation, and cryptographic integrity are mandatory.

---

## 1. Frame Structure

The Shard packet is a strictly ordered binary stream. **Network Byte Order (Big Endian)** is mandatory for all multi-byte fields. Offset-based parsing is required to ensure constant-time validation.

| Offset | Field          | Size     | Description                                               |
| :----- | :------------- | :------- | :-------------------------------------------------------- |
| 0      | `VERSION`      | 1 Byte   | Protocol version (Fixed: `0x01`).                         |
| 1      | `TYPE`         | 1 Byte   | `0x00`: Req, `0x01`: Resp, `0x02`: Error.                 |
| 2      | `SEQUENCE_ID`  | 8 Bytes  | Monotonically increasing 64-bit counter (**Big Endian**). |
| 10     | `TIMESTAMP`    | 8 Bytes  | Unix Epoch in milliseconds (**Big Endian**).              |
| 18     | `NONCE`        | 12 Bytes | Cryptographically secure random Nonce.                    |
| 30     | `PAYLOAD_LEN`  | 4 Bytes  | Length of ciphertext (**Big Endian**). **MAX: 1024**.     |
| 34     | `CIPHERTEXT`   | Variable | ChaCha20 encrypted data.                                  |
| End    | `AUTH_TAG`     | 16 Bytes | Poly1305 MAC (Authentication Tag).                        |

---

## 2. Cryptographic Hardening

### 2.1 AEAD (Authenticated Encryption)
- **Algorithm:** **ChaCha20-Poly1305**.
- **Nonce:** **MUST** be unique for every single packet. Reusing a nonce with the same key invalidates the security of the entire session.
- **AAD (Additional Authenticated Data):** The protocol header (Offsets 0 to 33) **MUST** be included as AAD. This ensures that metadata (`SEQUENCE_ID`, `PAYLOAD_LEN`, etc.) is cryptographically bound to the payload.

### 2.2 Key Derivation & Rotation (KDR)
To prevent long-term Master Key exposure:
- **Master PSK:** 32-byte Pre-Shared Key.
- **Session Key:** Generated via **HKDF-SHA256** using the `Master PSK` as input.
- **Salt:** A strictly defined 9-byte array: `SEQUENCE_ID` (8 bytes, Big Endian) followed by `VERSION` (1 byte).
- **Key Exhaustion:** Upon reaching the maximum value of `SEQUENCE_ID` ($2^{64}-1$), the counter **MUST NOT** wrap around. The session MUST be terminated and the Master PSK rotated.

### 2.3 Integrity & MTU Compliance
- **Anti-Fragmentation:** To ensure atomic delivery, `PAYLOAD_LEN` is hard-capped at **1024 bytes**. Total frame size stays within the 1280-byte safe MTU.
- **Silent Drop Policy:** If `AUTH_TAG` verification fails, the receiver **MUST** drop the packet silently. This specific failure MUST NOT trigger an error frame to prevent side-channel analysis. Other protocol-level errors (e.g., version mismatch) MAY return an error frame.

---

### 3. Anti-Replay & State Control

### 3.1 Sequence Validation
Both endpoints must maintain a local `LAST_SEQ` counter. 
- Incoming packets with a `SEQUENCE_ID` $\le$ `LAST_SEQ` **MUST** be discarded.
- Upon successful authentication, `LAST_SEQ` is updated to the current `SEQUENCE_ID`.
- **Note on Statelessness:** A client MAY initialize its starting `SEQUENCE_ID` using high-precision Unix timestamps (nanoseconds) to ensure monotonicity across restarts without persistent state.


### 3.2 Temporal Windowing
- The `TIMESTAMP` must be within a $\pm$ 5000ms window of the server's clock. Packets outside this drift window are rejected to mitigate long-term replay attempts.

---

## 4. Security Rationale

* **Why ChaCha20-Poly1305?** Provides high performance in software (Rust/Java) and is naturally resistant to timing attacks without requiring AES-NI hardware.
* **Why Silent Drop?** Minimizes the server's fingerprint. An attacker cannot distinguish between a closed port and a Shard-protected port without the correct PSK.
* **Why Big Endian?** Ensures strict interoperability between different CPU architectures and language runtimes (e.g., Rust to JVM).

---

## 5. Error Codes

Error frames (`TYPE: 0x02`) return a 1-byte status code in the decrypted payload. **Note:** `0x01` is reserved for internal logging and should not be transmitted (see Silent Drop).

- `0x01`: **AUTH_FAILURE** (Internal use only, do not transmit).
- `0x02`: **REPLAY_DETECTED** (Sequence ID or Timestamp violation).
- `0x03`: **DECRYPTION_FAILED** (Internal cryptographic error).
- `0x04`: **EXECUTION_TIMEOUT** (Payload processing exceeded deadline).
- `0x05`: **MALFORMED_FRAME** (Length mismatch or invalid version).
- `0x06`: **PAYLOAD_TOO_LARGE** (Exceeds the 1024-byte limit).
