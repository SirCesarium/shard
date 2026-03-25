# Shard Protocol Specification v2.0

**Status:** Draft / Major Update  
**Scope:** Stateful, Encrypted Binary Transport over UDP with Perfect Forward Secrecy (PFS).

## 1. Introduction
Shard 2.0 is a stateful application-layer protocol designed for secure, low-latency command delivery. It introduces a high-performance handshake mechanism using X25519 (ECDH) to establish unique session keys, ensuring Perfect Forward Secrecy and absolute protection against replay attacks by maintaining session state.

## 2. Cryptographic Primitives
Shard 2.0 utilizes industry-standard primitives:
- **Key Exchange:** X25519 (Elliptic Curve Diffie-Hellman).
- **Authenticated Encryption:** ChaCha20-Poly1305 (AEAD).
- **Key Derivation:** HKDF-SHA256.
- **Authentication:** Master Pre-Shared Key (PSK) used as a base entropy source for Handshake authentication.

---

## 3. Packet Structure
Every Shard packet consists of a fixed **34-byte Header**, followed by a variable-length **Payload**, and a **16-byte AUTH_TAG**.

### 3.1 Header (34 Bytes)
| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0      | 1    | VERSION | Protocol version (0x02). |
| 1      | 1    | TYPE | Frame type (0x00: Handshake Init, 0x01: Handshake Response, 0x02: Data, 0x03: Error). |
| 2      | 8    | SEQ_ID | 64-bit monotonic sequence ID (starts at 1 post-handshake). |
| 10     | 8    | TIMESTAMP | 64-bit Unix timestamp (milliseconds). |
| 18     | 12   | NONCE | 96-bit random nonce for AEAD. |
| 30     | 4    | LENGTH | 32-bit big-endian payload length (Max 1024). |

### 3.2 AUTH_TAG (16 Bytes)
The Poly1305 MAC appended at the end of every packet.

---

## 4. Protocol Flow (State Machine)

### 4.1 State: UNINITIALIZED
- **Client** generates an ephemeral X25519 keypair ($E_{c\_priv}$, $E_{c\_pub}$).
- **Client** sends `TYPE: 0x00` (Handshake Init).
- **Payload:** $E_{c\_pub}$ (32 bytes).
- **Encryption:** None (Handshake Init is plaintext, but integrity is verified via Master PSK in the next step).

### 4.2 State: NEGOTIATING
- **Server** receives $E_{c\_pub}$.
- **Server** generates its own ephemeral X25519 keypair ($E_{s\_priv}$, $E_{s\_pub}$).
- **Server** computes `SharedSecret = ECDH(E_s_priv, E_c_pub)`.
- **Server** derives `SessionKey = HKDF(SharedSecret, Salt=MasterPSK, Info="shard-session-v2")`.
- **Server** sends `TYPE: 0x01` (Handshake Response).
- **Payload:** $E_{s\_pub}$ (32 bytes).
- **Encryption:** The Handshake Response payload is encrypted with the `SessionKey`.

### 4.3 State: ESTABLISHED
- **Client** receives $E_{s\_pub}$, computes the same `SessionKey`.
- **Client** validates the response by decrypting the payload.
- All subsequent packets use `TYPE: 0x02` (Data) and are encrypted with the `SessionKey`.
- **Sequence ID:** Both parties track the last `SEQ_ID`. Any packet with `SEQ_ID <= LAST_SEQ` is silently dropped.

---

## 5. Security Mandates
1. **Silent Drop:** If a packet fails authentication (AEAD check) or handshake validation, it MUST be silently discarded. No error frame is sent to unauthenticated peers.
2. **Key Rotation:** A new `SessionKey` is generated for every handshake. Handshakes SHOULD be renegotiated every 1 hour or 1,000,000 packets.
3. **Perfect Forward Secrecy:** Since session keys are derived from ephemeral ECDH secrets, compromising the Master PSK does not allow decryption of past captured traffic.
4. **Anti-DoS:** Servers SHOULD implement a rate limiter on `Handshake Init` frames to prevent CPU exhaustion.

## 6. Implementation Notes
- **Zero-Copy:** Implementations should use zero-copy parsing for the 34-byte header.
- **MTU Safety:** Total packet size (Header + Payload + Tag) MUST NOT exceed 1500 bytes (Recommended max payload: 1024 bytes).
