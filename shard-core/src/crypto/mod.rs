//! Cryptographic primitives for the Shard protocol.
//!
//! This module implements AEAD (ChaCha20-Poly1305) and Key Derivation (HKDF-SHA256)
//! as defined in Section 2 of the Shard Protocol Specification v1.0.

pub mod aead;
pub mod hkdf;

use crate::error::ShardError;
use crate::frame::ShardHeader;
use zerocopy::IntoBytes;

/// Encrypts a plaintext payload using the Shard cryptographic stack.
///
/// Implements Section 2.1 and 2.2:
/// 1. Derives a session key from the master PSK and Sequence ID.
/// 2. Uses the full 34-byte header as AAD.
/// 3. Returns the authentication tag (Poly1305).
///
/// # Errors
/// Returns `ShardError::CryptoError` if key derivation or encryption fails.
pub fn encrypt_frame_payload(
    master_psk: &[u8; 32],
    header: &ShardHeader,
    payload: &mut [u8],
) -> Result<[u8; 16], ShardError> {
    let sequence_id = u64::from_be_bytes(header.sequence_id);
    let session_key = hkdf::derive_session_key(master_psk, sequence_id)?;

    // The entire header is used as AAD (Offsets 0 to 33).
    let aad = header.as_bytes();

    aead::encrypt(&session_key, &header.nonce, aad, payload)
}

/// Decrypts a ciphertext payload and verifies its integrity.
///
/// Implements Section 2.3 (Silent Drop Policy):
/// If authentication fails, the operation returns `ShardError::CryptoError`.
///
/// # Errors
/// Returns `ShardError::CryptoError` on authentication tag mismatch or decryption failure.
pub fn decrypt_frame_payload(
    master_psk: &[u8; 32],
    header: &ShardHeader,
    ciphertext: &mut Vec<u8>,
    auth_tag: &[u8; 16],
) -> Result<(), ShardError> {
    let sequence_id = u64::from_be_bytes(header.sequence_id);
    let session_key = hkdf::derive_session_key(master_psk, sequence_id)?;

    let aad = header.as_bytes();

    aead::decrypt(&session_key, &header.nonce, aad, ciphertext, auth_tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::VERSION;

    #[test]
    fn test_cryptographic_roundtrip() {
        let master_psk = [0u8; 32];
        let mut payload = b"shard protocol test payload".to_vec();
        let original_payload = payload.clone();

        let payload_len_u32 =
            u32::try_from(payload.len()).unwrap_or_else(|_| panic!("Payload length exceeds u32"));

        let header = ShardHeader {
            version: VERSION,
            frame_type: 0,
            sequence_id: 1u64.to_be_bytes(),
            timestamp: 0u64.to_be_bytes(),
            nonce: [0u8; 12],
            payload_len: payload_len_u32.to_be_bytes(),
        };

        // Encrypt
        let tag = encrypt_frame_payload(&master_psk, &header, &mut payload)
            .unwrap_or_else(|_| panic!("Encryption failed"));

        assert_ne!(payload, original_payload, "Payload must be encrypted");

        // Decrypt
        decrypt_frame_payload(&master_psk, &header, &mut payload, &tag)
            .unwrap_or_else(|_| panic!("Decryption failed"));

        assert_eq!(
            payload, original_payload,
            "Decrypted payload must match original"
        );
    }
}
