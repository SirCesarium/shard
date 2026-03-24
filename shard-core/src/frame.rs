//! Binary frame representation and parsing for the Shard protocol.

use crate::consts::{AUTH_TAG_SIZE, HEADER_SIZE, MAX_PAYLOAD_SIZE, VERSION};
use crate::error::ShardError;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Fixed-size header structure of a Shard packet.
///
/// Total size: 34 bytes.
/// Aligned to 1 byte (packed) to ensure strict adherence to the specification.
#[derive(Debug, Clone, Copy, Immutable, IntoBytes, FromBytes, KnownLayout)]
#[repr(C, packed)]
pub struct ShardHeader {
    /// Protocol version (0x01).
    pub version: u8,
    /// Frame type identifier.
    pub frame_type: u8,
    /// 64-bit monotonically increasing sequence ID (Big Endian).
    pub sequence_id: [u8; 8],
    /// 64-bit Unix timestamp in milliseconds (Big Endian).
    pub timestamp: [u8; 8],
    /// 96-bit unique cryptographic nonce.
    pub nonce: [u8; 12],
    /// 32-bit length of the ciphertext (Big Endian).
    pub payload_len: [u8; 4],
}

/// A complete Shard frame containing the header, ciphertext, and authentication tag.
#[derive(Debug, Clone)]
pub struct ShardFrame {
    /// Parsed header metadata.
    pub header: ShardHeader,
    /// Encrypted payload data.
    pub ciphertext: Vec<u8>,
    /// Poly1305 authentication tag (16 bytes).
    pub auth_tag: [u8; AUTH_TAG_SIZE],
}

impl ShardFrame {
    /// Parses a raw byte buffer into a `ShardFrame`.
    ///
    /// # Errors
    /// Returns `ShardError::BufferTooSmall` if the buffer size is less than 50 bytes.
    /// Returns `ShardError::InvalidVersion` if the version field is not 0x01.
    /// Returns `ShardError::CryptoError` if the payload length exceeds the hard cap.
    pub fn from_bytes(buffer: &[u8]) -> Result<Self, ShardError> {
        if buffer.len() < HEADER_SIZE + AUTH_TAG_SIZE {
            return Err(ShardError::BufferTooSmall);
        }

        // Parse header using zero-copy.
        let header_bytes = buffer
            .get(0..HEADER_SIZE)
            .ok_or(ShardError::BufferTooSmall)?;
        let header =
            ShardHeader::read_from_bytes(header_bytes).map_err(|_| ShardError::BufferTooSmall)?;

        // Validate version (Section 1).
        if header.version != VERSION {
            return Err(ShardError::InvalidVersion {
                expected: VERSION,
                found: header.version,
            });
        }

        // Parse and validate payload length (Section 2.3).
        let payload_len_raw = u32::from_be_bytes(header.payload_len);
        let payload_len = usize::try_from(payload_len_raw).map_err(|_| ShardError::CryptoError)?;

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ShardError::CryptoError);
        }

        let total_expected_size = HEADER_SIZE + payload_len + AUTH_TAG_SIZE;
        if buffer.len() < total_expected_size {
            return Err(ShardError::BufferTooSmall);
        }

        // Safety: total_expected_size is validated against buffer.len()
        let ciphertext = buffer[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec();

        let mut auth_tag = [0u8; AUTH_TAG_SIZE];
        let tag_start = total_expected_size - AUTH_TAG_SIZE;
        let tag_slice = buffer
            .get(tag_start..total_expected_size)
            .ok_or(ShardError::BufferTooSmall)?;
        auth_tag.copy_from_slice(tag_slice);

        Ok(Self {
            header,
            ciphertext,
            auth_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_frame_parsing() {
        let mut buffer = vec![0u8; 50];
        buffer[0] = 0x01; // Version
        buffer[1] = 0x00; // Type: Request

        let frame = ShardFrame::from_bytes(&buffer)
            .unwrap_or_else(|_| panic!("Failed to parse valid frame"));
        assert_eq!(frame.header.version, 0x01);
        assert_eq!(frame.ciphertext.len(), 0);
    }

    #[test]
    fn test_buffer_too_small() {
        let buffer = vec![0u8; 33];
        let result = ShardFrame::from_bytes(&buffer);
        assert!(matches!(result, Err(ShardError::BufferTooSmall)));
    }

    #[test]
    fn test_invalid_version() {
        let mut buffer = vec![0u8; 50];
        buffer[0] = 0x02;
        let result = ShardFrame::from_bytes(&buffer);
        assert!(matches!(result, Err(ShardError::InvalidVersion { .. })));
    }

    #[test]
    fn test_payload_length_overflow() {
        let mut buffer = vec![0u8; 1100];
        buffer[0] = 0x01;
        let overflow_len = 1025u32;
        buffer[30..34].copy_from_slice(&overflow_len.to_be_bytes());

        let result = ShardFrame::from_bytes(&buffer);
        assert!(matches!(result, Err(ShardError::CryptoError)));
    }
}
