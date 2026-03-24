//! Binary frame representation and parsing for the Shard protocol.

use crate::consts::{AUTH_TAG_SIZE, HEADER_SIZE, MAX_PAYLOAD_SIZE, VERSION};
use crate::error::ShardError;
use zerocopy::byteorder::big_endian::{U32, U64};
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
    pub sequence_id: U64,
    /// 64-bit Unix timestamp in milliseconds (Big Endian).
    pub timestamp: U64,
    /// 96-bit unique cryptographic nonce.
    pub nonce: [u8; 12],
    /// 32-bit length of the ciphertext (Big Endian).
    pub payload_len: U32,
}

/// A complete Shard frame containing the header, ciphertext, and authentication tag.
#[derive(Debug, Clone)]
pub struct ShardFrame<'a> {
    /// Parsed header metadata.
    pub header: ShardHeader,
    /// Encrypted payload data.
    pub ciphertext: &'a [u8],
    /// Poly1305 authentication tag (16 bytes).
    pub auth_tag: [u8; AUTH_TAG_SIZE],
}

impl<'a> ShardFrame<'a> {
    /// Parses a raw byte buffer into a `ShardFrame`.
    ///
    /// # Errors
    /// Returns `ShardError::BufferTooSmall` if the buffer size is less than 50 bytes.
    /// Returns `ShardError::InvalidVersion` if the version field is not 0x01.
    /// Returns `ShardError::InvalidPayloadLength` if the payload length exceeds the hard cap.
    pub fn from_bytes(buffer: &'a [u8]) -> Result<Self, ShardError> {
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
        let payload_len_raw = header.payload_len.get();
        let payload_len =
            usize::try_from(payload_len_raw).map_err(|_| ShardError::InvalidPayloadLength)?;

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ShardError::PayloadTooLarge(payload_len));
        }

        let total_expected_size = HEADER_SIZE
            .checked_add(payload_len)
            .and_then(|sum| sum.checked_add(AUTH_TAG_SIZE))
            .ok_or(ShardError::BufferTooSmall)?;
        if buffer.len() < total_expected_size {
            return Err(ShardError::BufferTooSmall);
        }

        // Safety: total_expected_size is validated against buffer.len()
        let ciphertext = buffer
            .get(HEADER_SIZE..HEADER_SIZE + payload_len)
            .ok_or(ShardError::BufferTooSmall)?;

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
    fn test_valid_frame_parsing() -> Result<(), ShardError> {
        use crate::crypto::encrypt_frame_payload;
        use zerocopy::big_endian::U64;

        let master_psk = [0u8; 32];
        let mut payload = b"hello".to_vec();
        let mut header = ShardHeader {
            version: VERSION,
            frame_type: 0,
            sequence_id: U64::new(1),
            timestamp: U64::new(0),
            nonce: [0u8; 12],
            payload_len: U32::new(5),
        };

        let tag = encrypt_frame_payload(&master_psk, &mut header, &mut payload)?;

        let mut buffer = Vec::new();
        buffer.extend_from_slice(header.as_bytes());
        buffer.extend_from_slice(&payload);
        buffer.extend_from_slice(&tag);

        let frame = ShardFrame::from_bytes(&buffer)?;

        assert_eq!(frame.header.version, VERSION);
        assert_eq!(frame.ciphertext.len(), 5);
        assert_eq!(frame.auth_tag, tag);

        Ok(())
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
        assert!(matches!(result, Err(ShardError::PayloadTooLarge(_))));
    }
}
