// ============================================================================
// RDP-CRYPTO: Core Types
// ============================================================================

use borsh::{BorshSerialize, BorshDeserialize};
use zeroize::Zeroize;

/// Size constants
pub const SCALAR_SIZE: usize = 32;
pub const POINT_SIZE: usize = 32;
pub const KEY_IMAGE_SIZE: usize = 32;
pub const COMMITMENT_SIZE: usize = 32;

/// Secret key (scalar)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub [u8; SCALAR_SIZE]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; SCALAR_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SCALAR_SIZE] {
        &self.0
    }
}

/// Public key (compressed Edwards point)
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PublicKey(pub [u8; POINT_SIZE]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; POINT_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; POINT_SIZE] {
        &self.0
    }
}

/// Key image (used to detect double-spend)
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct KeyImage(pub [u8; KEY_IMAGE_SIZE]);

impl KeyImage {
    pub fn from_bytes(bytes: [u8; KEY_IMAGE_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_IMAGE_SIZE] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; KEY_IMAGE_SIZE] {
        self.0
    }
}

/// Cryptographic errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid scalar value
    InvalidScalar,
    /// Invalid curve point
    InvalidPoint,
    /// Invalid signature
    InvalidSignature,
    /// Invalid key image
    InvalidKeyImage,
    /// Invalid ring size
    InvalidRingSize,
    /// Ring member index out of bounds
    IndexOutOfBounds,
    /// Verification failed
    VerificationFailed,
    /// Serialization error
    SerializationError,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::InvalidScalar => write!(f, "Invalid scalar"),
            CryptoError::InvalidPoint => write!(f, "Invalid point"),
            CryptoError::InvalidSignature => write!(f, "Invalid signature"),
            CryptoError::InvalidKeyImage => write!(f, "Invalid key image"),
            CryptoError::InvalidRingSize => write!(f, "Invalid ring size"),
            CryptoError::IndexOutOfBounds => write!(f, "Index out of bounds"),
            CryptoError::VerificationFailed => write!(f, "Verification failed"),
            CryptoError::SerializationError => write!(f, "Serialization error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_zeroize() {
        let mut sk = SecretKey::from_bytes([1u8; 32]);
        sk.zeroize();
        assert_eq!(sk.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_public_key_serialization() {
        let pk = PublicKey::from_bytes([42u8; 32]);
        let serialized = borsh::to_vec(&pk).unwrap();
        let deserialized: PublicKey = borsh::from_slice(&serialized).unwrap();
        assert_eq!(pk, deserialized);
    }

    #[test]
    fn test_key_image_serialization() {
        let ki = KeyImage::from_bytes([99u8; 32]);
        let serialized = borsh::to_vec(&ki).unwrap();
        let deserialized: KeyImage = borsh::from_slice(&serialized).unwrap();
        assert_eq!(ki, deserialized);
    }
}
