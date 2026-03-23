// ============================================================================
// On-Chain Crypto Types
// ============================================================================

use anchor_lang::prelude::*;

/// Size constants (must match rdp-crypto)
pub const SCALAR_SIZE: usize = 32;
pub const POINT_SIZE: usize = 32;
pub const KEY_IMAGE_SIZE: usize = 32;

/// Maximum ring size for on-chain verification
pub const MAX_RING_SIZE: usize = 16;

/// Minimum ring size required
pub const MIN_RING_SIZE: usize = 2;

/// Ring signature structure for on-chain verification
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct RingSignatureData {
    /// Initial challenge (32 bytes)
    pub c: [u8; SCALAR_SIZE],
    /// Response scalars (one per ring member, max 16)
    pub responses: Vec<[u8; SCALAR_SIZE]>,
    /// Key image (32 bytes)
    pub key_image: [u8; KEY_IMAGE_SIZE],
}

impl RingSignatureData {
    /// Get ring size
    pub fn ring_size(&self) -> usize {
        self.responses.len()
    }

    /// Validate basic structure
    pub fn validate(&self) -> Result<()> {
        require!(
            self.responses.len() >= MIN_RING_SIZE,
            RingVerifyError::RingSizeTooSmall
        );
        require!(
            self.responses.len() <= MAX_RING_SIZE,
            RingVerifyError::RingSizeTooLarge
        );
        Ok(())
    }
}

/// Errors for ring signature verification
#[error_code]
pub enum RingVerifyError {
    #[msg("Ring size too small (minimum 2)")]
    RingSizeTooSmall,
    #[msg("Ring size too large (maximum 16)")]
    RingSizeTooLarge,
    #[msg("Ring size mismatch with signature")]
    RingSizeMismatch,
    #[msg("Invalid point on curve")]
    InvalidPoint,
    #[msg("Invalid key image")]
    InvalidKeyImage,
    #[msg("Ring signature verification failed")]
    VerificationFailed,
    #[msg("Curve operation failed")]
    CurveOperationFailed,
}
