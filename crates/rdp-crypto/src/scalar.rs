// ============================================================================
// RDP-CRYPTO: Scalar Operations (mod l)
// ============================================================================
//
// Scalars are 256-bit integers modulo the order of the Ed25519 curve:
// l = 2^252 + 27742317777372353535851937790883648493
// ============================================================================

use curve25519_dalek::scalar::Scalar as DalekScalar;
use crate::types::{CryptoError, CryptoResult, SCALAR_SIZE};

/// Scalar wrapper for curve operations
#[derive(Clone, Copy, Debug)]
pub struct Scalar(pub(crate) DalekScalar);

impl Scalar {
    /// Create scalar from 32 bytes (little-endian, reduced mod l)
    pub fn from_bytes_mod_order(bytes: &[u8; SCALAR_SIZE]) -> Self {
        Self(DalekScalar::from_bytes_mod_order(*bytes))
    }

    /// Create scalar from 64 bytes (little-endian, reduced mod l)
    /// Used for hash-to-scalar operations
    pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        Self(DalekScalar::from_bytes_mod_order_wide(bytes))
    }

    /// Try to create scalar from canonical bytes
    pub fn from_canonical_bytes(bytes: &[u8; SCALAR_SIZE]) -> CryptoResult<Self> {
        let scalar = DalekScalar::from_canonical_bytes(*bytes);
        if scalar.is_some().into() {
            Ok(Self(scalar.unwrap()))
        } else {
            Err(CryptoError::InvalidScalar)
        }
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; SCALAR_SIZE] {
        self.0.to_bytes()
    }

    /// Zero scalar
    pub fn zero() -> Self {
        Self(DalekScalar::ZERO)
    }

    /// One scalar
    pub fn one() -> Self {
        Self(DalekScalar::ONE)
    }

    /// Generate random scalar (only available with std feature)
    #[cfg(feature = "std")]
    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes_mod_order_wide(&bytes)
    }

    /// Scalar addition
    pub fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }

    /// Scalar subtraction
    pub fn sub(&self, other: &Self) -> Self {
        Self(self.0 - other.0)
    }

    /// Scalar multiplication
    pub fn mul(&self, other: &Self) -> Self {
        Self(self.0 * other.0)
    }

    /// Scalar negation
    pub fn neg(&self) -> Self {
        Self(-self.0)
    }

    /// Scalar inversion (1/x mod l)
    pub fn invert(&self) -> Self {
        Self(self.0.invert())
    }

    /// Get internal dalek scalar
    fn _inner(&self) -> &DalekScalar {
        &self.0
    }
}

impl From<DalekScalar> for Scalar {
    fn from(s: DalekScalar) -> Self {
        Self(s)
    }
}

impl From<Scalar> for DalekScalar {
    fn from(s: Scalar) -> Self {
        s.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_arithmetic() {
        let a = Scalar::from_bytes_mod_order(&[1u8; 32]);
        let b = Scalar::from_bytes_mod_order(&[2u8; 32]);
        
        let c = a.add(&b);
        let d = c.sub(&a);
        
        assert_eq!(d.to_bytes(), b.to_bytes());
    }

    #[test]
    fn test_scalar_zero_one() {
        let zero = Scalar::zero();
        let one = Scalar::one();
        
        assert_eq!(zero.to_bytes(), [0u8; 32]);
        assert_ne!(one.to_bytes(), [0u8; 32]);
    }
}
