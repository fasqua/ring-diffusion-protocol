// ============================================================================
// RDP-CRYPTO: Point Operations (Edwards Curve)
// ============================================================================

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::traits::Identity;

use crate::scalar::Scalar;
use crate::types::{CryptoError, CryptoResult, POINT_SIZE};

/// Edwards curve point wrapper
#[derive(Clone, Copy, Debug)]
pub struct Point(pub(crate) EdwardsPoint);

impl Point {
    /// Get the Ed25519 basepoint (generator G)
    pub fn basepoint() -> Self {
        Self(ED25519_BASEPOINT_POINT)
    }

    /// Get the identity point (neutral element)
    pub fn identity() -> Self {
        Self(EdwardsPoint::identity())
    }

    /// Check if this is the identity point
    pub fn is_identity(&self) -> bool {
        self.0 == EdwardsPoint::identity()
    }

    /// Check if point is valid (on curve)
    pub fn is_valid(&self) -> bool {
        let compressed = self.0.compress();
        if let Some(decompressed) = compressed.decompress() {
            decompressed == self.0
        } else {
            false
        }
    }

    /// Create public key from secret key (P = x * G)
    pub fn from_secret_key(secret: &Scalar) -> Self {
        Self::basepoint().mul(secret)
    }

    /// Create point from compressed bytes
    pub fn from_bytes(bytes: &[u8; POINT_SIZE]) -> CryptoResult<Self> {
        let compressed = CompressedEdwardsY(*bytes);
        compressed
            .decompress()
            .map(Point)
            .ok_or(CryptoError::InvalidPoint)
    }

    /// Compress point to bytes
    pub fn to_bytes(&self) -> [u8; POINT_SIZE] {
        self.0.compress().to_bytes()
    }

    /// Scalar multiplication: self * scalar
    pub fn mul(&self, scalar: &Scalar) -> Self {
        Self(self.0 * scalar.0)
    }

    /// Point addition: self + other
    pub fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }

    /// Point subtraction: self - other
    pub fn sub(&self, other: &Self) -> Self {
        Self(self.0 - other.0)
    }

    /// Negate point: -self
    pub fn neg(&self) -> Self {
        Self(-self.0)
    }

    /// Multiply by cofactor (8 for Ed25519) to clear torsion
    pub fn mul_by_cofactor(&self) -> Self {
        Self(self.0.mul_by_cofactor())
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for Point {}

/// Secondary generator H (for Pedersen commitments)
/// Generated as hash_to_point with cofactor clearing to ensure
/// H is in the prime-order subgroup (no torsion component)
pub fn generator_h() -> Point {
    use sha2::{Sha512, Digest};
    
    let mut hasher = Sha512::new();
    hasher.update(b"RDP_GENERATOR_H_V1");
    let hash = hasher.finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    bytes[31] &= 0x7f; // Clear sign bit
    
    // Try to decompress as Edwards point
    if let Ok(point) = Point::from_bytes(&bytes) {
        if !point.is_identity() {
            // CRITICAL: Clear cofactor to ensure point is in prime-order subgroup
            // Without this, scalar multiplication is NOT associative!
            return point.mul_by_cofactor();
        }
    }
    
    // Fallback: multiply basepoint by hash scalar
    // Basepoint is already in prime-order subgroup, so result is too
    let scalar = Scalar::from_bytes_mod_order(&bytes);
    Point::basepoint().mul(&scalar)
}

/// Helper to create scalar from u64
#[cfg(test)]
fn scalar_from_u64(v: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&v.to_le_bytes());
    Scalar::from_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basepoint() {
        let g = Point::basepoint();
        assert!(!g.is_identity());
        assert!(g.is_valid());
    }

    #[test]
    fn test_identity() {
        let id = Point::identity();
        assert!(id.is_identity());
    }

    #[test]
    fn test_generator_h() {
        let h = generator_h();
        let g = Point::basepoint();
        
        assert_ne!(g.to_bytes(), h.to_bytes());
        assert!(!h.is_identity());
        assert!(h.is_valid());
    }

    #[test]
    fn test_generator_h_associativity() {
        // This test verifies that H is in the prime-order subgroup
        // by checking that scalar multiplication is associative
        let h = generator_h();
        
        let a = scalar_from_u64(5);
        let b = scalar_from_u64(7);
        let ab = a.mul(&b);
        
        let bh = h.mul(&b);
        let a_bh = bh.mul(&a);
        let ab_h = h.mul(&ab);
        
        assert_eq!(a_bh.to_bytes(), ab_h.to_bytes(), 
            "Generator H must be in prime-order subgroup for associativity");
    }

    #[test]
    fn test_from_secret_key() {
        let secret_bytes = [42u8; 32];
        let secret = Scalar::from_bytes_mod_order(&secret_bytes);
        let pubkey = Point::from_secret_key(&secret);
        
        let expected = Point::basepoint().mul(&secret);
        assert_eq!(pubkey.to_bytes(), expected.to_bytes());
        assert!(pubkey.is_valid());
    }

    #[test]
    fn test_point_serialization() {
        let g = Point::basepoint();
        let bytes = g.to_bytes();
        let recovered = Point::from_bytes(&bytes).unwrap();
        assert_eq!(g.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_point_addition() {
        let g = Point::basepoint();
        let two_g = g.add(&g);
        
        // Use proper scalar for 2
        let two = scalar_from_u64(2);
        let two_g_mul = g.mul(&two);
        
        assert_eq!(two_g.to_bytes(), two_g_mul.to_bytes());
    }

    #[test]
    fn test_point_subtraction() {
        let g = Point::basepoint();
        let id = g.sub(&g);
        assert!(id.is_identity());
    }

    #[test]
    fn test_scalar_mul_identity() {
        let g = Point::basepoint();
        let zero = Scalar::zero();
        let result = g.mul(&zero);
        assert!(result.is_identity());
    }
}
