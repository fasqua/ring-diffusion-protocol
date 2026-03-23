// ============================================================================
// RDP-CRYPTO: Key Image Generation
// ============================================================================
//
// Key image is a unique identifier for each secret key that:
// 1. Can be computed only by the owner of the secret key
// 2. Is the same regardless of which ring the key appears in
// 3. Does not reveal the secret key
//
// Formula: I = x * H_p(P)
// Where:
//   x = secret key (scalar)
//   P = public key = x * G
//   H_p = hash to point function
//   I = key image
//
// This allows detection of double-spends without revealing which
// ring member actually signed.
// ============================================================================

use crate::scalar::Scalar;
use crate::point::Point;
use crate::hash::hash_to_point_for_key_image;
use crate::types::{KeyImage, SecretKey, PublicKey, CryptoResult, CryptoError};

/// Generate key image from secret key
/// I = x * H_p(P) where P = x * G
pub fn generate_key_image(secret_key: &SecretKey) -> CryptoResult<KeyImage> {
    // Convert secret key bytes to scalar
    let x = Scalar::from_bytes_mod_order(secret_key.as_bytes());
    
    // Compute public key P = x * G
    let public_key = Point::from_secret_key(&x);
    let public_key_bytes = public_key.to_bytes();
    
    // Compute H_p(P)
    let hp = hash_to_point_for_key_image(&public_key_bytes);
    
    // Compute key image I = x * H_p(P)
    let key_image_point = hp.mul(&x);
    
    // Check that result is not identity (would indicate invalid key)
    if key_image_point.is_identity() {
        return Err(CryptoError::InvalidKeyImage);
    }
    
    Ok(KeyImage::from_bytes(key_image_point.to_bytes()))
}

/// Generate key image from secret key and pre-computed public key
/// This is faster if you already have the public key
pub fn generate_key_image_with_pubkey(
    secret_key: &SecretKey, 
    public_key: &PublicKey
) -> CryptoResult<KeyImage> {
    // Convert secret key bytes to scalar
    let x = Scalar::from_bytes_mod_order(secret_key.as_bytes());
    
    // Compute H_p(P)
    let hp = hash_to_point_for_key_image(public_key.as_bytes());
    
    // Compute key image I = x * H_p(P)
    let key_image_point = hp.mul(&x);
    
    // Check that result is not identity
    if key_image_point.is_identity() {
        return Err(CryptoError::InvalidKeyImage);
    }
    
    Ok(KeyImage::from_bytes(key_image_point.to_bytes()))
}

/// Verify that a key image is well-formed (on the curve and not identity)
pub fn verify_key_image(key_image: &KeyImage) -> CryptoResult<()> {
    // Try to decompress the point
    let point = Point::from_bytes(key_image.as_bytes())?;
    
    // Check it's not identity
    if point.is_identity() {
        return Err(CryptoError::InvalidKeyImage);
    }
    
    Ok(())
}

/// Derive public key from secret key
pub fn derive_public_key(secret_key: &SecretKey) -> PublicKey {
    let x = Scalar::from_bytes_mod_order(secret_key.as_bytes());
    let public_key = Point::from_secret_key(&x);
    PublicKey::from_bytes(public_key.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret_key() -> SecretKey {
        SecretKey::from_bytes([
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
            0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ])
    }

    #[test]
    fn test_key_image_generation() {
        let sk = test_secret_key();
        let ki = generate_key_image(&sk).unwrap();
        
        // Key image should not be all zeros
        assert_ne!(ki.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_key_image_deterministic() {
        let sk = test_secret_key();
        
        let ki1 = generate_key_image(&sk).unwrap();
        let ki2 = generate_key_image(&sk).unwrap();
        
        // Same secret key should always produce same key image
        assert_eq!(ki1.as_bytes(), ki2.as_bytes());
    }

    #[test]
    fn test_key_image_unique() {
        let sk1 = SecretKey::from_bytes([1u8; 32]);
        let sk2 = SecretKey::from_bytes([2u8; 32]);
        
        let ki1 = generate_key_image(&sk1).unwrap();
        let ki2 = generate_key_image(&sk2).unwrap();
        
        // Different secret keys should produce different key images
        assert_ne!(ki1.as_bytes(), ki2.as_bytes());
    }

    #[test]
    fn test_key_image_with_pubkey() {
        let sk = test_secret_key();
        let pk = derive_public_key(&sk);
        
        let ki1 = generate_key_image(&sk).unwrap();
        let ki2 = generate_key_image_with_pubkey(&sk, &pk).unwrap();
        
        // Both methods should produce same key image
        assert_eq!(ki1.as_bytes(), ki2.as_bytes());
    }

    #[test]
    fn test_verify_key_image() {
        let sk = test_secret_key();
        let ki = generate_key_image(&sk).unwrap();
        
        // Valid key image should verify
        assert!(verify_key_image(&ki).is_ok());
    }

    #[test]
    fn test_verify_invalid_key_image() {
        // Bytes that definitely don't decompress to a valid curve point
        // (high bit set in last byte with invalid y-coordinate)
        let invalid_ki = KeyImage::from_bytes([
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        ]);
        // This should fail because 2 is not a valid y-coordinate on the curve
        assert!(verify_key_image(&invalid_ki).is_err());
    }

    #[test]
    fn test_derive_public_key() {
        let sk = test_secret_key();
        let pk = derive_public_key(&sk);
        
        // Public key should not be all zeros
        assert_ne!(pk.as_bytes(), &[0u8; 32]);
    }
}
