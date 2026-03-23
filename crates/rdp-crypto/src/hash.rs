// ============================================================================
// RDP-CRYPTO: Hash Functions
// ============================================================================
//
// Hash functions for:
// - Hash to scalar (for challenges)
// - Hash to point (for key images and generator H)
// - General purpose hashing
// ============================================================================


use sha2::{Sha512, Digest};
use crate::scalar::Scalar;
use crate::point::Point;
use crate::types::SCALAR_SIZE;

/// Domain separation tags
const DOMAIN_HASH_TO_SCALAR: &[u8] = b"RDP_HASH_TO_SCALAR_V1";
const DOMAIN_HASH_TO_POINT: &[u8] = b"RDP_HASH_TO_POINT_V1";
const DOMAIN_RING_CHALLENGE: &[u8] = b"RDP_RING_CHALLENGE_V1";
const DOMAIN_KEY_IMAGE: &[u8] = b"RDP_KEY_IMAGE_V1";

/// Hash arbitrary data to a scalar
/// Uses SHA512, takes first 32 bytes, masks top bits to ensure < 2^252 < l
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_HASH_TO_SCALAR);
    hasher.update(data);
    let result = hasher.finalize();

    // Simple reduction: take first 32 bytes, mask top bits
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..32]);
    output[31] &= 0x0f;
    
    Scalar::from_bytes_mod_order(&output)
}

/// Hash multiple inputs to a scalar (for ring signature challenges)
pub fn hash_to_scalar_multiple(inputs: &[&[u8]]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_RING_CHALLENGE);
    for input in inputs {
        // Length-prefix each input to prevent ambiguity
        hasher.update(&(input.len() as u32).to_le_bytes());
        hasher.update(input);
    }
    let result = hasher.finalize();
    
    let mut wide_bytes = [0u8; 64];
    wide_bytes.copy_from_slice(&result);
    
    Scalar::from_bytes_mod_order_wide(&wide_bytes)
}

/// Hash data to a curve point using try-and-increment method
/// This is not constant-time but is safe for public inputs
pub fn hash_to_point(data: &[u8]) -> Point {
    let mut counter: u32 = 0;
    
    loop {
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_HASH_TO_POINT);
        hasher.update(data);
        hasher.update(&counter.to_le_bytes());
        let result = hasher.finalize();
        
        // Take first 32 bytes and try to decompress as point
        let mut point_bytes = [0u8; 32];
        point_bytes.copy_from_slice(&result[..32]);
        
        // Set high bit to make it a valid y-coordinate attempt
        point_bytes[31] &= 0x7f;
        
        if let Ok(point) = Point::from_bytes(&point_bytes) {
            // Multiply by cofactor (8) to ensure we're in the prime-order subgroup
            let eight = Scalar::from_bytes_mod_order(&[8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let cleared = point.mul(&eight);
            
            if !cleared.is_identity() {
                return cleared;
            }
        }
        
        counter += 1;
        if counter > 1000 {
            // This should never happen with proper hash function
            panic!("hash_to_point failed after 1000 iterations");
        }
    }
}

/// Hash for key image derivation: H_p(P) where P is public key
pub fn hash_to_point_for_key_image(public_key: &[u8; 32]) -> Point {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_KEY_IMAGE);
    hasher.update(public_key);
    let result = hasher.finalize();
    
    let mut data = [0u8; 64];
    data.copy_from_slice(&result);
    
    // Use the full hash output to find a point
    hash_to_point(&data)
}

/// Simple SHA-512 hash returning 32 bytes
pub fn hash_256(data: &[u8]) -> [u8; SCALAR_SIZE] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..32]);
    output
}

/// Concatenate and hash multiple byte slices
pub fn hash_concat(parts: &[&[u8]]) -> [u8; SCALAR_SIZE] {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    let result = hasher.finalize();
    
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..32]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_scalar_deterministic() {
        let data = b"test data";
        let s1 = hash_to_scalar(data);
        let s2 = hash_to_scalar(data);
        
        assert_eq!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn test_hash_to_scalar_different_inputs() {
        let s1 = hash_to_scalar(b"input1");
        let s2 = hash_to_scalar(b"input2");
        
        assert_ne!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn test_hash_to_point_deterministic() {
        let data = b"test point";
        let p1 = hash_to_point(data);
        let p2 = hash_to_point(data);
        
        assert_eq!(p1.to_bytes(), p2.to_bytes());
    }

    #[test]
    fn test_hash_to_point_not_identity() {
        let p = hash_to_point(b"any data");
        assert!(!p.is_identity());
    }

    #[test]
    fn test_domain_separation() {
        // Same input with different functions should give different results
        let data = b"same input";
        let scalar = hash_to_scalar(data);
        let point = hash_to_point(data);
        
        // The scalar bytes should not match the point bytes
        assert_ne!(scalar.to_bytes(), point.to_bytes());
    }
}
