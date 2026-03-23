// ============================================================================
// RDP-CRYPTO: Ring Signature Implementation (CLSAG Algorithm)
// ============================================================================
//
// CLSAG (Compact Linkable Spontaneous Anonymous Group) Signature
//
// Properties:
// - Signer anonymity: verifier cannot determine which ring member signed
// - Linkability: same signer produces same key image (prevents double-spend)
// - Unforgeability: cannot forge signature without secret key
//
// Structure:
// - c: initial challenge scalar
// - responses: one scalar per ring member
// - key_image: unique identifier for the signing key
// ============================================================================

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use borsh::{BorshSerialize, BorshDeserialize};
use crate::scalar::Scalar;
use crate::point::Point;
use crate::hash::{hash_to_scalar_multiple, hash_to_point_for_key_image};
use crate::key_image::generate_key_image;
use crate::types::{
    CryptoError, CryptoResult, SecretKey, PublicKey, KeyImage,
    SCALAR_SIZE, POINT_SIZE,
};

/// Maximum ring size supported
pub const MAX_RING_SIZE: usize = 32;

/// Minimum ring size required
pub const MIN_RING_SIZE: usize = 2;

/// Ring signature structure
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct RingSignature {
    /// Initial challenge
    pub c: [u8; SCALAR_SIZE],
    /// Response scalars (one per ring member)
    #[cfg(feature = "alloc")]
    pub responses: Vec<[u8; SCALAR_SIZE]>,
    #[cfg(not(feature = "alloc"))]
    pub responses: [u8; 0], // Placeholder for no-alloc (not usable)
    /// Key image (for linkability)
    pub key_image: [u8; POINT_SIZE],
}

impl RingSignature {
    /// Get the ring size
    #[cfg(feature = "alloc")]
    pub fn ring_size(&self) -> usize {
        self.responses.len()
    }

    /// Get key image as type
    pub fn get_key_image(&self) -> KeyImage {
        KeyImage::from_bytes(self.key_image)
    }
}

/// Sign a message with a ring signature
///
/// # Arguments
/// * `message` - The message to sign
/// * `ring` - Array of public keys (ring members)
/// * `secret_index` - Index of the signer's public key in the ring
/// * `secret_key` - The signer's secret key
///
/// # Returns
/// * `RingSignature` on success
#[cfg(feature = "std")]
pub fn sign(
    message: &[u8],
    ring: &[PublicKey],
    secret_index: usize,
    secret_key: &SecretKey,
) -> CryptoResult<RingSignature> {
    use rand::rngs::OsRng;
    sign_with_rng(message, ring, secret_index, secret_key, &mut OsRng)
}

/// Sign with custom RNG (for testing or deterministic signing)
#[cfg(feature = "std")]
pub fn sign_with_rng<R: rand_core::RngCore + rand_core::CryptoRng>(
    message: &[u8],
    ring: &[PublicKey],
    secret_index: usize,
    secret_key: &SecretKey,
    rng: &mut R,
) -> CryptoResult<RingSignature> {
    let ring_size = ring.len();
    
    // Validate inputs
    if ring_size < MIN_RING_SIZE || ring_size > MAX_RING_SIZE {
        return Err(CryptoError::InvalidRingSize);
    }
    if secret_index >= ring_size {
        return Err(CryptoError::IndexOutOfBounds);
    }

    // Convert secret key to scalar
    let x = Scalar::from_bytes_mod_order(secret_key.as_bytes());
    
    // Compute public key and verify it matches ring[secret_index]
    let computed_pubkey = Point::from_secret_key(&x);
    let expected_pubkey = Point::from_bytes(ring[secret_index].as_bytes())?;
    if computed_pubkey.to_bytes() != expected_pubkey.to_bytes() {
        return Err(CryptoError::InvalidSignature);
    }

    // Generate key image: I = x * H_p(P)
    let key_image = generate_key_image(secret_key)?;
    let key_image_point = Point::from_bytes(key_image.as_bytes())?;
    
    // H_p(P) for the signer
    let hp = hash_to_point_for_key_image(ring[secret_index].as_bytes());

    // Generate random scalar alpha
    let alpha = Scalar::random(rng);
    
    // Compute L_i = alpha * G and R_i = alpha * H_p(P_i) for signer
    let l_signer = Point::basepoint().mul(&alpha);
    let r_signer = hp.mul(&alpha);

    // Initialize arrays
    let mut responses = vec![[0u8; SCALAR_SIZE]; ring_size];
    let mut challenges = vec![Scalar::zero(); ring_size];
    
    // Compute initial challenge c_{secret_index + 1}
    let next_index = (secret_index + 1) % ring_size;
    challenges[next_index] = compute_challenge(
        message,
        ring,
        key_image.as_bytes(),
        &l_signer.to_bytes(),
        &r_signer.to_bytes(),
        secret_index,
    );

    // Go around the ring
    let mut i = next_index;
    loop {
        if i == secret_index {
            break;
        }

        // Generate random response for this index
        let s_i = Scalar::random(rng);
        responses[i] = s_i.to_bytes();

        // Get public key point for this index
        let p_i = Point::from_bytes(ring[i].as_bytes())?;
        let hp_i = hash_to_point_for_key_image(ring[i].as_bytes());

        // Compute L_i = s_i * G + c_i * P_i
        let l_i = Point::basepoint().mul(&s_i).add(&p_i.mul(&challenges[i]));
        
        // Compute R_i = s_i * H_p(P_i) + c_i * I
        let r_i = hp_i.mul(&s_i).add(&key_image_point.mul(&challenges[i]));

        // Compute next challenge
        let next_i = (i + 1) % ring_size;
        challenges[next_i] = compute_challenge(
            message,
            ring,
            key_image.as_bytes(),
            &l_i.to_bytes(),
            &r_i.to_bytes(),
            i,
        );

        i = next_i;
    }

    // Close the ring: compute response for signer
    // s_pi = alpha - c_pi * x
    let s_signer = alpha.sub(&challenges[secret_index].mul(&x));
    responses[secret_index] = s_signer.to_bytes();

    Ok(RingSignature {
        c: challenges[0].to_bytes(),
        responses,
        key_image: key_image.0,
    })
}

/// Verify a ring signature
///
/// # Arguments
/// * `message` - The message that was signed
/// * `ring` - Array of public keys (ring members)
/// * `signature` - The ring signature to verify
///
/// # Returns
/// * `Ok(())` if signature is valid
/// * `Err(CryptoError)` if signature is invalid
#[cfg(feature = "alloc")]
pub fn verify(
    message: &[u8],
    ring: &[PublicKey],
    signature: &RingSignature,
) -> CryptoResult<()> {
    let ring_size = ring.len();

    // Validate ring size
    if ring_size < MIN_RING_SIZE || ring_size > MAX_RING_SIZE {
        return Err(CryptoError::InvalidRingSize);
    }
    if signature.responses.len() != ring_size {
        return Err(CryptoError::InvalidSignature);
    }

    // Parse key image
    let key_image_point = Point::from_bytes(&signature.key_image)?;
    if key_image_point.is_identity() {
        return Err(CryptoError::InvalidKeyImage);
    }

    // Start with c_0
    let mut c = Scalar::from_bytes_mod_order(&signature.c);

    // Verify around the ring
    for i in 0..ring_size {
        let s_i = Scalar::from_bytes_mod_order(&signature.responses[i]);
        let p_i = Point::from_bytes(ring[i].as_bytes())?;
        let hp_i = hash_to_point_for_key_image(ring[i].as_bytes());

        // Compute L_i = s_i * G + c_i * P_i
        let l_i = Point::basepoint().mul(&s_i).add(&p_i.mul(&c));
        
        // Compute R_i = s_i * H_p(P_i) + c_i * I
        let r_i = hp_i.mul(&s_i).add(&key_image_point.mul(&c));

        // Compute next challenge
        c = compute_challenge(
            message,
            ring,
            &signature.key_image,
            &l_i.to_bytes(),
            &r_i.to_bytes(),
            i,
        );
    }

    // Verify that we got back to the original challenge
    if c.to_bytes() != signature.c {
        return Err(CryptoError::VerificationFailed);
    }

    Ok(())
}

/// Compute challenge hash
#[cfg(feature = "alloc")]
fn compute_challenge(
    message: &[u8],
    ring: &[PublicKey],
    key_image: &[u8; POINT_SIZE],
    l: &[u8; POINT_SIZE],
    r: &[u8; POINT_SIZE],
    index: usize,
) -> Scalar {
    use sha2::{Sha512, Digest};
    
    const DOMAIN_RING_CHALLENGE: &[u8] = b"RDP_RING_CHALLENGE_V1";
    
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_RING_CHALLENGE);
    
    // Length-prefix message (match on-chain)
    hasher.update(&(message.len() as u32).to_le_bytes());
    hasher.update(message);
    
    // Ring bytes with length prefix
    let ring_len = ring.len() * POINT_SIZE;
    hasher.update(&(ring_len as u32).to_le_bytes());
    for pk in ring {
        hasher.update(&pk.0);
    }
    
    // Key image with length prefix
    hasher.update(&(POINT_SIZE as u32).to_le_bytes());
    hasher.update(key_image);
    
    // L with length prefix
    hasher.update(&(POINT_SIZE as u32).to_le_bytes());
    hasher.update(l);
    
    // R with length prefix
    hasher.update(&(POINT_SIZE as u32).to_le_bytes());
    hasher.update(r);
    
    // Index with length prefix
    hasher.update(&4u32.to_le_bytes());
    hasher.update(&(index as u32).to_le_bytes());
    
    let result = hasher.finalize();

    // Simple scalar reduction: take first 32 bytes, mask top bits
    // output[31] &= 0x0f ensures result < 2^252 < l
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..32]);
    output[31] &= 0x0f;
    Scalar::from_bytes_mod_order(&output)
}


#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn generate_keypair(seed: u8) -> (SecretKey, PublicKey) {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[0] = seed;
        sk_bytes[31] = 1; // Ensure non-zero
        
        let sk = SecretKey::from_bytes(sk_bytes);
        let x = Scalar::from_bytes_mod_order(&sk_bytes);
        let pk_point = Point::from_secret_key(&x);
        let pk = PublicKey::from_bytes(pk_point.to_bytes());
        
        (sk, pk)
    }

    #[test]
    fn test_sign_verify_ring_size_2() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        let (sk0, pk0) = generate_keypair(1);
        let (_, pk1) = generate_keypair(2);
        
        let ring = vec![pk0, pk1];
        let message = b"test message";
        
        let signature = sign_with_rng(message, &ring, 0, &sk0, &mut rng).unwrap();
        
        assert!(verify(message, &ring, &signature).is_ok());
    }

    #[test]
    fn test_sign_verify_ring_size_4() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        let (sk2, pk2) = generate_keypair(3);
        let keypairs: Vec<_> = (0..4).map(|i| generate_keypair(i as u8)).collect();
        let mut ring: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();
        ring[2] = pk2; // Put our key at index 2
        
        let message = b"another test message";
        
        let signature = sign_with_rng(message, &ring, 2, &sk2, &mut rng).unwrap();
        
        assert!(verify(message, &ring, &signature).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        let (sk0, pk0) = generate_keypair(1);
        let (_, pk1) = generate_keypair(2);
        
        let ring = vec![pk0, pk1];
        let message = b"test message";
        let wrong_message = b"wrong message";
        
        let signature = sign_with_rng(message, &ring, 0, &sk0, &mut rng).unwrap();
        
        assert!(verify(wrong_message, &ring, &signature).is_err());
    }

    #[test]
    fn test_key_image_linkability() {
        let mut rng1 = StdRng::seed_from_u64(11111);
        let mut rng2 = StdRng::seed_from_u64(22222);
        
        let (sk0, pk0) = generate_keypair(1);
        let (_, pk1) = generate_keypair(2);
        let (_, pk2) = generate_keypair(3);
        
        // Sign with different rings but same secret key
        let ring1 = vec![pk0, pk1];
        let ring2 = vec![pk0, pk2];
        
        let sig1 = sign_with_rng(b"msg1", &ring1, 0, &sk0, &mut rng1).unwrap();
        let sig2 = sign_with_rng(b"msg2", &ring2, 0, &sk0, &mut rng2).unwrap();
        
        // Key images should be the same (linkable)
        assert_eq!(sig1.key_image, sig2.key_image);
    }

    #[test]
    fn test_different_signers_different_key_images() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        let (sk0, pk0) = generate_keypair(1);
        let (sk1, pk1) = generate_keypair(2);
        
        let ring = vec![pk0, pk1];
        
        let sig0 = sign_with_rng(b"msg", &ring, 0, &sk0, &mut rng.clone()).unwrap();
        let sig1 = sign_with_rng(b"msg", &ring, 1, &sk1, &mut rng).unwrap();
        
        // Different signers should have different key images
        assert_ne!(sig0.key_image, sig1.key_image);
    }

    #[test]
    fn test_invalid_ring_size() {
        let mut rng = StdRng::seed_from_u64(12345);
        let (sk0, pk0) = generate_keypair(1);
        
        // Ring size 1 is too small
        let ring = vec![pk0];
        let result = sign_with_rng(b"msg", &ring, 0, &sk0, &mut rng);
        
        assert!(matches!(result, Err(CryptoError::InvalidRingSize)));
    }

    #[test]
    fn test_index_out_of_bounds() {
        let mut rng = StdRng::seed_from_u64(12345);
        let (sk0, pk0) = generate_keypair(1);
        let (_, pk1) = generate_keypair(2);
        
        let ring = vec![pk0, pk1];
        let result = sign_with_rng(b"msg", &ring, 5, &sk0, &mut rng);
        
        assert!(matches!(result, Err(CryptoError::IndexOutOfBounds)));
    }
}
