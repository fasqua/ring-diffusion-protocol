// ============================================================================
// On-Chain Ring Signature Verifier
// ============================================================================
//
// Verifies CLSAG ring signatures using Solana's native curve25519 syscalls
// ============================================================================

use anchor_lang::prelude::*;
use solana_curve25519::edwards::{
    add_edwards, multiply_edwards, validate_edwards,
    PodEdwardsPoint,
};
use solana_curve25519::scalar::PodScalar;
use sha2::{Sha512, Digest};

use super::types::*;

/// Ed25519 basepoint (generator G) in compressed form
const BASEPOINT: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Identity point
const IDENTITY: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Domain separation for ring challenge
const DOMAIN_RING_CHALLENGE: &[u8] = b"RDP_RING_CHALLENGE_V1";
const DOMAIN_KEY_IMAGE: &[u8] = b"RDP_KEY_IMAGE_V1";
const DOMAIN_HASH_TO_POINT: &[u8] = b"RDP_HASH_TO_POINT_V1";

/// Verify a ring signature on-chain
pub fn verify_ring_signature(
    message: &[u8],
    ring: &[[u8; POINT_SIZE]],
    signature: &RingSignatureData,
) -> Result<()> {
    // Validate inputs
    signature.validate()?;
    require!(
        ring.len() == signature.ring_size(),
        RingVerifyError::RingSizeMismatch
    );

    // Validate key image is on curve and not identity
    let key_image = PodEdwardsPoint(signature.key_image);
    require!(
        validate_edwards(&key_image),
        RingVerifyError::InvalidKeyImage
    );
    require!(
        signature.key_image != IDENTITY,
        RingVerifyError::InvalidKeyImage
    );

    // Start with c_0
    let mut c = signature.c;

    // Verify around the ring
    for i in 0..ring.len() {
        if i < 3 || i == ring.len() - 1 {
            msg!("Iter {}", i);
        }
        // Validate ring member is on curve
        let p_i = PodEdwardsPoint(ring[i]);
        if !validate_edwards(&p_i) {
            msg!("Invalid point at {}: {:02x}{:02x}{:02x}{:02x}", i, ring[i][0], ring[i][1], ring[i][2], ring[i][3]);
            return Err(error!(RingVerifyError::InvalidPoint));
        }

        // Get response scalar
        let s_i = signature.responses[i];

        // Compute H_p(P_i) - hash public key to point for key image
        let hp_i = match hash_to_point_for_key_image(&ring[i]) {
            Ok(p) => p,
            Err(e) => {
                msg!("H_p failed at {}", i);
                return Err(e);
            }
        };
        
        // Debug first iteration
        if i == 0 {
            msg!("i=0 Hp: {:02x}{:02x}{:02x}{:02x}", hp_i[0], hp_i[1], hp_i[2], hp_i[3]);
        }

        // Compute L_i = s_i * G + c_i * P_i
        let l_i = match compute_l(&s_i, &c, &ring[i]) {
            Ok(l) => l,
            Err(e) => {
                msg!("compute_l failed at {}", i);
                return Err(e);
            }
        };

        // Compute R_i = s_i * H_p(P_i) + c_i * I
        let r_i = match compute_r(&s_i, &hp_i, &c, &signature.key_image) {
            Ok(r) => r,
            Err(e) => {
                msg!("compute_r failed at {}", i);
                return Err(e);
            }
        };

        // Compute next challenge
        c = compute_challenge(message, ring, &signature.key_image, &l_i, &r_i, i);
        
        // Debug: log first iteration values
        if i == 0 {
            msg!("i=0 L: {:02x}{:02x}{:02x}{:02x}", l_i[0], l_i[1], l_i[2], l_i[3]);
            msg!("i=0 R: {:02x}{:02x}{:02x}{:02x}", r_i[0], r_i[1], r_i[2], r_i[3]);
            msg!("i=0 c_next: {:02x}{:02x}{:02x}{:02x}", c[0], c[1], c[2], c[3]);
        }
    }

    // Verify that we got back to the original challenge
    msg!("Final c: {:02x}{:02x}{:02x}{:02x}", c[0], c[1], c[2], c[3]);
    msg!("Expect:  {:02x}{:02x}{:02x}{:02x}", signature.c[0], signature.c[1], signature.c[2], signature.c[3]);
    require!(
        c == signature.c,
        RingVerifyError::VerificationFailed
    );

    Ok(())
}

/// Compute L_i = s_i * G + c_i * P_i
fn compute_l(
    s: &[u8; SCALAR_SIZE],
    c: &[u8; SCALAR_SIZE],
    p: &[u8; POINT_SIZE],
) -> Result<[u8; POINT_SIZE]> {
    let basepoint = PodEdwardsPoint(BASEPOINT);
    let point_p = PodEdwardsPoint(*p);
    let scalar_s = PodScalar(*s);
    let scalar_c = PodScalar(*c);

    // s * G
    let sg = match multiply_edwards(&scalar_s, &basepoint) {
        Some(pt) => pt,
        None => {
            msg!("s*G failed, s={:02x}{:02x}", s[0], s[1]);
            return Err(error!(RingVerifyError::CurveOperationFailed));
        }
    };

    // c * P
    let cp = match multiply_edwards(&scalar_c, &point_p) {
        Some(pt) => pt,
        None => {
            msg!("c*P failed, c={:02x}{:02x}, P={:02x}{:02x}", c[0], c[1], p[0], p[1]);
            return Err(error!(RingVerifyError::CurveOperationFailed));
        }
    };

    // s * G + c * P
    let result = add_edwards(&sg, &cp)
        .ok_or(error!(RingVerifyError::CurveOperationFailed))?;

    Ok(result.0)
}

/// Compute R_i = s_i * H_p(P_i) + c_i * I
fn compute_r(
    s: &[u8; SCALAR_SIZE],
    hp: &[u8; POINT_SIZE],
    c: &[u8; SCALAR_SIZE],
    key_image: &[u8; POINT_SIZE],
) -> Result<[u8; POINT_SIZE]> {
    let point_hp = PodEdwardsPoint(*hp);
    let point_i = PodEdwardsPoint(*key_image);
    let scalar_s = PodScalar(*s);
    let scalar_c = PodScalar(*c);

    // s * H_p
    let shp = multiply_edwards(&scalar_s, &point_hp)
        .ok_or(error!(RingVerifyError::CurveOperationFailed))?;

    // c * I
    let ci = multiply_edwards(&scalar_c, &point_i)
        .ok_or(error!(RingVerifyError::CurveOperationFailed))?;

    // s * H_p + c * I
    let result = add_edwards(&shp, &ci)
        .ok_or(error!(RingVerifyError::CurveOperationFailed))?;

    Ok(result.0)
}

/// Hash public key to point for key image derivation
fn hash_to_point_for_key_image(public_key: &[u8; 32]) -> Result<[u8; POINT_SIZE]> {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_KEY_IMAGE);
    hasher.update(public_key);
    let result = hasher.finalize();

    let mut data = [0u8; 64];
    data.copy_from_slice(&result);

    hash_to_point(&data)
}

/// Hash to point using try-and-increment
fn hash_to_point(data: &[u8]) -> Result<[u8; POINT_SIZE]> {
    let mut counter: u32 = 0;

    loop {
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_HASH_TO_POINT);
        hasher.update(data);
        hasher.update(&counter.to_le_bytes());
        let result = hasher.finalize();

        let mut point_bytes = [0u8; 32];
        point_bytes.copy_from_slice(&result[..32]);
        point_bytes[31] &= 0x7f;

        let candidate = PodEdwardsPoint(point_bytes);
        if validate_edwards(&candidate) {
            // Multiply by cofactor 8
            let eight = PodScalar([8u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            if let Some(cleared) = multiply_edwards(&eight, &candidate) {
                if cleared.0 != IDENTITY {
                    return Ok(cleared.0);
                }
            }
        }

        counter += 1;
        require!(counter < 1000, RingVerifyError::CurveOperationFailed);
    }
}

/// Compute challenge hash
fn compute_challenge(
    message: &[u8],
    ring: &[[u8; POINT_SIZE]],
    key_image: &[u8; POINT_SIZE],
    l: &[u8; POINT_SIZE],
    r: &[u8; POINT_SIZE],
    index: usize,
) -> [u8; SCALAR_SIZE] {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_RING_CHALLENGE);

    // Length-prefix message
    hasher.update(&(message.len() as u32).to_le_bytes());
    hasher.update(message);

    // Ring bytes
    let ring_len = ring.len() * POINT_SIZE;
    hasher.update(&(ring_len as u32).to_le_bytes());
    for pk in ring {
        hasher.update(pk);
    }

    // Key image
    hasher.update(&(POINT_SIZE as u32).to_le_bytes());
    hasher.update(key_image);

    // L and R
    hasher.update(&(POINT_SIZE as u32).to_le_bytes());
    hasher.update(l);
    hasher.update(&(POINT_SIZE as u32).to_le_bytes());
    hasher.update(r);

    // Index
    hasher.update(&4u32.to_le_bytes());
    hasher.update(&(index as u32).to_le_bytes());

    let result = hasher.finalize();

    // Simple scalar reduction: take first 32 bytes, mask top bits
    // output[31] &= 0x0f ensures result < 2^252 < l
    let mut output = [0u8; 32];
    output.copy_from_slice(&result[..32]);
    output[31] &= 0x0f;
    output
}
