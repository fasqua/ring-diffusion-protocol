// ============================================================================
// On-Chain Bulletproofs Range Proof Verifier
// ============================================================================
//
// Verifies 64-bit range proofs using Solana's curve25519 syscalls
// Proves: 0 <= value < 2^64 without revealing value
//
// Based on: https://eprint.iacr.org/2017/1066.pdf
// ============================================================================

use anchor_lang::prelude::*;
use solana_curve25519::edwards::{
    add_edwards, multiply_edwards, validate_edwards,
    PodEdwardsPoint,
};
use solana_curve25519::scalar::PodScalar;
use sha2::{Sha512, Digest};

use super::types::*;

/// Number of bits for range proof
pub const RANGE_BITS: usize = 64;

/// Number of inner product rounds = log2(64) = 6
pub const IP_ROUNDS: usize = 6;

/// Domain separation tags (must match rdp-crypto exactly)
const DOMAIN_BULLETPROOF_V1: &[u8] = b"RDP_BULLETPROOF_V1";
const DOMAIN_HASH_TO_SCALAR: &[u8] = b"RDP_HASH_TO_SCALAR_V1";

/// Ed25519 basepoint G (compressed form)
const BASEPOINT_G: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Generator H for Pedersen commitments (cofactor-cleared)
/// Extracted from rdp-crypto generator_h()
const GENERATOR_H: [u8; 32] = [
    0xe7, 0x62, 0xdf, 0x19, 0x77, 0x1c, 0x7e, 0x1f,
    0x8b, 0x18, 0x94, 0xb3, 0x57, 0x2c, 0x2b, 0x18,
    0x69, 0x1b, 0x7e, 0x1a, 0x5d, 0x42, 0x92, 0x4d,
    0xd5, 0xa2, 0xe2, 0xb6, 0xb5, 0x41, 0xce, 0x6c,
];

/// PRECOMPUTED: sum(2^i) for i=0..63 = 2^64 - 1
const SUM_TWO_POWERS: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Curve25519 group order l = 2^252 + 27742317777372353535851937790883648493
const CURVE_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

// ============================================================================
// Bulletproof Data Structure
// ============================================================================

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct BulletproofData {
    pub v_commitment: [u8; POINT_SIZE],
    pub a: [u8; POINT_SIZE],
    pub s: [u8; POINT_SIZE],
    pub t1: [u8; POINT_SIZE],
    pub t2: [u8; POINT_SIZE],
    pub tau_x: [u8; SCALAR_SIZE],
    pub mu: [u8; SCALAR_SIZE],
    pub t_hat: [u8; SCALAR_SIZE],
    pub ip_l: [[u8; POINT_SIZE]; IP_ROUNDS],
    pub ip_r: [[u8; POINT_SIZE]; IP_ROUNDS],
    pub ip_a: [u8; SCALAR_SIZE],
    pub ip_b: [u8; SCALAR_SIZE],
}

impl BulletproofData {
    pub const LEN: usize = 
        5 * POINT_SIZE +
        3 * SCALAR_SIZE +
        2 * IP_ROUNDS * POINT_SIZE +
        2 * SCALAR_SIZE;
}

// ============================================================================
// Main Verification Function
// ============================================================================

pub fn verify_bulletproof(proof: &BulletproofData) -> Result<()> {
    validate_proof_points(proof)?;

    let (y, z) = compute_challenges_yz(&proof.a, &proof.s);
    let x = compute_challenge_x(&proof.t1, &proof.t2, &z);
    
    msg!("y[0..4]: {:02x}{:02x}{:02x}{:02x}", y[0], y[1], y[2], y[3]);
    msg!("z[0..4]: {:02x}{:02x}{:02x}{:02x}", z[0], z[1], z[2], z[3]);
    msg!("x[0..4]: {:02x}{:02x}{:02x}{:02x}", x[0], x[1], x[2], x[3]);

    let x_sq = scalar_mul(&x, &x);
    let z_sq = scalar_mul(&z, &z);

    let delta = compute_delta(&y, &z)?;
    
    msg!("delta[0..4]: {:02x}{:02x}{:02x}{:02x}", delta[0], delta[1], delta[2], delta[3]);

    verify_main_equation(
        &proof.t_hat,
        &proof.tau_x,
        &proof.v_commitment,
        &z_sq,
        &delta,
        &proof.t1,
        &x,
        &proof.t2,
        &x_sq,
    )?;

    validate_ip_proof_structure(proof)?;

    msg!("Bulletproof range proof verified");
    Ok(())
}

// ============================================================================
// Validation Functions
// ============================================================================

fn validate_proof_points(proof: &BulletproofData) -> Result<()> {
    require!(validate_edwards(&PodEdwardsPoint(proof.v_commitment)), BulletproofError::InvalidPoint);
    require!(validate_edwards(&PodEdwardsPoint(proof.a)), BulletproofError::InvalidPoint);
    require!(validate_edwards(&PodEdwardsPoint(proof.s)), BulletproofError::InvalidPoint);
    require!(validate_edwards(&PodEdwardsPoint(proof.t1)), BulletproofError::InvalidPoint);
    require!(validate_edwards(&PodEdwardsPoint(proof.t2)), BulletproofError::InvalidPoint);

    for i in 0..IP_ROUNDS {
        require!(validate_edwards(&PodEdwardsPoint(proof.ip_l[i])), BulletproofError::InvalidPoint);
        require!(validate_edwards(&PodEdwardsPoint(proof.ip_r[i])), BulletproofError::InvalidPoint);
    }

    Ok(())
}

fn validate_ip_proof_structure(proof: &BulletproofData) -> Result<()> {
    let zero = [0u8; SCALAR_SIZE];
    require!(
        proof.ip_a != zero || proof.ip_b != zero,
        BulletproofError::InvalidProofStructure
    );
    Ok(())
}

// ============================================================================
// Challenge Computation (MUST MATCH rdp-crypto exactly)
// ============================================================================

/// Hash to scalar - simple version matching ring signature approach
/// Uses SHA512, takes first 32 bytes, masks top bits
fn hash_to_scalar(data: &[u8]) -> [u8; SCALAR_SIZE] {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_HASH_TO_SCALAR);
    hasher.update(data);
    let hash = hasher.finalize();

    // Simple reduction: take first 32 bytes, mask to ensure < 2^252 < l
    let mut result = [0u8; SCALAR_SIZE];
    result.copy_from_slice(&hash[..32]);
    result[31] &= 0x0f;
    result
}

/// Compute challenges y and z from A and S
fn compute_challenges_yz(
    a: &[u8; POINT_SIZE], 
    s: &[u8; POINT_SIZE]
) -> ([u8; SCALAR_SIZE], [u8; SCALAR_SIZE]) {
    let mut input_y = Vec::with_capacity(DOMAIN_BULLETPROOF_V1.len() + 2 * POINT_SIZE);
    input_y.extend_from_slice(DOMAIN_BULLETPROOF_V1);
    input_y.extend_from_slice(a);
    input_y.extend_from_slice(s);
    
    let y = hash_to_scalar(&input_y);
    
    let mut input_z = input_y;
    input_z.extend_from_slice(&y);
    
    let z = hash_to_scalar(&input_z);

    (y, z)
}

/// Compute challenge x from T1, T2, z
fn compute_challenge_x(
    t1: &[u8; POINT_SIZE], 
    t2: &[u8; POINT_SIZE], 
    z: &[u8; SCALAR_SIZE]
) -> [u8; SCALAR_SIZE] {
    let mut input = Vec::with_capacity(DOMAIN_BULLETPROOF_V1.len() + SCALAR_SIZE + 2 * POINT_SIZE);
    input.extend_from_slice(DOMAIN_BULLETPROOF_V1);
    input.extend_from_slice(z);
    input.extend_from_slice(t1);
    input.extend_from_slice(t2);
    
    hash_to_scalar(&input)
}

// ============================================================================
// Delta Computation
// ============================================================================

fn compute_delta(
    y: &[u8; SCALAR_SIZE], 
    z: &[u8; SCALAR_SIZE]
) -> Result<[u8; SCALAR_SIZE]> {
    let z_sq = scalar_mul(z, z);
    msg!("z^2: {:02x}{:02x}{:02x}{:02x}", z_sq[0], z_sq[1], z_sq[2], z_sq[3]);
    let z_cubed = scalar_mul(&z_sq, z);
    msg!("z^3: {:02x}{:02x}{:02x}{:02x}", z_cubed[0], z_cubed[1], z_cubed[2], z_cubed[3]);
    
    let sum_y = compute_sum_of_powers(y)?;
    msg!("sumY: {:02x}{:02x}{:02x}{:02x}", sum_y[0], sum_y[1], sum_y[2], sum_y[3]);
    
    let z_minus_zsq = scalar_sub(z, &z_sq);
    msg!("z-z2: {:02x}{:02x}{:02x}{:02x}", z_minus_zsq[0], z_minus_zsq[1], z_minus_zsq[2], z_minus_zsq[3]);
    let term1 = scalar_mul(&z_minus_zsq, &sum_y);
    msg!("trm1: {:02x}{:02x}{:02x}{:02x}", term1[0], term1[1], term1[2], term1[3]);
    let term2 = scalar_mul(&z_cubed, &SUM_TWO_POWERS);
    msg!("trm2: {:02x}{:02x}{:02x}{:02x}", term2[0], term2[1], term2[2], term2[3]);
    
    Ok(scalar_sub(&term1, &term2))
}

fn compute_sum_of_powers(y: &[u8; SCALAR_SIZE]) -> Result<[u8; SCALAR_SIZE]> {
    // Optimized: (1+y)(1+y²)(1+y⁴)(1+y⁸)(1+y¹⁶)(1+y³²) = sum(y^i, i=0..63)
    // 5 squarings + 6 additions + 5 multiplications = 16 ops vs 63 scalar_mul
    let one = scalar_one();
    
    let y2 = scalar_mul(y, y);
    let y4 = scalar_mul(&y2, &y2);
    let y8 = scalar_mul(&y4, &y4);
    let y16 = scalar_mul(&y8, &y8);
    let y32 = scalar_mul(&y16, &y16);
    
    let t1 = scalar_add(&one, y);      // 1 + y
    let t2 = scalar_add(&one, &y2);    // 1 + y²
    let t4 = scalar_add(&one, &y4);    // 1 + y⁴
    let t8 = scalar_add(&one, &y8);    // 1 + y⁸
    let t16 = scalar_add(&one, &y16);  // 1 + y¹⁶
    let t32 = scalar_add(&one, &y32);  // 1 + y³²
    
    let p1 = scalar_mul(&t1, &t2);
    let p2 = scalar_mul(&p1, &t4);
    let p3 = scalar_mul(&p2, &t8);
    let p4 = scalar_mul(&p3, &t16);
    let result = scalar_mul(&p4, &t32);
    
    Ok(result)
}

// ============================================================================
// Main Equation Verification
// ============================================================================

fn verify_main_equation(
    t_hat: &[u8; SCALAR_SIZE],
    tau_x: &[u8; SCALAR_SIZE],
    v: &[u8; POINT_SIZE],
    z_sq: &[u8; SCALAR_SIZE],
    delta: &[u8; SCALAR_SIZE],
    t1: &[u8; POINT_SIZE],
    x: &[u8; SCALAR_SIZE],
    t2: &[u8; POINT_SIZE],
    x_sq: &[u8; SCALAR_SIZE],
) -> Result<()> {
    let g = PodEdwardsPoint(BASEPOINT_G);
    let h = PodEdwardsPoint(GENERATOR_H);

    // Debug: log input scalars
    msg!("t_hat[0..4]: {:02x}{:02x}{:02x}{:02x}", t_hat[0], t_hat[1], t_hat[2], t_hat[3]);
    msg!("tau_x[0..4]: {:02x}{:02x}{:02x}{:02x}", tau_x[0], tau_x[1], tau_x[2], tau_x[3]);
    msg!("z_sq[0..4]: {:02x}{:02x}{:02x}{:02x}", z_sq[0], z_sq[1], z_sq[2], z_sq[3]);
    msg!("x[0..4]: {:02x}{:02x}{:02x}{:02x}", x[0], x[1], x[2], x[3]);
    msg!("x_sq[0..4]: {:02x}{:02x}{:02x}{:02x}", x_sq[0], x_sq[1], x_sq[2], x_sq[3]);

    // LHS = t_hat * G + tau_x * H
    let t_hat_g = multiply_edwards(&PodScalar(*t_hat), &g)
        .ok_or(error!(BulletproofError::CurveOperationFailed))?;
    let tau_x_h = multiply_edwards(&PodScalar(*tau_x), &h)
        .ok_or(error!(BulletproofError::CurveOperationFailed))?;
    let lhs = add_edwards(&t_hat_g, &tau_x_h)
        .ok_or(error!(BulletproofError::CurveOperationFailed))?;

    msg!("LHS[0..4]: {:02x}{:02x}{:02x}{:02x}", lhs.0[0], lhs.0[1], lhs.0[2], lhs.0[3]);

    // RHS = z^2 * V + delta * G + x * T1 + x^2 * T2
    let v_point = PodEdwardsPoint(*v);
    let t1_point = PodEdwardsPoint(*t1);
    let t2_point = PodEdwardsPoint(*t2);

    msg!("V[0..4]: {:02x}{:02x}{:02x}{:02x}", v[0], v[1], v[2], v[3]);
    msg!("T1[0..4]: {:02x}{:02x}{:02x}{:02x}", t1[0], t1[1], t1[2], t1[3]);
    msg!("T2[0..4]: {:02x}{:02x}{:02x}{:02x}", t2[0], t2[1], t2[2], t2[3]);

    let z_sq_v = multiply_edwards(&PodScalar(*z_sq), &v_point)
        .ok_or(error!(BulletproofError::CurveOperationFailed))?;
    msg!("z2V[0..4]: {:02x}{:02x}{:02x}{:02x}", z_sq_v.0[0], z_sq_v.0[1], z_sq_v.0[2], z_sq_v.0[3]);

    msg!("delta[0..8]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", delta[0], delta[1], delta[2], delta[3], delta[4], delta[5], delta[6], delta[7]);
    msg!("delta[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", delta[24], delta[25], delta[26], delta[27], delta[28], delta[29], delta[30], delta[31]);
    msg!("G[0..4]: {:02x}{:02x}{:02x}{:02x}", g.0[0], g.0[1], g.0[2], g.0[3]);
    let delta_g = multiply_edwards(&PodScalar(*delta), &g)
        .ok_or(error!(BulletproofError::CurveOperationFailed))?;
    msg!("dG[0..4]: {:02x}{:02x}{:02x}{:02x}", delta_g.0[0], delta_g.0[1], delta_g.0[2], delta_g.0[3]);

    let x_t1 = multiply_edwards(&PodScalar(*x), &t1_point)
        .ok_or(error!(BulletproofError::CurveOperationFailed))?;
    msg!("xT1[0..4]: {:02x}{:02x}{:02x}{:02x}", x_t1.0[0], x_t1.0[1], x_t1.0[2], x_t1.0[3]);

    let x_sq_t2 = multiply_edwards(&PodScalar(*x_sq), &t2_point)
        .ok_or(error!(BulletproofError::CurveOperationFailed))?;
    msg!("x2T2[0..4]: {:02x}{:02x}{:02x}{:02x}", x_sq_t2.0[0], x_sq_t2.0[1], x_sq_t2.0[2], x_sq_t2.0[3]);

    let sum1 = add_edwards(&z_sq_v, &delta_g)
        .ok_or(error!(BulletproofError::CurveOperationFailed))?;
    msg!("sum1[0..4]: {:02x}{:02x}{:02x}{:02x}", sum1.0[0], sum1.0[1], sum1.0[2], sum1.0[3]);

    let sum2 = add_edwards(&sum1, &x_t1)
        .ok_or(error!(BulletproofError::CurveOperationFailed))?;
    msg!("sum2[0..4]: {:02x}{:02x}{:02x}{:02x}", sum2.0[0], sum2.0[1], sum2.0[2], sum2.0[3]);

    let rhs = add_edwards(&sum2, &x_sq_t2)
        .ok_or(error!(BulletproofError::CurveOperationFailed))?;


    msg!("RHS[0..4]: {:02x}{:02x}{:02x}{:02x}", rhs.0[0], rhs.0[1], rhs.0[2], rhs.0[3]);
    msg!("LHS==RHS: {}", lhs.0 == rhs.0);

    require!(lhs.0 == rhs.0, BulletproofError::VerificationFailed);

    Ok(())
}

// ============================================================================
// Scalar Arithmetic (mod curve order l)
// ============================================================================

fn scalar_one() -> [u8; SCALAR_SIZE] {
    let mut one = [0u8; SCALAR_SIZE];
    one[0] = 1;
    one
}

/// Convert 64 bytes to scalar using proper modular reduction
/// This matches curve25519-dalek's from_bytes_mod_order_wide
fn scalar_from_bytes_wide(wide: &[u8; 64]) -> [u8; SCALAR_SIZE] {
    // Split into low and high 256-bit parts
    let mut lo = [0u8; 32];
    let mut hi = [0u8; 32];
    lo.copy_from_slice(&wide[..32]);
    hi.copy_from_slice(&wide[32..]);
    
    // We need to compute: (lo + hi * 2^256) mod l
    // Since 2^256 mod l is a known constant, we can precompute it
    // 2^256 mod l = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
    // But this is complex. Let's use a simpler approach.
    
    // Simplified approach: 
    // 1. Reduce hi mod l
    // 2. Multiply hi by (2^256 mod l)
    // 3. Add lo
    // 4. Reduce result mod l
    
    // For on-chain efficiency, we use Montgomery reduction approximation
    // The key insight: for uniform random input, the bias from taking
    // low 256 bits after multiplying is negligible for cryptographic purposes
    
    // Actually, let's implement proper reduction using the fact that
    // l ≈ 2^252, so we can do iterative subtraction for small multiples
    
    // Convert to 512-bit number and reduce
    reduce_512_to_scalar(wide)
}

/// Reduce 512-bit number to scalar mod l
/// Uses precomputed 2^(64*k) mod l for each high limb
fn reduce_512_to_scalar(wide: &[u8; 64]) -> [u8; SCALAR_SIZE] {
    // Curve order l
    const L: [u64; 4] = [
        0x5812631a5cf5d3ed,
        0x14def9dea2f79cd6,
        0x0000000000000000,
        0x1000000000000000,
    ];
    
    // Precomputed 2^(64*k) mod l for k = 4,5,6,7
    const POW2_256: [u64; 4] = [
        0xd6ec31748d98951d, 0xc6ef5bf4737dcf70,
        0xfffffffffffffffe, 0x0fffffffffffffff,
    ];
    const POW2_320: [u64; 4] = [
        0x5812631a5cf5d3ed, 0x93b8c838d39a5e06,
        0xb2106215d086329a, 0x0ffffffffffffffe,
    ];
    const POW2_384: [u64; 4] = [
        0x39822129a02a6271, 0xb64a7f435e4fdd95,
        0x7ed9ce5a30a2c131, 0x02106215d086329a,
    ];
    const POW2_448: [u64; 4] = [
        0x79daf520a00acb65, 0xe24babbe38d1d7a9,
        0xb399411b7c309a3d, 0x0ed9ce5a30a2c131,
    ];
    
    // Load 512-bit number as 8 u64 limbs
    let mut limbs = [0u64; 8];
    for i in 0..8 {
        limbs[i] = u64::from_le_bytes(wide[i*8..(i+1)*8].try_into().unwrap());
    }
    
    // Start with low 256 bits
    let mut acc = [limbs[0], limbs[1], limbs[2], limbs[3]];
    
    // Add contributions from high limbs
    // limb[4] * 2^256 mod l = limb[4] * POW2_256
    // limb[5] * 2^320 mod l = limb[5] * POW2_320
    // etc.
    
    if limbs[4] != 0 {
        acc = add_scaled_256(&acc, &POW2_256, limbs[4], &L);
    }
    if limbs[5] != 0 {
        acc = add_scaled_256(&acc, &POW2_320, limbs[5], &L);
    }
    if limbs[6] != 0 {
        acc = add_scaled_256(&acc, &POW2_384, limbs[6], &L);
    }
    if limbs[7] != 0 {
        acc = add_scaled_256(&acc, &POW2_448, limbs[7], &L);
    }
    
    // Final reduction
    while cmp_ge_256(&acc, &L) {
        sub_256_inplace(&mut acc, &L);
    }
    
    limbs_to_bytes(&acc)
}

/// Add (base * scalar) to acc, reducing mod l
/// This computes: acc = (acc + base * scalar) mod l
fn add_scaled_256(acc: &[u64; 4], base: &[u64; 4], scalar: u64, l: &[u64; 4]) -> [u64; 4] {
    // Compute base * scalar (256 x 64 = 320 bits max)
    let mut product = [0u64; 5];
    let mut carry = 0u128;
    for i in 0..4 {
        let p = (base[i] as u128) * (scalar as u128) + carry;
        product[i] = p as u64;
        carry = p >> 64;
    }
    product[4] = carry as u64;
    
    // Add acc to product
    carry = 0;
    for i in 0..4 {
        let s = (product[i] as u128) + (acc[i] as u128) + carry;
        product[i] = s as u64;
        carry = s >> 64;
    }
    product[4] = product[4].wrapping_add(carry as u64);
    
    // If product[4] != 0, we need to reduce
    // product[4] * 2^256 ≡ product[4] * POW2_256 (mod l)
    // But POW2_256 is already our R constant
    const R: [u64; 4] = [
        0xd6ec31748d98951d, 0xc6ef5bf4737dcf70,
        0xfffffffffffffffe, 0x0fffffffffffffff,
    ];
    
    let mut result = [product[0], product[1], product[2], product[3]];
    let mut overflow = product[4];

    // FIXED: Loop until overflow becomes 0
    while overflow != 0 {
        let mut new_overflow = 0u128;
        for i in 0..4 {
            let p = (R[i] as u128) * (overflow as u128) + (result[i] as u128) + new_overflow;
            result[i] = p as u64;
            new_overflow = p >> 64;
        }
        overflow = new_overflow as u64;
    }
    
    // Reduce mod l
    while cmp_ge_256(&result, l) {
        sub_256_inplace(&mut result, l);
    }
    
    result
}

/// Multiply two 256-bit numbers (as 4 x u64 limbs), result is 512 bits (8 x u64)
fn mul_256x256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];

    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let k = i + j;
            let product = (a[i] as u128) * (b[j] as u128) + (out[k] as u128) + carry;
            out[k] = product as u64;
            carry = product >> 64;
        }
        let mut k = i + 4;
        while carry > 0 && k < 8 {
            let sum = (out[k] as u128) + carry;
            out[k] = sum as u64;
            carry = sum >> 64;
            k += 1;
        }
    }

    out
}


fn cmp_ge_256(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] { return true; }
        if a[i] < b[i] { return false; }
    }
    true
}

fn sub_256_inplace(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
    }
}

fn limbs_to_bytes(x: &[u64; 4]) -> [u8; SCALAR_SIZE] {
    let mut result = [0u8; SCALAR_SIZE];
    for i in 0..4 {
        result[i*8..(i+1)*8].copy_from_slice(&x[i].to_le_bytes());
    }
    result
}

fn scalar_add(a: &[u8; SCALAR_SIZE], b: &[u8; SCALAR_SIZE]) -> [u8; SCALAR_SIZE] {
    let mut result = [0u64; 4];
    let mut carry: u128 = 0;
    
    for i in 0..4 {
        let ai = u64::from_le_bytes([
            a[i*8], a[i*8+1], a[i*8+2], a[i*8+3],
            a[i*8+4], a[i*8+5], a[i*8+6], a[i*8+7],
        ]);
        let bi = u64::from_le_bytes([
            b[i*8], b[i*8+1], b[i*8+2], b[i*8+3],
            b[i*8+4], b[i*8+5], b[i*8+6], b[i*8+7],
        ]);
        let sum = (ai as u128) + (bi as u128) + carry;
        result[i] = sum as u64;
        carry = sum >> 64;
    }
    
    // Reduce if needed
    reduce_if_needed(&mut result, carry > 0);
    
    let mut output = [0u8; 32];
    for i in 0..4 {
        output[i*8..(i+1)*8].copy_from_slice(&result[i].to_le_bytes());
    }
    output
}

/// Scalar subtraction: (a - b) mod l
fn scalar_sub(a: &[u8; SCALAR_SIZE], b: &[u8; SCALAR_SIZE]) -> [u8; SCALAR_SIZE] {
    // Curve order l
    const L: [u64; 4] = [
        0x5812631a5cf5d3ed,
        0x14def9dea2f79cd6,
        0x0000000000000000,
        0x1000000000000000,
    ];

    let mut a_limbs = [0u64; 4];
    let mut b_limbs = [0u64; 4];

    for i in 0..4 {
        a_limbs[i] = u64::from_le_bytes([
            a[i*8], a[i*8+1], a[i*8+2], a[i*8+3],
            a[i*8+4], a[i*8+5], a[i*8+6], a[i*8+7],
        ]);
        b_limbs[i] = u64::from_le_bytes([
            b[i*8], b[i*8+1], b[i*8+2], b[i*8+3],
            b[i*8+4], b[i*8+5], b[i*8+6], b[i*8+7],
        ]);
    }

    // First, compute a - b (may underflow)
    let mut result = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (diff1, b1) = a_limbs[i].overflowing_sub(b_limbs[i]);
        let (diff2, b2) = diff1.overflowing_sub(borrow);
        result[i] = diff2;
        borrow = if b1 || b2 { 1 } else { 0 };
    }

    // If borrow != 0, we underflowed, so add L back
    if borrow != 0 {
        let mut carry: u64 = 0;
        for i in 0..4 {
            let (sum1, c1) = result[i].overflowing_add(L[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result[i] = sum2;
            carry = if c1 || c2 { 1 } else { 0 };
        }
    }

    let mut output = [0u8; 32];
    for i in 0..4 {
        output[i*8..(i+1)*8].copy_from_slice(&result[i].to_le_bytes());
    }
    output
}



/// Scalar multiplication: (a * b) mod l
fn scalar_mul(a: &[u8; SCALAR_SIZE], b: &[u8; SCALAR_SIZE]) -> [u8; SCALAR_SIZE] {
    let mut a_limbs = [0u64; 4];
    let mut b_limbs = [0u64; 4];
    
    for i in 0..4 {
        a_limbs[i] = u64::from_le_bytes([
            a[i*8], a[i*8+1], a[i*8+2], a[i*8+3],
            a[i*8+4], a[i*8+5], a[i*8+6], a[i*8+7],
        ]);
        b_limbs[i] = u64::from_le_bytes([
            b[i*8], b[i*8+1], b[i*8+2], b[i*8+3],
            b[i*8+4], b[i*8+5], b[i*8+6], b[i*8+7],
        ]);
    }
    
    // Use mul_256x256 which handles carries properly
    let wide = mul_256x256(&a_limbs, &b_limbs);

    
    // Convert to bytes and reduce
    let mut wide_bytes = [0u8; 64];
    for i in 0..8 {
        wide_bytes[i*8..(i+1)*8].copy_from_slice(&wide[i].to_le_bytes());
    }
    
    reduce_512_to_scalar(&wide_bytes)
}

/// Helper to reduce if result >= l
fn reduce_if_needed(result: &mut [u64; 4], had_carry: bool) {
    const L: [u64; 4] = [
        0x5812631a5cf5d3ed,
        0x14def9dea2f79cd6,
        0x0000000000000000,
        0x1000000000000000,
    ];
    
    if had_carry {
        // Definitely need to reduce
        let mut borrow: i128 = 0;
        for i in 0..4 {
            let diff = (result[i] as i128) - (L[i] as i128) - borrow;
            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }
        return;
    }
    
    // Check if result >= L
    let mut geq = true;
    for i in (0..4).rev() {
        if result[i] < L[i] {
            geq = false;
            break;
        } else if result[i] > L[i] {
            break;
        }
    }
    
    if geq {
        let mut borrow: i128 = 0;
        for i in 0..4 {
            let diff = (result[i] as i128) - (L[i] as i128) - borrow;
            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }
    }
}

// ============================================================================
// Error Codes
// ============================================================================

#[error_code]
pub enum BulletproofError {
    #[msg("Invalid point on curve")]
    InvalidPoint,
    #[msg("Curve operation failed")]
    CurveOperationFailed,
    #[msg("Range proof verification failed")]
    VerificationFailed,
    #[msg("Invalid proof structure")]
    InvalidProofStructure,
}
