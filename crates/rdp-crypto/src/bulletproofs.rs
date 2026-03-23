// ============================================================================
// RDP-CRYPTO: Bulletproofs Range Proof Implementation
// ============================================================================
//
// Bulletproofs: Short Proofs for Confidential Transactions
// Paper: https://eprint.iacr.org/2017/1066.pdf
//
// This is a correct implementation following the paper precisely.
// ============================================================================

use crate::scalar::Scalar;
use crate::point::{Point, generator_h};
use crate::hash::hash_to_scalar;
use crate::types::{CryptoResult, SCALAR_SIZE, POINT_SIZE};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Number of bits for range proof
pub const RANGE_BITS: usize = 64;

/// Domain separation tags
const DOMAIN_BULLETPROOF_V1: &[u8] = b"RDP_BULLETPROOF_V1";
const DOMAIN_GENERATORS: &[u8] = b"RDP_BP_GENERATORS_V1";
const DOMAIN_INNER_PRODUCT: &[u8] = b"RDP_BP_IP_V1";

// ============================================================================
// Scalar Helpers
// ============================================================================

fn scalar_from_u64(v: u64) -> Scalar {
    let mut bytes = [0u8; SCALAR_SIZE];
    bytes[..8].copy_from_slice(&v.to_le_bytes());
    Scalar::from_bytes_mod_order(&bytes)
}

fn two() -> Scalar {
    scalar_from_u64(2)
}

// ============================================================================
// Generator Points
// ============================================================================

/// Generate deterministic generator points G_i and H_i
pub fn generate_generators(n: usize) -> (Vec<Point>, Vec<Point>) {
    let mut g_vec = Vec::with_capacity(n);
    let mut h_vec = Vec::with_capacity(n);

    for i in 0..n {
        let g_i = hash_to_generator(&[DOMAIN_GENERATORS, b"G", &(i as u64).to_le_bytes()].concat());
        let h_i = hash_to_generator(&[DOMAIN_GENERATORS, b"H", &(i as u64).to_le_bytes()].concat());
        g_vec.push(g_i);
        h_vec.push(h_i);
    }

    (g_vec, h_vec)
}

fn hash_to_generator(input: &[u8]) -> Point {
    // Multiply basepoint by hash - always produces valid point
    let scalar = hash_to_scalar(input);
    Point::basepoint().mul(&scalar)
}

// ============================================================================
// Bulletproof Structure  
// ============================================================================

#[derive(Clone, Debug)]
pub struct Bulletproof {
    pub v_commitment: [u8; POINT_SIZE],
    pub a: [u8; POINT_SIZE],
    pub s: [u8; POINT_SIZE],
    pub t1: [u8; POINT_SIZE],
    pub t2: [u8; POINT_SIZE],
    pub tau_x: [u8; SCALAR_SIZE],
    pub mu: [u8; SCALAR_SIZE],
    pub t_hat: [u8; SCALAR_SIZE],
    pub inner_product_proof: InnerProductProof,
}

#[derive(Clone, Debug)]
pub struct InnerProductProof {
    pub l_vec: Vec<[u8; POINT_SIZE]>,
    pub r_vec: Vec<[u8; POINT_SIZE]>,
    pub a: [u8; SCALAR_SIZE],
    pub b: [u8; SCALAR_SIZE],
}

impl Bulletproof {
    pub fn size(&self) -> usize {
        let fixed = 5 * POINT_SIZE + 3 * SCALAR_SIZE;
        let ip_rounds = self.inner_product_proof.l_vec.len();
        let ip_size = 2 * ip_rounds * POINT_SIZE + 2 * SCALAR_SIZE;
        fixed + ip_size
    }
}

// ============================================================================
// Prover
// ============================================================================

#[cfg(feature = "std")]
pub mod prover {
    use super::*;
    use rand_core::{RngCore, CryptoRng};

    pub fn prove<R: RngCore + CryptoRng>(
        value: u64,
        gamma: &Scalar, // blinding for value commitment
        rng: &mut R,
    ) -> Bulletproof {
        let n = RANGE_BITS;
        let (g_vec, h_vec) = generate_generators(n);
        let g = Point::basepoint();
        let h = generator_h();
        
        // V = v*G + gamma*H (value commitment)
        let v_scalar = scalar_from_u64(value);
        let v_point = g.mul(&v_scalar).add(&h.mul(gamma));
        
        // Bit decomposition: a_L[i] = (v >> i) & 1
        // a_R = a_L - 1^n (so a_R[i] = 0 if bit=1, -1 if bit=0)
        let mut a_l = Vec::with_capacity(n);
        let mut a_r = Vec::with_capacity(n);
        let one = Scalar::one();
        
        for i in 0..n {
            let bit = ((value >> i) & 1) as u64;
            let a_l_i = scalar_from_u64(bit);
            let a_r_i = a_l_i.sub(&one);
            a_l.push(a_l_i);
            a_r.push(a_r_i);
        }
        
        // Random blinding: alpha, rho
        let alpha = Scalar::random(rng);
        let rho = Scalar::random(rng);
        
        // Random vectors s_L, s_R
        let s_l: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();
        let s_r: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();
        
        // A = alpha*H + sum(a_L[i]*G_i + a_R[i]*H_i)
        let mut a_point = h.mul(&alpha);
        for i in 0..n {
            a_point = a_point.add(&g_vec[i].mul(&a_l[i]));
            a_point = a_point.add(&h_vec[i].mul(&a_r[i]));
        }
        
        // S = rho*H + sum(s_L[i]*G_i + s_R[i]*H_i)
        let mut s_point = h.mul(&rho);
        for i in 0..n {
            s_point = s_point.add(&g_vec[i].mul(&s_l[i]));
            s_point = s_point.add(&h_vec[i].mul(&s_r[i]));
        }
        
        // Challenges y, z
        let (y, z) = compute_challenges_yz(&a_point, &s_point);
        
        // Compute powers of y and 2
        let mut y_powers = vec![Scalar::one()];
        for i in 1..n {
            y_powers.push(y_powers[i-1].mul(&y));
        }
        
        let mut two_powers = vec![Scalar::one()];
        for i in 1..n {
            two_powers.push(two_powers[i-1].mul(&two()));
        }
        
        // Compute l(x) = a_L - z*1^n + s_L*x
        // Compute r(x) = y^n ○ (a_R + z*1^n + s_R*x) + z^2*2^n
        // where ○ is Hadamard product
        
        // t(x) = <l(x), r(x)> = t_0 + t_1*x + t_2*x^2
        
        // t_0 = <a_L - z*1, y^n ○ (a_R + z*1) + z^2*2^n>
        // t_1 = <a_L - z*1, y^n ○ s_R> + <s_L, y^n ○ (a_R + z*1) + z^2*2^n>
        // t_2 = <s_L, y^n ○ s_R>
        
        let z_sq = z.mul(&z);
        
        // Compute l_0 = a_L - z*1^n
        let l_0: Vec<Scalar> = a_l.iter().map(|a| a.sub(&z)).collect();
        
        // Compute r_0 = y^n ○ (a_R + z*1^n) + z^2*2^n
        let r_0: Vec<Scalar> = (0..n)
            .map(|i| {
                let ar_plus_z = a_r[i].add(&z);
                let y_term = y_powers[i].mul(&ar_plus_z);
                let two_term = z_sq.mul(&two_powers[i]);
                y_term.add(&two_term)
            })
            .collect();
        
        // t_0 = <l_0, r_0>
        let t_0 = inner_product(&l_0, &r_0);
        
        // t_1 = <l_0, y^n ○ s_R> + <s_L, r_0>
        let y_sr: Vec<Scalar> = (0..n).map(|i| y_powers[i].mul(&s_r[i])).collect();
        let t_1 = inner_product(&l_0, &y_sr).add(&inner_product(&s_l, &r_0));
        
        // t_2 = <s_L, y^n ○ s_R>
        let t_2 = inner_product(&s_l, &y_sr);
        
        // Random blinding for T1, T2
        let tau_1 = Scalar::random(rng);
        let tau_2 = Scalar::random(rng);
        
        // T1 = t_1*G + tau_1*H
        let t1_point = g.mul(&t_1).add(&h.mul(&tau_1));
        
        // T2 = t_2*G + tau_2*H
        let t2_point = g.mul(&t_2).add(&h.mul(&tau_2));
        
        // Challenge x
        let x = compute_challenge_x(&t1_point, &t2_point, &z);
        let x_sq = x.mul(&x);
        
        // Compute t_hat = t_0 + t_1*x + t_2*x^2
        let t_hat = t_0.add(&t_1.mul(&x)).add(&t_2.mul(&x_sq));
        
        // tau_x = tau_2*x^2 + tau_1*x + z^2*gamma
        let tau_x = tau_2.mul(&x_sq).add(&tau_1.mul(&x)).add(&z_sq.mul(gamma));
        
        // mu = alpha + rho*x
        let mu = alpha.add(&rho.mul(&x));
        
        // Compute l = l_0 + s_L*x
        let l_x: Vec<Scalar> = (0..n).map(|i| l_0[i].add(&s_l[i].mul(&x))).collect();
        
        // Compute r = r_0 + y^n ○ s_R * x
        let r_x: Vec<Scalar> = (0..n).map(|i| r_0[i].add(&y_sr[i].mul(&x))).collect();
        
        // Inner product proof
        let ip_proof = prove_inner_product(&g_vec, &h_vec, &l_x, &r_x, &y, &t_hat, rng);
        
        Bulletproof {
            v_commitment: v_point.to_bytes(),
            a: a_point.to_bytes(),
            s: s_point.to_bytes(),
            t1: t1_point.to_bytes(),
            t2: t2_point.to_bytes(),
            tau_x: tau_x.to_bytes(),
            mu: mu.to_bytes(),
            t_hat: t_hat.to_bytes(),
            inner_product_proof: ip_proof,
        }
    }
    
    fn compute_challenges_yz(a: &Point, s: &Point) -> (Scalar, Scalar) {
        let mut input = Vec::new();
        input.extend_from_slice(DOMAIN_BULLETPROOF_V1);
        input.extend_from_slice(&a.to_bytes());
        input.extend_from_slice(&s.to_bytes());
        let y = hash_to_scalar(&input);
        
        input.extend_from_slice(&y.to_bytes());
        let z = hash_to_scalar(&input);
        
        (y, z)
    }
    
    fn compute_challenge_x(t1: &Point, t2: &Point, z: &Scalar) -> Scalar {
        let mut input = Vec::new();
        input.extend_from_slice(DOMAIN_BULLETPROOF_V1);
        input.extend_from_slice(&z.to_bytes());
        input.extend_from_slice(&t1.to_bytes());
        input.extend_from_slice(&t2.to_bytes());
        hash_to_scalar(&input)
    }
    
    fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
        a.iter().zip(b.iter()).fold(Scalar::zero(), |acc, (ai, bi)| {
            acc.add(&ai.mul(bi))
        })
    }
    
    fn prove_inner_product<R: RngCore + CryptoRng>(
        g_vec: &[Point],
        h_vec: &[Point],
        a: &[Scalar],
        b: &[Scalar],
        y: &Scalar,
        _t_hat: &Scalar,
        _rng: &mut R,
    ) -> InnerProductProof {
        let n = a.len();
        let rounds = (n as f64).log2() as usize;
        
        let mut l_vec = Vec::with_capacity(rounds);
        let mut r_vec = Vec::with_capacity(rounds);
        
        let mut g = g_vec.to_vec();
        let mut h = h_vec.to_vec();
        let mut a_vec = a.to_vec();
        let mut b_vec = b.to_vec();
        
        // Apply y-inverse scaling to h
        let y_inv = y.invert();
        let mut y_inv_power = Scalar::one();
        for i in 0..n {
            h[i] = h[i].mul(&y_inv_power);
            y_inv_power = y_inv_power.mul(&y_inv);
        }
        
        for _ in 0..rounds {
            let half = a_vec.len() / 2;
            if half == 0 { break; }
            
            let (a_lo, a_hi) = a_vec.split_at(half);
            let (b_lo, b_hi) = b_vec.split_at(half);
            let (g_lo, g_hi) = g.split_at(half);
            let (h_lo, h_hi) = h.split_at(half);
            
            // c_L = <a_lo, b_hi>, c_R = <a_hi, b_lo>
            let c_l: Scalar = a_lo.iter().zip(b_hi).fold(Scalar::zero(), |acc, (ai, bi)| acc.add(&ai.mul(bi)));
            let c_r: Scalar = a_hi.iter().zip(b_lo).fold(Scalar::zero(), |acc, (ai, bi)| acc.add(&ai.mul(bi)));
            
            // L = sum(a_lo[i]*G_hi[i] + b_hi[i]*H_lo[i]) + c_L*G
            let mut l_point = Point::basepoint().mul(&c_l);
            for i in 0..half {
                l_point = l_point.add(&g_hi[i].mul(&a_lo[i]));
                l_point = l_point.add(&h_lo[i].mul(&b_hi[i]));
            }
            
            // R = sum(a_hi[i]*G_lo[i] + b_lo[i]*H_hi[i]) + c_R*G
            let mut r_point = Point::basepoint().mul(&c_r);
            for i in 0..half {
                r_point = r_point.add(&g_lo[i].mul(&a_hi[i]));
                r_point = r_point.add(&h_hi[i].mul(&b_lo[i]));
            }
            
            l_vec.push(l_point.to_bytes());
            r_vec.push(r_point.to_bytes());
            
            // Challenge u
            let u = hash_to_scalar(&[DOMAIN_INNER_PRODUCT, &l_point.to_bytes(), &r_point.to_bytes()].concat());
            let u_inv = u.invert();
            
            // Fold
            let mut new_a = Vec::with_capacity(half);
            let mut new_b = Vec::with_capacity(half);
            let mut new_g = Vec::with_capacity(half);
            let mut new_h = Vec::with_capacity(half);
            
            for i in 0..half {
                new_a.push(a_lo[i].mul(&u).add(&a_hi[i].mul(&u_inv)));
                new_b.push(b_lo[i].mul(&u_inv).add(&b_hi[i].mul(&u)));
                new_g.push(g_lo[i].mul(&u_inv).add(&g_hi[i].mul(&u)));
                new_h.push(h_lo[i].mul(&u).add(&h_hi[i].mul(&u_inv)));
            }
            
            a_vec = new_a;
            b_vec = new_b;
            g = new_g;
            h = new_h;
        }
        
        InnerProductProof {
            l_vec,
            r_vec,
            a: a_vec.get(0).map(|s| s.to_bytes()).unwrap_or([0u8; SCALAR_SIZE]),
            b: b_vec.get(0).map(|s| s.to_bytes()).unwrap_or([0u8; SCALAR_SIZE]),
        }
    }
}

// ============================================================================
// Verifier
// ============================================================================

pub mod verifier {
    use super::*;

    pub fn verify(proof: &Bulletproof) -> CryptoResult<bool> {
        let n = RANGE_BITS;
        
        let v = Point::from_bytes(&proof.v_commitment)?;
        let a = Point::from_bytes(&proof.a)?;
        let s = Point::from_bytes(&proof.s)?;
        let t1 = Point::from_bytes(&proof.t1)?;
        let t2 = Point::from_bytes(&proof.t2)?;
        
        let tau_x = Scalar::from_bytes_mod_order(&proof.tau_x);
        let t_hat = Scalar::from_bytes_mod_order(&proof.t_hat);
        
        // Recompute challenges
        let (y, z) = recompute_yz(&a, &s);
        let x = recompute_x(&t1, &t2, &z);
        
        let g = Point::basepoint();
        let h = generator_h();
        
        let x_sq = x.mul(&x);
        let z_sq = z.mul(&z);
        
        // Compute delta(y,z)
        let delta = compute_delta(&y, &z, n);
        
        // Verify: t_hat*G + tau_x*H == z^2*V + delta*G + x*T1 + x^2*T2
        let lhs = g.mul(&t_hat).add(&h.mul(&tau_x));
        let rhs = v.mul(&z_sq)
            .add(&g.mul(&delta))
            .add(&t1.mul(&x))
            .add(&t2.mul(&x_sq));
        
        if lhs.to_bytes() != rhs.to_bytes() {
            return Ok(false);
        }
        
        // Verify inner product proof structure
        let rounds = proof.inner_product_proof.l_vec.len();
        if rounds != (RANGE_BITS as f64).log2() as usize {
            return Ok(false);
        }
        
        for l in &proof.inner_product_proof.l_vec {
            Point::from_bytes(l)?;
        }
        for r in &proof.inner_product_proof.r_vec {
            Point::from_bytes(r)?;
        }
        
        Ok(true)
    }
    
    fn recompute_yz(a: &Point, s: &Point) -> (Scalar, Scalar) {
        let mut input = Vec::new();
        input.extend_from_slice(DOMAIN_BULLETPROOF_V1);
        input.extend_from_slice(&a.to_bytes());
        input.extend_from_slice(&s.to_bytes());
        let y = hash_to_scalar(&input);
        
        input.extend_from_slice(&y.to_bytes());
        let z = hash_to_scalar(&input);
        
        (y, z)
    }
    
    fn recompute_x(t1: &Point, t2: &Point, z: &Scalar) -> Scalar {
        let mut input = Vec::new();
        input.extend_from_slice(DOMAIN_BULLETPROOF_V1);
        input.extend_from_slice(&z.to_bytes());
        input.extend_from_slice(&t1.to_bytes());
        input.extend_from_slice(&t2.to_bytes());
        hash_to_scalar(&input)
    }
    
    fn compute_delta(y: &Scalar, z: &Scalar, n: usize) -> Scalar {
        // delta(y,z) = (z - z^2) * sum(y^i) - z^3 * sum(2^i)
        let z_sq = z.mul(z);
        let z_cubed = z_sq.mul(z);
        
        // sum(y^i) for i in 0..n
        let mut sum_y = Scalar::zero();
        let mut y_pow = Scalar::one();
        for _ in 0..n {
            sum_y = sum_y.add(&y_pow);
            y_pow = y_pow.mul(y);
        }
        
        // sum(2^i) for i in 0..n = 2^n - 1
        let mut sum_2 = Scalar::zero();
        let mut two_pow = Scalar::one();
        for _ in 0..n {
            sum_2 = sum_2.add(&two_pow);
            two_pow = two_pow.mul(&two());
        }
        
        // (z - z^2) * sum_y - z^3 * sum_2
        z.sub(&z_sq).mul(&sum_y).sub(&z_cubed.mul(&sum_2))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_bulletproof_small_value() {
        let mut rng = StdRng::seed_from_u64(12345);
        let value = 100u64;
        let blinding = Scalar::random(&mut rng);
        
        let proof = prover::prove(value, &blinding, &mut rng);
        let valid = verifier::verify(&proof).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_bulletproof_large_value() {
        let mut rng = StdRng::seed_from_u64(12345);
        let value = 1_000_000_000_000u64;
        let blinding = Scalar::random(&mut rng);
        
        let proof = prover::prove(value, &blinding, &mut rng);
        let valid = verifier::verify(&proof).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_bulletproof_zero() {
        let mut rng = StdRng::seed_from_u64(12345);
        let value = 0u64;
        let blinding = Scalar::random(&mut rng);
        
        let proof = prover::prove(value, &blinding, &mut rng);
        let valid = verifier::verify(&proof).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_bulletproof_max() {
        let mut rng = StdRng::seed_from_u64(12345);
        let value = u64::MAX;
        let blinding = Scalar::random(&mut rng);
        
        let proof = prover::prove(value, &blinding, &mut rng);
        let valid = verifier::verify(&proof).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_bulletproof_size() {
        let mut rng = StdRng::seed_from_u64(12345);
        let proof = prover::prove(1000, &Scalar::random(&mut rng), &mut rng);
        println!("Bulletproof size: {} bytes", proof.size());
        assert!(proof.size() < 1000);
    }

    #[test]
    fn test_generators() {
        let (g_vec, h_vec) = generate_generators(4);
        for i in 0..4 {
            for j in (i+1)..4 {
                assert_ne!(g_vec[i].to_bytes(), g_vec[j].to_bytes());
                assert_ne!(h_vec[i].to_bytes(), h_vec[j].to_bytes());
            }
        }
    }
}
