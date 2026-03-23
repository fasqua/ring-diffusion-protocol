// ============================================================================
// RDP-CRYPTO: Pedersen Commitments
// ============================================================================
//
// Pedersen commitment: C = v*G + r*H
// Where:
//   v = value (amount)
//   r = blinding factor (random scalar)
//   G = base point (generator)
//   H = secondary generator (hash to point)
//
// Properties:
// - Hiding: commitment reveals nothing about v
// - Binding: cannot open to different v
// - Homomorphic: C1 + C2 = commit(v1 + v2, r1 + r2)
// ============================================================================

use crate::scalar::Scalar;
use crate::point::{Point, generator_h};
use crate::types::{CryptoError, CryptoResult, SCALAR_SIZE, POINT_SIZE};

/// Pedersen commitment
#[derive(Clone, Copy, Debug)]
pub struct PedersenCommitment {
    /// The commitment point C = v*G + r*H
    pub commitment: Point,
}

impl PedersenCommitment {
    /// Create a new Pedersen commitment
    /// C = v*G + r*H
    pub fn commit(value: u64, blinding: &Scalar) -> Self {
        // Convert value to scalar
        let mut value_bytes = [0u8; SCALAR_SIZE];
        value_bytes[..8].copy_from_slice(&value.to_le_bytes());
        let v = Scalar::from_bytes_mod_order(&value_bytes);

        // C = v*G + r*H
        let vg = Point::basepoint().mul(&v);
        let rh = generator_h().mul(blinding);
        let commitment = vg.add(&rh);

        Self { commitment }
    }

    /// Create commitment with random blinding factor
    #[cfg(feature = "std")]
    pub fn commit_random<R: rand_core::RngCore + rand_core::CryptoRng>(
        value: u64,
        rng: &mut R,
    ) -> (Self, Scalar) {
        let blinding = Scalar::random(rng);
        let commitment = Self::commit(value, &blinding);
        (commitment, blinding)
    }

    /// Verify that commitment opens to given value and blinding
    pub fn verify(&self, value: u64, blinding: &Scalar) -> bool {
        let expected = Self::commit(value, blinding);
        self.commitment.to_bytes() == expected.commitment.to_bytes()
    }

    /// Get commitment as bytes
    pub fn to_bytes(&self) -> [u8; POINT_SIZE] {
        self.commitment.to_bytes()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; POINT_SIZE]) -> CryptoResult<Self> {
        let commitment = Point::from_bytes(bytes)?;
        Ok(Self { commitment })
    }

    /// Add two commitments (homomorphic property)
    /// commit(v1, r1) + commit(v2, r2) = commit(v1+v2, r1+r2)
    pub fn add(&self, other: &Self) -> Self {
        Self {
            commitment: self.commitment.add(&other.commitment),
        }
    }

    /// Subtract two commitments
    /// commit(v1, r1) - commit(v2, r2) = commit(v1-v2, r1-r2)
    pub fn sub(&self, other: &Self) -> Self {
        Self {
            commitment: self.commitment.sub(&other.commitment),
        }
    }
}

/// Blinding factor for Pedersen commitment
#[derive(Clone)]
pub struct BlindingFactor(pub Scalar);

impl BlindingFactor {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; SCALAR_SIZE]) -> Self {
        Self(Scalar::from_bytes_mod_order(bytes))
    }

    /// Generate random blinding factor
    #[cfg(feature = "std")]
    pub fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        Self(Scalar::random(rng))
    }

    /// Get as scalar
    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; SCALAR_SIZE] {
        self.0.to_bytes()
    }

    /// Add two blinding factors
    pub fn add(&self, other: &Self) -> Self {
        Self(self.0.add(&other.0))
    }

    /// Subtract two blinding factors
    pub fn sub(&self, other: &Self) -> Self {
        Self(self.0.sub(&other.0))
    }
}

/// Commitment opening (value + blinding)
#[derive(Clone)]
pub struct CommitmentOpening {
    pub value: u64,
    pub blinding: BlindingFactor,
}

impl CommitmentOpening {
    pub fn new(value: u64, blinding: BlindingFactor) -> Self {
        Self { value, blinding }
    }

    /// Create commitment from this opening
    pub fn commit(&self) -> PedersenCommitment {
        PedersenCommitment::commit(self.value, self.blinding.as_scalar())
    }

    /// Verify commitment matches this opening
    pub fn verify(&self, commitment: &PedersenCommitment) -> bool {
        commitment.verify(self.value, self.blinding.as_scalar())
    }
}

/// Balance proof: proves sum of inputs = sum of outputs
/// Without revealing individual amounts
#[derive(Clone, Debug)]
pub struct BalanceProof {
    /// Difference commitment (should be commitment to zero)
    pub diff_commitment: [u8; POINT_SIZE],
    /// Blinding factor difference (proves diff commits to zero)
    pub blinding_diff: [u8; SCALAR_SIZE],
}

impl BalanceProof {
    /// Create balance proof from inputs and outputs
    /// Proves: sum(input_values) = sum(output_values)
    pub fn create(
        input_openings: &[CommitmentOpening],
        output_openings: &[CommitmentOpening],
    ) -> CryptoResult<Self> {
        // Sum input values and blindings
        let mut input_sum_value: u64 = 0;
        let mut input_sum_blinding = Scalar::zero();
        for opening in input_openings {
            input_sum_value = input_sum_value
                .checked_add(opening.value)
                .ok_or(CryptoError::InvalidScalar)?;
            input_sum_blinding = input_sum_blinding.add(opening.blinding.as_scalar());
        }

        // Sum output values and blindings
        let mut output_sum_value: u64 = 0;
        let mut output_sum_blinding = Scalar::zero();
        for opening in output_openings {
            output_sum_value = output_sum_value
                .checked_add(opening.value)
                .ok_or(CryptoError::InvalidScalar)?;
            output_sum_blinding = output_sum_blinding.add(opening.blinding.as_scalar());
        }

        // Values must balance
        if input_sum_value != output_sum_value {
            return Err(CryptoError::VerificationFailed);
        }

        // Compute blinding difference
        let blinding_diff = input_sum_blinding.sub(&output_sum_blinding);

        // Diff commitment = 0*G + blinding_diff*H
        // This commits to zero value
        let diff_commitment = generator_h().mul(&blinding_diff);

        Ok(Self {
            diff_commitment: diff_commitment.to_bytes(),
            blinding_diff: blinding_diff.to_bytes(),
        })
    }

    /// Verify balance proof
    /// Checks that input commitments - output commitments = commitment to zero
    pub fn verify(
        &self,
        input_commitments: &[PedersenCommitment],
        output_commitments: &[PedersenCommitment],
    ) -> CryptoResult<bool> {
        // Sum input commitments
        let mut input_sum = Point::identity();
        for c in input_commitments {
            input_sum = input_sum.add(&c.commitment);
        }

        // Sum output commitments
        let mut output_sum = Point::identity();
        for c in output_commitments {
            output_sum = output_sum.add(&c.commitment);
        }

        // Compute difference
        let diff = input_sum.sub(&output_sum);

        // Verify diff equals blinding_diff * H (commitment to zero)
        let blinding_diff = Scalar::from_bytes_mod_order(&self.blinding_diff);
        let expected_diff = generator_h().mul(&blinding_diff);

        Ok(diff.to_bytes() == expected_diff.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_commit_and_verify() {
        let mut rng = StdRng::seed_from_u64(12345);
        let value = 1000u64;
        
        let (commitment, blinding) = PedersenCommitment::commit_random(value, &mut rng);
        
        assert!(commitment.verify(value, &blinding));
        assert!(!commitment.verify(value + 1, &blinding));
    }

    #[test]
    fn test_commitment_deterministic() {
        let value = 500u64;
        let blinding_bytes = [42u8; 32];
        let blinding = Scalar::from_bytes_mod_order(&blinding_bytes);
        
        let c1 = PedersenCommitment::commit(value, &blinding);
        let c2 = PedersenCommitment::commit(value, &blinding);
        
        assert_eq!(c1.to_bytes(), c2.to_bytes());
    }

    #[test]
    fn test_commitment_hiding() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        // Same value, different blinding = different commitment
        let value = 1000u64;
        let (c1, _) = PedersenCommitment::commit_random(value, &mut rng);
        let (c2, _) = PedersenCommitment::commit_random(value, &mut rng);
        
        assert_ne!(c1.to_bytes(), c2.to_bytes());
    }

    #[test]
    fn test_homomorphic_addition() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        let v1 = 100u64;
        let v2 = 200u64;
        
        let (c1, r1) = PedersenCommitment::commit_random(v1, &mut rng);
        let (c2, r2) = PedersenCommitment::commit_random(v2, &mut rng);
        
        // c1 + c2 should equal commit(v1 + v2, r1 + r2)
        let c_sum = c1.add(&c2);
        let r_sum = r1.add(&r2);
        let c_direct = PedersenCommitment::commit(v1 + v2, &r_sum);
        
        assert_eq!(c_sum.to_bytes(), c_direct.to_bytes());
    }

    #[test]
    fn test_balance_proof() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        // Input: 100
        let input = CommitmentOpening::new(100, BlindingFactor::random(&mut rng));
        
        // Outputs: 60 + 40 = 100
        let output1 = CommitmentOpening::new(60, BlindingFactor::random(&mut rng));
        let output2 = CommitmentOpening::new(40, BlindingFactor::random(&mut rng));
        
        // Create proof
        let proof = BalanceProof::create(
            &[input.clone()],
            &[output1.clone(), output2.clone()],
        ).unwrap();
        
        // Verify proof
        let input_commitments = vec![input.commit()];
        let output_commitments = vec![output1.commit(), output2.commit()];
        
        assert!(proof.verify(&input_commitments, &output_commitments).unwrap());
    }

    #[test]
    fn test_balance_proof_fails_for_unbalanced() {
        let mut rng = StdRng::seed_from_u64(12345);
        
        let input = CommitmentOpening::new(100, BlindingFactor::random(&mut rng));
        let output = CommitmentOpening::new(101, BlindingFactor::random(&mut rng)); // Unbalanced!
        
        let result = BalanceProof::create(&[input], &[output]);
        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_serialization() {
        let mut rng = StdRng::seed_from_u64(12345);
        let (commitment, _) = PedersenCommitment::commit_random(1000, &mut rng);
        
        let bytes = commitment.to_bytes();
        let recovered = PedersenCommitment::from_bytes(&bytes).unwrap();
        
        assert_eq!(commitment.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_blinding_factor_arithmetic() {
        let b1 = BlindingFactor::from_bytes(&[1u8; 32]);
        let b2 = BlindingFactor::from_bytes(&[2u8; 32]);
        
        let sum = b1.add(&b2);
        let diff = sum.sub(&b2);
        
        assert_eq!(b1.to_bytes(), diff.to_bytes());
    }
}
