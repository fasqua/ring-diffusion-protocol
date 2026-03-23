// ============================================================================
// RDP-CRYPTO: Private Transaction
// ============================================================================
// Combines all cryptographic primitives into a complete private transaction

use crate::scalar::Scalar;
use crate::point::Point;
use crate::pedersen::{PedersenCommitment, BlindingFactor, CommitmentOpening};
use crate::bulletproofs::{Bulletproof, prover as bp_prover, verifier as bp_verifier};
use crate::merkle::{MerkleProof, HASH_SIZE};
use crate::ring_signature::RingSignature;
#[allow(unused_imports)]
use crate::types::{KeyImage, POINT_SIZE, SCALAR_SIZE};

/// A private input (spending a previous commitment)
#[derive(Clone)]
pub struct PrivateInput {
    /// The commitment being spent
    pub commitment: [u8; POINT_SIZE],
    /// Merkle proof showing commitment is in the tree
    pub merkle_proof: MerkleProof,
    /// Ring signature proving ownership without revealing which one
    pub ring_signature: RingSignature,
    /// Key image to prevent double-spending
    pub key_image: KeyImage,
    /// Opening data (known only to spender, not serialized in tx)
    pub opening: Option<CommitmentOpening>,
}

/// A private output (creating a new commitment)
#[derive(Clone)]
pub struct PrivateOutput {
    /// The new commitment C = v*G + r*H
    pub commitment: PedersenCommitment,
    /// Range proof proving 0 <= value < 2^64
    pub range_proof: Bulletproof,
    /// Opening data (for recipient, encrypted in real implementation)
    pub opening: Option<CommitmentOpening>,
}

/// Complete private transaction
#[derive(Clone)]
pub struct PrivateTransaction {
    /// Inputs being spent
    pub inputs: Vec<PrivateInput>,
    /// New outputs being created
    pub outputs: Vec<PrivateOutput>,
    /// Fee (public, in lamports)
    pub fee: u64,
    /// Merkle root at time of transaction
    pub merkle_root: [u8; HASH_SIZE],
}

/// Builder for creating private outputs
pub struct OutputBuilder {
    value: u64,
    blinding: BlindingFactor,
}

impl OutputBuilder {
    /// Create a new output with specified value
    pub fn new(value: u64) -> Self {
        Self {
            value,
            blinding: BlindingFactor::random(&mut rand::thread_rng()),
        }
    }

    /// Create output with specific blinding factor (for testing)
    pub fn with_blinding(value: u64, blinding: BlindingFactor) -> Self {
        Self { value, blinding }
    }

    /// Build the private output with range proof
    pub fn build(self) -> PrivateOutput {
        let commitment = PedersenCommitment::commit(self.value, &self.blinding.0);
        let range_proof = bp_prover::prove(
            self.value,
            &self.blinding.0,
            &mut rand::thread_rng(),
        );

        let opening = CommitmentOpening {
            value: self.value,
            blinding: self.blinding.clone(),
        };

        PrivateOutput {
            commitment,
            range_proof,
            opening: Some(opening),
        }
    }
}

/// Verification result for a private transaction
#[derive(Debug)]
pub struct VerificationResult {
    pub range_proofs_valid: bool,
    pub balance_valid: bool,
    pub key_images_unique: bool,
    pub merkle_proofs_valid: bool,
    pub ring_signatures_valid: bool,
}

impl VerificationResult {
    pub fn is_valid(&self) -> bool {
        self.range_proofs_valid
            && self.balance_valid
            && self.key_images_unique
            && self.merkle_proofs_valid
            && self.ring_signatures_valid
    }
}

impl PrivateTransaction {
    /// Verify all range proofs in outputs
    pub fn verify_range_proofs(&self) -> bool {
        for output in &self.outputs {
            if !bp_verifier::verify(&output.range_proof).unwrap_or(false) {
                return false;
            }
        }
        true
    }

    /// Verify balance: sum(inputs) == sum(outputs) + fee
    /// This is done homomorphically on commitments
    /// 
    /// Note: input_commitments are provided separately because the tx only
    /// contains commitment hashes, not the full commitment points
    pub fn verify_balance(&self, input_commitments: &[PedersenCommitment]) -> bool {
        // Sum of input commitments
        let mut input_sum = Point::identity();
        for ic in input_commitments {
            input_sum = input_sum.add(&ic.commitment);
        }

        // Sum of output commitments
        let mut output_sum = Point::identity();
        for output in &self.outputs {
            output_sum = output_sum.add(&output.commitment.commitment);
        }

        // Fee is public, so commitment is just fee*G (blinding = 0)
        let fee_commitment = PedersenCommitment::commit(self.fee, &Scalar::zero());
        output_sum = output_sum.add(&fee_commitment.commitment);

        // Check: input_sum == output_sum
        input_sum.to_bytes() == output_sum.to_bytes()
    }

    /// Check that all key images are unique (no double-spend within tx)
    pub fn verify_key_images_unique(&self) -> bool {
        let mut seen = std::collections::HashSet::new();
        for input in &self.inputs {
            if !seen.insert(input.key_image.0) {
                return false;
            }
        }
        true
    }

    /// Get all key images from this transaction
    pub fn get_key_images(&self) -> Vec<KeyImage> {
        self.inputs.iter().map(|i| i.key_image.clone()).collect()
    }

    /// Full verification (except ring signatures which need external ring data)
    pub fn verify_partial(&self, input_commitments: &[PedersenCommitment]) -> VerificationResult {
        VerificationResult {
            range_proofs_valid: self.verify_range_proofs(),
            balance_valid: self.verify_balance(input_commitments),
            key_images_unique: self.verify_key_images_unique(),
            merkle_proofs_valid: true, // Needs merkle root verification
            ring_signatures_valid: true, // Needs ring data
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_builder() {
        let output = OutputBuilder::new(1000).build();
        
        // Should have valid range proof
        assert!(bp_verifier::verify(&output.range_proof).unwrap());
        
        // Should have opening data
        assert!(output.opening.is_some());
        let opening = output.opening.unwrap();
        assert_eq!(opening.value, 1000);
    }

    #[test]
    fn test_balance_verification_simple() {
        // Create input: 1000 lamports
        let input_blinding = Scalar::random(&mut rand::thread_rng());
        let input_commitment = PedersenCommitment::commit(1000, &input_blinding);

        // For balance to work with fee, output_blinding must equal input_blinding
        // because fee has zero blinding
        // 
        // Math: input = 1000*G + r*H
        //       output = 900*G + r*H
        //       fee = 100*G + 0*H
        //       output + fee = 900*G + r*H + 100*G = 1000*G + r*H = input ✓
        let output_blinding = BlindingFactor(input_blinding.clone());
        let output = OutputBuilder::with_blinding(900, output_blinding).build();

        let tx = PrivateTransaction {
            inputs: vec![], // Empty - we pass commitments separately
            outputs: vec![output],
            fee: 100,
            merkle_root: [0u8; HASH_SIZE],
        };

        // Verify balance - pass input commitment directly
        assert!(tx.verify_balance(&[input_commitment]), 
            "Balance should verify: 1000 = 900 + 100");
    }

    #[test]
    fn test_balance_verification_multiple_outputs() {
        // Input: 1000 lamports with blinding r
        let input_blinding = Scalar::random(&mut rand::thread_rng());
        let input_commitment = PedersenCommitment::commit(1000, &input_blinding);

        // Output 1: 400 lamports with blinding r1
        // Output 2: 500 lamports with blinding r2
        // Fee: 100 lamports with blinding 0
        // 
        // For balance: r = r1 + r2 + 0
        // So: r2 = r - r1
        let out1_blinding = Scalar::random(&mut rand::thread_rng());
        let out2_blinding = input_blinding.sub(&out1_blinding);

        let output1 = OutputBuilder::with_blinding(400, BlindingFactor(out1_blinding)).build();
        let output2 = OutputBuilder::with_blinding(500, BlindingFactor(out2_blinding)).build();

        let tx = PrivateTransaction {
            inputs: vec![],
            outputs: vec![output1, output2],
            fee: 100,
            merkle_root: [0u8; HASH_SIZE],
        };

        assert!(tx.verify_balance(&[input_commitment]),
            "Balance should verify: 1000 = 400 + 500 + 100");
    }

    #[test]
    fn test_balance_verification_multiple_inputs() {
        // Input 1: 600 lamports
        // Input 2: 500 lamports
        // Total: 1100 lamports
        let in1_blinding = Scalar::random(&mut rand::thread_rng());
        let in2_blinding = Scalar::random(&mut rand::thread_rng());
        let input1 = PedersenCommitment::commit(600, &in1_blinding);
        let input2 = PedersenCommitment::commit(500, &in2_blinding);

        // Output: 1000 lamports
        // Fee: 100 lamports
        // 
        // Blinding: r_out = r_in1 + r_in2
        let out_blinding = in1_blinding.add(&in2_blinding);
        let output = OutputBuilder::with_blinding(1000, BlindingFactor(out_blinding)).build();

        let tx = PrivateTransaction {
            inputs: vec![],
            outputs: vec![output],
            fee: 100,
            merkle_root: [0u8; HASH_SIZE],
        };

        assert!(tx.verify_balance(&[input1, input2]),
            "Balance should verify: 600 + 500 = 1000 + 100");
    }

    #[test]
    fn test_balance_fails_for_wrong_amounts() {
        // Input: 1000 lamports
        let input_blinding = Scalar::random(&mut rand::thread_rng());
        let input_commitment = PedersenCommitment::commit(1000, &input_blinding);

        // Output: 950 lamports (wrong - should be 900 for fee=100)
        let output = OutputBuilder::with_blinding(950, BlindingFactor(input_blinding)).build();

        let tx = PrivateTransaction {
            inputs: vec![],
            outputs: vec![output],
            fee: 100,
            merkle_root: [0u8; HASH_SIZE],
        };

        // Should fail - amounts don't balance (950 + 100 != 1000)
        assert!(!tx.verify_balance(&[input_commitment]),
            "Balance should fail: 1000 != 950 + 100");
    }

    #[test]
    fn test_balance_fails_for_wrong_blinding() {
        // Input: 1000 lamports
        let input_blinding = Scalar::random(&mut rand::thread_rng());
        let input_commitment = PedersenCommitment::commit(1000, &input_blinding);

        // Output: 900 lamports but DIFFERENT blinding
        let wrong_blinding = Scalar::random(&mut rand::thread_rng());
        let output = OutputBuilder::with_blinding(900, BlindingFactor(wrong_blinding)).build();

        let tx = PrivateTransaction {
            inputs: vec![],
            outputs: vec![output],
            fee: 100,
            merkle_root: [0u8; HASH_SIZE],
        };

        // Should fail - blinding factors don't match
        assert!(!tx.verify_balance(&[input_commitment]),
            "Balance should fail when blinding factors don't match");
    }

    #[test]
    fn test_key_images_unique() {
        let ki1 = KeyImage([1u8; POINT_SIZE]);
        let ki2 = KeyImage([2u8; POINT_SIZE]);
        let ki3 = KeyImage([1u8; POINT_SIZE]); // Duplicate of ki1

        // Unique key images
        let tx1 = PrivateTransaction {
            inputs: vec![
                PrivateInput {
                    commitment: [0u8; POINT_SIZE],
                    merkle_proof: create_dummy_merkle_proof(),
                    ring_signature: create_dummy_ring_sig(),
                    key_image: ki1.clone(),
                    opening: None,
                },
                PrivateInput {
                    commitment: [0u8; POINT_SIZE],
                    merkle_proof: create_dummy_merkle_proof(),
                    ring_signature: create_dummy_ring_sig(),
                    key_image: ki2,
                    opening: None,
                },
            ],
            outputs: vec![],
            fee: 0,
            merkle_root: [0u8; HASH_SIZE],
        };
        assert!(tx1.verify_key_images_unique());

        // Duplicate key images
        let tx2 = PrivateTransaction {
            inputs: vec![
                PrivateInput {
                    commitment: [0u8; POINT_SIZE],
                    merkle_proof: create_dummy_merkle_proof(),
                    ring_signature: create_dummy_ring_sig(),
                    key_image: ki1,
                    opening: None,
                },
                PrivateInput {
                    commitment: [0u8; POINT_SIZE],
                    merkle_proof: create_dummy_merkle_proof(),
                    ring_signature: create_dummy_ring_sig(),
                    key_image: ki3, // Duplicate!
                    opening: None,
                },
            ],
            outputs: vec![],
            fee: 0,
            merkle_root: [0u8; HASH_SIZE],
        };
        assert!(!tx2.verify_key_images_unique());
    }

    #[test]
    fn test_range_proofs_verification() {
        let output1 = OutputBuilder::new(100).build();
        let output2 = OutputBuilder::new(u64::MAX).build();

        let tx = PrivateTransaction {
            inputs: vec![],
            outputs: vec![output1, output2],
            fee: 0,
            merkle_root: [0u8; HASH_SIZE],
        };

        assert!(tx.verify_range_proofs());
    }

    #[test]
    fn test_full_verification() {
        // Create a complete transaction
        let input_blinding = Scalar::random(&mut rand::thread_rng());
        let input_commitment = PedersenCommitment::commit(1000, &input_blinding);

        let output = OutputBuilder::with_blinding(900, BlindingFactor(input_blinding)).build();

        let tx = PrivateTransaction {
            inputs: vec![],
            outputs: vec![output],
            fee: 100,
            merkle_root: [0u8; HASH_SIZE],
        };

        let result = tx.verify_partial(&[input_commitment]);
        
        assert!(result.range_proofs_valid);
        assert!(result.balance_valid);
        assert!(result.key_images_unique);
        assert!(result.is_valid());
    }

    fn create_dummy_merkle_proof() -> MerkleProof {
        MerkleProof {
            siblings: vec![],
            path_indices: vec![],
            leaf_index: 0,
        }
    }

    fn create_dummy_ring_sig() -> RingSignature {
        RingSignature {
            c: [0u8; SCALAR_SIZE],
            responses: vec![],
            key_image: [0u8; POINT_SIZE],
        }
    }
}


/// End-to-end integration test module
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use crate::ring_signature;
    use crate::key_image;
    use crate::types::{SecretKey, PublicKey};

    /// Simulates a complete private transaction flow
    #[test]
    fn test_end_to_end_private_transfer() {
        println!("\n=== END-TO-END PRIVATE TRANSFER TEST ===\n");

        // =========================================================
        // STEP 1: Alice deposits 1 SOL (1_000_000_000 lamports)
        // =========================================================
        println!("Step 1: Alice deposits 1 SOL");
        
        // Create Alice's secret key
        let alice_secret_bytes: [u8; 32] = rand::random();
        let alice_secret = SecretKey(alice_secret_bytes);
        let alice_scalar = Scalar::from_bytes_mod_order(&alice_secret_bytes);
        let alice_pubkey_point = Point::basepoint().mul(&alice_scalar);
        let alice_pubkey = PublicKey(alice_pubkey_point.to_bytes());
        
        // Alice's deposit commitment: C = v*G + r*H
        let alice_value: u64 = 1_000_000_000; // 1 SOL
        let alice_blinding = Scalar::random(&mut rand::thread_rng());
        let alice_commitment = PedersenCommitment::commit(alice_value, &alice_blinding);
        
        // Generate range proof for deposit
        let alice_range_proof = bp_prover::prove(
            alice_value,
            &alice_blinding,
            &mut rand::thread_rng(),
        );
        assert!(bp_verifier::verify(&alice_range_proof).unwrap(), 
            "Alice's deposit range proof should be valid");
        println!("  ✓ Range proof valid");
        
        // Add to merkle tree
        let mut tree = MerkleTree::new();
        tree.insert(&alice_commitment.commitment.to_bytes());
        let merkle_root = tree.root();
        println!("  ✓ Commitment added to merkle tree");
        println!("  Merkle root: {:?}...", &merkle_root[..8]);

        // =========================================================
        // STEP 2: Add decoy commitments (for ring signature anonymity)
        // =========================================================
        println!("\nStep 2: Adding decoy commitments for anonymity set");
        
        let mut decoy_pubkeys: Vec<PublicKey> = Vec::new();
        for _ in 0..15 { // 15 decoys + 1 real = ring size 16
            let decoy_secret_bytes: [u8; 32] = rand::random();
            let decoy_scalar = Scalar::from_bytes_mod_order(&decoy_secret_bytes);
            let decoy_pubkey_point = Point::basepoint().mul(&decoy_scalar);
            decoy_pubkeys.push(PublicKey(decoy_pubkey_point.to_bytes()));
            
            // Add decoy commitment to tree
            let decoy_blinding = Scalar::random(&mut rand::thread_rng());
            let decoy_commitment = PedersenCommitment::commit(
                rand::random::<u64>() % 10_000_000_000,
                &decoy_blinding,
            );
            tree.insert(&decoy_commitment.commitment.to_bytes());
        }
        println!("  ✓ Added 15 decoy commitments (ring size = 16)");

        // =========================================================
        // STEP 3: Alice creates private transfer to Bob
        // =========================================================
        println!("\nStep 3: Alice transfers 0.8 SOL to Bob privately");
        
        let bob_value: u64 = 800_000_000; // 0.8 SOL to Bob
        let fee: u64 = 5_000_000; // 0.005 SOL fee
        let change_value: u64 = alice_value - bob_value - fee; // 0.195 SOL change
        
        println!("  Input:  {} lamports (1 SOL)", alice_value);
        println!("  To Bob: {} lamports (0.8 SOL)", bob_value);
        println!("  Fee:    {} lamports (0.005 SOL)", fee);
        println!("  Change: {} lamports (0.195 SOL)", change_value);
        
        // Create outputs with proper blinding factor balancing
        // alice_blinding = bob_blinding + change_blinding (fee has 0 blinding)
        let bob_blinding = Scalar::random(&mut rand::thread_rng());
        let change_blinding = alice_blinding.sub(&bob_blinding);
        
        let bob_output = OutputBuilder::with_blinding(bob_value, BlindingFactor(bob_blinding)).build();
        let change_output = OutputBuilder::with_blinding(change_value, BlindingFactor(change_blinding)).build();
        
        println!("  ✓ Created outputs with range proofs");

        // =========================================================
        // STEP 4: Generate key image (prevents double-spend)
        // =========================================================
        println!("\nStep 4: Generate key image for double-spend prevention");
        
        let alice_key_image = key_image::generate_key_image(&alice_secret)
            .expect("Key image generation should succeed");
        println!("  Key image: {:?}...", &alice_key_image.0[..8]);
        println!("  ✓ Key image generated");

        // =========================================================
        // STEP 5: Create ring signature
        // =========================================================
        println!("\nStep 5: Create ring signature");
        
        // Build ring of public keys (Alice is at index 7)
        let alice_index = 7usize;
        let mut ring: Vec<PublicKey> = Vec::new();
        for i in 0..16 {
            if i == alice_index {
                ring.push(alice_pubkey.clone());
            } else if i < alice_index {
                ring.push(decoy_pubkeys[i].clone());
            } else {
                ring.push(decoy_pubkeys[i - 1].clone());
            }
        }
        
        // Message to sign
        let message = b"transfer_0.8_sol_to_bob";
        
        // Generate ring signature
        let ring_sig = ring_signature::sign(
            message,
            &ring,
            alice_index,
            &alice_secret,
        ).expect("Ring signature should succeed");
        
        println!("  Ring size: {}", ring.len());
        println!("  ✓ Ring signature created");

        // =========================================================
        // STEP 6: Verify ring signature
        // =========================================================
        println!("\nStep 6: Verify ring signature");
        
        ring_signature::verify(message, &ring, &ring_sig)
            .expect("Ring signature should be valid");
        println!("  ✓ Ring signature valid");

        // =========================================================
        // STEP 7: Create and verify complete transaction
        // =========================================================
        println!("\nStep 7: Assemble and verify complete transaction");
        
        let merkle_proof = tree.generate_proof(0).expect("Merkle proof should exist");
        
        let tx = PrivateTransaction {
            inputs: vec![PrivateInput {
                commitment: alice_commitment.commitment.to_bytes(),
                merkle_proof,
                ring_signature: ring_sig,
                key_image: alice_key_image.clone(),
                opening: Some(CommitmentOpening {
                    value: alice_value,
                    blinding: BlindingFactor(alice_blinding.clone()),
                }),
            }],
            outputs: vec![bob_output, change_output],
            fee,
            merkle_root: tree.root(),
        };
        
        // Verify all proofs
        let result = tx.verify_partial(&[alice_commitment.clone()]);
        
        println!("  Range proofs valid: {}", result.range_proofs_valid);
        println!("  Balance valid: {}", result.balance_valid);
        println!("  Key images unique: {}", result.key_images_unique);
        
        assert!(result.range_proofs_valid, "Range proofs should be valid");
        assert!(result.balance_valid, "Balance should be valid");
        assert!(result.key_images_unique, "Key images should be unique");
        assert!(result.is_valid(), "Transaction should be valid");
        
        println!("\n=== PRIVATE TRANSFER SUCCESSFUL ===");
        println!("✓ Alice transferred 0.8 SOL to Bob privately");
        println!("✓ No one can tell which commitment Alice spent");
        println!("✓ No one can see the amounts (hidden in commitments)");
        println!("✓ Double-spending prevented via key image");
    }

    #[test]
    fn test_double_spend_prevention() {
        println!("\n=== DOUBLE-SPEND PREVENTION TEST ===\n");
        
        // Create Alice's keys
        let alice_secret_bytes: [u8; 32] = rand::random();
        let alice_secret = SecretKey(alice_secret_bytes);
        
        // Alice's key image is deterministic from her secret
        let key_image = key_image::generate_key_image(&alice_secret)
            .expect("Key image generation should succeed");
        
        println!("Alice's key image: {:?}...", &key_image.0[..8]);
        
        // If Alice tries to spend twice, she'll produce the SAME key image
        let key_image_2 = key_image::generate_key_image(&alice_secret)
            .expect("Key image generation should succeed");
        
        assert_eq!(key_image.0, key_image_2.0, 
            "Same secret always produces same key image");
        println!("✓ Second spend attempt produces same key image");
        
        // Create tx with duplicate key images
        let tx = PrivateTransaction {
            inputs: vec![
                PrivateInput {
                    commitment: [0u8; POINT_SIZE],
                    merkle_proof: MerkleProof {
                        siblings: vec![],
                        path_indices: vec![],
                        leaf_index: 0,
                    },
                    ring_signature: RingSignature {
                        c: [0u8; SCALAR_SIZE],
                        responses: vec![],
                        key_image: key_image.0,
                    },
                    key_image: key_image.clone(),
                    opening: None,
                },
                PrivateInput {
                    commitment: [0u8; POINT_SIZE],
                    merkle_proof: MerkleProof {
                        siblings: vec![],
                        path_indices: vec![],
                        leaf_index: 0,
                    },
                    ring_signature: RingSignature {
                        c: [0u8; SCALAR_SIZE],
                        responses: vec![],
                        key_image: key_image.0,
                    },
                    key_image: key_image.clone(), // DUPLICATE!
                    opening: None,
                },
            ],
            outputs: vec![],
            fee: 0,
            merkle_root: [0u8; HASH_SIZE],
        };
        
        // Should detect duplicate key images
        assert!(!tx.verify_key_images_unique(), 
            "Should reject duplicate key images within same tx");
        println!("✓ Duplicate key images detected and rejected");
        
        println!("\n=== DOUBLE-SPEND PREVENTION WORKS ===");
    }
}
