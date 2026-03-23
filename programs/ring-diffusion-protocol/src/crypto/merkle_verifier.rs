// ============================================================================
// On-Chain Merkle Proof Verifier
// ============================================================================
//
// Verifies Merkle proofs for commitment membership
// Uses SHA-256 for hashing
// ============================================================================

use anchor_lang::prelude::*;
use sha2::{Sha256, Digest};

/// Merkle tree depth
pub const MERKLE_DEPTH: usize = 20;

/// Hash size (32 bytes)
pub const HASH_SIZE: usize = 32;

/// Domain separation tags (must match rdp-crypto)
const DOMAIN_MERKLE_LEAF: &[u8] = b"RDP_MERKLE_LEAF_V1";
const DOMAIN_MERKLE_NODE: &[u8] = b"RDP_MERKLE_NODE_V1";

/// Merkle proof data for on-chain verification
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct MerkleProofData {
    /// Sibling hashes (20 for depth 20)
    pub siblings: Vec<[u8; HASH_SIZE]>,
    /// Leaf index in the tree
    pub leaf_index: u64,
}

impl MerkleProofData {
    /// Validate proof structure
    pub fn validate(&self) -> Result<()> {
        require!(
            self.siblings.len() == MERKLE_DEPTH,
            MerkleVerifyError::InvalidProofLength
        );
        Ok(())
    }
}

/// Errors for merkle verification
#[error_code]
pub enum MerkleVerifyError {
    #[msg("Invalid proof length (must be 20 siblings)")]
    InvalidProofLength,
    #[msg("Merkle proof verification failed")]
    VerificationFailed,
}

/// Hash a leaf (commitment) - must match rdp-crypto
pub fn hash_leaf(commitment: &[u8; 32]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MERKLE_LEAF);
    hasher.update(commitment);
    let result = hasher.finalize();
    
    let mut output = [0u8; HASH_SIZE];
    output.copy_from_slice(&result);
    output
}

/// Hash two nodes - must match rdp-crypto
pub fn hash_node(left: &[u8; HASH_SIZE], right: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MERKLE_NODE);
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    
    let mut output = [0u8; HASH_SIZE];
    output.copy_from_slice(&result);
    output
}

/// Verify merkle proof on-chain
pub fn verify_merkle_proof(
    commitment: &[u8; 32],
    root: &[u8; HASH_SIZE],
    proof: &MerkleProofData,
) -> Result<()> {
    proof.validate()?;

    let mut current = hash_leaf(commitment);
    let mut index = proof.leaf_index;

    for sibling in &proof.siblings {
        if index & 1 == 1 {
            // Current is on the right
            current = hash_node(sibling, &current);
        } else {
            // Current is on the left
            current = hash_node(&current, sibling);
        }
        index >>= 1;
    }

    require!(
        current == *root,
        MerkleVerifyError::VerificationFailed
    );

    Ok(())
}

/// Compute root from commitment and proof (without verification)
pub fn compute_root(
    commitment: &[u8; 32],
    proof: &MerkleProofData,
) -> [u8; HASH_SIZE] {
    let mut current = hash_leaf(commitment);
    let mut index = proof.leaf_index;

    for sibling in &proof.siblings {
        if index & 1 == 1 {
            current = hash_node(sibling, &current);
        } else {
            current = hash_node(&current, sibling);
        }
        index >>= 1;
    }

    current
}
