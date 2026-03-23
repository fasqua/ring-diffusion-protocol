// ============================================================================
// RDP-CRYPTO: Merkle Tree Operations
// ============================================================================
//
// Sparse Merkle Tree for commitment storage
// - Fixed depth (20 levels = 1M+ leaves)
// - Uses SHA-256 for hashing
// - Supports membership proofs
// ============================================================================

use sha2::{Sha256, Digest};
use crate::types::SCALAR_SIZE;

/// Merkle tree depth (20 levels = 2^20 = 1,048,576 leaves)
pub const MERKLE_DEPTH: usize = 20;

/// Hash size (32 bytes)
pub const HASH_SIZE: usize = 32;

/// Domain separation for merkle hashing
const DOMAIN_MERKLE_LEAF: &[u8] = b"RDP_MERKLE_LEAF_V1";
const DOMAIN_MERKLE_NODE: &[u8] = b"RDP_MERKLE_NODE_V1";

/// Zero hashes for empty subtrees (pre-computed)
/// zero_hashes[i] = hash of empty subtree at level i
pub fn compute_zero_hashes() -> [[u8; HASH_SIZE]; MERKLE_DEPTH + 1] {
    let mut zeros = [[0u8; HASH_SIZE]; MERKLE_DEPTH + 1];
    
    // Level 0: hash of zero leaf
    zeros[0] = hash_leaf(&[0u8; SCALAR_SIZE]);
    
    // Each level up: hash of two children
    for i in 1..=MERKLE_DEPTH {
        zeros[i] = hash_node(&zeros[i - 1], &zeros[i - 1]);
    }
    
    zeros
}

/// Hash a leaf (commitment)
pub fn hash_leaf(commitment: &[u8; SCALAR_SIZE]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_MERKLE_LEAF);
    hasher.update(commitment);
    let result = hasher.finalize();
    
    let mut output = [0u8; HASH_SIZE];
    output.copy_from_slice(&result);
    output
}

/// Hash two child nodes to create parent
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

/// Merkle proof structure
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// Sibling hashes from leaf to root
    pub siblings: Vec<[u8; HASH_SIZE]>,
    /// Path bits (0 = left, 1 = right)
    pub path_indices: Vec<bool>,
    /// Leaf index
    pub leaf_index: u64,
}

impl MerkleProof {
    /// Create new merkle proof
    pub fn new(siblings: Vec<[u8; HASH_SIZE]>, leaf_index: u64) -> Self {
        let path_indices = (0..siblings.len())
            .map(|i| (leaf_index >> i) & 1 == 1)
            .collect();
        
        Self {
            siblings,
            path_indices,
            leaf_index,
        }
    }

    /// Verify proof against root
    pub fn verify(&self, leaf: &[u8; SCALAR_SIZE], root: &[u8; HASH_SIZE]) -> bool {
        if self.siblings.len() != MERKLE_DEPTH {
            return false;
        }

        let mut current = hash_leaf(leaf);

        for (i, sibling) in self.siblings.iter().enumerate() {
            if self.path_indices[i] {
                // Current is on the right
                current = hash_node(sibling, &current);
            } else {
                // Current is on the left
                current = hash_node(&current, sibling);
            }
        }

        current == *root
    }

    /// Compute root from leaf and proof
    pub fn compute_root(&self, leaf: &[u8; SCALAR_SIZE]) -> [u8; HASH_SIZE] {
        let mut current = hash_leaf(leaf);

        for (i, sibling) in self.siblings.iter().enumerate() {
            if self.path_indices[i] {
                current = hash_node(sibling, &current);
            } else {
                current = hash_node(&current, sibling);
            }
        }

        current
    }
}

/// Simple in-memory Merkle tree for off-chain use
#[cfg(feature = "std")]
pub struct MerkleTree {
    /// All leaves (commitments hashed)
    leaves: Vec<[u8; HASH_SIZE]>,
    /// Current root
    root: [u8; HASH_SIZE],
    /// Zero hashes for empty subtrees
    zero_hashes: [[u8; HASH_SIZE]; MERKLE_DEPTH + 1],
}

#[cfg(feature = "std")]
impl MerkleTree {
    /// Create empty merkle tree
    pub fn new() -> Self {
        let zero_hashes = compute_zero_hashes();
        Self {
            leaves: Vec::new(),
            root: zero_hashes[MERKLE_DEPTH],
            zero_hashes,
        }
    }

    /// Get current root
    pub fn root(&self) -> [u8; HASH_SIZE] {
        self.root
    }

    /// Get number of leaves
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Insert a commitment and return its index
    pub fn insert(&mut self, commitment: &[u8; SCALAR_SIZE]) -> u64 {
        let leaf_hash = hash_leaf(commitment);
        let index = self.leaves.len() as u64;
        self.leaves.push(leaf_hash);
        self.recompute_root();
        index
    }

    /// Generate proof for leaf at index
    pub fn generate_proof(&self, index: u64) -> Option<MerkleProof> {
        if index >= self.leaves.len() as u64 {
            return None;
        }

        let mut siblings = Vec::with_capacity(MERKLE_DEPTH);
        let mut current_index = index as usize;
        let mut level_hashes: Vec<[u8; HASH_SIZE]> = self.leaves.clone();

        for level in 0..MERKLE_DEPTH {
            // Pad level to power of 2 with zero hashes
            let level_size = 1 << (MERKLE_DEPTH - level);
            while level_hashes.len() < level_size {
                level_hashes.push(self.zero_hashes[level]);
            }

            // Get sibling
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            siblings.push(level_hashes[sibling_index]);

            // Compute next level
            let mut next_level = Vec::with_capacity(level_hashes.len() / 2);
            for i in (0..level_hashes.len()).step_by(2) {
                next_level.push(hash_node(&level_hashes[i], &level_hashes[i + 1]));
            }
            level_hashes = next_level;
            current_index /= 2;
        }

        Some(MerkleProof::new(siblings, index))
    }

    /// Recompute root after insertions
    fn recompute_root(&mut self) {
        if self.leaves.is_empty() {
            self.root = self.zero_hashes[MERKLE_DEPTH];
            return;
        }

        let mut level_hashes = self.leaves.clone();

        for level in 0..MERKLE_DEPTH {
            // Pad to even number with zero hash
            if level_hashes.len() % 2 == 1 {
                level_hashes.push(self.zero_hashes[level]);
            }

            // Compute next level
            let mut next_level = Vec::with_capacity(level_hashes.len() / 2);
            for i in (0..level_hashes.len()).step_by(2) {
                next_level.push(hash_node(&level_hashes[i], &level_hashes[i + 1]));
            }
            level_hashes = next_level;
        }

        self.root = level_hashes[0];
    }
}

#[cfg(feature = "std")]
impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_leaf_deterministic() {
        let commitment = [42u8; 32];
        let h1 = hash_leaf(&commitment);
        let h2 = hash_leaf(&commitment);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_node_deterministic() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let h1 = hash_node(&left, &right);
        let h2 = hash_node(&left, &right);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_node_order_matters() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let h1 = hash_node(&a, &b);
        let h2 = hash_node(&b, &a);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_zero_hashes() {
        let zeros = compute_zero_hashes();
        // Each level should be different
        for i in 0..MERKLE_DEPTH {
            assert_ne!(zeros[i], zeros[i + 1]);
        }
    }

    #[test]
    fn test_merkle_tree_empty() {
        let tree = MerkleTree::new();
        let zeros = compute_zero_hashes();
        assert_eq!(tree.root(), zeros[MERKLE_DEPTH]);
        assert!(tree.is_empty());
    }

    #[test]
    fn test_merkle_tree_single_insert() {
        let mut tree = MerkleTree::new();
        let commitment = [1u8; 32];
        let index = tree.insert(&commitment);
        
        assert_eq!(index, 0);
        assert_eq!(tree.len(), 1);
        assert!(!tree.is_empty());
    }

    #[test]
    fn test_merkle_proof_single_leaf() {
        let mut tree = MerkleTree::new();
        let commitment = [1u8; 32];
        tree.insert(&commitment);
        
        let proof = tree.generate_proof(0).unwrap();
        let root = tree.root();
        
        assert!(proof.verify(&commitment, &root));
    }

    #[test]
    fn test_merkle_proof_multiple_leaves() {
        let mut tree = MerkleTree::new();
        
        let commitments: Vec<[u8; 32]> = (0..5)
            .map(|i| {
                let mut c = [0u8; 32];
                c[0] = i as u8;
                c
            })
            .collect();

        for c in &commitments {
            tree.insert(c);
        }

        let root = tree.root();

        // Verify all proofs
        for (i, c) in commitments.iter().enumerate() {
            let proof = tree.generate_proof(i as u64).unwrap();
            assert!(proof.verify(c, &root), "Proof failed for index {}", i);
        }
    }

    #[test]
    fn test_merkle_proof_wrong_commitment() {
        let mut tree = MerkleTree::new();
        let commitment = [1u8; 32];
        tree.insert(&commitment);
        
        let proof = tree.generate_proof(0).unwrap();
        let root = tree.root();
        
        let wrong_commitment = [2u8; 32];
        assert!(!proof.verify(&wrong_commitment, &root));
    }

    #[test]
    fn test_merkle_proof_wrong_root() {
        let mut tree = MerkleTree::new();
        let commitment = [1u8; 32];
        tree.insert(&commitment);
        
        let proof = tree.generate_proof(0).unwrap();
        let wrong_root = [0u8; 32];
        
        assert!(!proof.verify(&commitment, &wrong_root));
    }

    #[test]
    fn test_merkle_compute_root() {
        let mut tree = MerkleTree::new();
        let commitment = [1u8; 32];
        tree.insert(&commitment);
        
        let proof = tree.generate_proof(0).unwrap();
        let computed_root = proof.compute_root(&commitment);
        
        assert_eq!(computed_root, tree.root());
    }
}

#[cfg(test)]
mod compat_tests {
    use super::*;

    #[test]
    fn test_merkle_proof_format() {
        let mut tree = MerkleTree::new();
        
        let commitment1 = [1u8; 32];
        let commitment2 = [2u8; 32];
        let commitment3 = [3u8; 32];
        
        tree.insert(&commitment1);
        tree.insert(&commitment2);
        tree.insert(&commitment3);
        
        let proof = tree.generate_proof(0).unwrap();
        
        assert_eq!(proof.siblings.len(), MERKLE_DEPTH);
        assert_eq!(proof.leaf_index, 0);
        assert!(proof.verify(&commitment1, &tree.root()));
        
        println!("Root: {:02x?}", &tree.root()[..8]);
        println!("Leaf index: {}", proof.leaf_index);
        println!("Siblings: {}", proof.siblings.len());
    }

    #[test]
    fn test_hash_values_deterministic() {
        let commitment = [42u8; 32];
        let leaf_hash = hash_leaf(&commitment);
        
        // Run again - should be identical
        let leaf_hash2 = hash_leaf(&commitment);
        assert_eq!(leaf_hash, leaf_hash2);
        
        let left = [1u8; 32];
        let right = [2u8; 32];
        let node_hash = hash_node(&left, &right);
        let node_hash2 = hash_node(&left, &right);
        assert_eq!(node_hash, node_hash2);
    }
}
