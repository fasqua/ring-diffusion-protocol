// ============================================================================
// On-Chain Cryptographic Verification
// ============================================================================
//
// Uses Solana syscalls for efficient on-chain verification
// - Ring signature verification (solana-curve25519)
// - Merkle proof verification (SHA-256)
// - Bulletproofs range proof verification
// ============================================================================

pub mod ring_verifier;
pub mod merkle_verifier;
pub mod bulletproofs_verifier;
pub mod types;
pub mod scalar_reduce;

pub use ring_verifier::verify_ring_signature;
pub use merkle_verifier::{verify_merkle_proof, compute_root, MerkleProofData};
pub use bulletproofs_verifier::{verify_bulletproof, BulletproofData, BulletproofError, RANGE_BITS, IP_ROUNDS};
pub use types::*;
