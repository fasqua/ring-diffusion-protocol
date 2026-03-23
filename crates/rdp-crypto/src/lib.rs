// ============================================================================
// RDP-CRYPTO: Cryptographic Primitives for Ring Diffusion Protocol
// ============================================================================

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod scalar;
pub mod point;
pub mod hash;
pub mod ring_signature;
pub mod key_image;
pub mod types;
pub mod merkle;
pub mod pedersen;
pub mod bulletproofs;
pub mod stealth;

#[cfg(feature = "std")]
pub mod private_tx;

pub use types::*;
pub use ring_signature::{RingSignature, verify};
pub use key_image::generate_key_image;
pub use merkle::{MerkleProof, hash_leaf, hash_node, compute_zero_hashes, MERKLE_DEPTH, HASH_SIZE};
pub use pedersen::{PedersenCommitment, BlindingFactor, CommitmentOpening, BalanceProof};
pub use bulletproofs::{Bulletproof, RANGE_BITS as BP_RANGE_BITS};

#[cfg(feature = "std")]
pub use ring_signature::sign;

#[cfg(feature = "std")]
pub use merkle::MerkleTree;

#[cfg(feature = "std")]
pub use bulletproofs::prover as bulletproof_prover;

pub use bulletproofs::verifier as bulletproof_verifier;

#[cfg(feature = "std")]
pub use private_tx::{PrivateTransaction, PrivateInput, PrivateOutput, OutputBuilder, VerificationResult};


#[cfg(feature = "std")]
pub use stealth::{
    StealthMetaAddress, 
    StealthAddressOutput, 
    StealthKeyPair,
    generate_stealth_address,
    check_stealth_address,
    derive_stealth_private_key,
    derive_stealth_pubkey,
};
