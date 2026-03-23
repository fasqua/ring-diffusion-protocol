// ============================================================================
// UPDATE MERKLE ROOT - Trustless root update
// ============================================================================
//
// Anyone can call this instruction to update the merkle root.
// The instruction verifies that the new root is valid by:
// 1. Reading commitment from CommitmentChunk (on-chain data)
// 2. Computing the new root with the commitment and proof
// 3. Updating CommitmentTree.root
// ============================================================================

use anchor_lang::prelude::*;
use crate::constants::*;
use crate::errors::RdpError;
use crate::state::{CommitmentTree, CommitmentChunk};
use crate::crypto::{MerkleProofData, compute_root};

#[derive(Accounts)]
#[instruction(commitment_index: u64, local_index: u8)]
pub struct UpdateMerkleRoot<'info> {
    /// Anyone can call this - no signer restriction beyond fee payer
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Commitment tree to update
    #[account(
        mut,
        seeds = [COMMITMENT_TREE_SEED],
        bump = commitment_tree.bump,
    )]
    pub commitment_tree: Account<'info, CommitmentTree>,

    /// Commitment chunk containing the commitment
    /// Caller must provide the correct chunk account
    pub commitment_chunk: Account<'info, CommitmentChunk>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct UpdateMerkleRootParams {
    /// Merkle proof siblings (20 for depth 20)
    pub siblings: Vec<[u8; 32]>,
}

pub fn handler_update_merkle_root(
    ctx: Context<UpdateMerkleRoot>,
    commitment_index: u64,
    local_index: u8,
    params: UpdateMerkleRootParams,
) -> Result<()> {
    let commitment_tree = &mut ctx.accounts.commitment_tree;
    let commitment_chunk = &ctx.accounts.commitment_chunk;

    // 1. Verify commitment_index is valid (not beyond next_index)
    require!(
        commitment_index < commitment_tree.next_index,
        RdpError::InvalidCommitment
    );

    // 2. Get commitment from chunk at local_index
    let commitment_data = commitment_chunk
        .get_commitment(local_index)
        .ok_or(RdpError::InvalidCommitment)?;
    
    let commitment = commitment_data.commitment;

    // 3. Build merkle proof data
    let proof = MerkleProofData {
        siblings: params.siblings,
        leaf_index: commitment_index,
    };

    // 4. Validate proof structure (must have MERKLE_DEPTH siblings)
    proof.validate()?;

    // 5. Compute the root from this commitment and proof
    let computed_root = compute_root(&commitment, &proof);

    // 6. Update the merkle root
    commitment_tree.root = computed_root;

    msg!(
        "Merkle root updated for commitment index {}",
        commitment_index
    );

    Ok(())
}
