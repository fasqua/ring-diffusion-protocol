use anchor_lang::prelude::*;

pub mod constants;
pub mod errors;
pub mod state;
pub mod instructions;
pub mod crypto;

use instructions::*;

declare_id!("DHQtM2vuNrcD9UC42kfq1MNo9yucjPuReBHrsQvrpxjn");

#[program]
pub mod ring_diffusion_protocol {
    use super::*;

    pub fn initialize_pool(ctx: Context<InitializePool>, params: InitializePoolParams) -> Result<()> {
        instructions::initialize_pool::handler_initialize_pool(ctx, params)
    }

    pub fn update_pool_config(ctx: Context<UpdatePoolConfig>, params: UpdatePoolConfigParams) -> Result<()> {
        instructions::update_pool_config::handler_update_pool_config(ctx, params)
    }

    pub fn deposit_with_new_chunk(ctx: Context<DepositWithNewChunk>, commitment: [u8; 32], amount: u64) -> Result<()> {
        instructions::deposit::handler_deposit_with_new_chunk(ctx, commitment, amount)
    }

    pub fn deposit(ctx: Context<Deposit>, commitment: [u8; 32], amount: u64) -> Result<()> {
        instructions::deposit::handler_deposit(ctx, commitment, amount)
    }

    pub fn withdraw_authority(ctx: Context<WithdrawAuthority>, amount: u64) -> Result<()> {
        instructions::withdraw::handler_withdraw_authority(ctx, amount)
    }

    // =========================================================================
    // Six-Phase Withdraw (ring 16 + full bulletproof on-chain)
    // =========================================================================

    /// Phase 1: Create withdraw request with ring data
    pub fn prepare_withdraw(ctx: Context<PrepareWithdraw>, nonce: u64, params: PrepareWithdrawParams) -> Result<()> {
        let _ = nonce;
        instructions::prepare_withdraw::handler_prepare_withdraw(ctx, params)
    }

    /// Phase 2: Submit bulletproof part 1 (V, A, S)
    pub fn submit_proof_part1(ctx: Context<SubmitProofPart1>, nonce: u64, params: SubmitProofPart1Params) -> Result<()> {
        instructions::submit_proof::handler_submit_proof_part1(ctx, nonce, params)
    }

    /// Phase 3: Submit bulletproof part 2 (T1, T2, scalars)
    pub fn submit_proof_part2(ctx: Context<SubmitProofPart2>, nonce: u64, params: SubmitProofPart2Params) -> Result<()> {
        instructions::submit_proof_part2::handler_submit_proof_part2(ctx, nonce, params)
    }

    /// Phase 4: Submit bulletproof part 3 (ip_l)
    pub fn submit_proof_part3(ctx: Context<SubmitProofPart3>, nonce: u64, params: SubmitProofPart3Params) -> Result<()> {
        instructions::submit_proof_part3::handler_submit_proof_part3(ctx, nonce, params)
    }

    /// Phase 5: Submit bulletproof part 4 (ip_r, ip_a, ip_b)
    pub fn submit_proof_part4(ctx: Context<SubmitProofPart4>, nonce: u64, params: SubmitProofPart4Params) -> Result<()> {
        instructions::submit_proof_part4::handler_submit_proof_part4(ctx, nonce, params)
    }

    /// Phase 6: Execute withdraw with ring signature
    pub fn execute_withdraw(ctx: Context<ExecuteWithdraw>, key_image: [u8; 32], params: ExecuteWithdrawParams) -> Result<()> {
        instructions::execute_withdraw::handler_execute_withdraw(ctx, key_image, params)
    }

    /// Update merkle root - anyone can call (trustless)
    /// Phase 6 Alternative: Execute withdraw WITH merkle proof verification
    pub fn execute_withdraw_merkle(ctx: Context<ExecuteWithdrawMerkle>, key_image: [u8; 32], params: ExecuteWithdrawMerkleParams) -> Result<()> {
        instructions::execute_withdraw_merkle::handler_execute_withdraw_merkle(ctx, key_image, params)
    }

    pub fn update_merkle_root(ctx: Context<UpdateMerkleRoot>, commitment_index: u64, local_index: u8, params: UpdateMerkleRootParams) -> Result<()> {
        instructions::update_merkle_root::handler_update_merkle_root(ctx, commitment_index, local_index, params)
    }
}
