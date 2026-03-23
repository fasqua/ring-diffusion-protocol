// ============================================================================
// EXECUTE WITHDRAW WITH MERKLE PROOF
// ============================================================================
// Same as execute_withdraw but ALSO verifies merkle proof
// This ensures the commitment exists in the merkle tree
// ============================================================================

use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};

use crate::constants::*;
use crate::errors::RdpError;
use crate::state::{PoolConfig, PoolState, KeyImageAccount, WithdrawRequest, CommitmentTree};
use crate::state::{BulletproofPart1, BulletproofPart2, BulletproofPart3, BulletproofPart4};
use crate::crypto::{verify_ring_signature, RingSignatureData, verify_bulletproof, BulletproofData};
use crate::crypto::{verify_merkle_proof, MerkleProofData};
use crate::instructions::prepare_withdraw::WITHDRAW_REQUEST_SEED;
use crate::instructions::submit_proof::BULLETPROOF_PART1_SEED;
use crate::instructions::submit_proof_part2::BULLETPROOF_PART2_SEED;
use crate::instructions::submit_proof_part3::BULLETPROOF_PART3_SEED;
use crate::instructions::submit_proof_part4::BULLETPROOF_PART4_SEED;

#[derive(Accounts)]
#[instruction(key_image: [u8; 32])]
pub struct ExecuteWithdrawMerkle<'info> {
    #[account(mut)]
    pub withdrawer: Signer<'info>,

    #[account(seeds = [POOL_CONFIG_SEED], bump)]
    pub pool_config: Box<Account<'info, PoolConfig>>,

    #[account(mut, seeds = [POOL_STATE_SEED], bump)]
    pub pool_state: Box<Account<'info, PoolState>>,

    #[account(mut, seeds = [POOL_VAULT_SEED], bump)]
    /// CHECK: Pool vault PDA
    pub pool_vault: SystemAccount<'info>,

    /// Commitment tree for merkle verification
    #[account(seeds = [COMMITMENT_TREE_SEED], bump = commitment_tree.bump)]
    pub commitment_tree: Box<Account<'info, CommitmentTree>>,

    #[account(
        mut,
        close = withdrawer,
        seeds = [WITHDRAW_REQUEST_SEED, withdrawer.key().as_ref(), &withdraw_request.nonce.to_le_bytes()],
        bump = withdraw_request.bump,
        constraint = withdraw_request.owner == withdrawer.key() @ RdpError::Unauthorized,
        constraint = withdraw_request.status == 4 @ RdpError::ProofNotSubmitted,
    )]
    pub withdraw_request: Box<Account<'info, WithdrawRequest>>,

    #[account(
        mut,
        close = withdrawer,
        seeds = [BULLETPROOF_PART1_SEED, withdrawer.key().as_ref(), &withdraw_request.nonce.to_le_bytes()],
        bump = bp1.bump,
    )]
    pub bp1: Box<Account<'info, BulletproofPart1>>,

    #[account(
        mut,
        close = withdrawer,
        seeds = [BULLETPROOF_PART2_SEED, withdrawer.key().as_ref(), &withdraw_request.nonce.to_le_bytes()],
        bump = bp2.bump,
    )]
    pub bp2: Box<Account<'info, BulletproofPart2>>,

    #[account(
        mut,
        close = withdrawer,
        seeds = [BULLETPROOF_PART3_SEED, withdrawer.key().as_ref(), &withdraw_request.nonce.to_le_bytes()],
        bump = bp3.bump,
    )]
    pub bp3: Box<Account<'info, BulletproofPart3>>,

    #[account(
        mut,
        close = withdrawer,
        seeds = [BULLETPROOF_PART4_SEED, withdrawer.key().as_ref(), &withdraw_request.nonce.to_le_bytes()],
        bump = bp4.bump,
    )]
    pub bp4: Box<Account<'info, BulletproofPart4>>,

    #[account(
        init,
        payer = withdrawer,
        space = 8 + KeyImageAccount::LEN,
        seeds = [KEY_IMAGE_SEED, key_image.as_ref()],
        bump,
    )]
    pub key_image_account: Box<Account<'info, KeyImageAccount>>,

    #[account(
        mut,
        constraint = destination.key() == withdraw_request.destination @ RdpError::InvalidDestination
    )]
    /// CHECK: Validated
    pub destination: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ExecuteWithdrawMerkleParams {
    pub signature_c: [u8; 32],
    pub signature_responses: Vec<[u8; 32]>,
    /// Merkle proof data
    pub merkle_proof: MerkleProofData,
}

pub fn handler_execute_withdraw_merkle(
    ctx: Context<ExecuteWithdrawMerkle>,
    key_image: [u8; 32],
    params: ExecuteWithdrawMerkleParams,
) -> Result<()> {
    let pool_config = &ctx.accounts.pool_config;
    let pool_state = &mut ctx.accounts.pool_state;
    let pool_vault = &ctx.accounts.pool_vault;
    let commitment_tree = &ctx.accounts.commitment_tree;
    let wr = &ctx.accounts.withdraw_request;
    let key_image_account = &mut ctx.accounts.key_image_account;
    let clock = Clock::get()?;

    require!(!pool_config.paused, RdpError::PoolPaused);
    require!(pool_config.withdraw_enabled, RdpError::WithdrawDisabled);
    require!(!wr.is_expired(clock.unix_timestamp), RdpError::WithdrawRequestExpired);
    require!(params.signature_responses.len() == wr.ring_size as usize, RdpError::InvalidSignature);

    let amount = wr.amount;
    require!(pool_vault.lamports() >= amount, RdpError::InsufficientPoolBalance);

    // =========================================================================
    // MERKLE PROOF VERIFICATION (NEW!)
    // =========================================================================
    // The commitment is v_commitment from bulletproof
    let commitment = ctx.accounts.bp1.v_commitment;
    
    msg!("Verifying merkle proof...");
    verify_merkle_proof(&commitment, &commitment_tree.root, &params.merkle_proof)
        .map_err(|_| RdpError::InvalidMerkleProof)?;
    msg!("Merkle OK");

    // =========================================================================
    // RING SIGNATURE VERIFICATION
    // =========================================================================
    let mut message = Vec::with_capacity(40);
    message.extend_from_slice(wr.destination.as_ref());
    message.extend_from_slice(&amount.to_le_bytes());

    let ring_pubkeys = wr.get_ring_pubkeys();
    let signature = RingSignatureData {
        c: params.signature_c,
        responses: params.signature_responses,
        key_image,
    };

    msg!("Ring sig ({} members)...", ring_pubkeys.len());
    verify_ring_signature(&message, ring_pubkeys, &signature)
        .map_err(|_| RdpError::InvalidSignature)?;
    msg!("Ring OK");

    // =========================================================================
    // BULLETPROOF VERIFICATION
    // =========================================================================
    let bulletproof = Box::new(BulletproofData {
        v_commitment: ctx.accounts.bp1.v_commitment,
        a: ctx.accounts.bp1.a,
        s: ctx.accounts.bp1.s,
        t1: ctx.accounts.bp2.t1,
        t2: ctx.accounts.bp2.t2,
        tau_x: ctx.accounts.bp2.tau_x,
        mu: ctx.accounts.bp2.mu,
        t_hat: ctx.accounts.bp2.t_hat,
        ip_l: ctx.accounts.bp3.ip_l,
        ip_r: ctx.accounts.bp4.ip_r,
        ip_a: ctx.accounts.bp4.ip_a,
        ip_b: ctx.accounts.bp4.ip_b,
    });

    msg!("Bulletproof...");
    verify_bulletproof(&bulletproof).map_err(|_| RdpError::InvalidRangeProof)?;
    msg!("BP OK");

    // =========================================================================
    // FINALIZE
    // =========================================================================
    key_image_account.key_image = key_image;
    key_image_account.spent_at_slot = clock.slot;
    key_image_account.amount = amount;

    let fee = amount.checked_mul(pool_config.fee_basis_points as u64)
        .ok_or(RdpError::MathOverflow)?
        .checked_div(10000).ok_or(RdpError::MathOverflow)?;
    let amount_after_fee = amount.checked_sub(fee).ok_or(RdpError::MathOverflow)?;

    let vault_bump = ctx.bumps.pool_vault;
    transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            Transfer {
                from: pool_vault.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
            },
            &[&[POOL_VAULT_SEED, &[vault_bump]]],
        ),
        amount_after_fee,
    )?;

    pool_state.total_withdrawals = pool_state.total_withdrawals.checked_add(amount).ok_or(RdpError::MathOverflow)?;
    pool_state.total_fees_collected = pool_state.total_fees_collected.checked_add(fee).ok_or(RdpError::MathOverflow)?;

    msg!("Withdrew {} (fee {}) with merkle proof", amount_after_fee, fee);
    Ok(())
}
