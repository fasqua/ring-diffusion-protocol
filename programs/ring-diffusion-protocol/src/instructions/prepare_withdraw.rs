// ============================================================================
// Prepare Withdraw Instruction (Phase 1 of Three-Phase Withdraw)
// ============================================================================

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::RdpError;
use crate::state::{PoolConfig, WithdrawRequest, MAX_RING_SIZE_STORAGE};

pub const WITHDRAW_REQUEST_SEED: &[u8] = b"withdraw_request";

#[derive(Accounts)]
#[instruction(nonce: u64)]
pub struct PrepareWithdraw<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        seeds = [POOL_CONFIG_SEED],
        bump,
    )]
    pub pool_config: Account<'info, PoolConfig>,

    #[account(
        init,
        payer = owner,
        space = WithdrawRequest::LEN,
        seeds = [WITHDRAW_REQUEST_SEED, owner.key().as_ref(), &nonce.to_le_bytes()],
        bump,
    )]
    pub withdraw_request: Account<'info, WithdrawRequest>,

    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct PrepareWithdrawParams {
    pub nonce: u64,
    pub destination: Pubkey,
    pub amount: u64,
    pub ring_pubkeys: Vec<[u8; 32]>,
}

pub fn handler_prepare_withdraw(
    ctx: Context<PrepareWithdraw>,
    params: PrepareWithdrawParams,
) -> Result<()> {
    let pool_config = &ctx.accounts.pool_config;
    let withdraw_request = &mut ctx.accounts.withdraw_request;
    let clock = Clock::get()?;

    require!(!pool_config.paused, RdpError::PoolPaused);
    require!(pool_config.withdraw_enabled, RdpError::WithdrawDisabled);
    require!(params.amount >= MIN_WITHDRAW_AMOUNT, RdpError::AmountTooSmall);

    let ring_size = params.ring_pubkeys.len();
    require!(
        ring_size >= pool_config.min_ring_size as usize,
        RdpError::RingSizeTooSmall
    );
    require!(
        ring_size <= pool_config.max_ring_size as usize,
        RdpError::RingSizeTooLarge
    );
    require!(
        ring_size <= MAX_RING_SIZE_STORAGE,
        RdpError::RingSizeTooLarge
    );

    // Initialize
    withdraw_request.owner = ctx.accounts.owner.key();
    withdraw_request.destination = params.destination;
    withdraw_request.amount = params.amount;
    withdraw_request.ring_size = ring_size as u8;
    withdraw_request.status = 0; // pending_proof
    withdraw_request.has_bulletproof = false;
    withdraw_request.created_at = clock.unix_timestamp;
    withdraw_request.bump = ctx.bumps.withdraw_request;
    withdraw_request.nonce = params.nonce;

    // Copy ring pubkeys
    for (i, pubkey) in params.ring_pubkeys.iter().enumerate() {
        withdraw_request.ring_pubkeys[i] = *pubkey;
    }

    msg!(
        "PrepareWithdraw: {} lamports, ring_size={}, status=pending_proof",
        params.amount,
        ring_size
    );

    Ok(())
}
