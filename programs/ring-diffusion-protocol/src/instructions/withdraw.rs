// ============================================================================
// Withdraw Instructions
// ============================================================================

use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};

use crate::constants::*;
use crate::errors::RdpError;
use crate::state::{PoolConfig, PoolState, KeyImageAccount};
use crate::crypto::{verify_ring_signature, RingSignatureData, verify_bulletproof, BulletproofData};

// ============================================================================
// Withdraw Authority (Phase 1 - Temporary)
// ============================================================================

#[derive(Accounts)]
pub struct WithdrawAuthority<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [POOL_CONFIG_SEED],
        bump,
        has_one = authority @ RdpError::Unauthorized,
    )]
    pub pool_config: Account<'info, PoolConfig>,

    #[account(
        mut,
        seeds = [POOL_STATE_SEED],
        bump,
    )]
    pub pool_state: Account<'info, PoolState>,

    #[account(
        mut,
        seeds = [POOL_VAULT_SEED],
        bump,
    )]
    /// CHECK: Pool vault PDA, validated by seeds
    pub pool_vault: SystemAccount<'info>,

    #[account(mut)]
    /// CHECK: Destination for withdrawn funds
    pub destination: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler_withdraw_authority(
    ctx: Context<WithdrawAuthority>,
    amount: u64,
) -> Result<()> {
    let pool_config = &ctx.accounts.pool_config;
    let pool_state = &mut ctx.accounts.pool_state;
    let pool_vault = &ctx.accounts.pool_vault;

    // Validate pool state
    require!(!pool_config.paused, RdpError::PoolPaused);
    require!(pool_config.withdraw_enabled, RdpError::WithdrawDisabled);
    require!(amount >= MIN_WITHDRAW_AMOUNT, RdpError::AmountTooSmall);

    // Check vault has enough balance
    let vault_balance = pool_vault.lamports();
    require!(vault_balance >= amount, RdpError::InsufficientPoolBalance);

    // Calculate fee
    let fee = amount
        .checked_mul(pool_config.fee_basis_points as u64)
        .ok_or(RdpError::MathOverflow)?
        .checked_div(10000)
        .ok_or(RdpError::MathOverflow)?;

    let amount_after_fee = amount
        .checked_sub(fee)
        .ok_or(RdpError::MathOverflow)?;

    // Transfer from vault to destination using CPI with signer seeds
    let vault_bump = ctx.bumps.pool_vault;
    let seeds = &[POOL_VAULT_SEED, &[vault_bump]];
    let signer_seeds = &[&seeds[..]];

    transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            Transfer {
                from: pool_vault.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
            },
            signer_seeds,
        ),
        amount_after_fee,
    )?;

    // Update pool state
    pool_state.total_withdrawals = pool_state
        .total_withdrawals
        .checked_add(amount)
        .ok_or(RdpError::MathOverflow)?;

    pool_state.total_fees_collected = pool_state
        .total_fees_collected
        .checked_add(fee)
        .ok_or(RdpError::MathOverflow)?;

    msg!(
        "Withdraw: {} lamports (fee: {}), destination: {}",
        amount_after_fee,
        fee,
        ctx.accounts.destination.key()
    );

    Ok(())
}

// ============================================================================
// Withdraw with Ring Signature + Bulletproof (Phase 2+)
// ============================================================================

#[derive(Accounts)]
#[instruction(
    ring_pubkeys: Vec<[u8; 32]>,
    signature_c: [u8; 32],
    signature_responses: Vec<[u8; 32]>,
    key_image: [u8; 32],
)]
pub struct WithdrawWithRingSig<'info> {
    #[account(mut)]
    pub withdrawer: Signer<'info>,

    #[account(
        seeds = [POOL_CONFIG_SEED],
        bump,
    )]
    pub pool_config: Account<'info, PoolConfig>,

    #[account(
        mut,
        seeds = [POOL_STATE_SEED],
        bump,
    )]
    pub pool_state: Account<'info, PoolState>,

    #[account(
        mut,
        seeds = [POOL_VAULT_SEED],
        bump,
    )]
    /// CHECK: Pool vault PDA, validated by seeds
    pub pool_vault: SystemAccount<'info>,

    #[account(
        init,
        payer = withdrawer,
        space = 8 + KeyImageAccount::LEN,
        seeds = [KEY_IMAGE_SEED, key_image.as_ref()],
        bump,
    )]
    pub key_image_account: Account<'info, KeyImageAccount>,

    #[account(mut)]
    /// CHECK: Destination for withdrawn funds
    pub destination: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler_withdraw_with_ring_sig(
    ctx: Context<WithdrawWithRingSig>,
    ring_pubkeys: Vec<[u8; 32]>,
    signature_c: [u8; 32],
    signature_responses: Vec<[u8; 32]>,
    key_image: [u8; 32],
    amount: u64,
    range_proof: Option<BulletproofData>,
) -> Result<()> {
    let pool_config = &ctx.accounts.pool_config;
    let pool_state = &mut ctx.accounts.pool_state;
    let pool_vault = &ctx.accounts.pool_vault;
    let key_image_account = &mut ctx.accounts.key_image_account;

    // Validate pool state
    require!(!pool_config.paused, RdpError::PoolPaused);
    require!(pool_config.withdraw_enabled, RdpError::WithdrawDisabled);
    require!(amount >= MIN_WITHDRAW_AMOUNT, RdpError::AmountTooSmall);

    // Validate ring size
    require!(
        ring_pubkeys.len() >= pool_config.min_ring_size as usize,
        RdpError::RingSizeTooSmall
    );
    require!(
        ring_pubkeys.len() <= pool_config.max_ring_size as usize,
        RdpError::RingSizeTooLarge
    );
    require!(
        ring_pubkeys.len() == signature_responses.len(),
        RdpError::InvalidSignature
    );

    // Check vault has enough balance
    let vault_balance = pool_vault.lamports();
    require!(vault_balance >= amount, RdpError::InsufficientPoolBalance);

    // Construct message to verify
    let message = construct_withdraw_message(
        &ctx.accounts.destination.key(),
        amount,
    );

    // Construct ring signature data
    let signature = RingSignatureData {
        c: signature_c,
        responses: signature_responses,
        key_image,
    };

    // Verify ring signature
    verify_ring_signature(&message, &ring_pubkeys, &signature)
        .map_err(|_| RdpError::InvalidSignature)?;

    // Verify Bulletproof range proof if provided
    if let Some(ref proof) = range_proof {
        msg!("Verifying Bulletproof range proof...");
        verify_bulletproof(proof)
            .map_err(|e| {
                msg!("Bulletproof verification failed: {:?}", e);
                RdpError::InvalidRangeProof
            })?;
        msg!("Range proof verified successfully");
    }

    // Key image account being initialized proves this key image hasn't been used
    key_image_account.key_image = key_image;
    key_image_account.spent_at_slot = Clock::get()?.slot;
    key_image_account.amount = amount;

    // Calculate fee
    let fee = amount
        .checked_mul(pool_config.fee_basis_points as u64)
        .ok_or(RdpError::MathOverflow)?
        .checked_div(10000)
        .ok_or(RdpError::MathOverflow)?;

    let amount_after_fee = amount
        .checked_sub(fee)
        .ok_or(RdpError::MathOverflow)?;

    // Transfer from vault to destination using CPI with signer seeds
    let vault_bump = ctx.bumps.pool_vault;
    let seeds = &[POOL_VAULT_SEED, &[vault_bump]];
    let signer_seeds = &[&seeds[..]];

    transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            Transfer {
                from: pool_vault.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
            },
            signer_seeds,
        ),
        amount_after_fee,
    )?;

    // Update pool state
    pool_state.total_withdrawals = pool_state
        .total_withdrawals
        .checked_add(amount)
        .ok_or(RdpError::MathOverflow)?;

    pool_state.total_fees_collected = pool_state
        .total_fees_collected
        .checked_add(fee)
        .ok_or(RdpError::MathOverflow)?;

    msg!(
        "Ring sig withdraw: {} lamports (fee: {}), key_image: {:?}, range_proof: {}",
        amount_after_fee,
        fee,
        &key_image[..8],
        range_proof.is_some()
    );

    Ok(())
}

/// Construct withdrawal message for signing
fn construct_withdraw_message(destination: &Pubkey, amount: u64) -> Vec<u8> {
    let mut message = Vec::with_capacity(40);
    message.extend_from_slice(destination.as_ref());
    message.extend_from_slice(&amount.to_le_bytes());
    message
}
