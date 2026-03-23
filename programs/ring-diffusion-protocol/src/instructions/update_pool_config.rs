// ============================================================================
// RING DIFFUSION PROTOCOL - UPDATE POOL CONFIG INSTRUCTION
// ============================================================================

use anchor_lang::prelude::*;
use crate::state::PoolConfig;
use crate::constants::*;
use crate::errors::RdpError;

#[derive(Accounts)]
pub struct UpdatePoolConfig<'info> {
    /// Authority who controls the pool (must match pool_config.authority)
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Pool configuration account (PDA)
    #[account(
        mut,
        seeds = [POOL_CONFIG_SEED],
        bump = pool_config.bump,
        has_one = authority @ RdpError::Unauthorized
    )]
    pub pool_config: Account<'info, PoolConfig>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct UpdatePoolConfigParams {
    /// New fee in basis points (None = keep current)
    pub fee_basis_points: Option<u16>,
    /// New minimum ring size (None = keep current)
    pub min_ring_size: Option<u8>,
    /// New maximum ring size (None = keep current)
    pub max_ring_size: Option<u8>,
    /// Enable/disable deposits (None = keep current)
    pub deposit_enabled: Option<bool>,
    /// Enable/disable withdrawals (None = keep current)
    pub withdraw_enabled: Option<bool>,
    /// Pause/unpause pool (None = keep current)
    pub paused: Option<bool>,
}

pub fn handler_update_pool_config(
    ctx: Context<UpdatePoolConfig>,
    params: UpdatePoolConfigParams,
) -> Result<()> {
    let pool_config = &mut ctx.accounts.pool_config;

    // Update fee if provided
    if let Some(fee) = params.fee_basis_points {
        require!(
            fee <= MAX_FEE_BASIS_POINTS,
            RdpError::InvalidFeeConfig
        );
        pool_config.fee_basis_points = fee;
        msg!("Updated fee to {} basis points", fee);
    }

    // Update min ring size if provided
    if let Some(min_size) = params.min_ring_size {
        require!(
            min_size >= MIN_RING_SIZE,
            RdpError::RingSizeBelowMinimum
        );
        // Ensure min <= max
        let max_size = params.max_ring_size.unwrap_or(pool_config.max_ring_size);
        require!(
            min_size <= max_size,
            RdpError::InvalidRingSize
        );
        pool_config.min_ring_size = min_size;
        msg!("Updated min_ring_size to {}", min_size);
    }

    // Update max ring size if provided
    if let Some(max_size) = params.max_ring_size {
        require!(
            max_size <= MAX_RING_SIZE,
            RdpError::RingSizeAboveMaximum
        );
        // Ensure min <= max
        let min_size = params.min_ring_size.unwrap_or(pool_config.min_ring_size);
        require!(
            min_size <= max_size,
            RdpError::InvalidRingSize
        );
        pool_config.max_ring_size = max_size;
        msg!("Updated max_ring_size to {}", max_size);
    }

    // Update deposit enabled if provided
    if let Some(enabled) = params.deposit_enabled {
        pool_config.deposit_enabled = enabled;
        msg!("Updated deposit_enabled to {}", enabled);
    }

    // Update withdraw enabled if provided
    if let Some(enabled) = params.withdraw_enabled {
        pool_config.withdraw_enabled = enabled;
        msg!("Updated withdraw_enabled to {}", enabled);
    }

    // Update paused if provided
    if let Some(paused) = params.paused {
        pool_config.paused = paused;
        msg!("Updated paused to {}", paused);
    }

    msg!("Pool config updated by {}", ctx.accounts.authority.key());

    Ok(())
}
