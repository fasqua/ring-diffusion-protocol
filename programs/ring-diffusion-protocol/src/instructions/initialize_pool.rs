// ============================================================================
// RING DIFFUSION PROTOCOL - INITIALIZE POOL INSTRUCTION
// ============================================================================

use anchor_lang::prelude::*;
use crate::state::{PoolConfig, PoolState, CommitmentTree};
use crate::constants::*;
use crate::errors::RdpError;

#[derive(Accounts)]
pub struct InitializePool<'info> {
    /// Authority who will control the pool
    #[account(mut)]
    pub authority: Signer<'info>,
    
    /// Pool configuration account (PDA)
    #[account(
        init,
        payer = authority,
        space = PoolConfig::LEN,
        seeds = [POOL_CONFIG_SEED],
        bump
    )]
    pub pool_config: Account<'info, PoolConfig>,
    
    /// Pool state account (PDA)
    #[account(
        init,
        payer = authority,
        space = PoolState::LEN,
        seeds = [POOL_STATE_SEED],
        bump
    )]
    pub pool_state: Account<'info, PoolState>,
    
    /// Commitment tree account (PDA)
    #[account(
        init,
        payer = authority,
        space = CommitmentTree::LEN,
        seeds = [COMMITMENT_TREE_SEED],
        bump
    )]
    pub commitment_tree: Account<'info, CommitmentTree>,
    
    /// Pool vault for holding SOL (PDA)
    /// CHECK: This is a PDA that will hold SOL, validated by seeds
    #[account(
        mut,
        seeds = [POOL_VAULT_SEED],
        bump
    )]
    pub pool_vault: SystemAccount<'info>,
    
    /// Fee collector address
    /// CHECK: This can be any account that will receive fees
    pub fee_collector: UncheckedAccount<'info>,
    
    /// System program
    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct InitializePoolParams {
    /// Fee in basis points (e.g., 50 = 0.5%)
    pub fee_basis_points: u16,
    /// Minimum ring size
    pub min_ring_size: u8,
    /// Maximum ring size
    pub max_ring_size: u8,
}

pub fn handler_initialize_pool(ctx: Context<InitializePool>, params: InitializePoolParams) -> Result<()> {
    // Validate parameters
    require!(
        params.fee_basis_points <= MAX_FEE_BASIS_POINTS,
        RdpError::InvalidFeeConfig
    );
    require!(
        params.min_ring_size >= MIN_RING_SIZE,
        RdpError::RingSizeBelowMinimum
    );
    require!(
        params.max_ring_size <= MAX_RING_SIZE,
        RdpError::RingSizeAboveMaximum
    );
    require!(
        params.min_ring_size <= params.max_ring_size,
        RdpError::InvalidRingSize
    );
    
    // Initialize pool config
    let pool_config = &mut ctx.accounts.pool_config;
    pool_config.authority = ctx.accounts.authority.key();
    pool_config.fee_collector = ctx.accounts.fee_collector.key();
    pool_config.fee_basis_points = params.fee_basis_points;
    pool_config.min_ring_size = params.min_ring_size;
    pool_config.max_ring_size = params.max_ring_size;
    pool_config.deposit_enabled = true;
    pool_config.withdraw_enabled = true;
    pool_config.paused = false;
    pool_config.bump = ctx.bumps.pool_config;
    
    // Initialize pool state
    let pool_state = &mut ctx.accounts.pool_state;
    pool_state.total_deposits = 0;
    pool_state.total_withdrawals = 0;
    pool_state.total_fees_collected = 0;
    pool_state.commitment_count = 0;
    pool_state.chunk_count = 0;
    pool_state.current_epoch = 0;
    pool_state.last_deposit_timestamp = 0;
    pool_state.last_withdraw_timestamp = 0;
    pool_state.bump = ctx.bumps.pool_state;
    
    // Initialize commitment tree
    let commitment_tree = &mut ctx.accounts.commitment_tree;
    commitment_tree.root = [0u8; 32]; // Empty tree root
    commitment_tree.next_index = 0;
    commitment_tree.depth = MERKLE_TREE_DEPTH;
    commitment_tree.bump = ctx.bumps.commitment_tree;
    
    msg!("Ring Diffusion Protocol pool initialized");
    msg!("Authority: {}", ctx.accounts.authority.key());
    msg!("Fee: {} basis points", params.fee_basis_points);
    msg!("Ring size: {} - {}", params.min_ring_size, params.max_ring_size);
    
    Ok(())
}
