// ============================================================================
// RING DIFFUSION PROTOCOL - DEPOSIT INSTRUCTION
// ============================================================================

use anchor_lang::prelude::*;
use anchor_lang::system_program;
use crate::state::{PoolConfig, PoolState, CommitmentChunk, CommitmentTree};
use crate::constants::*;
use crate::errors::RdpError;

#[derive(Accounts)]
#[instruction(commitment: [u8; 32], amount: u64)]
pub struct Deposit<'info> {
    /// Depositor
    #[account(mut)]
    pub depositor: Signer<'info>,
    
    /// Pool configuration (verify pool is active)
    #[account(
        seeds = [POOL_CONFIG_SEED],
        bump = pool_config.bump,
    )]
    pub pool_config: Account<'info, PoolConfig>,
    
    /// Pool state (update stats)
    #[account(
        mut,
        seeds = [POOL_STATE_SEED],
        bump = pool_state.bump,
    )]
    pub pool_state: Account<'info, PoolState>,
    
    /// Commitment tree (update root)
    #[account(
        mut,
        seeds = [COMMITMENT_TREE_SEED],
        bump = commitment_tree.bump,
    )]
    pub commitment_tree: Account<'info, CommitmentTree>,
    
    /// Current commitment chunk (may need to create new one)
    #[account(
        mut,
        seeds = [COMMITMENT_CHUNK_SEED, &pool_state.chunk_count.to_le_bytes()],
        bump,
    )]
    pub commitment_chunk: Account<'info, CommitmentChunk>,
    
    /// Pool vault to receive SOL
    /// CHECK: PDA that holds pool funds
    #[account(
        mut,
        seeds = [POOL_VAULT_SEED],
        bump,
    )]
    pub pool_vault: SystemAccount<'info>,
    
    /// System program for transfer
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositWithNewChunk<'info> {
    /// Depositor
    #[account(mut)]
    pub depositor: Signer<'info>,
    
    /// Pool configuration (verify pool is active)
    #[account(
        seeds = [POOL_CONFIG_SEED],
        bump = pool_config.bump,
    )]
    pub pool_config: Account<'info, PoolConfig>,
    
    /// Pool state (update stats)
    #[account(
        mut,
        seeds = [POOL_STATE_SEED],
        bump = pool_state.bump,
    )]
    pub pool_state: Account<'info, PoolState>,
    
    /// Commitment tree (update root)
    #[account(
        mut,
        seeds = [COMMITMENT_TREE_SEED],
        bump = commitment_tree.bump,
    )]
    pub commitment_tree: Account<'info, CommitmentTree>,
    
    /// New commitment chunk to create
    #[account(
        init,
        payer = depositor,
        space = CommitmentChunk::LEN,
        seeds = [COMMITMENT_CHUNK_SEED, &pool_state.chunk_count.to_le_bytes()],
        bump,
    )]
    pub commitment_chunk: Account<'info, CommitmentChunk>,
    
    /// Pool vault to receive SOL
    /// CHECK: PDA that holds pool funds
    #[account(
        mut,
        seeds = [POOL_VAULT_SEED],
        bump,
    )]
    pub pool_vault: SystemAccount<'info>,
    
    /// System program for transfer
    pub system_program: Program<'info, System>,
}

pub fn handler_deposit(ctx: Context<Deposit>, commitment: [u8; 32], amount: u64) -> Result<()> {
    let pool_config = &ctx.accounts.pool_config;
    let pool_state = &mut ctx.accounts.pool_state;
    let commitment_tree = &mut ctx.accounts.commitment_tree;
    let commitment_chunk = &mut ctx.accounts.commitment_chunk;
    
    // Verify pool is operational and deposits enabled
    require!(pool_config.can_deposit(), RdpError::DepositsDisabled);
    
    // Verify minimum deposit amount
    require!(amount >= MIN_DEPOSIT_AMOUNT, RdpError::DepositBelowMinimum);
    
    // Transfer SOL from depositor to vault
    system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.depositor.to_account_info(),
                to: ctx.accounts.pool_vault.to_account_info(),
            },
        ),
        amount,
    )?;
    
    // Get current timestamp
    let clock = Clock::get()?;
    let timestamp = clock.unix_timestamp;
    
    // Add commitment to chunk
    let local_index = commitment_chunk.add_commitment(commitment, timestamp)?;
    let global_index = commitment_chunk.global_index(local_index);
    
    // Update pool state
    pool_state.record_deposit(amount, timestamp)?;
    
    // Update commitment tree next index
    commitment_tree.next_index = global_index + 1;
    
    // TODO: Update merkle root (will implement in Phase 2)
    
    // Emit event
    emit!(DepositEvent {
        depositor: ctx.accounts.depositor.key(),
        commitment,
        amount,
        index: global_index,
        timestamp,
    });
    
    msg!("Deposit successful: {} lamports, index {}", amount, global_index);
    
    Ok(())
}

pub fn handler_deposit_with_new_chunk(
    ctx: Context<DepositWithNewChunk>, 
    commitment: [u8; 32], 
    amount: u64
) -> Result<()> {
    let pool_config = &ctx.accounts.pool_config;
    let pool_state = &mut ctx.accounts.pool_state;
    let commitment_tree = &mut ctx.accounts.commitment_tree;
    let commitment_chunk = &mut ctx.accounts.commitment_chunk;
    
    // Verify pool is operational and deposits enabled
    require!(pool_config.can_deposit(), RdpError::DepositsDisabled);
    
    // Verify minimum deposit amount
    require!(amount >= MIN_DEPOSIT_AMOUNT, RdpError::DepositBelowMinimum);
    
    // Transfer SOL from depositor to vault
    system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.depositor.to_account_info(),
                to: ctx.accounts.pool_vault.to_account_info(),
            },
        ),
        amount,
    )?;
    
    // Get current timestamp
    let clock = Clock::get()?;
    let timestamp = clock.unix_timestamp;
    
    // Initialize new chunk
    commitment_chunk.chunk_index = pool_state.chunk_count;
    commitment_chunk.count = 0;
    commitment_chunk.bump = ctx.bumps.commitment_chunk;
    
    // Add commitment to new chunk
    let local_index = commitment_chunk.add_commitment(commitment, timestamp)?;
    let global_index = commitment_chunk.global_index(local_index);
    
    // Update pool state
    pool_state.record_deposit(amount, timestamp)?;
    pool_state.chunk_count += 1;
    
    // Update commitment tree next index
    commitment_tree.next_index = global_index + 1;
    
    // TODO: Update merkle root (will implement in Phase 2)
    
    // Emit event
    emit!(DepositEvent {
        depositor: ctx.accounts.depositor.key(),
        commitment,
        amount,
        index: global_index,
        timestamp,
    });
    
    msg!("Deposit successful (new chunk): {} lamports, index {}", amount, global_index);
    
    Ok(())
}

#[event]
pub struct DepositEvent {
    pub depositor: Pubkey,
    pub commitment: [u8; 32],
    pub amount: u64,
    pub index: u64,
    pub timestamp: i64,
}
