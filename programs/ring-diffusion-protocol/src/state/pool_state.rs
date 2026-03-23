// ============================================================================
// RING DIFFUSION PROTOCOL - POOL STATE
// ============================================================================

use anchor_lang::prelude::*;

#[account]
pub struct PoolState {
    /// Total SOL deposited (in lamports)
    pub total_deposits: u64,
    
    /// Total SOL withdrawn (in lamports)
    pub total_withdrawals: u64,
    
    /// Total fees collected (in lamports)
    pub total_fees_collected: u64,
    
    /// Number of commitments in pool
    pub commitment_count: u64,
    
    /// Number of commitment chunks
    pub chunk_count: u64,
    
    /// Current epoch for tracking
    pub current_epoch: u64,
    
    /// Last deposit timestamp
    pub last_deposit_timestamp: i64,
    
    /// Last withdrawal timestamp
    pub last_withdraw_timestamp: i64,
    
    /// Bump seed for PDA
    pub bump: u8,
    
    /// Reserved for future upgrades
    pub _reserved: [u8; 64],
}

impl Default for PoolState {
    fn default() -> Self {
        Self {
            total_deposits: 0,
            total_withdrawals: 0,
            total_fees_collected: 0,
            commitment_count: 0,
            chunk_count: 0,
            current_epoch: 0,
            last_deposit_timestamp: 0,
            last_withdraw_timestamp: 0,
            bump: 0,
            _reserved: [0u8; 64],
        }
    }
}

impl PoolState {
    /// Account size in bytes
    /// 8 (discriminator) + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 1 + 64 = 137 bytes
    pub const LEN: usize = 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 1 + 64;
    
    /// Get current pool balance (deposits - withdrawals)
    pub fn current_balance(&self) -> u64 {
        self.total_deposits.saturating_sub(self.total_withdrawals)
    }
    
    /// Record a deposit
    pub fn record_deposit(&mut self, amount: u64, timestamp: i64) -> Result<()> {
        self.total_deposits = self.total_deposits
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        self.commitment_count = self.commitment_count
            .checked_add(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        self.last_deposit_timestamp = timestamp;
        Ok(())
    }
    
    /// Record a withdrawal
    pub fn record_withdrawal(&mut self, amount: u64, fee: u64, timestamp: i64) -> Result<()> {
        self.total_withdrawals = self.total_withdrawals
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        self.total_fees_collected = self.total_fees_collected
            .checked_add(fee)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        self.last_withdraw_timestamp = timestamp;
        Ok(())
    }
}
