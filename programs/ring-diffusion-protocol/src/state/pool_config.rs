// ============================================================================
// RING DIFFUSION PROTOCOL - POOL CONFIG STATE
// ============================================================================

use anchor_lang::prelude::*;

#[account]
pub struct PoolConfig {
    /// Authority that can update config
    pub authority: Pubkey,
    
    /// Fee collector address (where fees are sent)
    pub fee_collector: Pubkey,
    
    /// Fee in basis points (50 = 0.5%)
    pub fee_basis_points: u16,
    
    /// Minimum ring size for withdrawals
    pub min_ring_size: u8,
    
    /// Maximum ring size for withdrawals
    pub max_ring_size: u8,
    
    /// Whether deposits are enabled
    pub deposit_enabled: bool,
    
    /// Whether withdrawals are enabled
    pub withdraw_enabled: bool,
    
    /// Emergency pause (stops everything)
    pub paused: bool,
    
    /// Bump seed for PDA
    pub bump: u8,
    
    /// Reserved for future upgrades
    pub _reserved: [u8; 64],
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            authority: Pubkey::default(),
            fee_collector: Pubkey::default(),
            fee_basis_points: 0,
            min_ring_size: 0,
            max_ring_size: 0,
            deposit_enabled: false,
            withdraw_enabled: false,
            paused: false,
            bump: 0,
            _reserved: [0u8; 64],
        }
    }
}

impl PoolConfig {
    /// Account size in bytes
    /// 8 (discriminator) + 32 + 32 + 2 + 1 + 1 + 1 + 1 + 1 + 1 + 64 = 144 bytes
    pub const LEN: usize = 8 + 32 + 32 + 2 + 1 + 1 + 1 + 1 + 1 + 1 + 64;
    
    /// Check if pool is operational
    pub fn is_operational(&self) -> bool {
        !self.paused
    }
    
    /// Check if deposits are allowed
    pub fn can_deposit(&self) -> bool {
        self.is_operational() && self.deposit_enabled
    }
    
    /// Check if withdrawals are allowed
    pub fn can_withdraw(&self) -> bool {
        self.is_operational() && self.withdraw_enabled
    }
    
    /// Validate ring size
    pub fn is_valid_ring_size(&self, ring_size: u8) -> bool {
        ring_size >= self.min_ring_size && ring_size <= self.max_ring_size
    }
}
