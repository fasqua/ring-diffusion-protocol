// ============================================================================
// WithdrawRequest State - Three-Phase Withdraw
// ============================================================================

use anchor_lang::prelude::*;

pub const MAX_RING_SIZE_STORAGE: usize = 16;

#[account]
pub struct WithdrawRequest {
    pub owner: Pubkey,
    pub destination: Pubkey,
    pub amount: u64,
    pub ring_size: u8,
    pub status: u8,  // 0=pending, 1=proof_submitted, 2=executed
    pub ring_pubkeys: [[u8; 32]; MAX_RING_SIZE_STORAGE],
    pub has_bulletproof: bool,
    pub created_at: i64,
    pub bump: u8,
    pub nonce: u64,
}

impl WithdrawRequest {
    pub const LEN: usize = 8 +  // discriminator
        32 +                     // owner
        32 +                     // destination
        8 +                      // amount
        1 +                      // ring_size
        1 +                      // status
        (32 * MAX_RING_SIZE_STORAGE) + // ring_pubkeys
        1 +                      // has_bulletproof
        8 +                      // created_at
        1 +                      // bump
        8;                       // nonce
    
    pub fn is_expired(&self, current_timestamp: i64) -> bool {
        const EXPIRY_SECONDS: i64 = 24 * 60 * 60;
        current_timestamp > self.created_at + EXPIRY_SECONDS
    }
    
    pub fn get_ring_pubkeys(&self) -> &[[u8; 32]] {
        &self.ring_pubkeys[..self.ring_size as usize]
    }
}
