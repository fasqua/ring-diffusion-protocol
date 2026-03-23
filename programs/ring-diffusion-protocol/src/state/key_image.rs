// ============================================================================
// Key Image Account
// ============================================================================
//
// Stores spent key images to prevent double-spending
// Each key image can only be used once
// ============================================================================

use anchor_lang::prelude::*;

/// Key image account - proves a key image has been spent
#[account]
pub struct KeyImageAccount {
    /// The key image (32 bytes)
    pub key_image: [u8; 32],
    /// Slot when this key image was spent
    pub spent_at_slot: u64,
    /// Amount that was withdrawn
    pub amount: u64,
}

impl KeyImageAccount {
    pub const LEN: usize = 32 + 8 + 8; // key_image + spent_at_slot + amount
}
