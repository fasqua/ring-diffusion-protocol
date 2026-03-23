// ============================================================================
// Bulletproof Storage - Split into 4 parts to avoid stack overflow
// ============================================================================

use anchor_lang::prelude::*;

pub const IP_ROUNDS: usize = 6;

/// Part 1: V, A, S commitments (137 bytes)
#[account]
pub struct BulletproofPart1 {
    pub nonce: u64,
    pub owner: Pubkey,
    pub v_commitment: [u8; 32],
    pub a: [u8; 32],
    pub s: [u8; 32],
    pub bump: u8,
}

impl BulletproofPart1 {
    pub const LEN: usize = 8 + 32 + 32 + 32 + 32 + 1;
}

/// Part 2: T1, T2, tau_x, mu, t_hat (201 bytes)
#[account]
pub struct BulletproofPart2 {
    pub nonce: u64,
    pub owner: Pubkey,
    pub t1: [u8; 32],
    pub t2: [u8; 32],
    pub tau_x: [u8; 32],
    pub mu: [u8; 32],
    pub t_hat: [u8; 32],
    pub bump: u8,
}

impl BulletproofPart2 {
    pub const LEN: usize = 8 + 32 + 32 + 32 + 32 + 32 + 32 + 1;
}

/// Part 3: ip_l array (232 bytes)
#[account]
pub struct BulletproofPart3 {
    pub nonce: u64,
    pub owner: Pubkey,
    pub ip_l: [[u8; 32]; IP_ROUNDS],
    pub bump: u8,
}

impl BulletproofPart3 {
    pub const LEN: usize = 8 + 32 + (32 * IP_ROUNDS) + 1;
}

/// Part 4: ip_r, ip_a, ip_b (296 bytes)
#[account]
pub struct BulletproofPart4 {
    pub nonce: u64,
    pub owner: Pubkey,
    pub ip_r: [[u8; 32]; IP_ROUNDS],
    pub ip_a: [u8; 32],
    pub ip_b: [u8; 32],
    pub bump: u8,
}

impl BulletproofPart4 {
    pub const LEN: usize = 8 + 32 + (32 * IP_ROUNDS) + 32 + 32 + 1;
}
