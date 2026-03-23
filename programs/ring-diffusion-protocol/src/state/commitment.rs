// ============================================================================
// RING DIFFUSION PROTOCOL - COMMITMENT STATE
// ============================================================================

use anchor_lang::prelude::*;
use crate::constants::COMMITMENTS_PER_CHUNK;

/// Single commitment data stored within a chunk
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, Debug, PartialEq)]
pub struct CommitmentData {
    /// The commitment hash (32 bytes)
    pub commitment: [u8; 32],
    
    /// Timestamp when commitment was added
    pub timestamp: i64,
}

impl CommitmentData {
    pub const LEN: usize = 32 + 8; // 40 bytes
}

/// Chunk containing multiple commitments (16 per chunk)
/// More cost-efficient than 1 account per commitment
#[account]
pub struct CommitmentChunk {
    /// Chunk index (0, 1, 2, ...)
    pub chunk_index: u64,
    
    /// Number of commitments in this chunk (0-16)
    pub count: u8,
    
    /// Bump seed for PDA
    pub bump: u8,
    
    /// Array of commitments in this chunk
    pub commitments: [CommitmentData; COMMITMENTS_PER_CHUNK],
}

impl CommitmentChunk {
    /// Account size in bytes
    /// 8 (discriminator) + 8 + 1 + 1 + (40 * 16) = 658 bytes
    pub const LEN: usize = 8 + 8 + 1 + 1 + (CommitmentData::LEN * COMMITMENTS_PER_CHUNK);
    
    /// Check if chunk is full
    pub fn is_full(&self) -> bool {
        self.count as usize >= COMMITMENTS_PER_CHUNK
    }
    
    /// Add commitment to chunk, returns the local index within chunk
    pub fn add_commitment(&mut self, commitment: [u8; 32], timestamp: i64) -> Result<u8> {
        require!(!self.is_full(), crate::errors::RdpError::CommitmentChunkFull);
        
        let index = self.count;
        self.commitments[index as usize] = CommitmentData {
            commitment,
            timestamp,
        };
        self.count += 1;
        
        Ok(index)
    }
    
    /// Get commitment at index
    pub fn get_commitment(&self, index: u8) -> Option<&CommitmentData> {
        if index < self.count {
            Some(&self.commitments[index as usize])
        } else {
            None
        }
    }
    
    /// Calculate global commitment index
    pub fn global_index(&self, local_index: u8) -> u64 {
        self.chunk_index * COMMITMENTS_PER_CHUNK as u64 + local_index as u64
    }
}

impl Default for CommitmentChunk {
    fn default() -> Self {
        Self {
            chunk_index: 0,
            count: 0,
            bump: 0,
            commitments: [CommitmentData::default(); COMMITMENTS_PER_CHUNK],
        }
    }
}

/// Merkle tree root tracking
#[account]
#[derive(Default)]
pub struct CommitmentTree {
    /// Current merkle root
    pub root: [u8; 32],
    
    /// Next commitment index (global)
    pub next_index: u64,
    
    /// Tree depth (20 = supports 1M+ commitments)
    pub depth: u8,
    
    /// Bump seed for PDA
    pub bump: u8,
    
    /// Reserved for future upgrades
    pub _reserved: [u8; 32],
}

impl CommitmentTree {
    /// Account size in bytes
    /// 8 (discriminator) + 32 + 8 + 1 + 1 + 32 = 82 bytes
    pub const LEN: usize = 8 + 32 + 8 + 1 + 1 + 32;
    
    /// Calculate which chunk index a commitment belongs to
    pub fn chunk_index_for_commitment(commitment_index: u64) -> u64 {
        commitment_index / COMMITMENTS_PER_CHUNK as u64
    }
    
    /// Calculate local index within chunk
    pub fn local_index_for_commitment(commitment_index: u64) -> u8 {
        (commitment_index % COMMITMENTS_PER_CHUNK as u64) as u8
    }
}
