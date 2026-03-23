// ============================================================================
// RING DIFFUSION PROTOCOL - CONSTANTS
// ============================================================================

// Pool Configuration
pub const MIN_RING_SIZE: u8 = 4;
pub const MAX_RING_SIZE: u8 = 255;
pub const DEFAULT_FEE_BASIS_POINTS: u16 = 50; // 0.5%
pub const MAX_FEE_BASIS_POINTS: u16 = 500;    // 5% max

// Commitment Chunk Configuration
// Reduced from 64 to 16 to avoid stack overflow in Solana BPF
pub const COMMITMENTS_PER_CHUNK: usize = 16;

// Merkle Tree Configuration  
pub const MERKLE_TREE_DEPTH: u8 = 20; // Supports 2^20 = 1,048,576 commitments

// Minimum Amounts (in lamports)
pub const MIN_DEPOSIT_AMOUNT: u64 = 10_000_000;  // 0.01 SOL
pub const MIN_WITHDRAW_AMOUNT: u64 = 10_000_000; // 0.01 SOL

// PDA Seeds
pub const POOL_CONFIG_SEED: &[u8] = b"pool_config";
pub const POOL_STATE_SEED: &[u8] = b"pool_state";
pub const POOL_VAULT_SEED: &[u8] = b"pool_vault";
pub const COMMITMENT_CHUNK_SEED: &[u8] = b"commitment_chunk";
pub const COMMITMENT_TREE_SEED: &[u8] = b"commitment_tree";
pub const KEY_IMAGE_SEED: &[u8] = b"key_image";
pub const ASSET_POOL_SEED: &[u8] = b"asset_pool";
pub const FEE_COLLECTOR_SEED: &[u8] = b"fee_collector";
