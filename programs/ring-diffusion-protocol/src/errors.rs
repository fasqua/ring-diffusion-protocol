use anchor_lang::prelude::*;

#[error_code]
pub enum RdpError {
    #[msg("Unauthorized access")]
    Unauthorized,

    #[msg("Pool is paused")]
    PoolPaused,

    #[msg("Deposits are disabled")]
    DepositDisabled,

    #[msg("Deposits are disabled")]
    DepositsDisabled,

    #[msg("Withdrawals are disabled")]
    WithdrawDisabled,

    #[msg("Pool already initialized")]
    PoolAlreadyInitialized,

    #[msg("Amount too small")]
    AmountTooSmall,

    #[msg("Deposit below minimum")]
    DepositBelowMinimum,

    #[msg("Amount too large")]
    AmountTooLarge,

    #[msg("Insufficient pool balance")]
    InsufficientPoolBalance,

    #[msg("Math overflow")]
    MathOverflow,

    #[msg("Invalid commitment")]
    InvalidCommitment,

    #[msg("Commitment already exists")]
    CommitmentExists,

    #[msg("Commitment chunk full")]
    ChunkFull,

    #[msg("Commitment chunk full")]
    CommitmentChunkFull,

    #[msg("Invalid chunk index")]
    InvalidChunkIndex,

    #[msg("Ring size too small")]
    RingSizeTooSmall,

    #[msg("Ring size too large")]
    RingSizeTooLarge,

    #[msg("Ring size below minimum")]
    RingSizeBelowMinimum,

    #[msg("Ring size above maximum")]
    RingSizeAboveMaximum,

    #[msg("Invalid ring size")]
    InvalidRingSize,

    #[msg("Invalid ring signature")]
    InvalidSignature,

    #[msg("Key image already spent")]
    KeyImageSpent,

    #[msg("Invalid key image")]
    InvalidKeyImage,

    #[msg("Invalid fee basis points")]
    InvalidFeeBasisPoints,

    #[msg("Invalid fee configuration")]
    InvalidFeeConfig,

    #[msg("Invalid ring size configuration")]
    InvalidRingSizeConfig,

    #[msg("Invalid merkle proof")]
    InvalidMerkleProof,

    #[msg("Merkle tree full")]
    MerkleTreeFull,

    #[msg("Invalid range proof")]
    InvalidRangeProof,

    #[msg("Withdraw request has expired")]
    WithdrawRequestExpired,

    #[msg("Invalid destination address")]
    InvalidDestination,

    #[msg("Proof already submitted")]
    ProofAlreadySubmitted,

    #[msg("Proof not yet submitted")]
    ProofNotSubmitted,
}
