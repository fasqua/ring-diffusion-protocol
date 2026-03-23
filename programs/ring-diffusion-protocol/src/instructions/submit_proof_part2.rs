use anchor_lang::prelude::*;
use crate::errors::RdpError;
use crate::state::{WithdrawRequest, BulletproofPart2};
use crate::instructions::prepare_withdraw::WITHDRAW_REQUEST_SEED;

pub const BULLETPROOF_PART2_SEED: &[u8] = b"bp2";

#[derive(Accounts)]
#[instruction(nonce: u64)]
pub struct SubmitProofPart2<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [WITHDRAW_REQUEST_SEED, owner.key().as_ref(), &nonce.to_le_bytes()],
        bump = withdraw_request.bump,
        constraint = withdraw_request.owner == owner.key() @ RdpError::Unauthorized,
        constraint = withdraw_request.status == 1 @ RdpError::ProofNotSubmitted,
    )]
    pub withdraw_request: Account<'info, WithdrawRequest>,

    #[account(
        init,
        payer = owner,
        space = 8 + BulletproofPart2::LEN,
        seeds = [BULLETPROOF_PART2_SEED, owner.key().as_ref(), &nonce.to_le_bytes()],
        bump,
    )]
    pub bulletproof_part2: Account<'info, BulletproofPart2>,

    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SubmitProofPart2Params {
    pub t1: [u8; 32],
    pub t2: [u8; 32],
    pub tau_x: [u8; 32],
    pub mu: [u8; 32],
    pub t_hat: [u8; 32],
}

pub fn handler_submit_proof_part2(
    ctx: Context<SubmitProofPart2>,
    nonce: u64,
    params: SubmitProofPart2Params,
) -> Result<()> {
    let wr = &mut ctx.accounts.withdraw_request;
    let bp = &mut ctx.accounts.bulletproof_part2;

    require!(!wr.is_expired(Clock::get()?.unix_timestamp), RdpError::WithdrawRequestExpired);

    bp.nonce = nonce;
    bp.owner = ctx.accounts.owner.key();
    bp.t1 = params.t1;
    bp.t2 = params.t2;
    bp.tau_x = params.tau_x;
    bp.mu = params.mu;
    bp.t_hat = params.t_hat;
    bp.bump = ctx.bumps.bulletproof_part2;

    wr.status = 2;
    msg!("Part2 stored");
    Ok(())
}
