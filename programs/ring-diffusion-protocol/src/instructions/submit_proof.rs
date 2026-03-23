use anchor_lang::prelude::*;
use crate::errors::RdpError;
use crate::state::{WithdrawRequest, BulletproofPart1};
use crate::instructions::prepare_withdraw::WITHDRAW_REQUEST_SEED;

pub const BULLETPROOF_PART1_SEED: &[u8] = b"bp1";

#[derive(Accounts)]
#[instruction(nonce: u64)]
pub struct SubmitProofPart1<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [WITHDRAW_REQUEST_SEED, owner.key().as_ref(), &nonce.to_le_bytes()],
        bump = withdraw_request.bump,
        constraint = withdraw_request.owner == owner.key() @ RdpError::Unauthorized,
        constraint = withdraw_request.status == 0 @ RdpError::ProofAlreadySubmitted,
    )]
    pub withdraw_request: Account<'info, WithdrawRequest>,

    #[account(
        init,
        payer = owner,
        space = 8 + BulletproofPart1::LEN,
        seeds = [BULLETPROOF_PART1_SEED, owner.key().as_ref(), &nonce.to_le_bytes()],
        bump,
    )]
    pub bulletproof_part1: Account<'info, BulletproofPart1>,

    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SubmitProofPart1Params {
    pub v_commitment: [u8; 32],
    pub a: [u8; 32],
    pub s: [u8; 32],
}

pub fn handler_submit_proof_part1(
    ctx: Context<SubmitProofPart1>,
    nonce: u64,
    params: SubmitProofPart1Params,
) -> Result<()> {
    let wr = &mut ctx.accounts.withdraw_request;
    let bp = &mut ctx.accounts.bulletproof_part1;

    require!(!wr.is_expired(Clock::get()?.unix_timestamp), RdpError::WithdrawRequestExpired);

    bp.nonce = nonce;
    bp.owner = ctx.accounts.owner.key();
    bp.v_commitment = params.v_commitment;
    bp.a = params.a;
    bp.s = params.s;
    bp.bump = ctx.bumps.bulletproof_part1;

    wr.status = 1;
    msg!("Part1 stored");
    Ok(())
}
