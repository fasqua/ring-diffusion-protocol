use anchor_lang::prelude::*;
use crate::errors::RdpError;
use crate::state::{WithdrawRequest, BulletproofPart3, IP_ROUNDS};
use crate::instructions::prepare_withdraw::WITHDRAW_REQUEST_SEED;

pub const BULLETPROOF_PART3_SEED: &[u8] = b"bp3";

#[derive(Accounts)]
#[instruction(nonce: u64)]
pub struct SubmitProofPart3<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [WITHDRAW_REQUEST_SEED, owner.key().as_ref(), &nonce.to_le_bytes()],
        bump = withdraw_request.bump,
        constraint = withdraw_request.owner == owner.key() @ RdpError::Unauthorized,
        constraint = withdraw_request.status == 2 @ RdpError::ProofNotSubmitted,
    )]
    pub withdraw_request: Account<'info, WithdrawRequest>,

    #[account(
        init,
        payer = owner,
        space = 8 + BulletproofPart3::LEN,
        seeds = [BULLETPROOF_PART3_SEED, owner.key().as_ref(), &nonce.to_le_bytes()],
        bump,
    )]
    pub bulletproof_part3: Account<'info, BulletproofPart3>,

    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SubmitProofPart3Params {
    pub ip_l: [[u8; 32]; IP_ROUNDS],
}

pub fn handler_submit_proof_part3(
    ctx: Context<SubmitProofPart3>,
    nonce: u64,
    params: SubmitProofPart3Params,
) -> Result<()> {
    let wr = &mut ctx.accounts.withdraw_request;
    let bp = &mut ctx.accounts.bulletproof_part3;

    require!(!wr.is_expired(Clock::get()?.unix_timestamp), RdpError::WithdrawRequestExpired);

    bp.nonce = nonce;
    bp.owner = ctx.accounts.owner.key();
    bp.ip_l = params.ip_l;
    bp.bump = ctx.bumps.bulletproof_part3;

    wr.status = 3;
    msg!("Part3 stored");
    Ok(())
}
