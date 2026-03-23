use anchor_lang::prelude::*;
use crate::errors::RdpError;
use crate::state::{WithdrawRequest, BulletproofPart4, IP_ROUNDS};
use crate::instructions::prepare_withdraw::WITHDRAW_REQUEST_SEED;

pub const BULLETPROOF_PART4_SEED: &[u8] = b"bp4";

#[derive(Accounts)]
#[instruction(nonce: u64)]
pub struct SubmitProofPart4<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [WITHDRAW_REQUEST_SEED, owner.key().as_ref(), &nonce.to_le_bytes()],
        bump = withdraw_request.bump,
        constraint = withdraw_request.owner == owner.key() @ RdpError::Unauthorized,
        constraint = withdraw_request.status == 3 @ RdpError::ProofNotSubmitted,
    )]
    pub withdraw_request: Account<'info, WithdrawRequest>,

    #[account(
        init,
        payer = owner,
        space = 8 + BulletproofPart4::LEN,
        seeds = [BULLETPROOF_PART4_SEED, owner.key().as_ref(), &nonce.to_le_bytes()],
        bump,
    )]
    pub bulletproof_part4: Account<'info, BulletproofPart4>,

    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SubmitProofPart4Params {
    pub ip_r: [[u8; 32]; IP_ROUNDS],
    pub ip_a: [u8; 32],
    pub ip_b: [u8; 32],
}

pub fn handler_submit_proof_part4(
    ctx: Context<SubmitProofPart4>,
    nonce: u64,
    params: SubmitProofPart4Params,
) -> Result<()> {
    let wr = &mut ctx.accounts.withdraw_request;
    let bp = &mut ctx.accounts.bulletproof_part4;

    require!(!wr.is_expired(Clock::get()?.unix_timestamp), RdpError::WithdrawRequestExpired);

    bp.nonce = nonce;
    bp.owner = ctx.accounts.owner.key();
    bp.ip_r = params.ip_r;
    bp.ip_a = params.ip_a;
    bp.ip_b = params.ip_b;
    bp.bump = ctx.bumps.bulletproof_part4;

    wr.status = 4; // Ready to execute
    wr.has_bulletproof = true;
    msg!("Part4 stored - ready to execute");
    Ok(())
}
