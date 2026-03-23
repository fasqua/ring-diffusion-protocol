import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram, ComputeBudgetProgram } from "@solana/web3.js";
import { RingDiffusionProtocol } from "../target/types/ring_diffusion_protocol";
import * as fs from "fs";

const WITHDRAW_REQUEST_SEED = Buffer.from("withdraw_request");
const BP1_SEED = Buffer.from("bp1");
const BP2_SEED = Buffer.from("bp2");
const BP3_SEED = Buffer.from("bp3");
const BP4_SEED = Buffer.from("bp4");
const KEY_IMAGE_SEED = Buffer.from("key_image");
const POOL_CONFIG_SEED = Buffer.from("pool_config");
const POOL_STATE_SEED = Buffer.from("pool_state");
const POOL_VAULT_SEED = Buffer.from("pool_vault");

async function main() {
    console.log("╔══════════════════════════════════════════════════════════════╗");
    console.log("║     E2E TEST: SIX-PHASE WITHDRAW WITH BULLETPROOF            ║");
    console.log("╚══════════════════════════════════════════════════════════════╝");

    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);
    const program = anchor.workspace.RingDiffusionProtocol as Program<RingDiffusionProtocol>;
    const wallet = provider.wallet as anchor.Wallet;

    console.log(`Wallet: ${wallet.publicKey.toBase58()}`);
    const balance = await provider.connection.getBalance(wallet.publicKey);
    console.log(`Balance: ${balance / 1e9} SOL`);

    // Load test data
    console.log("\n=== Loading Test Data ===");
    const testData = JSON.parse(fs.readFileSync("tests/e2e-test-data.json", "utf8"));
    console.log(`Amount: ${testData.deposit.amount / 1e9} SOL`);
    console.log(`Ring size: ${testData.withdraw.ring_pubkeys.length}`);
    // Stealth address info
    const stealthDestination = new PublicKey(Buffer.from(testData.withdraw.destination_bytes));
    console.log(`Stealth destination: ${stealthDestination.toBase58().slice(0,20)}...`);
    if (testData.stealth) {
        console.log(`Ephemeral pubkey (R): ${testData.stealth.ephemeral_pubkey.slice(0,16)}...`);
    }

    // PDAs
    const [poolConfig] = PublicKey.findProgramAddressSync([POOL_CONFIG_SEED], program.programId);
    const [poolState] = PublicKey.findProgramAddressSync([POOL_STATE_SEED], program.programId);
    const [poolVault] = PublicKey.findProgramAddressSync([POOL_VAULT_SEED], program.programId);

    const vaultBalance = await provider.connection.getBalance(poolVault);
    console.log(`Pool Vault Balance: ${vaultBalance / 1e9} SOL`);

    if (vaultBalance < testData.deposit.amount) {
        console.log("❌ Vault balance too low");
        return;
    }

    // Nonce
    const nonce = new anchor.BN(Date.now());
    const nonceBuffer = nonce.toArrayLike(Buffer, "le", 8);

    // PDAs
    const [withdrawRequest] = PublicKey.findProgramAddressSync(
        [WITHDRAW_REQUEST_SEED, wallet.publicKey.toBuffer(), nonceBuffer], program.programId
    );
    const [bp1Pda] = PublicKey.findProgramAddressSync(
        [BP1_SEED, wallet.publicKey.toBuffer(), nonceBuffer], program.programId
    );
    const [bp2Pda] = PublicKey.findProgramAddressSync(
        [BP2_SEED, wallet.publicKey.toBuffer(), nonceBuffer], program.programId
    );
    const [bp3Pda] = PublicKey.findProgramAddressSync(
        [BP3_SEED, wallet.publicKey.toBuffer(), nonceBuffer], program.programId
    );
    const [bp4Pda] = PublicKey.findProgramAddressSync(
        [BP4_SEED, wallet.publicKey.toBuffer(), nonceBuffer], program.programId
    );
    const keyImageBytes: number[] = testData.withdraw.key_image_bytes;
    const [keyImagePda] = PublicKey.findProgramAddressSync(
        [KEY_IMAGE_SEED, Buffer.from(keyImageBytes)], program.programId
    );

    console.log(`\nNonce: ${nonce.toString()}`);

    // Phase 1-5 same as before...
    console.log("\n=== Phase 1: prepare_withdraw ===");
    try {
        const ringPubkeys: number[][] = testData.withdraw.ring_pubkeys_bytes;
        const tx1 = await program.methods
            .prepareWithdraw(nonce, {
                nonce: nonce,
                destination: new PublicKey(Buffer.from(testData.withdraw.destination_bytes)),
                amount: new anchor.BN(testData.deposit.amount),
                ringPubkeys: ringPubkeys,
            })
            .accountsStrict({
                owner: wallet.publicKey,
                poolConfig: poolConfig,
                withdrawRequest: withdrawRequest,
                systemProgram: SystemProgram.programId,
            })
            .rpc();
        console.log(`✅ Phase 1: ${tx1.slice(0,20)}...`);
    } catch (e: any) {
        console.log(`❌ Phase 1: ${e.message}`);
        return;
    }

    console.log("\n=== Phase 2: submit_proof_part1 ===");
    try {
        const bp = testData.withdraw.bulletproof;
        const tx2 = await program.methods
            .submitProofPart1(nonce, {
                vCommitment: bp.v_commitment as number[],
                a: bp.a as number[],
                s: bp.s as number[],
            })
            .accountsStrict({
                owner: wallet.publicKey,
                withdrawRequest: withdrawRequest,
                bulletproofPart1: bp1Pda,
                systemProgram: SystemProgram.programId,
            })
            .rpc();
        console.log(`✅ Phase 2: ${tx2.slice(0,20)}...`);
    } catch (e: any) {
        console.log(`❌ Phase 2: ${e.message}`);
        return;
    }

    console.log("\n=== Phase 3: submit_proof_part2 ===");
    try {
        const bp = testData.withdraw.bulletproof;
        const tx3 = await program.methods
            .submitProofPart2(nonce, {
                t1: bp.t1 as number[],
                t2: bp.t2 as number[],
                tauX: bp.tau_x as number[],
                mu: bp.mu as number[],
                tHat: bp.t_hat as number[],
            })
            .accountsStrict({
                owner: wallet.publicKey,
                withdrawRequest: withdrawRequest,
                bulletproofPart2: bp2Pda,
                systemProgram: SystemProgram.programId,
            })
            .rpc();
        console.log(`✅ Phase 3: ${tx3.slice(0,20)}...`);
    } catch (e: any) {
        console.log(`❌ Phase 3: ${e.message}`);
        return;
    }

    console.log("\n=== Phase 4: submit_proof_part3 ===");
    try {
        const bp = testData.withdraw.bulletproof;
        const tx4 = await program.methods
            .submitProofPart3(nonce, {
                ipL: bp.ip_l as number[][],
            })
            .accountsStrict({
                owner: wallet.publicKey,
                withdrawRequest: withdrawRequest,
                bulletproofPart3: bp3Pda,
                systemProgram: SystemProgram.programId,
            })
            .rpc();
        console.log(`✅ Phase 4: ${tx4.slice(0,20)}...`);
    } catch (e: any) {
        console.log(`❌ Phase 4: ${e.message}`);
        return;
    }

    console.log("\n=== Phase 5: submit_proof_part4 ===");
    try {
        const bp = testData.withdraw.bulletproof;
        const tx5 = await program.methods
            .submitProofPart4(nonce, {
                ipR: bp.ip_r as number[][],
                ipA: bp.ip_a as number[],
                ipB: bp.ip_b as number[],
            })
            .accountsStrict({
                owner: wallet.publicKey,
                withdrawRequest: withdrawRequest,
                bulletproofPart4: bp4Pda,
                systemProgram: SystemProgram.programId,
            })
            .rpc();
        console.log(`✅ Phase 5: ${tx5.slice(0,20)}...`);
    } catch (e: any) {
        console.log(`❌ Phase 5: ${e.message}`);
        return;
    }

    // Phase 6 with increased compute budget
    console.log("\n=== Phase 6: execute_withdraw (with 1.4M CU) ===");
    try {
        const sigResponses: number[][] = testData.withdraw.signature_responses_bytes;
        
        // Add compute budget instruction
        const computeIx = ComputeBudgetProgram.setComputeUnitLimit({
            units: 1_400_000
        });

        const tx6 = await program.methods
            .executeWithdraw(keyImageBytes, {
                signatureC: testData.withdraw.signature_c_bytes as number[],
                signatureResponses: sigResponses,
            })
            .accountsStrict({
                withdrawer: wallet.publicKey,
                poolConfig: poolConfig,
                poolState: poolState,
                poolVault: poolVault,
                withdrawRequest: withdrawRequest,
                bp1: bp1Pda,
                bp2: bp2Pda,
                bp3: bp3Pda,
                bp4: bp4Pda,
                keyImageAccount: keyImagePda,
                destination: new PublicKey(Buffer.from(testData.withdraw.destination_bytes)),
                systemProgram: SystemProgram.programId,
            })
            .preInstructions([computeIx])
            .rpc();

        console.log(`✅ Phase 6: ${tx6.slice(0,20)}...`);
        console.log("\n🎉 FULL E2E WITHDRAW SUCCESSFUL!");

        const finalBalance = await provider.connection.getBalance(wallet.publicKey);
        console.log(`Final balance: ${finalBalance / 1e9} SOL`);

    } catch (e: any) {
        console.log(`❌ Phase 6 failed: ${e.message}`);
        if (e.logs) {
            console.log("\nLogs:");
            e.logs.slice(-30).forEach((l: string) => console.log(`  ${l}`));
        }
    }
}

main().catch(console.error);
