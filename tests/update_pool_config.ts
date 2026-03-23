import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import { RingDiffusionProtocol } from "../target/types/ring_diffusion_protocol";

async function main() {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);
    const program = anchor.workspace.RingDiffusionProtocol as Program<RingDiffusionProtocol>;
    const wallet = provider.wallet as anchor.Wallet;

    const [poolConfig] = PublicKey.findProgramAddressSync(
        [Buffer.from("pool_config")],
        program.programId
    );

    console.log("Updating pool config...");
    console.log("Pool Config PDA:", poolConfig.toBase58());
    console.log("Authority:", wallet.publicKey.toBase58());

    try {
        const tx = await program.methods
            .updatePoolConfig({
                feeBasisPoints: null,
                minRingSize: 4,
                maxRingSize: null,
                depositEnabled: null,
                withdrawEnabled: null,
                paused: null,
            })
            .accounts({
                authority: wallet.publicKey,
                poolConfig: poolConfig,
            })
            .rpc();

        console.log("✅ Updated! Tx:", tx);

        // Verify
        const config = await program.account.poolConfig.fetch(poolConfig);
        console.log("\nNew Pool Config:");
        console.log("  Min Ring Size:", config.minRingSize);
        console.log("  Max Ring Size:", config.maxRingSize);
        console.log("  Fee:", config.feeBasisPoints, "bps");
    } catch (e) {
        console.error("❌ Error:", e);
    }
}

main().catch(console.error);
