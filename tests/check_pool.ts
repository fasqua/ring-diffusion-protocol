import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import { RingDiffusionProtocol } from "../target/types/ring_diffusion_protocol";

async function main() {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);
    const program = anchor.workspace.RingDiffusionProtocol as Program<RingDiffusionProtocol>;
    
    const [poolConfig] = PublicKey.findProgramAddressSync(
        [Buffer.from("pool_config")], 
        program.programId
    );
    
    const config = await program.account.poolConfig.fetch(poolConfig);
    console.log("Pool Config:");
    console.log(`  Min Ring Size: ${config.minRingSize}`);
    console.log(`  Max Ring Size: ${config.maxRingSize}`);
    console.log(`  Fee: ${config.feeBasisPoints} bps`);
}

main();
