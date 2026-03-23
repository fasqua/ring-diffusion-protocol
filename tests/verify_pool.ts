import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Connection } from "@solana/web3.js";
import { RingDiffusionProtocol } from "../target/types/ring_diffusion_protocol";
import * as fs from "fs";

async function main() {
  const connection = new Connection("https://api.devnet.solana.com", "confirmed");
  
  const programId = new PublicKey("DHQtM2vuNrcD9UC42kfq1MNo9yucjPuReBHrsQvrpxjn");
  
  // Setup minimal provider for reading
  const provider = new anchor.AnchorProvider(connection, {} as any, {});
  
  const idlPath = "./target/idl/ring_diffusion_protocol.json";
  const idl = JSON.parse(fs.readFileSync(idlPath, "utf-8"));
  const program = new Program(idl, provider) as Program<RingDiffusionProtocol>;

  // Derive PDAs
  const [poolConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_config")], programId
  );
  const [poolState] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_state")], programId
  );
  const [poolVault] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_vault")], programId
  );

  console.log("╔══════════════════════════════════════════════════════╗");
  console.log("║           POOL VERIFICATION                          ║");
  console.log("╚══════════════════════════════════════════════════════╝\n");

  // Fetch PoolConfig
  const config = await program.account.poolConfig.fetch(poolConfig);
  console.log("=== PoolConfig ===");
  console.log("  Authority:", config.authority.toBase58());
  console.log("  Fee:", config.feeBasisPoints / 100, "%");
  console.log("  Min Ring Size:", config.minRingSize);
  console.log("  Max Ring Size:", config.maxRingSize);
  console.log("  Deposit Enabled:", config.depositEnabled);
  console.log("  Withdraw Enabled:", config.withdrawEnabled);
  console.log("  Paused:", config.paused);

  // Fetch PoolState
  const state = await program.account.poolState.fetch(poolState);
  console.log("\n=== PoolState ===");
  console.log("  Total Deposits:", state.totalDeposits.toNumber() / 1e9, "SOL");
  console.log("  Total Withdrawals:", state.totalWithdrawals.toNumber() / 1e9, "SOL");
  console.log("  Total Fees:", state.totalFeesCollected.toNumber() / 1e9, "SOL");
  console.log("  Commitment Count:", state.commitmentCount.toNumber());
  console.log("  Chunk Count:", state.chunkCount.toNumber());

  // Check vault balance
  const vaultBalance = await connection.getBalance(poolVault);
  console.log("\n=== Pool Vault ===");
  console.log("  Address:", poolVault.toBase58());
  console.log("  Balance:", vaultBalance / 1e9, "SOL");

  console.log("\n✅ Pool is ready for deposits!");
}

main().catch(console.error);
