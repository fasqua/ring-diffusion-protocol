import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram, Keypair, Connection, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { RingDiffusionProtocol } from "../target/types/ring_diffusion_protocol";
import * as fs from "fs";
import * as crypto from "crypto";

async function main() {
  // Setup connection
  const connection = new Connection("https://api.devnet.solana.com", "confirmed");
  
  // Load wallet
  const walletPath = "./rdp-wallet.json";
  const walletKeypair = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(walletPath, "utf-8")))
  );
  
  console.log("╔══════════════════════════════════════════════════════╗");
  console.log("║              TEST DEPOSIT                             ║");
  console.log("╚══════════════════════════════════════════════════════╝\n");
  
  console.log("Wallet:", walletKeypair.publicKey.toBase58());
  
  const balance = await connection.getBalance(walletKeypair.publicKey);
  console.log("Balance:", balance / LAMPORTS_PER_SOL, "SOL");

  // Setup provider
  const wallet = new anchor.Wallet(walletKeypair);
  const provider = new anchor.AnchorProvider(connection, wallet, { commitment: "confirmed" });
  anchor.setProvider(provider);

  // Load program
  const programId = new PublicKey("DHQtM2vuNrcD9UC42kfq1MNo9yucjPuReBHrsQvrpxjn");
  const idl = JSON.parse(fs.readFileSync("./target/idl/ring_diffusion_protocol.json", "utf-8"));
  const program = new Program(idl, provider) as Program<RingDiffusionProtocol>;

  // Derive PDAs
  const [poolConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_config")], programId
  );
  const [poolState] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_state")], programId
  );
  const [commitmentTree] = PublicKey.findProgramAddressSync(
    [Buffer.from("commitment_tree")], programId
  );
  const [poolVault] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_vault")], programId
  );

  // Get current chunk count to create new chunk
  const state = await program.account.poolState.fetch(poolState);
  const currentChunkCount = state.chunkCount.toNumber();
  
  // Derive new chunk PDA
  const chunkIndexBuffer = Buffer.alloc(8);
  chunkIndexBuffer.writeBigUInt64LE(BigInt(currentChunkCount));
  const [newChunkPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("commitment_chunk"), chunkIndexBuffer],
    programId
  );

  console.log("\n=== Deposit Details ===");
  console.log("Current chunk count:", currentChunkCount);
  console.log("New chunk PDA:", newChunkPda.toBase58());

  // Load commitment from test data
  const testData = JSON.parse(fs.readFileSync("tests/e2e-test-data.json", "utf8"));
  const commitment = Buffer.from(testData.deposit.commitment_bytes);
  console.log("Commitment:", commitment.toString('hex').slice(0, 32) + "...");

  // Use amount from test data
  const depositAmount = new anchor.BN(testData.deposit.amount);
  console.log("Amount:", depositAmount.toNumber() / LAMPORTS_PER_SOL, "SOL");

  console.log("\nDepositing...");

  try {
    const tx = await program.methods
      .depositWithNewChunk(Array.from(commitment), depositAmount)
      .accountsStrict({
        depositor: walletKeypair.publicKey,
        poolConfig: poolConfig,
        poolState: poolState,
        commitmentTree: commitmentTree,
        commitmentChunk: newChunkPda,
        poolVault: poolVault,
        systemProgram: SystemProgram.programId,
      })
      .signers([walletKeypair])
      .rpc();

    console.log("\n✅ Deposit successful!");
    console.log("Transaction:", tx);
    console.log("\nView on explorer:");
    console.log(`https://explorer.solana.com/tx/${tx}?cluster=devnet`);

    // Verify deposit
    const newState = await program.account.poolState.fetch(poolState);
    console.log("\n=== Updated Pool State ===");
    console.log("Total Deposits:", newState.totalDeposits.toNumber() / LAMPORTS_PER_SOL, "SOL");
    console.log("Commitment Count:", newState.commitmentCount.toNumber());
    console.log("Chunk Count:", newState.chunkCount.toNumber());

    // Save commitment data for later withdrawal test
    const depositData = {
      commitment: commitment.toString('hex'),
      amount: depositAmount.toNumber(),
      chunkIndex: currentChunkCount,
      timestamp: Date.now(),
    };
    fs.writeFileSync("tests/last_deposit.json", JSON.stringify(depositData, null, 2));
    console.log("\n📁 Deposit data saved to tests/last_deposit.json");

  } catch (error) {
    console.error("\n❌ Deposit failed:", error);
    throw error;
  }
}

main().catch(console.error);
