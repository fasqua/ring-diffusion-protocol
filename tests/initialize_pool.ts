import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram, Keypair, Connection } from "@solana/web3.js";
import { RingDiffusionProtocol } from "../target/types/ring_diffusion_protocol";
import * as fs from "fs";

async function main() {
  // Setup connection
  const connection = new Connection("https://api.devnet.solana.com", "confirmed");
  
  // Load wallet
  const walletPath = "./rdp-wallet.json";
  const walletKeypair = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(walletPath, "utf-8")))
  );
  
  console.log("=== Initialize Pool ===");
  console.log("Wallet:", walletKeypair.publicKey.toBase58());
  
  // Check balance
  const balance = await connection.getBalance(walletKeypair.publicKey);
  console.log("Balance:", balance / 1e9, "SOL");
  
  if (balance < 0.1 * 1e9) {
    console.error("Insufficient balance!");
    return;
  }

  // Setup Anchor provider
  const wallet = new anchor.Wallet(walletKeypair);
  const provider = new anchor.AnchorProvider(connection, wallet, {
    commitment: "confirmed",
  });
  anchor.setProvider(provider);

  // Load program
  const programId = new PublicKey("DHQtM2vuNrcD9UC42kfq1MNo9yucjPuReBHrsQvrpxjn");
  
  // Load IDL
  const idlPath = "./target/idl/ring_diffusion_protocol.json";
  const idl = JSON.parse(fs.readFileSync(idlPath, "utf-8"));
  const program = new Program(idl, provider) as Program<RingDiffusionProtocol>;

  // Derive PDAs
  const [poolConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_config")],
    programId
  );
  const [poolState] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_state")],
    programId
  );
  const [commitmentTree] = PublicKey.findProgramAddressSync(
    [Buffer.from("commitment_tree")],
    programId
  );
  const [poolVault] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_vault")],
    programId
  );

  // Fee collector - using authority wallet for now (fees go to authority)
  const feeCollector = walletKeypair.publicKey;

  console.log("");
  console.log("PDAs:");
  console.log("  PoolConfig:", poolConfig.toBase58());
  console.log("  PoolState:", poolState.toBase58());
  console.log("  CommitmentTree:", commitmentTree.toBase58());
  console.log("  PoolVault:", poolVault.toBase58());
  console.log("  FeeCollector:", feeCollector.toBase58());

  // Check if already initialized
  const poolConfigInfo = await connection.getAccountInfo(poolConfig);
  if (poolConfigInfo !== null) {
    console.log("\n>>> Pool already initialized!");
    return;
  }

  // Initialize parameters
  const params = {
    feeBasisPoints: 50,    // 0.5% fee
    minRingSize: 16,       // Minimum as per constants
    maxRingSize: 64,       // Reasonable max
  };

  console.log("");
  console.log("Parameters:");
  console.log("  Fee:", params.feeBasisPoints / 100, "%");
  console.log("  Min Ring Size:", params.minRingSize);
  console.log("  Max Ring Size:", params.maxRingSize);

  console.log("");
  console.log("Initializing pool...");

  try {
    const tx = await program.methods
      .initializePool(params)
      .accountsStrict({
        authority: walletKeypair.publicKey,
        poolConfig: poolConfig,
        poolState: poolState,
        commitmentTree: commitmentTree,
        poolVault: poolVault,
        feeCollector: feeCollector,
        systemProgram: SystemProgram.programId,
      })
      .signers([walletKeypair])
      .rpc();

    console.log("");
    console.log("✅ Pool initialized successfully!");
    console.log("Transaction:", tx);
    console.log("");
    console.log("View on Solana Explorer:");
    console.log(`https://explorer.solana.com/tx/${tx}?cluster=devnet`);
    
  } catch (error) {
    console.error("❌ Error initializing pool:", error);
    throw error;
  }
}

main().catch(console.error);
