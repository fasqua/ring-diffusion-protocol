import { PublicKey, Connection } from "@solana/web3.js";

const PROGRAM_ID = new PublicKey("DHQtM2vuNrcD9UC42kfq1MNo9yucjPuReBHrsQvrpxjn");
const connection = new Connection("https://api.devnet.solana.com", "confirmed");

async function main() {
  const [poolConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_config")],
    PROGRAM_ID
  );

  const [poolState] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_state")],
    PROGRAM_ID
  );

  const [commitmentTree] = PublicKey.findProgramAddressSync(
    [Buffer.from("commitment_tree")],
    PROGRAM_ID
  );

  const [poolVault] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_vault")],
    PROGRAM_ID
  );

  console.log("=== PDAs for Program ===");
  console.log("Program ID:", PROGRAM_ID.toBase58());
  console.log("");
  console.log("PoolConfig:", poolConfig.toBase58());
  console.log("PoolState:", poolState.toBase58());
  console.log("CommitmentTree:", commitmentTree.toBase58());
  console.log("PoolVault:", poolVault.toBase58());
  
  console.log("");
  console.log("=== Checking if accounts exist ===");
  
  const poolConfigInfo = await connection.getAccountInfo(poolConfig);
  console.log("PoolConfig exists:", poolConfigInfo !== null);
  
  const poolStateInfo = await connection.getAccountInfo(poolState);
  console.log("PoolState exists:", poolStateInfo !== null);
  
  const poolVaultInfo = await connection.getAccountInfo(poolVault);
  console.log("PoolVault exists:", poolVaultInfo !== null);
  
  if (poolConfigInfo === null) {
    console.log("");
    console.log(">>> Pool NOT initialized. Need to call initialize_pool()");
  } else {
    console.log("");
    console.log(">>> Pool already initialized!");
  }
}

main().catch(console.error);
