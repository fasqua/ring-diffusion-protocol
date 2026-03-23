import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, ComputeBudgetProgram } from "@solana/web3.js";
import { RingDiffusionProtocol } from "../target/types/ring_diffusion_protocol";
import { createHash } from "crypto";

const COMMITMENT_TREE_SEED = Buffer.from("commitment_tree");
const COMMITMENT_CHUNK_SEED = Buffer.from("commitment_chunk");
const MERKLE_DEPTH = 20;

// Domain separation (must match on-chain)
const DOMAIN_MERKLE_LEAF = Buffer.from("RDP_MERKLE_LEAF_V1");
const DOMAIN_MERKLE_NODE = Buffer.from("RDP_MERKLE_NODE_V1");

// Hash functions matching on-chain
function hashLeaf(commitment: Buffer): Buffer {
    const hasher = createHash("sha256");
    hasher.update(DOMAIN_MERKLE_LEAF);
    hasher.update(commitment);
    return hasher.digest();
}

function hashNode(left: Buffer, right: Buffer): Buffer {
    const hasher = createHash("sha256");
    hasher.update(DOMAIN_MERKLE_NODE);
    hasher.update(left);
    hasher.update(right);
    return hasher.digest();
}

// Compute zero hashes for empty subtrees
function computeZeroHashes(): Buffer[] {
    const zeros: Buffer[] = [];
    zeros[0] = hashLeaf(Buffer.alloc(32, 0));
    
    for (let i = 1; i <= MERKLE_DEPTH; i++) {
        zeros[i] = hashNode(zeros[i - 1], zeros[i - 1]);
    }
    return zeros;
}

// Simple merkle tree class
class MerkleTree {
    leaves: Buffer[] = [];
    zeroHashes: Buffer[];
    
    constructor() {
        this.zeroHashes = computeZeroHashes();
    }
    
    insert(commitment: Buffer): number {
        const leafHash = hashLeaf(commitment);
        const index = this.leaves.length;
        this.leaves.push(leafHash);
        return index;
    }
    
    getRoot(): Buffer {
        if (this.leaves.length === 0) {
            return this.zeroHashes[MERKLE_DEPTH];
        }
        
        let levelHashes = [...this.leaves];
        
        for (let level = 0; level < MERKLE_DEPTH; level++) {
            // Pad to even with zero hash
            if (levelHashes.length % 2 === 1) {
                levelHashes.push(this.zeroHashes[level]);
            }
            
            const nextLevel: Buffer[] = [];
            for (let i = 0; i < levelHashes.length; i += 2) {
                nextLevel.push(hashNode(levelHashes[i], levelHashes[i + 1]));
            }
            levelHashes = nextLevel;
        }
        
        return levelHashes[0];
    }
    
    generateProof(index: number): Buffer[] {
        if (index >= this.leaves.length) {
            throw new Error("Index out of bounds");
        }
        
        const siblings: Buffer[] = [];
        let currentIndex = index;
        let levelHashes = [...this.leaves];
        
        for (let level = 0; level < MERKLE_DEPTH; level++) {
            // Pad level
            const levelSize = 1 << (MERKLE_DEPTH - level);
            while (levelHashes.length < levelSize) {
                levelHashes.push(this.zeroHashes[level]);
            }
            
            // Get sibling
            const siblingIndex = currentIndex % 2 === 0 ? currentIndex + 1 : currentIndex - 1;
            siblings.push(levelHashes[siblingIndex]);
            
            // Compute next level
            const nextLevel: Buffer[] = [];
            for (let i = 0; i < levelHashes.length; i += 2) {
                nextLevel.push(hashNode(levelHashes[i], levelHashes[i + 1]));
            }
            levelHashes = nextLevel;
            currentIndex = Math.floor(currentIndex / 2);
        }
        
        return siblings;
    }
}

async function main() {
    console.log("╔══════════════════════════════════════════════════════════════╗");
    console.log("║           TEST: UPDATE MERKLE ROOT                           ║");
    console.log("╚══════════════════════════════════════════════════════════════╝");

    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);
    const program = anchor.workspace.RingDiffusionProtocol as Program<RingDiffusionProtocol>;
    const wallet = provider.wallet as anchor.Wallet;

    // PDAs
    const [commitmentTree] = PublicKey.findProgramAddressSync(
        [COMMITMENT_TREE_SEED], program.programId
    );

    // 1. Fetch current commitment tree state
    console.log("\n=== Fetching Commitment Tree ===");
    const treeState = await program.account.commitmentTree.fetch(commitmentTree);
    console.log(`Current root: ${Buffer.from(treeState.root).toString("hex").slice(0,16)}...`);
    console.log(`Next index: ${treeState.nextIndex.toString()}`);
    console.log(`Depth: ${treeState.depth}`);

    const totalCommitments = treeState.nextIndex.toNumber();
    if (totalCommitments === 0) {
        console.log("No commitments yet. Nothing to update.");
        return;
    }

    // 2. Fetch all commitments from chunks
    console.log("\n=== Fetching Commitments from Chunks ===");
    const tree = new MerkleTree();
    const chunksNeeded = Math.ceil(totalCommitments / 16);
    
    for (let chunkIdx = 0; chunkIdx < chunksNeeded; chunkIdx++) {
        const [chunkPda] = PublicKey.findProgramAddressSync(
            [COMMITMENT_CHUNK_SEED, Buffer.from(new anchor.BN(chunkIdx).toArray("le", 8))],
            program.programId
        );
        
        try {
            const chunk = await program.account.commitmentChunk.fetch(chunkPda);
            console.log(`Chunk ${chunkIdx}: ${chunk.count} commitments`);
            
            for (let i = 0; i < chunk.count; i++) {
                const commitment = Buffer.from(chunk.commitments[i].commitment);
                tree.insert(commitment);
            }
        } catch (e) {
            console.log(`Chunk ${chunkIdx}: not found (skipping)`);
        }
    }

    console.log(`\nTotal commitments loaded: ${tree.leaves.length}`);

    // 3. Compute new root
    const computedRoot = tree.getRoot();
    console.log(`\nComputed root: ${computedRoot.toString("hex").slice(0,16)}...`);
    console.log(`Current root:  ${Buffer.from(treeState.root).toString("hex").slice(0,16)}...`);

    // 4. Update merkle root for the last commitment
    const lastIndex = tree.leaves.length - 1;
    const proof = tree.generateProof(lastIndex);
    
    console.log(`\n=== Updating Merkle Root (index ${lastIndex}) ===`);
    console.log(`Proof siblings: ${proof.length}`);

    const chunkIndex = lastIndex; // 1 commitment per chunk
    const [chunkPda] = PublicKey.findProgramAddressSync(
        [COMMITMENT_CHUNK_SEED, Buffer.from(new anchor.BN(chunkIndex).toArray("le", 8))],
        program.programId
    );

    try {
        const tx = await program.methods
            .updateMerkleRoot(new anchor.BN(lastIndex), 0, {
                siblings: proof.map(s => Array.from(s) as number[]),
            })
            .accountsStrict({
                payer: wallet.publicKey,
                commitmentTree: commitmentTree,
                commitmentChunk: chunkPda,
            })
            .preInstructions([ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 })]).rpc();

        console.log(`✅ Transaction: ${tx.slice(0, 20)}...`);

        // 5. Verify updated root
        const updatedTree = await program.account.commitmentTree.fetch(commitmentTree);
        console.log(`\nUpdated root: ${Buffer.from(updatedTree.root).toString("hex").slice(0,16)}...`);
        console.log(`Expected:     ${computedRoot.toString("hex").slice(0,16)}...`);
        
        const rootsMatch = Buffer.from(updatedTree.root).equals(computedRoot);
        console.log(`\n${rootsMatch ? "✅ ROOTS MATCH!" : "❌ ROOTS DO NOT MATCH"}`);

    } catch (e: any) {
        console.log(`❌ Error: ${e.message}`);
        if (e.logs) {
            console.log("\nLogs:");
            e.logs.slice(-10).forEach((l: string) => console.log(`  ${l}`));
        }
    }
}

main().catch(console.error);
