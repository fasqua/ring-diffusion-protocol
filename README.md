<div align="center">

# 🌀 Ring Diffusion Protocol (RDP)

### Privacy-Preserving Transactions on Solana — Without Trusted Setup

[![Solana](https://img.shields.io/badge/Solana-Devnet-blueviolet?style=for-the-badge&logo=solana)](https://solana.com)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange?style=for-the-badge&logo=rust)](https://rust-lang.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Unaudited-red?style=for-the-badge)]()

---

*Built by KausaLayer*

</div>

---

## ⚠️ Security Notice

This software is deployed on **Solana Devnet only** and has **not been audited**. Do not use with real funds. For research and testing purposes only.

---

## Table of Contents

- [What is RDP?](#what-is-rdp)
- [Why RDP?](#why-rdp)
- [How It Works](#how-it-works)
- [Technical Specifications](#technical-specifications)
- [Cryptographic Primitives](#cryptographic-primitives)
- [Program Instructions](#program-instructions)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [FAQ](#faq)

---

## What is RDP?

**Ring Diffusion Protocol** enables private transactions on Solana. Users deposit SOL into a shared pool and withdraw to a completely different address — with **no on-chain link** between deposit and withdrawal.

### The Problem

Every Solana transaction is permanently public:
- Your wallet balance is visible to everyone
- Every transfer is traceable
- Your entire financial history is on display

### The Solution

RDP breaks the on-chain link using four cryptographic layers:

| Layer | Primitive | Protection |
|:-----:|-----------|------------|
| 1 | **Ring Signature** | Hides which deposit is being spent |
| 2 | **Bulletproof** | Hides the transaction amount |
| 3 | **Key Image** | Prevents double-spending |
| 4 | **Stealth Address** | Hides the receiver |

---

## Why RDP?

### No Trusted Setup Required

RDP uses **transparent cryptography** that requires no trusted setup ceremony. Every proof is self-contained and mathematically verifiable by anyone, anytime. There are no secret parameters that must be trusted.

### Flexible Amounts

Unlike fixed-denomination mixers, RDP supports **any amount** thanks to Bulletproof range proofs.

### Fully Permissionless

No screening, no gatekeeping. Anyone can use RDP.

---

## How It Works

### Deposit Flow
```
┌─────────────┐                                    ┌─────────────────┐
│    USER     │                                    │   RDP PROGRAM   │
└──────┬──────┘                                    └────────┬────────┘
       │                                                    │
       │  1. Generate random blinding factor: r             │
       │  2. Create Pedersen commitment: C = v*G + r*H      │
       │  3. Store r securely (CRITICAL!)                   │
       │                                                    │
       │  4. deposit(C, amount)                             │
       │  ─────────────────────────────────────────────────►│
       │                                                    │
       │                    5. Store C in CommitmentChunk   │
       │                    6. Lock SOL in pool vault       │
       │                                                    │
       │  7. Deposit confirmed                              │
       │  ◄─────────────────────────────────────────────────│
       ▼                                                    ▼
```

### Withdraw Flow (6 Phases)

Due to Solana's 1,232-byte transaction limit, withdrawal requires 6 separate transactions:
```
┌────────────────────────────────────────────────────────────────────────┐
│                         WITHDRAW FLOW                                  │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  PHASE 1: prepare_withdraw                                            │
│  └── Submit ring members, stealth destination, amount                │
│                                                                        │
│  PHASE 2-5: submit_proof_part1 → part4                                │
│  └── Submit Bulletproof components                                   │
│                                                                        │
│  PHASE 6: execute_withdraw                                            │
│  └── Verify ring signature + bulletproof                              │
│  └── Check key image (double-spend prevention)                        │
│  └── Transfer SOL to stealth destination                              │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Merkle Tree

All deposit commitments are organized in a Merkle tree:
- **Depth:** 20 levels (supports 1,048,576+ deposits)
- **Update:** Anyone can call `update_merkle_root` (trustless)

---

## Technical Specifications

### Deployment Information

| Parameter | Value |
|-----------|-------|
| **Program ID** | `DHQtM2vuNrcD9UC42kfq1MNo9yucjPuReBHrsQvrpxjn` |
| **Network** | Solana Devnet |

### Protocol Parameters

| Parameter | Value |
|-----------|-------|
| Ring Size | 4 (configurable up to 255) |
| Merkle Depth | 20 |
| Fee | 0.5% |

---

## Cryptographic Primitives

### 1. Ring Signatures (LSAG)

Linkable Spontaneous Anonymous Group signatures allow proving ownership of ONE commitment in a set without revealing which one.

### 2. Bulletproofs (Range Proofs)

Zero-knowledge proofs that a committed value is within valid range [0, 2⁶⁴) without revealing the value.

### 3. Key Images (Double-Spend Prevention)

Each private key produces a unique, deterministic key image. Once recorded on-chain, that deposit cannot be spent again.

### 4. Stealth Addresses (DKSAP)

Dual-Key Stealth Address Protocol enables one-time receiver addresses:
- Receiver publishes spend & view public keys
- Sender generates ephemeral key and one-time stealth address
- Only receiver can derive the private key to spend

### 5. Merkle Tree

SHA-256 based Merkle tree with domain separation for commitment membership proofs.

---

## Program Instructions

### User Instructions

| Instruction | Description |
|-------------|-------------|
| `deposit` | Deposit SOL with Pedersen commitment |
| `prepare_withdraw` | Initialize withdrawal with ring |
| `submit_proof_part1-4` | Submit Bulletproof components |
| `execute_withdraw` | Verify proofs, transfer funds |
| `update_merkle_root` | Update merkle root (anyone) |

### Admin Instructions

| Instruction | Description |
|-------------|-------------|
| `initialize_pool` | Create pool (one-time) |
| `update_pool_config` | Modify pool settings |

---

## Quick Start

### Prerequisites

- Rust 1.70+
- Solana CLI 1.18+
- Anchor 0.30+
- Node.js 18+

### Installation
```bash
git clone <repository-url>
cd ring-diffusion-protocol
yarn install
anchor build
```

### Running Tests
```bash
export ANCHOR_PROVIDER_URL=https://api.devnet.solana.com
export ANCHOR_WALLET=./rdp-wallet.json

# Generate test data
cargo run --manifest-path crates/rdp-crypto/Cargo.toml \
    --bin generate_test_data -- 20000000

# Run E2E test
yarn run ts-node tests/e2e_six_phase_withdraw.ts
```

---

## Project Structure
```
ring-diffusion-protocol/
├── programs/ring-diffusion-protocol/   # On-chain Solana program
│   └── src/
│       ├── crypto/                     # Ring, Bulletproof, Merkle verifiers
│       ├── instructions/               # All program instructions
│       └── state/                      # Account structures
├── crates/rdp-crypto/                  # Off-chain crypto library
│   └── src/
│       ├── ring_signature.rs
│       ├── bulletproofs.rs
│       ├── stealth.rs
│       └── merkle.rs
└── tests/                              # Integration tests
```

| Component | Lines of Code |
|-----------|------:|
| On-chain Rust | 3,639 |
| Off-chain Rust | 3,793 |
| TypeScript Tests | 896 |
| **Total** | **8,328** |

---

## FAQ

### Why not ZK-SNARKs?

ZK-SNARKs require a trusted setup ceremony. RDP's approach requires no trust.

### Why 6 transactions?

Solana's 1,232-byte transaction limit. Bulletproofs alone are ~700 bytes.

### What if I lose my secret?

Funds are lost forever. There is no recovery mechanism. Store your secret securely.

---

## Contributing

Contributions welcome. Priority areas: security review, optimization, testing.

---

## License

MIT License

---

<div align="center">

*Ring Diffusion Protocol — Privacy without trust.*

*Built by KausaLayer*

</div>
