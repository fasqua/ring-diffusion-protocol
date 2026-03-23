use clap::Parser;
use rdp_crypto::bulletproofs::prover::prove;
use rdp_crypto::bulletproofs::verifier::verify;
use rdp_crypto::scalar::Scalar;
use rdp_crypto::pedersen::PedersenCommitment;
use serde::Serialize;
use rand::rngs::OsRng;

#[derive(Parser, Debug)]
#[command(name = "gen-bulletproof")]
#[command(about = "Generate bulletproof range proof for testing")]
struct Args {
    /// Value in lamports (default: 1 SOL = 1_000_000_000)
    #[arg(short, long, default_value = "1000000000")]
    value: u64,
}

#[derive(Serialize)]
struct BulletproofOutput {
    value: u64,
    blinding_hex: String,
    commitment_hex: String,
    proof: ProofData,
    /// For on-chain BulletproofData struct (as number arrays for TypeScript)
    onchain_data: OnchainBulletproofData,
}

#[derive(Serialize)]
struct ProofData {
    v_commitment: String,
    a: String,
    s: String,
    t1: String,
    t2: String,
    tau_x: String,
    mu: String,
    t_hat: String,
    ip_l: Vec<String>,
    ip_r: Vec<String>,
    ip_a: String,
    ip_b: String,
}

#[derive(Serialize)]
struct OnchainBulletproofData {
    #[serde(rename = "vCommitment")]
    v_commitment: Vec<u8>,
    a: Vec<u8>,
    s: Vec<u8>,
    t1: Vec<u8>,
    t2: Vec<u8>,
    #[serde(rename = "tauX")]
    tau_x: Vec<u8>,
    mu: Vec<u8>,
    #[serde(rename = "tHat")]
    t_hat: Vec<u8>,
    #[serde(rename = "ipL")]
    ip_l: Vec<Vec<u8>>,
    #[serde(rename = "ipR")]
    ip_r: Vec<Vec<u8>>,
    #[serde(rename = "ipA")]
    ip_a: Vec<u8>,
    #[serde(rename = "ipB")]
    ip_b: Vec<u8>,
}

fn main() {
    let args = Args::parse();
    let value = args.value;

    eprintln!("Generating bulletproof for value: {} lamports ({:.4} SOL)", 
              value, value as f64 / 1_000_000_000.0);

    // Generate random blinding factor
    let mut rng = OsRng;
    let gamma = Scalar::random(&mut rng);

    // Generate bulletproof
    let proof = prove(value, &gamma, &mut rng);

    // Compute commitment
    let commitment = PedersenCommitment::commit(value, &gamma);

    // Verify locally (verify only needs the proof, commitment is embedded)
    let verification = verify(&proof);
    match &verification {
        Ok(_) => eprintln!("Local verification: PASS ✓"),
        Err(e) => eprintln!("Local verification: FAIL ✗ ({:?})", e),
    }

    // Build output
    let output = BulletproofOutput {
        value,
        blinding_hex: hex::encode(gamma.to_bytes()),
        commitment_hex: hex::encode(commitment.to_bytes()),
        proof: ProofData {
            v_commitment: hex::encode(&proof.v_commitment),
            a: hex::encode(&proof.a),
            s: hex::encode(&proof.s),
            t1: hex::encode(&proof.t1),
            t2: hex::encode(&proof.t2),
            tau_x: hex::encode(&proof.tau_x),
            mu: hex::encode(&proof.mu),
            t_hat: hex::encode(&proof.t_hat),
            ip_l: proof.inner_product_proof.l_vec.iter().map(|p| hex::encode(p)).collect(),
            ip_r: proof.inner_product_proof.r_vec.iter().map(|p| hex::encode(p)).collect(),
            ip_a: hex::encode(&proof.inner_product_proof.a),
            ip_b: hex::encode(&proof.inner_product_proof.b),
        },
        onchain_data: OnchainBulletproofData {
            v_commitment: proof.v_commitment.to_vec(),
            a: proof.a.to_vec(),
            s: proof.s.to_vec(),
            t1: proof.t1.to_vec(),
            t2: proof.t2.to_vec(),
            tau_x: proof.tau_x.to_vec(),
            mu: proof.mu.to_vec(),
            t_hat: proof.t_hat.to_vec(),
            ip_l: proof.inner_product_proof.l_vec.iter().map(|p| p.to_vec()).collect(),
            ip_r: proof.inner_product_proof.r_vec.iter().map(|p| p.to_vec()).collect(),
            ip_a: proof.inner_product_proof.a.to_vec(),
            ip_b: proof.inner_product_proof.b.to_vec(),
        },
    };

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
