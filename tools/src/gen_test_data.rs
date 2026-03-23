//! Generate complete E2E test data for RDP withdraw

use clap::Parser;
use rdp_crypto::{
    ring_signature::{sign as ring_sign, verify as ring_verify},
    bulletproof_prover::prove as bp_prove,
    bulletproof_verifier::verify as bp_verify,
    pedersen::PedersenCommitment,
    types::{PublicKey, SecretKey},
    scalar::Scalar,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::json;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "20000000")]
    amount: u64,
    #[arg(long, default_value = "16")]
    ring_size: usize,
    #[arg(long)]
    destination: String,
}

fn random_secret_key(rng: &mut impl RngCore) -> SecretKey {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    SecretKey::from_bytes(bytes)
}

fn secret_to_public(sk: &SecretKey) -> PublicKey {
    use curve25519_dalek::scalar::Scalar as DalekScalar;
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    
    let scalar = DalekScalar::from_bytes_mod_order(*sk.as_bytes());
    let point = &scalar * ED25519_BASEPOINT_TABLE;
    PublicKey::from_bytes(point.compress().to_bytes())
}

fn main() {
    let args = Args::parse();
    
    eprintln!("=== Generating RDP Test Data ===");
    eprintln!("Amount: {} lamports ({:.4} SOL)", args.amount, args.amount as f64 / 1e9);
    eprintln!("Ring size: {}", args.ring_size);
    eprintln!("Destination: {}", args.destination);
    
    let destination_bytes: [u8; 32] = bs58::decode(&args.destination)
        .into_vec()
        .expect("Invalid base58")
        .try_into()
        .expect("Must be 32 bytes");
    
    let mut rng = OsRng;
    
    // 1. Keypair
    eprintln!("[1/5] Keypair");
    let secret_key = random_secret_key(&mut rng);
    let public_key = secret_to_public(&secret_key);
    
    // 2. Commitment
    eprintln!("[2/5] Commitment");
    let blinding = Scalar::random(&mut rng);
    let commitment = PedersenCommitment::commit(args.amount, &blinding);
    
    // 3. Ring
    eprintln!("[3/5] Ring");
    let signer_index = args.ring_size - 1;
    let mut ring: Vec<PublicKey> = (0..args.ring_size - 1)
        .map(|_| secret_to_public(&random_secret_key(&mut rng)))
        .collect();
    ring.push(public_key.clone());
    
    // 4. Message
    let mut message = Vec::with_capacity(40);
    message.extend_from_slice(&destination_bytes);
    message.extend_from_slice(&args.amount.to_le_bytes());
    
    // 5. Ring signature
    eprintln!("[4/5] Ring signature");
    let signature = ring_sign(&message, &ring, signer_index, &secret_key)
        .expect("Ring sign failed");
    ring_verify(&message, &ring, &signature).expect("Ring verify failed");
    eprintln!("      Verified ✓");
    
    // 6. Bulletproof
    eprintln!("[5/5] Bulletproof");
    let bulletproof = bp_prove(args.amount, &blinding, &mut rng);
    bp_verify(&bulletproof).expect("BP verify failed");
    eprintln!("      Verified ✓");
    
    // Output
    let ip = &bulletproof.inner_product_proof;
    
    let output = json!({
        "deposit": {
            "amount": args.amount,
            "secret_key": hex::encode(secret_key.as_bytes()),
            "public_key": hex::encode(public_key.as_bytes()),
            "blinding": hex::encode(blinding.to_bytes()),
            "commitment": hex::encode(commitment.to_bytes()),
            "commitment_bytes": commitment.to_bytes().to_vec(),
        },
        "withdraw": {
            "destination": args.destination,
            "destination_bytes": destination_bytes.to_vec(),
            "ring_pubkeys": ring.iter().map(|pk| hex::encode(pk.as_bytes())).collect::<Vec<_>>(),
            "ring_pubkeys_bytes": ring.iter().map(|pk| pk.as_bytes().to_vec()).collect::<Vec<_>>(),
            "signer_index": signer_index,
            "key_image": hex::encode(signature.key_image),
            "key_image_bytes": signature.key_image.to_vec(),
            "signature_c": hex::encode(signature.c),
            "signature_c_bytes": signature.c.to_vec(),
            "signature_responses": signature.responses.iter().map(|r| hex::encode(r)).collect::<Vec<_>>(),
            "signature_responses_bytes": signature.responses.iter().map(|r| r.to_vec()).collect::<Vec<_>>(),
            "message": hex::encode(&message),
            "message_bytes": message.clone(),
            "bulletproof": {
                "v_commitment": bulletproof.v_commitment.to_vec(),
                "a": bulletproof.a.to_vec(),
                "s": bulletproof.s.to_vec(),
                "t1": bulletproof.t1.to_vec(),
                "t2": bulletproof.t2.to_vec(),
                "tau_x": bulletproof.tau_x.to_vec(),
                "mu": bulletproof.mu.to_vec(),
                "t_hat": bulletproof.t_hat.to_vec(),
                "ip_l": ip.l_vec.iter().map(|p| p.to_vec()).collect::<Vec<_>>(),
                "ip_r": ip.r_vec.iter().map(|p| p.to_vec()).collect::<Vec<_>>(),
                "ip_a": ip.a.to_vec(),
                "ip_b": ip.b.to_vec(),
            }
        }
    });
    
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    eprintln!("\n✅ Done");
}
