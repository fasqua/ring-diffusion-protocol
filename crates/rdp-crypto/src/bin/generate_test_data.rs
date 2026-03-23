use rdp_crypto::bulletproofs::prover::prove as bulletproof_prove;
use rdp_crypto::pedersen::PedersenCommitment;
use rdp_crypto::ring_signature;
use rdp_crypto::scalar::Scalar;
use rdp_crypto::point::Point;
use rdp_crypto::types::{PublicKey, SecretKey};
use rdp_crypto::stealth::{StealthKeyPair, generate_stealth_address};
use rand::rngs::OsRng;
use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let amount: u64 = if args.len() > 1 {
        args[1].parse().expect("Invalid amount")
    } else {
        20_000_000 // Default 0.02 SOL
    };

    println!("Generating test data for amount: {} lamports ({} SOL)", amount, amount as f64 / 1e9);

    let mut rng = OsRng;

    // ========================================================================
    // STEALTH ADDRESS GENERATION
    // ========================================================================
    // Generate receiver's stealth keypair (spend + view keys)
    let receiver_stealth = StealthKeyPair::generate(&mut rng);
    
    // Generate one-time stealth address for this withdraw
    let stealth_output = generate_stealth_address(&receiver_stealth.meta_address(), &mut rng)
        .expect("Failed to generate stealth address");
    
    // The stealth_pubkey becomes our destination (one-time address)
    let destination: [u8; 32] = stealth_output.stealth_pubkey;
    
    println!("Stealth destination: {}", hex::encode(&destination[..8]));
    println!("Ephemeral pubkey (R): {}", hex::encode(&stealth_output.ephemeral_pubkey[..8]));

    // ========================================================================
    // DEPOSIT KEYPAIR GENERATION
    // ========================================================================
    let secret_scalar = Scalar::random(&mut rng);
    let public_point = Point::basepoint().mul(&secret_scalar);

    let secret_key = SecretKey(secret_scalar.to_bytes());
    let public_key = PublicKey(public_point.to_bytes());

    // Generate blinding factor and commitment
    let blinding = Scalar::random(&mut rng);
    let commitment = PedersenCommitment::commit(amount, &blinding);

    // ========================================================================
    // RING GENERATION
    // ========================================================================
    let mut ring_pubkeys: Vec<PublicKey> = vec![public_key.clone()];
    let mut ring_pubkeys_bytes: Vec<Vec<u8>> = vec![public_key.0.to_vec()];
    for _ in 1..4 {
        let fake_sk = Scalar::random(&mut rng);
        let fake_pk = Point::basepoint().mul(&fake_sk);
        ring_pubkeys_bytes.push(fake_pk.to_bytes().to_vec());
        ring_pubkeys.push(PublicKey(fake_pk.to_bytes()));
    }

    // ========================================================================
    // RING SIGNATURE
    // ========================================================================
    // Message = destination (32 bytes) + amount (8 bytes) - MUST MATCH ON-CHAIN!
    let mut message = Vec::with_capacity(40);
    message.extend_from_slice(&destination);
    message.extend_from_slice(&amount.to_le_bytes());

    println!("Message length: {} bytes", message.len());

    let ring_sig = ring_signature::sign_with_rng(
        &message,
        &ring_pubkeys,
        0,
        &secret_key,
        &mut rng,
    ).expect("Failed to create ring signature");

    // ========================================================================
    // BULLETPROOF
    // ========================================================================
    let bulletproof = bulletproof_prove(amount, &blinding, &mut rng);

    // ========================================================================
    // BUILD JSON OUTPUT
    // ========================================================================
    let json = serde_json::json!({
        "deposit": {
            "amount": amount,
            "blinding": hex::encode(blinding.to_bytes()),
            "commitment": hex::encode(commitment.to_bytes()),
            "commitment_bytes": commitment.to_bytes().to_vec(),
            "public_key": hex::encode(public_key.0),
            "secret_key": hex::encode(secret_key.0),
        },
        "withdraw": {
            "destination": hex::encode(&destination),
            "destination_bytes": destination.to_vec(),
            "ring_pubkeys": ring_pubkeys_bytes.iter()
                .map(|pk| hex::encode(pk))
                .collect::<Vec<_>>(),
            "ring_pubkeys_bytes": ring_pubkeys_bytes,
            "key_image": hex::encode(ring_sig.key_image),
            "key_image_bytes": ring_sig.key_image.to_vec(),
            "signature_c": hex::encode(ring_sig.c),
            "signature_c_bytes": ring_sig.c.to_vec(),
            "signature_responses": ring_sig.responses.iter()
                .map(|r| r.to_vec())
                .collect::<Vec<_>>(),
            "signature_responses_bytes": ring_sig.responses.iter()
                .map(|r| r.to_vec())
                .collect::<Vec<_>>(),
            "ring_signature": {
                "c": hex::encode(ring_sig.c),
                "c_bytes": ring_sig.c.to_vec(),
                "responses": ring_sig.responses.iter()
                    .map(|r| r.to_vec())
                    .collect::<Vec<_>>(),
            },
            "bulletproof": {
                "v_commitment": bulletproof.v_commitment.to_vec(),
                "a": bulletproof.a.to_vec(),
                "s": bulletproof.s.to_vec(),
                "t1": bulletproof.t1.to_vec(),
                "t2": bulletproof.t2.to_vec(),
                "tau_x": bulletproof.tau_x.to_vec(),
                "mu": bulletproof.mu.to_vec(),
                "t_hat": bulletproof.t_hat.to_vec(),
                "ip_l": bulletproof.inner_product_proof.l_vec.iter()
                    .map(|p| p.to_vec())
                    .collect::<Vec<_>>(),
                "ip_r": bulletproof.inner_product_proof.r_vec.iter()
                    .map(|p| p.to_vec())
                    .collect::<Vec<_>>(),
                "ip_a": bulletproof.inner_product_proof.a.to_vec(),
                "ip_b": bulletproof.inner_product_proof.b.to_vec(),
            }
        },
        "stealth": {
            "receiver_spend_pubkey": hex::encode(&receiver_stealth.spend_pubkey),
            "receiver_spend_pubkey_bytes": receiver_stealth.spend_pubkey.to_vec(),
            "receiver_view_pubkey": hex::encode(&receiver_stealth.view_pubkey),
            "receiver_view_pubkey_bytes": receiver_stealth.view_pubkey.to_vec(),
            "receiver_spend_secret": hex::encode(&receiver_stealth.spend_secret),
            "receiver_spend_secret_bytes": receiver_stealth.spend_secret.to_vec(),
            "receiver_view_secret": hex::encode(&receiver_stealth.view_secret),
            "receiver_view_secret_bytes": receiver_stealth.view_secret.to_vec(),
            "ephemeral_pubkey": hex::encode(&stealth_output.ephemeral_pubkey),
            "ephemeral_pubkey_bytes": stealth_output.ephemeral_pubkey.to_vec(),
            "stealth_pubkey": hex::encode(&stealth_output.stealth_pubkey),
            "stealth_pubkey_bytes": stealth_output.stealth_pubkey.to_vec(),
        }
    });

    let output_file = format!("tests/e2e-test-data-{}sol.json", amount as f64 / 1e9);
    fs::write(&output_file, serde_json::to_string_pretty(&json).unwrap())
        .expect("Failed to write file");

    println!("✅ Test data saved to {}", output_file);

    fs::write("tests/e2e-test-data.json", serde_json::to_string_pretty(&json).unwrap())
        .expect("Failed to write file");
    println!("✅ Also updated tests/e2e-test-data.json");
}
