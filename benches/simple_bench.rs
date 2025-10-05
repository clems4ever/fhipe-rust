use fhipe_rust::v1::{
    setup::ipe_setup,
    keygen::ipe_keygen,
    encrypt::ipe_encrypt,
    decrypt::ipe_decrypt,
};
use ark_bls12_381::Fr;
use ark_std::rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Instant;

const VECTOR_DIM: usize = 384;
const NUM_VECTORS: usize = 50;
const SEARCH_SPACE: usize = 10000;

fn main() {
    println!("=== FHIPE Performance Benchmark ===");
    println!("Vector dimension: {}", VECTOR_DIM);
    println!("Number of vectors: {}", NUM_VECTORS);
    println!("Search space size: {}\n", SEARCH_SPACE);

    // Setup phase
    println!("[1/5] Running IPE.Setup...");
    let start = Instant::now();
    let lambda = 128;
    let (pp, msk) = ipe_setup(lambda, VECTOR_DIM, SEARCH_SPACE);
    let setup_time = start.elapsed();
    println!("  ✓ Setup completed in {:.2?}\n", setup_time);

    let mut rng = StdRng::seed_from_u64(42);

    // Generate random vectors (small values to ensure inner products are in search space)
    println!("[2/5] Generating {} random vectors...", NUM_VECTORS);
    let start = Instant::now();
    let vectors: Vec<Vec<Fr>> = (0..NUM_VECTORS)
        .map(|_| {
            (0..VECTOR_DIM)
                .map(|_| Fr::from((rand::random::<u8>() % 10) as u64))
                .collect()
        })
        .collect();
    let gen_time = start.elapsed();
    println!("  ✓ Vector generation completed in {:.2?}\n", gen_time);

    // Batch encryption benchmark
    println!("[3/5] Encrypting {} vectors...", NUM_VECTORS);
    let start = Instant::now();
    let ciphertexts: Vec<_> = vectors
        .iter()
        .map(|v| {
            ipe_encrypt(&msk, v, &mut rng)
        })
        .collect();
    let encrypt_time = start.elapsed();
    let encrypt_per_vector = encrypt_time / NUM_VECTORS as u32;
    println!("  ✓ Batch encryption completed in {:.2?}", encrypt_time);
    println!("  ✓ Average time per encryption: {:.2?}", encrypt_per_vector);
    println!("  ✓ Encryption throughput: {:.2} vectors/sec\n", 
             NUM_VECTORS as f64 / encrypt_time.as_secs_f64());

    // Generate query vector and key
    println!("[4/5] Generating query vector and secret key...");
    let start = Instant::now();
    let query: Vec<Fr> = (0..VECTOR_DIM)
        .map(|_| Fr::from((rand::random::<u8>() % 10) as u64))
        .collect();
    let sk = ipe_keygen(&msk, &query, &mut rng);
    let keygen_time = start.elapsed();
    println!("  ✓ Key generation completed in {:.2?}\n", keygen_time);

    // Batch decryption benchmark
    println!("[5/5] Decrypting {} ciphertexts with the same key...", NUM_VECTORS);
    let start = Instant::now();
    let mut successful_decryptions = 0;
    for ct in &ciphertexts {
        if let Some(_result) = ipe_decrypt(&pp, &sk, ct) {
            successful_decryptions += 1;
        }
    }
    let decrypt_time = start.elapsed();
    let decrypt_per_vector = decrypt_time / NUM_VECTORS as u32;
    println!("  ✓ Batch decryption completed in {:.2?}", decrypt_time);
    println!("  ✓ Average time per decryption: {:.2?}", decrypt_per_vector);
    println!("  ✓ Decryption throughput: {:.2} vectors/sec", 
             NUM_VECTORS as f64 / decrypt_time.as_secs_f64());
    println!("  ✓ Successful decryptions: {}/{}\n", successful_decryptions, NUM_VECTORS);

    // Summary
    println!("=== Performance Summary ===");
    println!("Setup time:                {:.2?}", setup_time);
    println!("Total encryption time:     {:.2?} ({:.2?}/vector)", encrypt_time, encrypt_per_vector);
    println!("Key generation time:       {:.2?}", keygen_time);
    println!("Total decryption time:     {:.2?} ({:.2?}/vector)", decrypt_time, decrypt_per_vector);
    println!("\nThroughput:");
    println!("  Encryption: {:.2} ops/sec", NUM_VECTORS as f64 / encrypt_time.as_secs_f64());
    println!("  Decryption: {:.2} ops/sec", NUM_VECTORS as f64 / decrypt_time.as_secs_f64());
}
