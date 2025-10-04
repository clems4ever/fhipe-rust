use fhipe_rust::{
    setup::ipe_setup,
    keygen::ipe_keygen,
    encrypt::ipe_encrypt,
    decrypt::ipe_decrypt,
    parallel::{parallel_encrypt, parallel_decrypt},
};
use ark_bls12_381::Fr;
use ark_std::rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Instant;

const VECTOR_DIM: usize = 256;
const NUM_VECTORS: usize = 50;
const SEARCH_SPACE: usize = 1000000;

/// Compute inner product <x, y> in cleartext
fn compute_inner_product(x: &[Fr], y: &[Fr]) -> Fr {
    assert_eq!(x.len(), y.len(), "Vectors must have same dimension");
    x.iter().zip(y.iter()).map(|(xi, yi)| *xi * yi).sum()
}

fn main() {
    println!("=== FHIPE Parallel vs Sequential Performance Benchmark ===");
    println!("Vector dimension: {}", VECTOR_DIM);
    println!("Number of vectors: {}", NUM_VECTORS);
    println!("Search space size: {}\n", SEARCH_SPACE);
    println!("Available parallelism: {} threads\n", rayon::current_num_threads());

    // Setup phase
    println!("[Setup] Running IPE.Setup...");
    let start = Instant::now();
    let lambda = 128;
    let (pp, msk) = ipe_setup(lambda, VECTOR_DIM, SEARCH_SPACE);
    let setup_time = start.elapsed();
    println!("  ✓ Setup completed in {:.2?}\n", setup_time);

    let mut rng = StdRng::seed_from_u64(42);

    // Generate random vectors
    println!("[Data] Generating {} random vectors...", NUM_VECTORS);
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

    // ========== SEQUENTIAL ENCRYPTION ==========
    println!("=== SEQUENTIAL ENCRYPTION ===");
    let start = Instant::now();
    let ciphertexts_seq: Vec<_> = vectors
        .iter()
        .map(|v| {
            ipe_encrypt(&msk, v, &mut rng)
        })
        .collect();
    let encrypt_time_seq = start.elapsed();
    let encrypt_per_vector_seq = encrypt_time_seq / NUM_VECTORS as u32;
    println!("  Total time:     {:.2?}", encrypt_time_seq);
    println!("  Per vector:     {:.2?}", encrypt_per_vector_seq);
    println!("  Throughput:     {:.2} vectors/sec\n", 
             NUM_VECTORS as f64 / encrypt_time_seq.as_secs_f64());

    // ========== PARALLEL ENCRYPTION ==========
    println!("=== PARALLEL ENCRYPTION ===");
    let start = Instant::now();
    let ciphertexts_par = parallel_encrypt(&msk, &vectors, &mut rng);
    let encrypt_time_par = start.elapsed();
    let encrypt_per_vector_par = encrypt_time_par / NUM_VECTORS as u32;
    println!("  Total time:     {:.2?}", encrypt_time_par);
    println!("  Per vector:     {:.2?}", encrypt_per_vector_par);
    println!("  Throughput:     {:.2} vectors/sec", 
             NUM_VECTORS as f64 / encrypt_time_par.as_secs_f64());
    
    let speedup_enc = encrypt_time_seq.as_secs_f64() / encrypt_time_par.as_secs_f64();
    println!("  🚀 Speedup:     {:.2}x\n", speedup_enc);

    // Generate query vector and key
    println!("[KeyGen] Generating query vector and secret key...");
    let start = Instant::now();
    let query: Vec<Fr> = (0..VECTOR_DIM)
        .map(|_| Fr::from((rand::random::<u8>() % 10) as u64))
        .collect();
    let sk = ipe_keygen(&msk, &query, &mut rng);
    let keygen_time = start.elapsed();
    println!("  ✓ Key generation completed in {:.2?}\n", keygen_time);

    // ========== SEQUENTIAL DECRYPTION ==========
    println!("=== SEQUENTIAL DECRYPTION ===");
    let start = Instant::now();
    let mut results_seq = Vec::new();
    for ct in &ciphertexts_seq {
        results_seq.push(ipe_decrypt(&pp, &sk, ct));
    }
    let decrypt_time_seq = start.elapsed();
    let successful_decryptions_seq = results_seq.iter().filter(|r| r.is_some()).count();
    let decrypt_per_vector_seq = decrypt_time_seq / NUM_VECTORS as u32;
    println!("  Total time:     {:.2?}", decrypt_time_seq);
    println!("  Per vector:     {:.2?}", decrypt_per_vector_seq);
    println!("  Throughput:     {:.2} vectors/sec", 
             NUM_VECTORS as f64 / decrypt_time_seq.as_secs_f64());
    println!("  Success rate:   {}/{}\n", successful_decryptions_seq, NUM_VECTORS);

    // ========== PARALLEL DECRYPTION ==========
    println!("=== PARALLEL DECRYPTION ===");
    let start = Instant::now();
    let results_par = parallel_decrypt(&pp, &sk, &ciphertexts_par);
    let decrypt_time_par = start.elapsed();
    let successful_decryptions_par = results_par.iter().filter(|r| r.is_some()).count();
    let decrypt_per_vector_par = decrypt_time_par / NUM_VECTORS as u32;
    println!("  Total time:     {:.2?}", decrypt_time_par);
    println!("  Per vector:     {:.2?}", decrypt_per_vector_par);
    println!("  Throughput:     {:.2} vectors/sec", 
             NUM_VECTORS as f64 / decrypt_time_par.as_secs_f64());
    println!("  Success rate:   {}/{}", successful_decryptions_par, NUM_VECTORS);
    
    let speedup_dec = decrypt_time_seq.as_secs_f64() / decrypt_time_par.as_secs_f64();
    println!("  🚀 Speedup:     {:.2}x\n", speedup_dec);

    // ========== CORRECTNESS VERIFICATION ==========
    println!("=== CORRECTNESS VERIFICATION ===");
    println!("Computing expected inner products in cleartext...");
    
    let mut mismatches = 0;
    let mut correct = 0;
    
    for (i, (y_vec, result)) in vectors.iter().zip(results_par.iter()).enumerate() {
        // Compute expected inner product <query, y_vec> in cleartext
        let expected = compute_inner_product(&query, y_vec);
        
        match result {
            Some(decrypted) => {
                if *decrypted == expected {
                    correct += 1;
                } else {
                    mismatches += 1;
                    println!("  ❌ Mismatch at vector {}: expected {:?}, got {:?}", i, expected, decrypted);
                }
            }
            None => {
                println!("  ⚠️  Decryption failed for vector {} (expected {:?})", i, expected);
            }
        }
    }
    
    println!("  ✓ Correct decryptions: {}/{}", correct, NUM_VECTORS);
    if mismatches > 0 {
        println!("  ❌ Mismatches found: {}", mismatches);
        panic!("Correctness verification failed!");
    } else if correct == NUM_VECTORS {
        println!("  ✅ All decryptions are correct!\n");
    }
    
    // ========== SUMMARY ==========
    println!("=== PERFORMANCE SUMMARY ===");
    println!("Setup time:              {:.2?}", setup_time);
    println!("KeyGen time:             {:.2?}\n", keygen_time);
    
    println!("Encryption (sequential): {:.2?} ({:.2?}/vector)", encrypt_time_seq, encrypt_per_vector_seq);
    println!("Encryption (parallel):   {:.2?} ({:.2?}/vector)", encrypt_time_par, encrypt_per_vector_par);
    println!("  → Speedup: {:.2}x\n", speedup_enc);
    
    println!("Decryption (sequential): {:.2?} ({:.2?}/vector)", decrypt_time_seq, decrypt_per_vector_seq);
    println!("Decryption (parallel):   {:.2?} ({:.2?}/vector)", decrypt_time_par, decrypt_per_vector_par);
    println!("  → Speedup: {:.2}x\n", speedup_dec);
    
    let total_seq = encrypt_time_seq + decrypt_time_seq;
    let total_par = encrypt_time_par + decrypt_time_par;
    let total_speedup = total_seq.as_secs_f64() / total_par.as_secs_f64();
    
    println!("Total batch time (sequential): {:.2?}", total_seq);
    println!("Total batch time (parallel):   {:.2?}", total_par);
    println!("  → Overall Speedup: {:.2}x 🚀", total_speedup);
}
