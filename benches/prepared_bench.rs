use fhipe_rust::{
    setup::ipe_setup,
    keygen::ipe_keygen,
    encrypt::ipe_encrypt,
    decrypt::{ipe_decrypt, prepare_secret_key, ipe_decrypt_prepared},
    parallel::parallel_decrypt,
};
use ark_bls12_381::Fr;
use ark_std::rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Instant;

const VECTOR_DIM: usize = 256;
const NUM_DECRYPTS: usize = 100;
const SEARCH_SPACE: usize = 1000000;

fn main() {
    println!("=== Prepared Pairings Performance Comparison ===");
    println!("This benchmark isolates the prepared pairings optimization");
    println!("by comparing sequential decryption with and without preparation.\n");
    println!("Vector dimension: {}", VECTOR_DIM);
    println!("Number of decryptions: {}", NUM_DECRYPTS);
    println!("Search space size: {}\n", SEARCH_SPACE);
    println!("NOTE: For production use, combine prepared pairings with parallelism");
    println!("      via parallel_decrypt() for maximum performance!\n");

    // Setup
    let lambda = 128;
    let (pp, msk) = ipe_setup(lambda, VECTOR_DIM, SEARCH_SPACE);
    let mut rng = StdRng::seed_from_u64(42);

    // Generate query and key
    let query: Vec<Fr> = (0..VECTOR_DIM)
        .map(|_| Fr::from((rand::random::<u8>() % 10) as u64))
        .collect();
    let sk = ipe_keygen(&msk, &query, &mut rng);

    // Generate test ciphertexts
    println!("[Preparation] Generating {} ciphertexts...", NUM_DECRYPTS);
    let ciphertexts: Vec<_> = (0..NUM_DECRYPTS)
        .map(|_| {
            let y: Vec<Fr> = (0..VECTOR_DIM)
                .map(|_| Fr::from((rand::random::<u8>() % 10) as u64))
                .collect();
            ipe_encrypt(&msk, &y, &mut rng)
        })
        .collect();
    println!("  ✓ Done\n");

    // ========== WITHOUT PREPARED PAIRINGS ==========
    println!("=== WITHOUT PREPARED PAIRINGS (standard ipe_decrypt) ===");
    let start = Instant::now();
    let mut results_standard = Vec::new();
    for ct in &ciphertexts {
        results_standard.push(ipe_decrypt(&pp, &sk, ct));
    }
    let time_standard = start.elapsed();
    let per_decrypt_standard = time_standard / NUM_DECRYPTS as u32;
    println!("  Total time:     {:.2?}", time_standard);
    println!("  Per decrypt:    {:.2?}", per_decrypt_standard);
    println!("  Throughput:     {:.2} decrypts/sec\n", 
             NUM_DECRYPTS as f64 / time_standard.as_secs_f64());

    // ========== WITH PREPARED PAIRINGS ==========
    println!("=== WITH PREPARED PAIRINGS (prepare once, reuse) ===");
    let start = Instant::now();
    let prepared_sk = prepare_secret_key(&sk);
    let prep_time = start.elapsed();
    println!("  Preparation:    {:.2?}", prep_time);

    let start = Instant::now();
    let mut results_prepared = Vec::new();
    for ct in &ciphertexts {
        results_prepared.push(ipe_decrypt_prepared(&pp, &prepared_sk, ct));
    }
    let time_prepared = start.elapsed();
    let per_decrypt_prepared = time_prepared / NUM_DECRYPTS as u32;
    println!("  Decrypt time:   {:.2?}", time_prepared);
    println!("  Per decrypt:    {:.2?}", per_decrypt_prepared);
    println!("  Throughput:     {:.2} decrypts/sec\n", 
             NUM_DECRYPTS as f64 / time_prepared.as_secs_f64());

    // ========== COMPARISON ==========
    println!("=== PERFORMANCE COMPARISON (Sequential Only) ===");
    let speedup = time_standard.as_secs_f64() / time_prepared.as_secs_f64();
    let time_saved = time_standard - time_prepared;
    let percent_faster = ((time_standard.as_secs_f64() - time_prepared.as_secs_f64()) 
                          / time_standard.as_secs_f64()) * 100.0;
    
    println!("Standard approach:  {:.2?} total", time_standard);
    println!("Prepared approach:  {:.2?} prep + {:.2?} decrypt = {:.2?} total", 
             prep_time, time_prepared, prep_time + time_prepared);
    println!("Time saved:         {:.2?}", time_saved);
    println!("Speedup:            {:.2}x", speedup);
    println!("Performance gain:   {:.1}% faster\n", percent_faster);

    // ========== PARALLEL COMPARISON ==========
    println!("=== PARALLEL DECRYPTION (uses prepared pairings internally) ===");
    println!("Available parallelism: {} threads", rayon::current_num_threads());
    let start = Instant::now();
    let results_parallel = parallel_decrypt(&pp, &sk, &ciphertexts);
    let time_parallel = start.elapsed();
    let per_decrypt_parallel = time_parallel / NUM_DECRYPTS as u32;
    println!("  Total time:     {:.2?}", time_parallel);
    println!("  Per decrypt:    {:.2?}", per_decrypt_parallel);
    println!("  Throughput:     {:.2} decrypts/sec", 
             NUM_DECRYPTS as f64 / time_parallel.as_secs_f64());
    
    let parallel_speedup = time_standard.as_secs_f64() / time_parallel.as_secs_f64();
    println!("\n🚀 Parallel speedup vs standard: {:.2}x", parallel_speedup);
    println!("   (combines prepared pairings + multi-core parallelism)\n");

    // Verify correctness
    assert_eq!(results_standard.len(), results_prepared.len());
    let all_match = results_standard.iter()
        .zip(results_prepared.iter())
        .all(|(a, b)| a == b);
    
    if all_match {
        println!("✅ Correctness verified: All results match!");
    } else {
        panic!("❌ Results mismatch!");
    }
    
    // Verify parallel results too
    assert_eq!(results_standard.len(), results_parallel.len());
    let parallel_match = results_standard.iter()
        .zip(results_parallel.iter())
        .all(|(a, b)| a == b);
    
    if parallel_match {
        println!("✅ Parallel results also correct!");
    } else {
        panic!("❌ Parallel results mismatch!");
    }
}
