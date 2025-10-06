/// Comprehensive benchmark comparing v1 (full dimension) vs v3 (compressed dimension)
/// 
/// Tests:
/// 1. Ranking accuracy on random vectors
/// 2. Ranking accuracy on close/similar vectors
/// 3. Throughput comparison (encryption/decryption)

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_std::rand::SeedableRng;
use rand::rngs::StdRng;
use rand::Rng as RandRng;
use std::time::Instant;

// V1: Full dimension IPE
use fhipe_rust::v1::setup::ipe_setup as v1_setup;
use fhipe_rust::v1::keygen::ipe_keygen as v1_keygen;
use fhipe_rust::v1::parallel::{parallel_encrypt as v1_parallel_encrypt, parallel_decrypt as v1_parallel_decrypt};

// V3: Compressed dimension IPE with random projection
use fhipe_rust::v3::setup::ipe_setup as v3_setup;
use fhipe_rust::v3::keygen::ipe_keygen as v3_keygen;
use fhipe_rust::v3::parallel::{parallel_encrypt as v3_parallel_encrypt, parallel_decrypt as v3_parallel_decrypt};
use fhipe_rust::v3::compression::RandomProjection;

const FULL_DIM: usize = 384;        // Original dimension
const COMPRESSED_DIM: usize = 128;   // Compressed dimension (1.5x reduction) - need more dims for accuracy!
const NUM_TEST_VECTORS: usize = 32;  // Number of test vectors
const SEARCH_SPACE: usize = 1000000; // Search space for discrete log
const EPSILON: f64 = 0.1;            // 10% approximation error

/// Compute plaintext dot product
fn dot_product(x: &[Fr], y: &[Fr]) -> Fr {
    x.iter().zip(y.iter()).map(|(xi, yi)| *xi * yi).sum()
}

/// Convert Fr to f64 for ranking comparison
fn fr_to_f64(x: Fr) -> f64 {
    let bigint = x.into_bigint();
    bigint.0[0] as f64
}

/// Generate test data: query vector and data vectors
struct TestData {
    query: Vec<Fr>,
    data_vectors: Vec<Vec<Fr>>,
    true_dot_products: Vec<Fr>,
}

/// Generate random test vectors
fn generate_random_vectors(dim: usize, num_vectors: usize, seed: u64) -> TestData {
    let mut rng = StdRng::seed_from_u64(seed);
    
    // Random query vector with values in [0, 100)
    let query: Vec<Fr> = (0..dim)
        .map(|_| Fr::from(rng.gen_range(0u64..100u64)))
        .collect();
    
    // Random data vectors with values in [0, 100)
    let data_vectors: Vec<Vec<Fr>> = (0..num_vectors)
        .map(|_| {
            (0..dim)
                .map(|_| Fr::from(rng.gen_range(0u64..100u64)))
                .collect()
        })
        .collect();
    
    // Compute true dot products
    let true_dot_products: Vec<Fr> = data_vectors
        .iter()
        .map(|y| dot_product(&query, y))
        .collect();
    
    TestData {
        query,
        data_vectors,
        true_dot_products,
    }
}

/// Generate close/similar test vectors (clustered around query)
fn generate_close_vectors(dim: usize, num_vectors: usize, seed: u64) -> TestData {
    let mut rng = StdRng::seed_from_u64(seed);
    
    // Base query vector
    let query: Vec<Fr> = (0..dim)
        .map(|_| Fr::from(rng.gen_range(0u64..100u64)))
        .collect();
    
    // Data vectors close to query (small random perturbations)
    let data_vectors: Vec<Vec<Fr>> = (0..num_vectors)
        .map(|_| {
            query
                .iter()
                .map(|&q_i| {
                    // Add small noise: ±5
                    let noise = rng.gen_range(0i64..11i64) - 5;
                    if noise >= 0 {
                        q_i + Fr::from(noise as u64)
                    } else {
                        q_i - Fr::from((-noise) as u64)
                    }
                })
                .collect()
        })
        .collect();
    
    // Compute true dot products
    let true_dot_products: Vec<Fr> = data_vectors
        .iter()
        .map(|y| dot_product(&query, y))
        .collect();
    
    TestData {
        query,
        data_vectors,
        true_dot_products,
    }
}

/// Compute ranking from dot products
fn compute_ranking(dot_products: &[Fr]) -> Vec<usize> {
    let mut indexed: Vec<(usize, f64)> = dot_products
        .iter()
        .enumerate()
        .map(|(i, &dp)| (i, fr_to_f64(dp)))
        .collect();
    
    // Sort by dot product (descending)
    indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    
    // Return indices in ranked order
    indexed.iter().map(|(i, _)| *i).collect()
}

/// Compute Kendall's Tau (ranking correlation)
fn kendall_tau(ranking1: &[usize], ranking2: &[usize]) -> f64 {
    let n = ranking1.len();
    
    // Create inverse mappings (position of each element)
    let mut pos1 = vec![0; n];
    let mut pos2 = vec![0; n];
    for i in 0..n {
        pos1[ranking1[i]] = i;
        pos2[ranking2[i]] = i;
    }
    
    // Count concordant and discordant pairs
    let mut concordant = 0;
    let mut discordant = 0;
    
    for i in 0..n {
        for j in (i + 1)..n {
            let diff1 = pos1[i] as i32 - pos1[j] as i32;
            let diff2 = pos2[i] as i32 - pos2[j] as i32;
            
            if diff1 * diff2 > 0 {
                concordant += 1;
            } else if diff1 * diff2 < 0 {
                discordant += 1;
            }
        }
    }
    
    let total_pairs = (n * (n - 1)) / 2;
    (concordant as f64 - discordant as f64) / total_pairs as f64
}

/// Test ranking accuracy with random projection
fn test_ranking_accuracy(test_name: &str, test_data: TestData) {
    let separator = "=".repeat(80);
    println!("\n{}", separator);
    println!("  Testing: {}", test_name);
    println!("{}", separator);
    
    let mut rng = StdRng::seed_from_u64(12345);
    
    // Create random projection
    let rp = RandomProjection::new(FULL_DIM, COMPRESSED_DIM, EPSILON, &mut rng);
    
    println!("Compression: {} → {} dimensions ({:.1}x reduction)",
             FULL_DIM, COMPRESSED_DIM, FULL_DIM as f64 / COMPRESSED_DIM as f64);
    
    // Compress vectors
    let query_compressed = rp.compress(&test_data.query);
    let data_compressed: Vec<Vec<Fr>> = test_data
        .data_vectors
        .iter()
        .map(|v| rp.compress(v))
        .collect();
    
    // Compute compressed dot products (in plaintext, for accuracy measurement)
    let compressed_dot_products: Vec<Fr> = data_compressed
        .iter()
        .map(|y| dot_product(&query_compressed, y))
        .collect();
    
    // Compute rankings
    let true_ranking = compute_ranking(&test_data.true_dot_products);
    let compressed_ranking = compute_ranking(&compressed_dot_products);
    
    // Compute Kendall's Tau
    let tau = kendall_tau(&true_ranking, &compressed_ranking);
    
    println!("\nRanking Correlation (Kendall's Tau): {:.4}", tau);
    println!("  (1.0 = perfect correlation, 0.0 = random, -1.0 = inverse)");
    
    // Show top-10 comparison
    println!("\nTop-10 Comparison:");
    println!("  Rank | True Index | Compressed Index | Match?");
    println!("  -----|------------|------------------|-------");
    for rank in 0..10.min(NUM_TEST_VECTORS) {
        let true_idx = true_ranking[rank];
        let comp_idx = compressed_ranking[rank];
        let match_str = if true_idx == comp_idx { "✓" } else { "✗" };
        println!("  {:4} | {:10} | {:16} | {}", rank + 1, true_idx, comp_idx, match_str);
    }
    
    // Compute Top-K accuracy
    let top_k_values = vec![1, 5, 10, 20];
    println!("\nTop-K Accuracy:");
    for k in top_k_values {
        if k > NUM_TEST_VECTORS {
            continue;
        }
        let true_top_k: std::collections::HashSet<_> = true_ranking[..k].iter().collect();
        let comp_top_k: std::collections::HashSet<_> = compressed_ranking[..k].iter().collect();
        let intersection = true_top_k.intersection(&comp_top_k).count();
        let accuracy = intersection as f64 / k as f64;
        println!("  Top-{:2}: {:.1}% ({}/{} correct)", k, accuracy * 100.0, intersection, k);
    }
}

fn bench_accuracy(_c: &mut Criterion) {
    println!("\n\n");
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║                    RANKING ACCURACY ANALYSIS                               ║");
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    
    // Test 1: Random vectors
    let random_data = generate_random_vectors(FULL_DIM, NUM_TEST_VECTORS, 42);
    test_ranking_accuracy("Random Vectors (uncorrelated)", random_data);
    
    // Test 2: Close vectors
    let close_data = generate_close_vectors(FULL_DIM, NUM_TEST_VECTORS, 123);
    test_ranking_accuracy("Close Vectors (similar/clustered)", close_data);
}

fn bench_v1_throughput(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(999);
    
    // Setup v1 with full dimension
    let (pp, msk) = v1_setup(128, FULL_DIM, SEARCH_SPACE);
    
    // Generate query and data vectors
    let query: Vec<Fr> = (0..FULL_DIM).map(|_| Fr::from(rng.gen_range(0u64..10u64))).collect();
    let data_vectors: Vec<Vec<Fr>> = (0..NUM_TEST_VECTORS)
        .map(|_| (0..FULL_DIM).map(|_| Fr::from(rng.gen_range(0u64..10u64))).collect())
        .collect();
    
    let sk = v1_keygen(&msk, &query, &mut rng);
    
    // Benchmark encryption
    c.bench_function("v1_encryption_throughput", |b| {
        b.iter(|| {
            let _cts = v1_parallel_encrypt(black_box(&msk), black_box(&data_vectors), &mut rng);
        });
    });
    
    // Pre-encrypt for decryption benchmark
    let ciphertexts = v1_parallel_encrypt(&msk, &data_vectors, &mut rng);
    
    // Benchmark decryption
    c.bench_function("v1_decryption_throughput", |b| {
        b.iter(|| {
            let _results = v1_parallel_decrypt(black_box(&pp), black_box(&sk), black_box(&ciphertexts));
        });
    });
}

fn bench_v3_throughput(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(999);
    
    // Setup v3 with compressed dimension
    let (pp, msk) = v3_setup(128, COMPRESSED_DIM, SEARCH_SPACE);
    
    // Create random projection
    let rp = RandomProjection::new(FULL_DIM, COMPRESSED_DIM, EPSILON, &mut rng);
    
    // Generate full-dimensional vectors
    let query_full: Vec<Fr> = (0..FULL_DIM).map(|_| Fr::from(rng.gen_range(0u64..10u64))).collect();
    let data_vectors_full: Vec<Vec<Fr>> = (0..NUM_TEST_VECTORS)
        .map(|_| (0..FULL_DIM).map(|_| Fr::from(rng.gen_range(0u64..10u64))).collect())
        .collect();
    
    // Compress vectors
    let query = rp.compress(&query_full);
    let data_vectors: Vec<Vec<Fr>> = data_vectors_full.iter().map(|v| rp.compress(v)).collect();
    
    let sk = v3_keygen(&msk, &query, &mut rng);
    
    // Benchmark encryption
    c.bench_function("v3_encryption_throughput", |b| {
        b.iter(|| {
            let _cts = v3_parallel_encrypt(black_box(&msk), black_box(&data_vectors), &mut rng);
        });
    });
    
    // Pre-encrypt for decryption benchmark
    let ciphertexts = v3_parallel_encrypt(&msk, &data_vectors, &mut rng);
    
    // Benchmark decryption
    c.bench_function("v3_decryption_throughput", |b| {
        b.iter(|| {
            let _results = v3_parallel_decrypt(black_box(&pp), black_box(&sk), black_box(&ciphertexts));
        });
    });
}

fn bench_comparison(_c: &mut Criterion) {
    println!("\n\n");
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║                    PERFORMANCE COMPARISON                                  ║");
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    
    let mut rng = StdRng::seed_from_u64(777);
    
    // Setup both versions
    let (pp_v1, msk_v1) = v1_setup(128, FULL_DIM, SEARCH_SPACE);
    let (pp_v3, msk_v3) = v3_setup(128, COMPRESSED_DIM, SEARCH_SPACE);
    
    // Create random projection for v3
    let rp = RandomProjection::new(FULL_DIM, COMPRESSED_DIM, EPSILON, &mut rng);
    
    // Generate test vectors
    let query_full: Vec<Fr> = (0..FULL_DIM).map(|_| Fr::from(rng.gen_range(0u64..10u64))).collect();
    let data_vectors_full: Vec<Vec<Fr>> = (0..NUM_TEST_VECTORS)
        .map(|_| (0..FULL_DIM).map(|_| Fr::from(rng.gen_range(0u64..10u64))).collect())
        .collect();
    
    // Compress for v3
    let query_compressed = rp.compress(&query_full);
    let data_vectors_compressed: Vec<Vec<Fr>> = data_vectors_full.iter()
        .map(|v| rp.compress(v))
        .collect();
    
    // Generate keys
    let sk_v1 = v1_keygen(&msk_v1, &query_full, &mut rng);
    let sk_v3 = v3_keygen(&msk_v3, &query_compressed, &mut rng);
    
    // ===== V1 Encryption =====
    println!("\n[V1] Encrypting {} vectors ({} dimensions each)...", NUM_TEST_VECTORS, FULL_DIM);
    let start = Instant::now();
    let cts_v1 = v1_parallel_encrypt(&msk_v1, &data_vectors_full, &mut rng);
    let time_v1_enc = start.elapsed();
    let throughput_v1_enc = NUM_TEST_VECTORS as f64 / time_v1_enc.as_secs_f64();
    println!("  Time: {:.2?} ({:.2} encryptions/sec)", time_v1_enc, throughput_v1_enc);
    
    // ===== V3 Encryption =====
    println!("\n[V3] Encrypting {} vectors ({} dimensions each)...", NUM_TEST_VECTORS, COMPRESSED_DIM);
    let start = Instant::now();
    let cts_v3 = v3_parallel_encrypt(&msk_v3, &data_vectors_compressed, &mut rng);
    let time_v3_enc = start.elapsed();
    let throughput_v3_enc = NUM_TEST_VECTORS as f64 / time_v3_enc.as_secs_f64();
    println!("  Time: {:.2?} ({:.2} encryptions/sec)", time_v3_enc, throughput_v3_enc);
    
    let speedup_enc = time_v1_enc.as_secs_f64() / time_v3_enc.as_secs_f64();
    println!("\n  ⚡ SPEEDUP: {:.2}x faster", speedup_enc);
    
    // ===== V1 Decryption =====
    println!("\n[V1] Decrypting {} ciphertexts ({} pairings each)...", NUM_TEST_VECTORS, FULL_DIM + 1);
    let start = Instant::now();
    let _results_v1 = v1_parallel_decrypt(&pp_v1, &sk_v1, &cts_v1);
    let time_v1_dec = start.elapsed();
    let throughput_v1_dec = NUM_TEST_VECTORS as f64 / time_v1_dec.as_secs_f64();
    println!("  Time: {:.2?} ({:.2} decryptions/sec)", time_v1_dec, throughput_v1_dec);
    
    // ===== V3 Decryption =====
    println!("\n[V3] Decrypting {} ciphertexts ({} pairings each)...", NUM_TEST_VECTORS, COMPRESSED_DIM + 1);
    let start = Instant::now();
    let _results_v3 = v3_parallel_decrypt(&pp_v3, &sk_v3, &cts_v3);
    let time_v3_dec = start.elapsed();
    let throughput_v3_dec = NUM_TEST_VECTORS as f64 / time_v3_dec.as_secs_f64();
    println!("  Time: {:.2?} ({:.2} decryptions/sec)", time_v3_dec, throughput_v3_dec);
    
    let speedup_dec = time_v1_dec.as_secs_f64() / time_v3_dec.as_secs_f64();
    println!("\n  ⚡ SPEEDUP: {:.2}x faster", speedup_dec);
    
    // ===== Summary =====
    println!("\n");
    println!("╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║                           SUMMARY                                          ║");
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!("\nDimensions:");
    println!("  V1 (full):       {} dimensions", FULL_DIM);
    println!("  V3 (compressed): {} dimensions ({:.1}x reduction)", COMPRESSED_DIM, FULL_DIM as f64 / COMPRESSED_DIM as f64);
    
    println!("\nEncryption:");
    println!("  V1: {:.2?} ({:.1} enc/s)", time_v1_enc, throughput_v1_enc);
    println!("  V3: {:.2?} ({:.1} enc/s)", time_v3_enc, throughput_v3_enc);
    println!("  Speedup: {:.2}x", speedup_enc);
    
    println!("\nDecryption:");
    println!("  V1: {:.2?} ({:.1} dec/s)", time_v1_dec, throughput_v1_dec);
    println!("  V3: {:.2?} ({:.1} dec/s)", time_v3_dec, throughput_v3_dec);
    println!("  Speedup: {:.2}x", speedup_dec);
    
    println!("\n");
}

criterion_group!(
    benches,
    bench_accuracy,
    bench_comparison,
    bench_v1_throughput,
    bench_v3_throughput,
);
criterion_main!(benches);
