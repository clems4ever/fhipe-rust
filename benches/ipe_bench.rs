use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use fhipe_rust::{
    setup::ipe_setup,
    keygen::ipe_keygen,
    encrypt::ipe_encrypt,
    decrypt::ipe_decrypt,
};
use ark_bls12_381::Fr;
use ark_std::rand::SeedableRng;
use rand::rngs::StdRng;

const VECTOR_DIM: usize = 384;
const NUM_VECTORS: usize = 50;
const SEARCH_SPACE: usize = 10000; // Reduced for faster benchmarking

fn benchmark_batch_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_encryption");
    group.sample_size(10); // Fewer samples since operations are slow
    group.measurement_time(std::time::Duration::from_secs(30)); // 30 seconds per benchmark
    
    // Setup: Generate MSK once
    let lambda = 128;
    println!("\n[Setup] Generating master secret key...");
    let (_pp, msk) = ipe_setup(lambda, VECTOR_DIM, SEARCH_SPACE);
    
    // Generate NUM_VECTORS random vectors to encrypt (small values)
    println!("[Setup] Generating {} vectors of dimension {}...", NUM_VECTORS, VECTOR_DIM);
    let vectors: Vec<Vec<Fr>> = (0..NUM_VECTORS)
        .map(|_| (0..VECTOR_DIM).map(|_| Fr::from((rand::random::<u8>() % 10) as u64)).collect())
        .collect();
    
    println!("[Benchmark] Starting batch encryption benchmark...");
    group.bench_function(
        BenchmarkId::new("encrypt_batch", format!("{}_vectors_dim_{}", NUM_VECTORS, VECTOR_DIM)),
        |b| {
            b.iter(|| {
                let mut local_rng = StdRng::seed_from_u64(42);
                for vector in &vectors {
                    let _ct = ipe_encrypt(black_box(&msk), black_box(vector), &mut local_rng);
                }
            });
        },
    );
    
    group.finish();
}

fn benchmark_batch_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_decryption");
    group.sample_size(10); // Fewer samples since operations are slow
    group.measurement_time(std::time::Duration::from_secs(30)); // 30 seconds per benchmark
    
    // Setup: Generate MSK once
    let lambda = 128;
    let (pp, msk) = ipe_setup(lambda, VECTOR_DIM, SEARCH_SPACE);
    let mut rng = StdRng::seed_from_u64(42);
    
    // Generate NUM_VECTORS random vectors and encrypt them
    println!("\n[Setup] Encrypting {} vectors of dimension {}...", NUM_VECTORS, VECTOR_DIM);
    let vectors: Vec<Vec<Fr>> = (0..NUM_VECTORS)
        .map(|_| {
            // Use small values to ensure inner products are in search space
            (0..VECTOR_DIM).map(|_| Fr::from((rand::random::<u8>() % 10) as u64)).collect()
        })
        .collect();
    
    let ciphertexts: Vec<_> = vectors
        .iter()
        .map(|v| ipe_encrypt(&msk, v, &mut rng))
        .collect();
    
    println!("[Setup] Encryption complete. Generating query vector and key...");
    
    // Generate a random query vector
    let query: Vec<Fr> = (0..VECTOR_DIM)
        .map(|_| Fr::from((rand::random::<u8>() % 10) as u64))
        .collect();
    
    // Generate secret key for query once (as a client would)
    let sk = ipe_keygen(&msk, &query, &mut rng);
    
    println!("[Benchmark] Starting batch decryption benchmark...");
    group.bench_function(
        BenchmarkId::new("decrypt_batch", format!("{}_vectors_dim_{}", NUM_VECTORS, VECTOR_DIM)),
        |b| {
            b.iter(|| {
                // Decrypt all ciphertexts with the same secret key
                for ct in &ciphertexts {
                    let _result = ipe_decrypt(black_box(&pp), black_box(&sk), black_box(ct));
                }
            });
        },
    );
    
    group.finish();
}

fn benchmark_single_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_operations");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(20)); // 20 seconds per benchmark
    
    let lambda = 128;
    println!("\n[Setup] Generating master secret key for single operation benchmarks...");
    let (pp, msk) = ipe_setup(lambda, VECTOR_DIM, SEARCH_SPACE);
    let mut rng = StdRng::seed_from_u64(42);
    
    // Test vector with small values
    let vector: Vec<Fr> = (0..VECTOR_DIM)
        .map(|_| Fr::from((rand::random::<u8>() % 10) as u64))
        .collect();
    
    // Benchmark single encryption
    group.bench_function(
        BenchmarkId::new("single_encrypt", format!("dim_{}", VECTOR_DIM)),
        |b| {
            b.iter(|| {
                let mut local_rng = StdRng::seed_from_u64(42);
                let _ct = ipe_encrypt(black_box(&msk), black_box(&vector), &mut local_rng);
            });
        },
    );
    
    // Benchmark single key generation
    group.bench_function(
        BenchmarkId::new("single_keygen", format!("dim_{}", VECTOR_DIM)),
        |b| {
            b.iter(|| {
                let mut local_rng = StdRng::seed_from_u64(42);
                let _sk = ipe_keygen(black_box(&msk), black_box(&vector), &mut local_rng);
            });
        },
    );
    
    // Prepare for decryption benchmark
    let ct = ipe_encrypt(&msk, &vector, &mut rng);
    let sk = ipe_keygen(&msk, &vector, &mut rng);
    
    // Benchmark single decryption
    group.bench_function(
        BenchmarkId::new("single_decrypt", format!("dim_{}", VECTOR_DIM)),
        |b| {
            b.iter(|| {
                let _result = ipe_decrypt(black_box(&pp), black_box(&sk), black_box(&ct));
            });
        },
    );
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_single_operations,
    benchmark_batch_encryption,
    benchmark_batch_decryption
);
criterion_main!(benches);
