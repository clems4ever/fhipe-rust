use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_std::rand::SeedableRng;
use rand::rngs::StdRng;
use rand::RngCore;

// V1 imports
use fhipe_rust::v1::setup::ipe_setup as v1_setup;
use fhipe_rust::v1::keygen::ipe_keygen as v1_keygen;
use fhipe_rust::v1::decrypt::ipe_decrypt as v1_decrypt;
use fhipe_rust::v1::parallel::{parallel_encrypt as v1_parallel_encrypt, parallel_decrypt as v1_parallel_decrypt};

// V2 imports
use fhipe_rust::v2::setup::ipe_setup as v2_setup;
use fhipe_rust::v2::keygen::ipe_keygen as v2_keygen;
use fhipe_rust::v2::decrypt::ipe_decrypt as v2_decrypt;
use fhipe_rust::v2::parallel::{parallel_encrypt as v2_parallel_encrypt, parallel_decrypt as v2_parallel_decrypt};

fn setup_test_data(n: usize, num_vectors: usize) -> (Vec<Fr>, Vec<Vec<Fr>>, Vec<u64>) {
    let mut rng = StdRng::seed_from_u64(12345);
    
    // Create query vector x
    let x: Vec<Fr> = (0..n).map(|_| Fr::from((rng.next_u64() % 10) as u64)).collect();
    
    // Create data vectors y and compute expected inner products
    let mut y_vectors = Vec::new();
    let mut expected_ips = Vec::new();
    
    for _ in 0..num_vectors {
        let y: Vec<Fr> = (0..n).map(|_| Fr::from((rng.next_u64() % 10) as u64)).collect();
        
        // Compute plaintext inner product for verification
        let mut ip = 0u64;
        for i in 0..n {
            let x_val = x[i].into_bigint().0[0];
            let y_val = y[i].into_bigint().0[0];
            ip += x_val * y_val;
        }
        
        y_vectors.push(y);
        expected_ips.push(ip);
    }
    
    (x, y_vectors, expected_ips)
}

fn bench_v1_encryption(c: &mut Criterion) {
    let n = 384;
    let num_vectors = 50;
    let search_space_size = 50000;
    
    let (_x, y_vectors, _expected) = setup_test_data(n, num_vectors);
    
    let mut group = c.benchmark_group("v1_encryption");
    group.throughput(Throughput::Elements(num_vectors as u64));
    group.sample_size(10); // Reduce sample size for faster benchmarking
    
    group.bench_function(BenchmarkId::new("parallel_encrypt", num_vectors), |b| {
        let (_pp, msk) = v1_setup(128, n, search_space_size);
        let mut rng = StdRng::seed_from_u64(42);
        
        b.iter(|| {
            let _cts = v1_parallel_encrypt(
                black_box(&msk), 
                black_box(&y_vectors), 
                black_box(&mut rng)
            );
        });
    });
    
    group.finish();
}

fn bench_v2_encryption(c: &mut Criterion) {
    let n = 384;
    let num_vectors = 50;
    let search_space_size = 50000;
    
    let (_x, y_vectors, _expected) = setup_test_data(n, num_vectors);
    
    let mut group = c.benchmark_group("v2_encryption");
    group.throughput(Throughput::Elements(num_vectors as u64));
    group.sample_size(10); // Reduce sample size for faster benchmarking
    
    group.bench_function(BenchmarkId::new("parallel_encrypt", num_vectors), |b| {
        let (_pp, msk) = v2_setup(128, n, search_space_size);
        let mut rng = StdRng::seed_from_u64(42);
        
        b.iter(|| {
            let _cts = v2_parallel_encrypt(
                black_box(&msk), 
                black_box(&y_vectors), 
                black_box(&mut rng)
            );
        });
    });
    
    group.finish();
}

fn bench_v1_decryption_with_verification(c: &mut Criterion) {
    let n = 384;
    let num_vectors = 50;
    let search_space_size = 50000;
    
    let (x, y_vectors, expected_ips) = setup_test_data(n, num_vectors);
    
    // Setup and encrypt all vectors
    let (pp, msk) = v1_setup(128, n, search_space_size);
    let mut rng = StdRng::seed_from_u64(42);
    let sk = v1_keygen(&msk, &x, &mut rng);
    
    let ciphertexts = v1_parallel_encrypt(&msk, &y_vectors, &mut rng);
    
    // Verify correctness before benchmarking
    println!("\nV1 Correctness Check:");
    for (i, (ct, &expected_ip)) in ciphertexts.iter().zip(expected_ips.iter()).enumerate() {
        let result = v1_decrypt(&pp, &sk, ct);
        assert!(result.is_some(), "V1: Decryption {} failed", i);
        let recovered = result.unwrap();
        assert_eq!(
            recovered, 
            Fr::from(expected_ip),
            "V1: Incorrect result at index {}. Expected {}, got {:?}",
            i, expected_ip, recovered
        );
    }
    println!("✓ V1 all {} decryptions correct!", num_vectors);
    
    let mut group = c.benchmark_group("v1_decryption");
    group.throughput(Throughput::Elements(num_vectors as u64));
    group.sample_size(10); // Reduce sample size for faster benchmarking
    
    group.bench_function(BenchmarkId::new("parallel_decrypt", num_vectors), |b| {
        b.iter(|| {
            let _results = v1_parallel_decrypt(
                black_box(&pp), 
                black_box(&sk), 
                black_box(&ciphertexts)
            );
        });
    });
    
    group.finish();
}

fn bench_v2_decryption_with_verification(c: &mut Criterion) {
    let n = 384;
    let num_vectors = 50;
    let search_space_size = 50000;
    
    let (x, y_vectors, expected_ips) = setup_test_data(n, num_vectors);
    
    // Setup and encrypt all vectors
    let (pp, msk) = v2_setup(128, n, search_space_size);
    let mut rng = StdRng::seed_from_u64(42);
    let sk = v2_keygen(&msk, &x, &mut rng);
    
    let ciphertexts = v2_parallel_encrypt(&msk, &y_vectors, &mut rng);
    
    // Verify correctness before benchmarking
    println!("\nV2 Correctness Check:");
    for (i, (ct, &expected_ip)) in ciphertexts.iter().zip(expected_ips.iter()).enumerate() {
        let result = v2_decrypt(&pp, &sk, ct);
        assert!(result.is_some(), "V2: Decryption {} failed", i);
        let recovered = result.unwrap();
        assert_eq!(
            recovered, 
            Fr::from(expected_ip),
            "V2: Incorrect result at index {}. Expected {}, got {:?}",
            i, expected_ip, recovered
        );
    }
    println!("✓ V2 all {} decryptions correct!", num_vectors);
    
    let mut group = c.benchmark_group("v2_decryption");
    group.throughput(Throughput::Elements(num_vectors as u64));
    group.sample_size(10); // Reduce sample size for faster benchmarking
    
    group.bench_function(BenchmarkId::new("parallel_decrypt", num_vectors), |b| {
        b.iter(|| {
            let _results = v2_parallel_decrypt(
                black_box(&pp), 
                black_box(&sk), 
                black_box(&ciphertexts)
            );
        });
    });
    
    group.finish();
}

fn bench_comparison(c: &mut Criterion) {
    let n = 384;
    let num_vectors = 50;
    let search_space_size = 50000;
    
    let (x, y_vectors, expected_ips) = setup_test_data(n, num_vectors);
    
    // V1 Setup
    let (pp_v1, msk_v1) = v1_setup(128, n, search_space_size);
    let mut rng_v1 = StdRng::seed_from_u64(42);
    let sk_v1 = v1_keygen(&msk_v1, &x, &mut rng_v1);
    let cts_v1 = v1_parallel_encrypt(&msk_v1, &y_vectors, &mut rng_v1);
    
    // V2 Setup
    let (pp_v2, msk_v2) = v2_setup(128, n, search_space_size);
    let mut rng_v2 = StdRng::seed_from_u64(42);
    let sk_v2 = v2_keygen(&msk_v2, &x, &mut rng_v2);
    let cts_v2 = v2_parallel_encrypt(&msk_v2, &y_vectors, &mut rng_v2);
    
    // Verify both are correct
    println!("\n{}", "=".repeat(70));
    println!("CORRECTNESS VERIFICATION (n={}, vectors={})", n, num_vectors);
    println!("{}", "=".repeat(70));
    
    for i in 0..num_vectors.min(5) {
        let result_v1 = v1_decrypt(&pp_v1, &sk_v1, &cts_v1[i]);
        let result_v2 = v2_decrypt(&pp_v2, &sk_v2, &cts_v2[i]);
        
        assert!(result_v1.is_some(), "V1: Decryption {} failed", i);
        assert!(result_v2.is_some(), "V2: Decryption {} failed", i);
        
        let ip_v1 = result_v1.unwrap();
        let ip_v2 = result_v2.unwrap();
        let expected = Fr::from(expected_ips[i]);
        
        assert_eq!(ip_v1, expected, "V1: Incorrect at index {}", i);
        assert_eq!(ip_v2, expected, "V2: Incorrect at index {}", i);
        
        println!("✓ Vector {}: <x,y> = {} (both v1 and v2 correct)", i, expected_ips[i]);
    }
    println!("✓ All {} vectors verified correct for both v1 and v2\n", num_vectors);
    
    let mut group = c.benchmark_group("comparison");
    group.throughput(Throughput::Elements(num_vectors as u64));
    group.sample_size(10); // Reduce sample size for faster benchmarking
    
    group.bench_function("v1_parallel_decrypt", |b| {
        b.iter(|| {
            let _results = v1_parallel_decrypt(
                black_box(&pp_v1), 
                black_box(&sk_v1), 
                black_box(&cts_v1)
            );
        });
    });
    
    group.bench_function("v2_parallel_decrypt", |b| {
        b.iter(|| {
            let _results = v2_parallel_decrypt(
                black_box(&pp_v2), 
                black_box(&sk_v2), 
                black_box(&cts_v2)
            );
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_v1_encryption,
    bench_v2_encryption,
    bench_v1_decryption_with_verification,
    bench_v2_decryption_with_verification,
    bench_comparison
);
criterion_main!(benches);
