use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_std::rand::SeedableRng;
use rand::rngs::StdRng;
use rand::Rng as RandRng;
use fhipe_rust::v3::compression::RandomProjection;

fn dot_product(x: &[Fr], y: &[Fr]) -> Fr {
    x.iter().zip(y.iter()).map(|(xi, yi)| *xi * yi).sum()
}

fn fr_to_f64(x: Fr) -> f64 {
    let bigint = x.into_bigint();
    bigint.0[0] as f64
}

fn main() {
    let mut rng = StdRng::seed_from_u64(42);
    
    let source_dim = 384;
    let target_dim = 256;  // Match benchmark setting
    
    println!("Testing Random Projection Accuracy");
    println!("Source dim: {}, Target dim: {}", source_dim, target_dim);
    println!();
    
    // Create random projection
    let rp = RandomProjection::new(source_dim, target_dim, 0.1, &mut rng);
    
    // Test 1: Random vectors
    println!("=== Test 1: Random Vectors ===");
    let query: Vec<Fr> = (0..source_dim).map(|_| Fr::from(rng.gen_range(0u64..100u64))).collect();
    
    let mut data: Vec<Vec<Fr>> = Vec::new();
    for _ in 0..10 {
        data.push((0..source_dim).map(|_| Fr::from(rng.gen_range(0u64..100u64))).collect());
    }
    
    // Compute true dot products
    let true_dots: Vec<f64> = data.iter().map(|d| fr_to_f64(dot_product(&query, d))).collect();
    
    // Compress and compute compressed dot products
    let query_comp = rp.compress(&query);
    let data_comp: Vec<Vec<Fr>> = data.iter().map(|d| rp.compress(d)).collect();
    let comp_dots: Vec<f64> = data_comp.iter().map(|d| fr_to_f64(dot_product(&query_comp, d))).collect();
    
    println!("Original dot products:");
    for (i, &d) in true_dots.iter().enumerate() {
        println!("  Vec {}: {:.0}", i, d);
    }
    
    println!("\nCompressed dot products (should preserve ranking):");
    for (i, &d) in comp_dots.iter().enumerate() {
        println!("  Vec {}: {:.0}", i, d);
    }
    
    // Check ranking preservation
    let mut true_ranked: Vec<usize> = (0..10).collect();
    true_ranked.sort_by(|&a, &b| true_dots[b].partial_cmp(&true_dots[a]).unwrap());
    
    let mut comp_ranked: Vec<usize> = (0..10).collect();
    comp_ranked.sort_by(|&a, &b| comp_dots[b].partial_cmp(&comp_dots[a]).unwrap());
    
    println!("\nRanking comparison:");
    println!("  True ranking: {:?}", true_ranked);
    println!("  Comp ranking: {:?}", comp_ranked);
    
    let mut matches = 0;
    for i in 0..10 {
        if true_ranked[i] == comp_ranked[i] {
            matches += 1;
        }
    }
    println!("  Exact matches: {}/10", matches);
    
    // Test 2: Close vectors
    println!("\n=== Test 2: Close Vectors (clustered) ===");
    let base: Vec<Fr> = (0..source_dim).map(|_| Fr::from(50u64)).collect();
    
    let mut close_data: Vec<Vec<Fr>> = Vec::new();
    for _ in 0..10 {
        let perturbed: Vec<Fr> = base.iter()
            .map(|&b| {
                let noise = rng.gen_range(-5i64..6i64);
                if noise >= 0 {
                    b + Fr::from(noise as u64)
                } else {
                    b - Fr::from((-noise) as u64)
                }
            })
            .collect();
        close_data.push(perturbed);
    }
    
    let close_query = base.clone();
    
    // Compute true dot products
    let true_dots2: Vec<f64> = close_data.iter().map(|d| fr_to_f64(dot_product(&close_query, d))).collect();
    
    // Compress
    let close_query_comp = rp.compress(&close_query);
    let close_data_comp: Vec<Vec<Fr>> = close_data.iter().map(|d| rp.compress(d)).collect();
    let comp_dots2: Vec<f64> = close_data_comp.iter().map(|d| fr_to_f64(dot_product(&close_query_comp, d))).collect();
    
    println!("Original dot products:");
    for (i, &d) in true_dots2.iter().enumerate() {
        println!("  Vec {}: {:.0}", i, d);
    }
    
    println!("\nCompressed dot products:");
    for (i, &d) in comp_dots2.iter().enumerate() {
        println!("  Vec {}: {:.0}", i, d);
    }
    
    // Check ranking
    let mut true_ranked2: Vec<usize> = (0..10).collect();
    true_ranked2.sort_by(|&a, &b| true_dots2[b].partial_cmp(&true_dots2[a]).unwrap());
    
    let mut comp_ranked2: Vec<usize> = (0..10).collect();
    comp_ranked2.sort_by(|&a, &b| comp_dots2[b].partial_cmp(&comp_dots2[a]).unwrap());
    
    println!("\nRanking comparison:");
    println!("  True ranking: {:?}", true_ranked2);
    println!("  Comp ranking: {:?}", comp_ranked2);
    
    let mut matches2 = 0;
    for i in 0..10 {
        if true_ranked2[i] == comp_ranked2[i] {
            matches2 += 1;
        }
    }
    println!("  Exact matches: {}/10", matches2);
    
    println!("\n=== VERDICT ===");
    if matches >= 7 && matches2 >= 7 {
        println!("✓ Random projection is working well!");
    } else {
        println!("✗ Random projection is NOT preserving rankings properly!");
        println!("  This needs to be fixed before running full benchmarks.");
    }
}
