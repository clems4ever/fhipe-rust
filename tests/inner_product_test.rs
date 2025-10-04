//! Test to verify that FH-IPE correctly computes inner products

use fhipe_rust::{setup, keygen, encrypt, decrypt};
use fhipe_rust::util::field_inner_product;
use ark_bls12_381::{Fr, Bls12_381, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{UniformRand, Field, PrimeField};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn test_inner_product_correctness_multiple_vectors() {
    let mut rng = StdRng::seed_from_u64(12345);
    let n = 10; // vector dimension
    
    // Setup
    let (pp, msk) = setup(n, &mut rng);
    
    // Generate 10 random vectors
    let vectors: Vec<Vec<Fr>> = (0..10)
        .map(|_| (0..n).map(|_| Fr::rand(&mut rng)).collect())
        .collect();
    
    // Use the first vector as the key vector
    let x = &vectors[0];
    let sk = keygen(&msk, &pp, x, &mut rng);
    
    // Compute base pairing e(g1, g2) for verification
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let base_pairing = <Bls12_381 as Pairing>::pairing(g1, g2);
    
    println!("\nTesting inner products between vector 0 and all 10 vectors:");
    println!("Vector dimension: {}", n);
    
    // For each vector (including the first one with itself)
    for (i, y) in vectors.iter().enumerate() {
        // Compute expected inner product in the clear
        let expected_ip = field_inner_product(x, y);
        
        // Encrypt y and decrypt to get e(g1, g2)^<x,y>
        let ct = encrypt(&pp, y, &mut rng);
        let result_gt = decrypt(&pp, &sk, &ct);
        
        // Compute expected pairing result: e(g1, g2)^<x,y>
        let expected_gt = base_pairing.0.pow(expected_ip.into_bigint());
        
        println!("Vector {}: <x, y> computed via IPE matches clear computation: {}", 
                 i, result_gt == expected_gt);
        
        // Assert correctness
        assert_eq!(result_gt, expected_gt,
                   "IPE decryption for vector {} should equal e(g1,g2)^<x,y>", i);
    }
    
    println!("\n✓ All 10 inner products computed correctly via FH-IPE!");
}

#[test]
fn test_inner_product_zero_orthogonal() {
    let mut rng = StdRng::seed_from_u64(99999);
    let n = 4;
    
    let (pp, msk) = setup(n, &mut rng);
    
    // Create orthogonal vectors: x = [1, 0, 0, 0], y = [0, 1, 0, 0]
    let x = vec![Fr::from(1u64), Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)];
    let y = vec![Fr::from(0u64), Fr::from(1u64), Fr::from(0u64), Fr::from(0u64)];
    
    let ip_clear = field_inner_product(&x, &y);
    assert_eq!(ip_clear, Fr::from(0u64), "Orthogonal vectors should have zero inner product");
    
    let sk = keygen(&msk, &pp, &x, &mut rng);
    let ct = encrypt(&pp, &y, &mut rng);
    let result = decrypt(&pp, &sk, &ct);
    
    // e(g1, g2)^0 should equal 1 in GT
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let base_pairing = <Bls12_381 as Pairing>::pairing(g1, g2);
    let expected = base_pairing.0.pow(Fr::from(0u64).into_bigint());
    
    assert_eq!(result, expected, "Zero inner product should give e(g1,g2)^0");
    println!("✓ Zero inner product verified!");
}

#[test]
fn test_inner_product_negative_values() {
    let mut rng = StdRng::seed_from_u64(54321);
    let n = 5;
    
    let (pp, msk) = setup(n, &mut rng);
    
    // Test with negative field elements (represented as p - value)
    let x = vec![
        Fr::from(3u64),
        -Fr::from(2u64),  // -2 in Fr
        Fr::from(1u64),
        Fr::from(0u64),
        -Fr::from(4u64),  // -4 in Fr
    ];
    
    let y = vec![
        Fr::from(2u64),
        Fr::from(3u64),
        -Fr::from(1u64),  // -1 in Fr
        Fr::from(5u64),
        Fr::from(2u64),
    ];
    
    // Expected: 3*2 + (-2)*3 + 1*(-1) + 0*5 + (-4)*2 = 6 - 6 - 1 + 0 - 8 = -9
    let ip_clear = field_inner_product(&x, &y);
    let expected_scalar = Fr::from(3u64) * Fr::from(2u64) 
                        + (-Fr::from(2u64)) * Fr::from(3u64)
                        + Fr::from(1u64) * (-Fr::from(1u64))
                        + (-Fr::from(4u64)) * Fr::from(2u64);
    assert_eq!(ip_clear, expected_scalar);
    
    let sk = keygen(&msk, &pp, &x, &mut rng);
    let ct = encrypt(&pp, &y, &mut rng);
    let result = decrypt(&pp, &sk, &ct);
    
    // Verify against e(g1, g2)^<x,y>
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    let base_pairing = <Bls12_381 as Pairing>::pairing(g1, g2);
    let expected = base_pairing.0.pow(ip_clear.into_bigint());
    
    assert_eq!(result, expected, "Inner product with negative values should be correct");
    println!("✓ Negative values inner product verified!");
}
