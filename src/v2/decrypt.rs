use ark_bls12_381::Bls12_381;
use ark_ec::{
    pairing::Pairing,
    CurveGroup,
};
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use std::collections::HashMap;

use crate::v2::setup::PublicParams;
use crate::v2::keygen::SecretKey;
use crate::v2::encrypt::Ciphertext;

type Gt = <Bls12_381 as Pairing>::TargetField;
type Fr = ark_bls12_381::Fr;
type G1Prepared = <Bls12_381 as Pairing>::G1Prepared;
type G2Prepared = <Bls12_381 as Pairing>::G2Prepared;

/// Baby-Step Giant-Step algorithm for discrete logarithm in GT
/// 
/// Find z such that base^z = target, where 0 ≤ z < max_value
/// 
/// Complexity: O(√max_value) time, O(√max_value) space
/// 
/// # Algorithm
/// 1. Let m = ⌈√max_value⌉
/// 2. Baby steps: Compute and store base^j for j = 0..m in a hash table
/// 3. Giant steps: Compute base^(-m), then check if target * (base^(-m))^i is in table
/// 4. If found at index j with giant step i, then z = i*m + j
fn baby_step_giant_step(base: Gt, target: Gt, max_value: usize) -> Option<Fr> {
    if max_value == 0 {
        return None;
    }
    
    // Special case: check if target == 1 (z = 0)
    if target == Gt::from(1u64) {
        return Some(Fr::from(0u64));
    }
    
    // m = ceiling(sqrt(max_value))
    let m = (max_value as f64).sqrt().ceil() as usize;
    
    // Pre-allocate serialization buffer to avoid repeated allocations
    let mut scratch_buffer = Vec::with_capacity(576); // GT elements serialize to 576 bytes
    
    // Baby steps: Build hash table using serialized bytes as keys
    let mut baby_steps = HashMap::with_capacity(m + 1);
    let mut current = Gt::from(1u64); // base^0
    
    for j in 0..=m {
        // Serialize to bytes for consistent hashing
        scratch_buffer.clear();
        current.serialize_compressed(&mut scratch_buffer).unwrap();
        baby_steps.insert(scratch_buffer.clone(), j);
        
        if j < m {
            current *= base; // Compute base^(j+1)
        }
    }
    
    // base_m is the last computed value (base^m)
    let base_m = current;
    
    // Compute base^(-m) = (base^m)^(-1)
    let base_inv_m = base_m.inverse().unwrap();
    
    // Giant steps: Check if target * (base^(-m))^i is in the baby_steps table
    let mut gamma = target;
    
    for i in 0..=m {
        // Serialize gamma to check if it's in the baby steps
        scratch_buffer.clear();
        gamma.serialize_compressed(&mut scratch_buffer).unwrap();
        
        if let Some(&j) = baby_steps.get(&scratch_buffer) {
            // Found! z = i*m + j
            let z_val = i * m + j;
            if z_val < max_value {
                return Some(Fr::from(z_val as u64));
            }
        }
        
        if i < m {
            gamma *= base_inv_m; // Compute target * (base^(-m))^(i+1)
        }
    }
    
    // Not found in search space
    None
}

/// IPE.Decrypt(pp, sk, ct): Decryption algorithm for Inner Product Encryption with correlated bases
/// 
/// # Arguments
/// * `pp` - Public parameters containing the search space S
/// * `sk` - Secret key sk = (K1, K2) where K2 is a vector with correlated bases
/// * `ct` - Ciphertext ct = (C1, C2) where C2 is a vector with correlated bases
/// 
/// # Returns
/// * `Option<Fr>` - The inner product z if found, None otherwise
/// 
/// This function computes:
/// - D1 = e(K1, C1) = e(g1, g2)^(α·β·det(B))
/// - D2 = multi_pairing(K2, C2) = ∏ᵢ e(K2[i], C2[i]) = ∏ᵢ e(Uᵢ, Vᵢ)^(α·β·uᵢ·vᵢ)
/// Since e(Uᵢ, Vᵢ) = e(g1, g2), this simplifies to: D2 = e(g1, g2)^(α·β·Σᵢ uᵢ·vᵢ) = e(g1, g2)^(α·β·det(B)·<x,y>)
/// Then searches for z ∈ S such that (D1)^z = D2
///
/// Key improvement: Uses CONSTANT number of pairings (1 for D1, 1 multi-pairing for D2)
/// regardless of vector dimension n!
pub fn ipe_decrypt(pp: &PublicParams, sk: &SecretKey, ct: &Ciphertext) -> Option<Fr> {
    // Compute D1 = e(K1, C1) using prepared pairings
    let k1_prep: G1Prepared = G1Prepared::from(sk.k1.into_affine());
    let c1_prep: G2Prepared = G2Prepared::from(ct.c1.into_affine());
    let ml_d1 = Bls12_381::multi_miller_loop(std::iter::once(k1_prep), std::iter::once(c1_prep));
    let d1 = Bls12_381::final_exponentiation(ml_d1).unwrap().0;
    
    // Compute D2 = ∏ᵢ e(K2[i], C2[i]) using multi-pairing
    // K2[i] = Uᵢ^(α·uᵢ), C2[i] = Vᵢ^(β·vᵢ)
    // e(K2[i], C2[i]) = e(Uᵢ, Vᵢ)^(α·β·uᵢ·vᵢ) = e(g1, g2)^(α·β·uᵢ·vᵢ)
    // ∏ᵢ e(K2[i], C2[i]) = e(g1, g2)^(α·β·Σᵢ uᵢ·vᵢ) = e(g1, g2)^(α·β·det(B)·<x,y>)
    let k2_prep: Vec<G1Prepared> = sk.k2.iter().map(|p| G1Prepared::from(p.into_affine())).collect();
    let c2_prep: Vec<G2Prepared> = ct.c2.iter().map(|p| G2Prepared::from(p.into_affine())).collect();
    let ml_d2 = Bls12_381::multi_miller_loop(k2_prep.into_iter(), c2_prep.into_iter());
    let d2 = Bls12_381::final_exponentiation(ml_d2).unwrap().0;
    
    // Search for z ∈ S such that (D1)^z = D2 using Baby-Step Giant-Step
    // This is more efficient than linear search: O(√|S|) instead of O(|S|)
    baby_step_giant_step(d1, d2, pp.search_space_size)
}

/// Prepared secret key to speed up repeated decryptions with the same key
#[derive(Clone)]
pub struct PreparedSecretKey {
    pub k1_prep: G1Prepared,
    pub k2_prep: Vec<G1Prepared>,
}

/// Prepare a secret key once to reuse pairing precomputations across decryptions
pub fn prepare_secret_key(sk: &SecretKey) -> PreparedSecretKey {
    let k1_prep = G1Prepared::from(sk.k1.into_affine());
    let k2_prep = sk.k2.iter().map(|p| G1Prepared::from(p.into_affine())).collect();
    PreparedSecretKey { k1_prep, k2_prep }
}

/// IPE.Decrypt using a prepared secret key (reuses prepared K2 across decryptions)
pub fn ipe_decrypt_prepared(pp: &PublicParams, psk: &PreparedSecretKey, ct: &Ciphertext) -> Option<Fr> {
    // Prepare C1 once per ciphertext
    let c1_prep: G2Prepared = G2Prepared::from(ct.c1.into_affine());
    let ml_d1 = Bls12_381::multi_miller_loop(std::iter::once(psk.k1_prep.clone()), std::iter::once(c1_prep));
    let d1 = Bls12_381::final_exponentiation(ml_d1).unwrap().0;

    // Prepare C2 per ciphertext, reuse prepared K2 from the secret key
    let c2_prep: Vec<G2Prepared> = ct.c2.iter().map(|p| G2Prepared::from(p.into_affine())).collect();
    let ml_d2 = Bls12_381::multi_miller_loop(psk.k2_prep.clone().into_iter(), c2_prep.into_iter());
    let d2 = Bls12_381::final_exponentiation(ml_d2).unwrap().0;

    baby_step_giant_step(d1, d2, pp.search_space_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::setup::ipe_setup;
    use crate::v2::keygen::ipe_keygen;
    use crate::v2::encrypt::ipe_encrypt;
    use ark_bls12_381::Fr;
    use ark_ff::PrimeField;
    use ark_std::rand::SeedableRng;
    use rand::rngs::StdRng;
    use rand::Rng as RandRng;

    #[test]
    fn test_decrypt() {
        let lambda = 128;
        let n = 5;
        let search_space_size = 1000;
        
        let (pp, msk) = ipe_setup(lambda, n, search_space_size);
        let mut rng = StdRng::seed_from_u64(42);
        
        // Create test vectors with known small values
        let x: Vec<Fr> = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4), Fr::from(5)];
        let y: Vec<Fr> = vec![Fr::from(1), Fr::from(1), Fr::from(1), Fr::from(1), Fr::from(1)];
        
        // KeyGen
        let sk = ipe_keygen(&msk, &x, &mut rng);
        
        // Encrypt
        let ct = ipe_encrypt(&msk, &y, &mut rng);
        
        // Decrypt - should find inner product = 1+2+3+4+5 = 15
        let result = ipe_decrypt(&pp, &sk, &ct);
        
        // Verify that the inner product was found
        assert!(result.is_some());
        assert_eq!(result.unwrap(), Fr::from(15));
        
        println!("Decrypt test passed!");
        println!("Successfully recovered inner product = 15");
    }
    
    #[test]
    fn test_full_ipe_flow() {
        let lambda = 128;
        let n = 3;
        let search_space_size = 100;
        
        let (pp, msk) = ipe_setup(lambda, n, search_space_size);
        let mut rng = StdRng::seed_from_u64(123);
        
        // Create test vectors with small known values
        let x: Vec<Fr> = vec![Fr::from(2), Fr::from(3), Fr::from(4)];
        let y: Vec<Fr> = vec![Fr::from(5), Fr::from(6), Fr::from(7)];
        
        // Full IPE flow: Setup -> KeyGen -> Encrypt -> Decrypt
        let sk = ipe_keygen(&msk, &x, &mut rng);
        let ct = ipe_encrypt(&msk, &y, &mut rng);
        let result = ipe_decrypt(&pp, &sk, &ct);
        
        // The decryption should find <x,y> = 2*5 + 3*6 + 4*7 = 10 + 18 + 28 = 56
        assert!(result.is_some());
        assert_eq!(result.unwrap(), Fr::from(56));
        
        println!("Full IPE flow test passed!");
        println!("Successfully recovered inner product = 56");
    }

    #[test]
    fn test_decrypt_prepared_secret_key() {
        let lambda = 128;
        let n = 4;
        let search_space_size = 1000;

        let (pp, msk) = ipe_setup(lambda, n, search_space_size);
        let mut rng = StdRng::seed_from_u64(777);

        // Create test vectors
        let x: Vec<Fr> = vec![Fr::from(3), Fr::from(1), Fr::from(4), Fr::from(1)];
        let y: Vec<Fr> = vec![Fr::from(5), Fr::from(9), Fr::from(2), Fr::from(6)];

        // KeyGen and prepare secret key
        let sk = ipe_keygen(&msk, &x, &mut rng);
        let psk = prepare_secret_key(&sk);

        // Encrypt and decrypt using prepared secret key
        let ct = ipe_encrypt(&msk, &y, &mut rng);
        let result = ipe_decrypt_prepared(&pp, &psk, &ct);

        // <x,y> = 3*5 + 1*9 + 4*2 + 1*6 = 15 + 9 + 8 + 6 = 38
        assert!(result.is_some());
        assert_eq!(result.unwrap(), Fr::from(38u64));
    }

    #[test]
    fn test_correctness_vs_plaintext() {
        println!("\n=== Testing v2 Decryption Correctness vs Plaintext ===\n");
        
        let lambda = 128;
        let n = 10;
        let search_space_size = 10000;
        
        let (pp, msk) = ipe_setup(lambda, n, search_space_size);
        let mut rng = StdRng::seed_from_u64(999);
        
        // Test with multiple random vectors
        for test_num in 0..5 {
            // Generate random vectors with small values to keep inner product in search space
            let x: Vec<Fr> = (0..n).map(|_| Fr::from(rng.gen::<u8>() % 10)).collect();
            let y: Vec<Fr> = (0..n).map(|_| Fr::from(rng.gen::<u8>() % 10)).collect();
            
            // Compute plaintext inner product
            let mut plaintext_ip = 0u64;
            for i in 0..n {
                // Extract scalar values (assuming small values for testing)
                let x_val = x[i].into_bigint().0[0];
                let y_val = y[i].into_bigint().0[0];
                plaintext_ip += x_val * y_val;
            }
            
            // IPE flow
            let sk = ipe_keygen(&msk, &x, &mut rng);
            let ct = ipe_encrypt(&msk, &y, &mut rng);
            let result = ipe_decrypt(&pp, &sk, &ct);
            
            // Verify correctness
            assert!(result.is_some(), "Test {}: Decryption failed!", test_num);
            let recovered_ip = result.unwrap();
            assert_eq!(
                recovered_ip, 
                Fr::from(plaintext_ip),
                "Test {}: Mismatch! Expected {}, got {:?}",
                test_num,
                plaintext_ip,
                recovered_ip
            );
            
            println!("✓ Test {}: Plaintext <x,y> = {} ✓ Recovered = {}", 
                     test_num, plaintext_ip, plaintext_ip);
        }
        
        println!("\n✓ All correctness tests passed!");
        println!("  • v2 scheme with correlated bases produces correct results");
        println!("  • Single-pairing aggregation preserves functionality");
    }
}

