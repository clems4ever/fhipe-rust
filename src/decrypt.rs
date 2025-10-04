use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, Field};
use ark_serialize::CanonicalSerialize;
use std::collections::HashMap;

use crate::setup::PublicParams;
use crate::keygen::SecretKey;
use crate::encrypt::Ciphertext;

type Gt = <Bls12_381 as Pairing>::TargetField;
type Fr = ark_bls12_381::Fr;

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
    
    // Baby steps: Build hash table using serialized bytes as keys
    let mut baby_steps = HashMap::new();
    let mut current = Gt::from(1u64); // base^0
    
    for j in 0..=m {
        // Serialize to bytes for consistent hashing
        let mut bytes = Vec::new();
        current.serialize_compressed(&mut bytes).unwrap();
        baby_steps.insert(bytes, j);
        
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
        let mut bytes = Vec::new();
        gamma.serialize_compressed(&mut bytes).unwrap();
        
        if let Some(&j) = baby_steps.get(&bytes) {
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

/// IPE.Decrypt(pp, sk, ct): Decryption algorithm for Inner Product Encryption
/// 
/// # Arguments
/// * `pp` - Public parameters containing the search space S
/// * `sk` - Secret key sk = (K1, K2) where K2 is a vector
/// * `ct` - Ciphertext ct = (C1, C2) where C2 is a vector
/// 
/// # Returns
/// * `Option<Fr>` - The inner product z if found, None otherwise
/// 
/// This function computes D1 = e(K1, C1) and D2 = e(K2, C2), then searches
/// for z ∈ S such that (D1)^z = D2
pub fn ipe_decrypt(pp: &PublicParams, sk: &SecretKey, ct: &Ciphertext) -> Option<Fr> {
    // Compute D1 = e(K1, C1)
    // e: G1 × G2 → GT
    let d1 = Bls12_381::pairing(sk.k1, ct.c1).0;
    
    // Compute D2 = e(K2, C2) = ∏ e(K2[i], C2[i])
    // This is the product of pairings over the vectors
    let mut d2 = Gt::from(1u64); // multiplicative identity
    
    for i in 0..sk.k2.len() {
        let pairing_i = Bls12_381::pairing(sk.k2[i], ct.c2[i]).0;
        d2 *= pairing_i;
    }
    
    // Search for z ∈ S such that (D1)^z = D2 using Baby-Step Giant-Step
    // This is more efficient than linear search: O(√|S|) instead of O(|S|)
    baby_step_giant_step(d1, d2, pp.search_space_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::ipe_setup;
    use crate::keygen::ipe_keygen;
    use crate::encrypt::ipe_encrypt;
    use ark_bls12_381::Fr;
    use ark_std::rand::SeedableRng;
    use rand::rngs::StdRng;

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
}

