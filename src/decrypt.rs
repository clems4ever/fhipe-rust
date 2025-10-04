use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, Field};

use crate::setup::PublicParams;
use crate::keygen::SecretKey;
use crate::encrypt::Ciphertext;

type Gt = <Bls12_381 as Pairing>::TargetField;
type Fr = ark_bls12_381::Fr;

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
    
    // Search for z ∈ S such that (D1)^z = D2
    // S = {0, 1, ..., search_space_size - 1}
    for z_val in 0..pp.search_space_size {
        let z = Fr::from(z_val as u64);
        
        // Compute D1^z
        let d1_pow_z = d1.pow(z.into_bigint().0);
        
        // Check if D1^z == D2
        if d1_pow_z == d2 {
            return Some(z);
        }
    }
    
    // If no z found, output ⊥ (None)
    None
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

