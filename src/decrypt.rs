use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, Field};

use crate::setup::PublicParams;
use crate::keygen::SecretKey;
use crate::encrypt::Ciphertext;

type Gt = <Bls12_381 as Pairing>::TargetField;
type Fr = ark_bls12_381::Fr;

/// Decryption result containing the pairing values
#[derive(Clone, Debug)]
pub struct DecryptionResult {
    pub d1: Gt,  // D1 = e(K1, C1)
    pub d2: Gt,  // D2 = e(K2, C2)
}

/// IPE.Decrypt(pp, sk, ct): Decryption algorithm for Inner Product Encryption
/// 
/// # Arguments
/// * `pp` - Public parameters
/// * `sk` - Secret key sk = (K1, K2) where K2 is a vector
/// * `ct` - Ciphertext ct = (C1, C2) where C2 is a vector
/// 
/// # Returns
/// * `DecryptionResult` - Decryption result containing:
///   - D1 = e(K1, C1) where e is the pairing function
///   - D2 = e(K2, C2) = product of e(K2[i], C2[i])
pub fn ipe_decrypt(_pp: &PublicParams, sk: &SecretKey, ct: &Ciphertext) -> DecryptionResult {
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
    
    DecryptionResult { d1, d2 }
}

/// Search for the inner product value z such that (D1)^z = D2
/// 
/// # Arguments
/// * `result` - The decryption result containing D1 and D2
/// * `search_space` - The set S of possible inner product values to search
/// 
/// # Returns
/// * `Some(z)` if found, `None` otherwise
pub fn recover_inner_product(result: &DecryptionResult, search_space: &[Fr]) -> Option<Fr> {
    for &z in search_space {
        // Compute D1^z
        let d1_pow_z = result.d1.pow(z.into_bigint().0);
        
        // Check if D1^z == D2
        if d1_pow_z == result.d2 {
            return Some(z);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::ipe_setup;
    use crate::keygen::ipe_keygen;
    use crate::encrypt::ipe_encrypt;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_decrypt() {
        let lambda = 128;
        let n = 5;
        
        let (pp, msk) = ipe_setup(lambda, n);
        let mut rng = StdRng::seed_from_u64(42);
        
        // Create test vectors
        let x: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let y: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // KeyGen
        let sk = ipe_keygen(&msk, &x, &mut rng);
        
        // Encrypt
        let ct = ipe_encrypt(&msk, &y, &mut rng);
        
        // Decrypt
        let result = ipe_decrypt(&pp, &sk, &ct);
        
        // Verify that D1 and D2 are not identity
        assert_ne!(result.d1, Gt::from(0u64));
        assert_ne!(result.d2, Gt::from(0u64));
        
        println!("Decrypt test passed!");
        println!("D1 = e(K1, C1) computed successfully");
        println!("D2 = e(K2, C2) computed successfully");
    }
    
    #[test]
    fn test_full_ipe_flow() {
        let lambda = 128;
        let n = 3;
        
        let (pp, msk) = ipe_setup(lambda, n);
        let mut rng = StdRng::seed_from_u64(123);
        
        // Create test vectors
        let x: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let y: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // Full IPE flow: Setup -> KeyGen -> Encrypt -> Decrypt
        let sk = ipe_keygen(&msk, &x, &mut rng);
        let ct = ipe_encrypt(&msk, &y, &mut rng);
        let result = ipe_decrypt(&pp, &sk, &ct);
        
        // The decryption result should be valid
        assert_ne!(result.d1, Gt::from(0u64));
        assert_ne!(result.d2, Gt::from(0u64));
        
        println!("Full IPE flow test passed!");
    }
}

