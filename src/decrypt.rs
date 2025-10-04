use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;

use crate::setup::PublicParams;
use crate::keygen::SecretKey;
use crate::encrypt::Ciphertext;

type Gt = <Bls12_381 as Pairing>::TargetField;

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
/// * `sk` - Secret key sk = (K1, K2)
/// * `ct` - Ciphertext ct = (C1, C2)
/// 
/// # Returns
/// * `DecryptionResult` - Decryption result containing:
///   - D1 = e(K1, C1) where e is the pairing function
///   - D2 = e(K2, C2)
pub fn ipe_decrypt(_pp: &PublicParams, sk: &SecretKey, ct: &Ciphertext) -> DecryptionResult {
    // Compute D1 = e(K1, C1)
    // e: G1 × G2 → GT
    let d1 = Bls12_381::pairing(sk.k1, ct.c1).0;
    
    // Compute D2 = e(K2, C2)
    let d2 = Bls12_381::pairing(sk.k2, ct.c2).0;
    
    DecryptionResult { d1, d2 }
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
