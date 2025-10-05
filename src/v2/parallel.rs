/// Parallel optimizations for FHIPE operations using Rayon
/// 
/// This module provides parallel versions of encrypt and decrypt operations
/// that can significantly speed up batch processing on multi-core systems.

use rayon::prelude::*;
use ark_std::rand::Rng;

use crate::v1::setup::{PublicParams, MasterSecretKey};
use crate::v1::keygen::SecretKey;
use crate::v1::encrypt::{ipe_encrypt, Ciphertext};
use crate::v1::decrypt::{prepare_secret_key, ipe_decrypt_prepared};
use ark_bls12_381::Fr;

/// Parallel batch encryption of multiple vectors
/// 
/// Encrypts multiple data vectors in parallel across available CPU cores.
/// This is significantly faster than sequential encryption for large batches.
/// 
/// # Arguments
/// * `msk` - Master secret key
/// * `vectors` - Slice of vectors to encrypt
/// * `rng` - Random number generator (note: will be cloned for each thread)
/// 
/// # Returns
/// * `Vec<Ciphertext>` - Vector of ciphertexts in the same order as input vectors
/// 
/// # Performance
/// Expected speedup: ~N cores for large batches (embarrassingly parallel)
pub fn parallel_encrypt<R: Rng + Clone + Send + Sync>(
    msk: &MasterSecretKey, 
    vectors: &[Vec<Fr>], 
    rng: &mut R
) -> Vec<Ciphertext> {
    // Clone RNG for parallel processing
    // Each thread will get its own RNG to avoid contention
    let base_rng = rng.clone();
    
    vectors.par_iter()
        .map(|v| {
            let mut thread_rng = base_rng.clone();
            ipe_encrypt(msk, v, &mut thread_rng)
        })
        .collect()
}

/// Parallel batch decryption of multiple ciphertexts with the same key
/// 
/// Decrypts multiple ciphertexts in parallel across available CPU cores.
/// Uses prepared pairings to optimize repeated decryptions with the same key.
/// This is significantly faster than sequential decryption for large batches.
/// 
/// # Arguments
/// * `pp` - Public parameters
/// * `sk` - Secret key (same key used for all decryptions)
/// * `ciphertexts` - Slice of ciphertexts to decrypt
/// 
/// # Returns
/// * `Vec<Option<Fr>>` - Vector of decrypted values (None if decryption fails)
/// 
/// # Performance
/// Expected speedup: ~N cores for large batches (embarrassingly parallel)
/// Additional optimization: Prepares the secret key once and reuses it across all decryptions
pub fn parallel_decrypt(
    pp: &PublicParams,
    sk: &SecretKey,
    ciphertexts: &[Ciphertext]
) -> Vec<Option<Fr>> {
    // Prepare the secret key once to reuse prepared K2 across all decryptions
    let prepared_sk = prepare_secret_key(sk);
    
    ciphertexts.par_iter()
        .map(|ct| ipe_decrypt_prepared(pp, &prepared_sk, ct))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::setup::ipe_setup;
    use crate::v1::keygen::ipe_keygen;
    use ark_std::rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_parallel_encrypt_decrypt() {
        let lambda = 128;
        let n = 3;
        let search_space_size = 100;
        
        let (pp, msk) = ipe_setup(lambda, n, search_space_size);
        let mut rng = StdRng::seed_from_u64(789);
        
        // Create query vector
        let x: Vec<Fr> = vec![Fr::from(2), Fr::from(3), Fr::from(4)];
        let sk = ipe_keygen(&msk, &x, &mut rng);
        
        // Create multiple data vectors
        let y_vectors = vec![
            vec![Fr::from(1), Fr::from(2), Fr::from(3)], // <x,y> = 2+6+12 = 20
            vec![Fr::from(5), Fr::from(6), Fr::from(7)], // <x,y> = 10+18+28 = 56
            vec![Fr::from(1), Fr::from(1), Fr::from(1)], // <x,y> = 2+3+4 = 9
        ];
        
        // Parallel encrypt
        let ciphertexts = parallel_encrypt(&msk, &y_vectors, &mut rng);
        assert_eq!(ciphertexts.len(), 3);
        
        // Parallel decrypt
        let results = parallel_decrypt(&pp, &sk, &ciphertexts);
        
        // Verify results
        assert_eq!(results.len(), 3);
        assert!(results[0].is_some());
        assert_eq!(results[0].unwrap(), Fr::from(20));
        assert!(results[1].is_some());
        assert_eq!(results[1].unwrap(), Fr::from(56));
        assert!(results[2].is_some());
        assert_eq!(results[2].unwrap(), Fr::from(9));
        
        println!("Parallel encrypt/decrypt test passed!");
    }
}
