use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{Zero, UniformRand};
use rand::Rng;
use rayon::prelude::*;

use crate::v3::setup::MasterSecretKey;

/// Secret key for IPE
#[derive(Clone, Debug)]
pub struct SecretKey {
    pub k1: G1Projective,      // K1 = g1^(α·det(B))
    pub k2: Vec<G1Projective>, // K2 = g1^(α·x·B) - vector of group elements
}

/// IPE.KeyGen(msk, x): Key generation algorithm for Inner Product Encryption
/// 
/// # Arguments
/// * `msk` - Master secret key containing g1, g2, B, B*
/// * `x` - Vector x ∈ Z_q^n for which to generate the secret key
/// * `rng` - Random number generator
/// 
/// # Returns
/// * `SecretKey` - Secret key sk = (K1, K2) where:
///   - K1 = g1^(α·det(B))
///   - K2 = g1^(α·x·B)
pub fn ipe_keygen<R: Rng>(msk: &MasterSecretKey, x: &[Fr], rng: &mut R) -> SecretKey {
    let n = msk.pp.dimension;
    
    // Verify input vector dimension
    assert_eq!(x.len(), n, "Input vector x must have dimension {}", n);
    
    // Choose uniformly random α ← Z_q
    let alpha = Fr::rand(rng);
    
    // Use cached det(B) from MSK instead of recomputing
    let det_b = msk.det_b;
    
    // Compute K1 = g1^(α·det(B))
    let k1 = msk.g1 * (alpha * det_b);
    
    // Compute x·B (matrix-vector multiplication)
    let x_b = matrix_vector_mult(x, &msk.b_matrix);
    
    // Compute K2 = g1^(α·(x·B)) using parallel scalar multiplications (fallback)
    let k2: Vec<G1Projective> = x_b
        .into_par_iter()
        .map(|xb_i| msk.g1 * (alpha * xb_i))
        .collect();
    
    SecretKey { k1, k2 }
}

/// Multiply a row vector by a matrix: result = x · B (optimized version)
pub(crate) fn matrix_vector_mult(x: &[Fr], matrix: &[Vec<Fr>]) -> Vec<Fr> {
    let n = matrix.len();
    
    // Parallelize over output elements for better performance
    // Each column can be computed independently
    (0..n).into_par_iter()
        .map(|j| {
            // result[j] = sum_i(x[i] * matrix[i][j])
            let mut sum = Fr::zero();
            for i in 0..n {
                sum += x[i] * matrix[i][j];
            }
            sum
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::setup::ipe_setup;
    use ark_std::rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_keygen() {
        let lambda = 128;
        let n = 5;
        let search_space_size = 1000;
        
        let (_pp, msk) = ipe_setup(lambda, n, search_space_size);
        let mut rng = StdRng::seed_from_u64(42);
        
        // Create a test vector
        let x: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // Generate secret key
        let sk = ipe_keygen(&msk, &x, &mut rng);
        
        // Verify that K1 is not identity and K2 has correct dimension
        assert_ne!(sk.k1, G1Projective::zero());
        assert_eq!(sk.k2.len(), n);
        assert!(sk.k2.iter().all(|&k| k != G1Projective::zero()));
        
        println!("KeyGen test passed!");
    }
    
    #[test]
    #[should_panic(expected = "Input vector x must have dimension")]
    fn test_keygen_wrong_dimension() {
        let lambda = 128;
        let n = 5;
        let search_space_size = 1000;
        
        let (_pp, msk) = ipe_setup(lambda, n, search_space_size);
        let mut rng = StdRng::seed_from_u64(42);
        
        // Create a test vector with wrong dimension
        let x: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        
        // This should panic
        let _sk = ipe_keygen(&msk, &x, &mut rng);
    }
}
