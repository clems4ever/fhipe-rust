use ark_bls12_381::{Fr, G2Projective};
use ark_ff::{Zero, UniformRand};
use rand::Rng;
use rayon::prelude::*;

use crate::v2::setup::MasterSecretKey;

/// Ciphertext for IPE with correlated bases
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub c1: G2Projective,       // C1 = g2^β
    pub c2: Vec<G2Projective>,  // C2[i] = Vᵢ^(β·vᵢ) - will be used in multi-pairing
}

/// IPE.Encrypt(msk, y): Encryption algorithm for Inner Product Encryption with correlated bases
/// 
/// # Arguments
/// * `msk` - Master secret key containing g1, g2, B, B*, and correlated bases Vᵢ
/// * `y` - Vector y ∈ Z_q^n to encrypt
/// * `rng` - Random number generator
/// 
/// # Returns
/// * `Ciphertext` - Ciphertext ct = (C1, C2) where:
///   - C1 = g2^β
///   - C2[i] = Vᵢ^(β·vᵢ) where v = y·B* and Vᵢ = g₂^(γᵢ⁻¹)
///   - Multi-pairing e(K2, C2) = ∏ᵢ e(K2[i], C2[i]) computed in single operation
pub fn ipe_encrypt<R: Rng>(msk: &MasterSecretKey, y: &[Fr], rng: &mut R) -> Ciphertext {
    let n = msk.pp.dimension;
    
    // Verify input vector dimension
    assert_eq!(y.len(), n, "Input vector y must have dimension {}", n);
    
    // Choose uniformly random β ← Z_q
    let beta = Fr::rand(rng);
    
    // Compute C1 = g2^β
    let c1 = msk.g2 * beta;
    
    // Compute v = y·B* (matrix-vector multiplication)
    let v = matrix_vector_mult(y, &msk.b_star_matrix);
    
    // Compute C2[i] = Vᵢ^(β·vᵢ) using correlated bases
    // When paired with K2[i] = Uᵢ^(α·uᵢ), we get e(Uᵢ, Vᵢ)^(α·β·uᵢ·vᵢ)
    // Multi-pairing aggregates: ∏ᵢ e(Uᵢ, Vᵢ)^(α·β·uᵢ·vᵢ) = e(g1, g2)^(α·β·Σᵢ uᵢ·vᵢ)
    let c2: Vec<G2Projective> = v
        .into_par_iter()
        .zip(&msk.v_bases)
        .map(|(v_i, &base_i)| base_i * (beta * v_i))
        .collect();
    
    Ciphertext { c1, c2 }
}

/// Multiply a row vector by a matrix: result = y · B* (optimized version)
fn matrix_vector_mult(y: &[Fr], matrix: &[Vec<Fr>]) -> Vec<Fr> {
    let n = matrix.len();
    
    // Parallelize over output elements for better performance
    // Each column can be computed independently
    (0..n).into_par_iter()
        .map(|j| {
            // result[j] = sum_i(y[i] * matrix[i][j])
            let mut sum = Fr::zero();
            for i in 0..n {
                sum += y[i] * matrix[i][j];
            }
            sum
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::setup::ipe_setup;
    use ark_std::rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_encrypt() {
        let lambda = 128;
        let n = 5;
        let search_space_size = 1000;
        
        let (_pp, msk) = ipe_setup(lambda, n, search_space_size);
        let mut rng = StdRng::seed_from_u64(42);
        
        // Create a test vector
        let y: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // Encrypt
        let ct = ipe_encrypt(&msk, &y, &mut rng);
        
        // Verify that C1 and C2 are not identity elements
        assert_ne!(ct.c1, G2Projective::zero());
        assert_eq!(ct.c2.len(), n);
        assert!(ct.c2.iter().all(|&c| c != G2Projective::zero()));
        
        println!("Encrypt test passed!");
    }
    
    #[test]
    #[should_panic(expected = "Input vector y must have dimension")]
    fn test_encrypt_wrong_dimension() {
        let lambda = 128;
        let n = 5;
        let search_space_size = 1000;
        
        let (_pp, msk) = ipe_setup(lambda, n, search_space_size);
        let mut rng = StdRng::seed_from_u64(42);
        
        // Create a test vector with wrong dimension
        let y: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        
        // This should panic
        let _ct = ipe_encrypt(&msk, &y, &mut rng);
    }
}
