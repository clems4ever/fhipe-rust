use ark_bls12_381::{Fr, G2Projective};
use ark_ff::{Zero, UniformRand};
use rand::Rng;

use crate::setup::MasterSecretKey;

/// Ciphertext for IPE
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub c1: G2Projective,  // C1 = g2^β
    pub c2: G2Projective,  // C2 = g2^(β·y·B*)
}

/// IPE.Encrypt(msk, y): Encryption algorithm for Inner Product Encryption
/// 
/// # Arguments
/// * `msk` - Master secret key containing g1, g2, B, B*
/// * `y` - Vector y ∈ Z_q^n to encrypt
/// * `rng` - Random number generator
/// 
/// # Returns
/// * `Ciphertext` - Ciphertext ct = (C1, C2) where:
///   - C1 = g2^β
///   - C2 = g2^(β·y·B*)
pub fn ipe_encrypt<R: Rng>(msk: &MasterSecretKey, y: &[Fr], rng: &mut R) -> Ciphertext {
    let n = msk.pp.dimension;
    
    // Verify input vector dimension
    assert_eq!(y.len(), n, "Input vector y must have dimension {}", n);
    
    // Choose uniformly random β ← Z_q
    let beta = Fr::rand(rng);
    
    // Compute C1 = g2^β
    let c1 = msk.g2 * beta;
    
    // Compute y·B* (matrix-vector multiplication)
    let y_b_star = matrix_vector_mult(y, &msk.b_star_matrix);
    
    // Compute C2 = g2^(β·y·B*)
    // Similar to keygen, we interpret y·B* as a vector and compute the sum
    let beta_y_b_star = vector_scalar_mult(&y_b_star, beta);
    let sum_y_b_star = vector_sum(&beta_y_b_star);
    let c2 = msk.g2 * sum_y_b_star;
    
    Ciphertext { c1, c2 }
}

/// Multiply a row vector by a matrix: result = y · B*
fn matrix_vector_mult(y: &[Fr], matrix: &[Vec<Fr>]) -> Vec<Fr> {
    let n = matrix.len();
    let mut result = vec![Fr::zero(); n];
    
    // y · B* where y is a row vector and B* is n×n matrix
    // result[j] = sum_i(y[i] * B*[i][j])
    for j in 0..n {
        for i in 0..n {
            result[j] += y[i] * matrix[i][j];
        }
    }
    
    result
}

/// Multiply a vector by a scalar
fn vector_scalar_mult(vector: &[Fr], scalar: Fr) -> Vec<Fr> {
    vector.iter().map(|&v| v * scalar).collect()
}

/// Compute the sum of all components in a vector
fn vector_sum(vector: &[Fr]) -> Fr {
    vector.iter().fold(Fr::zero(), |acc, &x| acc + x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::ipe_setup;
    use ark_std::rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_encrypt() {
        let lambda = 128;
        let n = 5;
        
        let (_pp, msk) = ipe_setup(lambda, n);
        let mut rng = StdRng::seed_from_u64(42);
        
        // Create a test vector
        let y: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        
        // Encrypt
        let ct = ipe_encrypt(&msk, &y, &mut rng);
        
        // Verify that C1 and C2 are not identity (zero in additive notation)
        assert_ne!(ct.c1, G2Projective::zero());
        assert_ne!(ct.c2, G2Projective::zero());
        
        println!("Encrypt test passed!");
    }
    
    #[test]
    #[should_panic(expected = "Input vector y must have dimension")]
    fn test_encrypt_wrong_dimension() {
        let lambda = 128;
        let n = 5;
        
        let (_pp, msk) = ipe_setup(lambda, n);
        let mut rng = StdRng::seed_from_u64(42);
        
        // Create a test vector with wrong dimension
        let y: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
        
        // This should panic
        let _ct = ipe_encrypt(&msk, &y, &mut rng);
    }
}
