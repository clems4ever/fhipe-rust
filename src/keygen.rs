use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{Zero, One, UniformRand};
use rand::Rng;

use crate::setup::MasterSecretKey;

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
    
    // Compute det(B)
    let det_b = matrix_determinant(&msk.b_matrix);
    
    // Compute K1 = g1^(α·det(B))
    let k1 = msk.g1 * (alpha * det_b);
    
    // Compute x·B (matrix-vector multiplication)
    let x_b = matrix_vector_mult(x, &msk.b_matrix);
    
    // Compute K2 = g1^(α·(x·B))
    // This is a VECTOR of group elements: [g1^(α·(x·B)[0]), g1^(α·(x·B)[1]), ..., g1^(α·(x·B)[n-1])]
    let k2: Vec<G1Projective> = x_b.iter()
        .map(|&xb_i| msk.g1 * (alpha * xb_i))
        .collect();
    
    SecretKey { k1, k2 }
}

/// Compute matrix determinant using Laplace expansion
fn matrix_determinant(matrix: &[Vec<Fr>]) -> Fr {
    let n = matrix.len();
    
    if n == 1 {
        return matrix[0][0];
    }
    
    if n == 2 {
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
    }
    
    let mut det = Fr::zero();
    let mut sign = Fr::one();
    
    for j in 0..n {
        let minor = get_minor(matrix, 0, j);
        let cofactor = sign * matrix[0][j] * matrix_determinant(&minor);
        det += cofactor;
        sign = -sign;
    }
    
    det
}

/// Get the minor matrix by removing row i and column j
fn get_minor(matrix: &[Vec<Fr>], row: usize, col: usize) -> Vec<Vec<Fr>> {
    let n = matrix.len();
    let mut minor = vec![vec![Fr::zero(); n - 1]; n - 1];
    
    let mut minor_row = 0;
    for i in 0..n {
        if i == row {
            continue;
        }
        let mut minor_col = 0;
        for j in 0..n {
            if j == col {
                continue;
            }
            minor[minor_row][minor_col] = matrix[i][j];
            minor_col += 1;
        }
        minor_row += 1;
    }
    
    minor
}

/// Multiply a row vector by a matrix: result = x · B
fn matrix_vector_mult(x: &[Fr], matrix: &[Vec<Fr>]) -> Vec<Fr> {
    let n = matrix.len();
    let mut result = vec![Fr::zero(); n];
    
    // x · B where x is a row vector and B is n×n matrix
    // result[j] = sum_i(x[i] * B[i][j])
    for j in 0..n {
        for i in 0..n {
            result[j] += x[i] * matrix[i][j];
        }
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::ipe_setup;
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
