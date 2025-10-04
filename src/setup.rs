use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ff::{Field, Zero, One, UniformRand};
use ark_std::rand::SeedableRng;
use rand::rngs::StdRng;

/// Public parameters for FHIPE
#[derive(Clone)]
pub struct PublicParams {
    pub security_param: usize,
    pub dimension: usize,
}

/// Master secret key for FHIPE
#[derive(Clone)]
pub struct MasterSecretKey {
    pub pp: PublicParams,
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub b_matrix: Vec<Vec<Fr>>,      // B matrix (n x n)
    pub b_star_matrix: Vec<Vec<Fr>>, // B* matrix (n x n)
}

/// IPE.Setup(1^λ, S): Setup algorithm for Inner Product Encryption
/// 
/// # Arguments
/// * `lambda` - Security parameter
/// * `n` - Dimension of the vectors (S in the paper)
/// 
/// # Returns
/// * `PublicParams` - Public parameters
/// * `MasterSecretKey` - Master secret key containing pp, g1, g2, B, B*
pub fn ipe_setup(lambda: usize, n: usize) -> (PublicParams, MasterSecretKey) {
    // Initialize RNG with security parameter as seed
    let mut rng = StdRng::seed_from_u64(lambda as u64);
    
    // Sample generators g1 ∈ G1 and g2 ∈ G2
    let g1 = G1Projective::rand(&mut rng);
    let g2 = G2Projective::rand(&mut rng);
    
    // Sample B ← GL_n(Z_q) - generate a random invertible matrix
    let b_matrix = generate_invertible_matrix(n, &mut rng);
    
    // Compute B^(-1)
    let b_inverse = matrix_inverse(&b_matrix);
    
    // Compute det(B)
    let det_b = matrix_determinant(&b_matrix);
    
    // Compute B* = det(B) · (B^(-1))^T
    let b_star_matrix = matrix_scalar_mult(&matrix_transpose(&b_inverse), det_b);
    
    // Create public parameters
    let pp = PublicParams {
        security_param: lambda,
        dimension: n,
    };
    
    // Create master secret key
    let msk = MasterSecretKey {
        pp: pp.clone(),
        g1,
        g2,
        b_matrix,
        b_star_matrix,
    };
    
    (pp, msk)
}

/// Generate a random invertible matrix over Fr
fn generate_invertible_matrix<R: rand::Rng>(n: usize, rng: &mut R) -> Vec<Vec<Fr>> {
    loop {
        let mut matrix = vec![vec![Fr::zero(); n]; n];
        
        // Generate random matrix
        for i in 0..n {
            for j in 0..n {
                matrix[i][j] = Fr::rand(rng);
            }
        }
        
        // Check if determinant is non-zero (invertible)
        let det = matrix_determinant(&matrix);
        if !det.is_zero() {
            return matrix;
        }
    }
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

/// Compute matrix inverse using Gauss-Jordan elimination
fn matrix_inverse(matrix: &[Vec<Fr>]) -> Vec<Vec<Fr>> {
    let n = matrix.len();
    let mut aug = vec![vec![Fr::zero(); 2 * n]; n];
    
    // Create augmented matrix [A | I]
    for i in 0..n {
        for j in 0..n {
            aug[i][j] = matrix[i][j];
        }
        aug[i][n + i] = Fr::one();
    }
    
    // Forward elimination
    for i in 0..n {
        // Find pivot
        let mut pivot = i;
        for j in (i + 1)..n {
            if aug[j][i] != Fr::zero() {
                pivot = j;
                break;
            }
        }
        
        // Swap rows if needed
        if pivot != i {
            aug.swap(i, pivot);
        }
        
        // Scale pivot row
        let pivot_val = aug[i][i];
        let pivot_inv = pivot_val.inverse().unwrap();
        for j in 0..(2 * n) {
            aug[i][j] *= pivot_inv;
        }
        
        // Eliminate column
        for j in 0..n {
            if i != j && aug[j][i] != Fr::zero() {
                let factor = aug[j][i];
                let row_i = aug[i].clone();
                for k in 0..(2 * n) {
                    aug[j][k] -= factor * row_i[k];
                }
            }
        }
    }
    
    // Extract inverse from augmented matrix
    let mut inverse = vec![vec![Fr::zero(); n]; n];
    for i in 0..n {
        for j in 0..n {
            inverse[i][j] = aug[i][n + j];
        }
    }
    
    inverse
}

/// Transpose a matrix
fn matrix_transpose(matrix: &[Vec<Fr>]) -> Vec<Vec<Fr>> {
    let n = matrix.len();
    let mut transpose = vec![vec![Fr::zero(); n]; n];
    
    for i in 0..n {
        for j in 0..n {
            transpose[j][i] = matrix[i][j];
        }
    }
    
    transpose
}

/// Multiply a matrix by a scalar
fn matrix_scalar_mult(matrix: &[Vec<Fr>], scalar: Fr) -> Vec<Vec<Fr>> {
    let n = matrix.len();
    let mut result = vec![vec![Fr::zero(); n]; n];
    
    for i in 0..n {
        for j in 0..n {
            result[i][j] = matrix[i][j] * scalar;
        }
    }
    
    result
}
