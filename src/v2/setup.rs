use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ff::{Field, Zero, One, UniformRand};
use rayon::prelude::*;
use ark_std::rand::SeedableRng;
use rand::rngs::StdRng;

/// Public parameters for FHIPE
/// pp = (G1, G2, GT, q, e, S) in the paper
/// Note: G1, G2, GT, q, e are implicitly defined by the BLS12-381 curve
#[derive(Clone)]
pub struct PublicParams {
    pub security_param: usize,
    pub dimension: usize,
    pub search_space_size: usize,  // S = {0, 1, ..., search_space_size - 1}
}

/// Master secret key for FHIPE
#[derive(Clone)]
pub struct MasterSecretKey {
    pub pp: PublicParams,
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub b_matrix: Vec<Vec<Fr>>,      // B matrix (n x n)
    pub b_star_matrix: Vec<Vec<Fr>>, // B* matrix (n x n)
    pub det_b: Fr,                   // det(B) - precomputed and cached
    pub gamma: Vec<Fr>,              // γᵢ values for correlated bases
    pub u_bases: Vec<G1Projective>,  // Uᵢ = g₁^(γᵢ) for i=1..n
    pub v_bases: Vec<G2Projective>,  // Vᵢ = g₂^(γᵢ⁻¹) for i=1..n
}

/// IPE.Setup(1^λ, S): Setup algorithm for Inner Product Encryption
/// 
/// # Arguments
/// * `seed` - Seed of the random generator
/// * `n` - Dimension of the vectors
/// * `search_space_size` - Size of the search space S = {0, 1, ..., search_space_size - 1}
/// 
/// # Returns
/// * `PublicParams` - Public parameters pp = (G1, G2, GT, q, e, S)
/// * `MasterSecretKey` - Master secret key containing pp, g1, g2, B, B*
pub fn ipe_setup(seed: usize, n: usize, search_space_size: usize) -> (PublicParams, MasterSecretKey) {
    // Initialize RNG with security parameter as seed
    let mut rng = StdRng::seed_from_u64(seed as u64);
    
    // Sample generators g1 ∈ G1 and g2 ∈ G2
    let g1 = G1Projective::rand(&mut rng);
    let g2 = G2Projective::rand(&mut rng);
    
    // Sample B ← GL_n(Z_q) - generate a random invertible matrix
    let b_matrix = generate_invertible_matrix(n, &mut rng);
    
    // Compute det(B) - will be cached in MSK to avoid recomputation
    let det_b = matrix_determinant(&b_matrix);
    
    // Compute B^(-1)
    let b_inverse = matrix_inverse(&b_matrix);
    
    // Compute B* = det(B) · (B^(-1))^T
    let b_star_matrix = matrix_scalar_mult(&matrix_transpose(&b_inverse), det_b);
    
    // Generate correlated bases: Uᵢ = g₁^(γᵢ), Vᵢ = g₂^(γᵢ⁻¹)
    // This ensures e(Uᵢ, Vᵢ) = e(g₁, g₂) for all i
    let mut gamma = Vec::with_capacity(n);
    let mut u_bases = Vec::with_capacity(n);
    let mut v_bases = Vec::with_capacity(n);
    
    for _ in 0..n {
        // Sample random γᵢ ∈ Zq*
        let gamma_i = Fr::rand(&mut rng);
        
        // Compute γᵢ⁻¹
        let gamma_i_inv = gamma_i.inverse().unwrap();
        
        // Uᵢ = g₁^(γᵢ)
        let u_i = g1 * gamma_i;
        
        // Vᵢ = g₂^(γᵢ⁻¹)
        let v_i = g2 * gamma_i_inv;
        
        gamma.push(gamma_i);
        u_bases.push(u_i);
        v_bases.push(v_i);
    }
    
    // Create public parameters
    let pp = PublicParams {
        security_param: seed,
        dimension: n,
        search_space_size,
    };
    
    // Create master secret key with cached determinant and correlated bases
    let msk = MasterSecretKey {
        pp: pp.clone(),
        g1,
        g2,
        b_matrix,
        b_star_matrix,
        det_b, // Cache the determinant to avoid recomputation in KeyGen
        gamma,
        u_bases,
        v_bases,
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

/// Compute matrix determinant using Gaussian elimination (O(n³) instead of O(n!) for Laplace)
fn matrix_determinant(matrix: &[Vec<Fr>]) -> Fr {
    let n = matrix.len();
    
    if n == 1 {
        return matrix[0][0];
    }
    
    if n == 2 {
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
    }
    
    // Create a mutable copy for Gaussian elimination
    let mut m = matrix.to_vec();
    let mut det = Fr::one();
    
    // Gaussian elimination with partial pivoting
    for i in 0..n {
        // Find pivot
        let mut max_row = i;
        for k in (i + 1)..n {
            if !m[k][i].is_zero() {
                max_row = k;
                break;
            }
        }
        
        // Swap rows if needed
        if max_row != i {
            m.swap(i, max_row);
            det = -det; // Row swap changes sign of determinant
        }
        
        // If diagonal element is zero, determinant is zero
        if m[i][i].is_zero() {
            return Fr::zero();
        }
        
        // Multiply determinant by diagonal element
        det *= m[i][i];
        
        // Eliminate column: process rows k > i in parallel
        let pivot_row = m[i].clone();
        let pivot_elem = pivot_row[i];
        let inv_pivot = pivot_elem.inverse().unwrap();
        // Split mutable slice at i+1 to satisfy borrows, then parallelize
        let (_head, tail) = m.split_at_mut(i + 1);
        tail.par_iter_mut().for_each(|row_k| {
            // factor = m[k][i] / pivot_elem = m[k][i] * inv_pivot
            let factor = row_k[i] * inv_pivot;
            if factor != Fr::zero() {
                for j in i..n {
                    row_k[j] -= factor * pivot_row[j];
                }
            }
        });
    }
    
    det
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
        let pivot_row = aug[i].clone();
        
        // Eliminate column in parallel for rows above and below i
        // Rows above i
        if i > 0 {
            let (top, _rest) = aug.split_at_mut(i);
            top.par_iter_mut().for_each(|row_j| {
                let factor = row_j[i];
                if factor != Fr::zero() {
                    for k in 0..(2 * n) {
                        row_j[k] -= factor * pivot_row[k];
                    }
                }
            });
        }
        // Rows below i
        if i + 1 < n {
            let (_head, bottom) = aug.split_at_mut(i + 1);
            bottom.par_iter_mut().for_each(|row_j| {
                let factor = row_j[i];
                if factor != Fr::zero() {
                    for k in 0..(2 * n) {
                        row_j[k] -= factor * pivot_row[k];
                    }
                }
            });
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
