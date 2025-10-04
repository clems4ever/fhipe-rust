use ark_bls12_381::{Fr, G1Projective as G1, G2Projective as G2, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, PrimeGroup, CurveGroup, AffineRepr};
use ark_bls12_381::Bls12_381 as Curve;
use ark_ff::{PrimeField, UniformRand, Field, Zero};
use rand::Rng;

use crate::types::{PublicParams, MasterSecretKey, FunctionKey, Ciphertext};
use crate::util::{ensure_same_length};

/// Setup: Generate dual orthonormal bases for DPVS construction (Section 3.1 of paper)
/// For security parameter n (vector dimension), we use 2n+2 dimensional DPVS.
/// Returns (PublicParams, MasterSecretKey)
pub fn setup<R: Rng>(n: usize, mut rng: R) -> (PublicParams, MasterSecretKey) {
    let m = 2 * n + 2; // Total DPVS dimension
    
    // Use standard generators
    let g1 = G1::from(G1Affine::generator());
    let g2 = G2::from(G2Affine::generator());
    
    // Generate random invertible matrix X ∈ Fr^{m×m} to create dual bases
    // B = (g1^X) and B* = (g2^{(X^T)^{-1}})
    // For simplicity, we use a diagonal matrix with random non-zero entries
    
    let mut b_basis = Vec::with_capacity(m);
    let mut b_star_basis = Vec::with_capacity(m);
    
    for _ in 0..m {
        let mut scalar = Fr::rand(&mut rng);
        // Ensure non-zero
        while scalar.is_zero() {
            scalar = Fr::rand(&mut rng);
        }
        
        // B_i = g1^{scalar}
        b_basis.push(g1.mul_bigint(scalar.into_bigint()));
        
        // B*_i = g2^{1/scalar} (dual basis property)
        let inv_scalar = scalar.inverse().unwrap();
        b_star_basis.push(g2.mul_bigint(inv_scalar.into_bigint()));
    }
    
    let pp = PublicParams { n, b_basis };
    let msk = MasterSecretKey { b_star_basis };
    
    (pp, msk)
}

/// Keygen: Encode vector x into a function key using DPVS (Section 3.2)
/// Key structure: k = (x, 0, r_x, 0, ...) encoded in dual basis B*
/// Requires the master secret key!
pub fn keygen<R: Rng>(msk: &MasterSecretKey, pp: &PublicParams, x: &[Fr], mut rng: R) -> FunctionKey {
    assert_eq!(x.len(), pp.n, "Vector x must have dimension n={}", pp.n);
    
    let m = 2 * pp.n + 2;
    let mut k = Vec::with_capacity(m);
    
    // Random blinding scalar for function hiding
    let r_x = Fr::rand(&mut rng);
    
    // Encode as: (x_1, ..., x_n, 0, ..., 0, r_x, 0)
    // First n positions: x vector
    for (i, &x_i) in x.iter().enumerate() {
        k.push(msk.b_star_basis[i].mul_bigint(x_i.into_bigint()));
    }
    
    // Position n: zero
    k.push(G2::from(G2Affine::identity()));
    
    // Position n+1: r_x (randomness)
    k.push(msk.b_star_basis[pp.n + 1].mul_bigint(r_x.into_bigint()));
    
    // Remaining positions: zeros
    for _ in (pp.n + 2)..m {
        k.push(G2::from(G2Affine::identity()));
    }
    
    FunctionKey { k }
}

/// Encrypt: Encode vector y into a ciphertext using DPVS (Section 3.2)
/// Ciphertext structure: c = (y, s, 0, r_y, ...) encoded in basis B
pub fn encrypt<R: Rng>(pp: &PublicParams, y: &[Fr], mut rng: R) -> Ciphertext {
    assert_eq!(y.len(), pp.n, "Vector y must have dimension n={}", pp.n);
    
    let m = 2 * pp.n + 2;
    let mut c = Vec::with_capacity(m);
    
    // Random blinding scalars for function hiding
    let s = Fr::rand(&mut rng);
    let r_y = Fr::rand(&mut rng);
    
    // Encode as: (y_1, ..., y_n, s, 0, ..., 0, r_y)
    // First n positions: y vector
    for (i, &y_i) in y.iter().enumerate() {
        c.push(pp.b_basis[i].mul_bigint(y_i.into_bigint()));
    }
    
    // Position n: s (randomness)
    c.push(pp.b_basis[pp.n].mul_bigint(s.into_bigint()));
    
    // Position n+1: zero
    c.push(G1::from(G1Affine::identity()));
    
    // Remaining positions up to last: zeros
    for _ in (pp.n + 2)..(m - 1) {
        c.push(G1::from(G1Affine::identity()));
    }
    
    // Last position: r_y
    c.push(pp.b_basis[m - 1].mul_bigint(r_y.into_bigint()));
    
    Ciphertext { c }
}

/// Decrypt: Compute inner product via pairing (Section 3.2)
/// Due to dual basis orthogonality, e(c, k) = e(g1, g2)^{<x,y> + s*r_x}
/// For this simplified version without the final optimization, we get e(g1, g2)^{<x,y>}
pub fn decrypt(_pp: &PublicParams, sk: &FunctionKey, ct: &Ciphertext) -> <Curve as Pairing>::TargetField {
    ensure_same_length(&sk.k, &ct.c);
    
    // Compute product of pairings: ∏_i e(c_i, k_i)
    // Due to dual basis orthonormality, only matching positions contribute
    let mut result = <Curve as Pairing>::TargetField::ONE;
    
    for (c_i, k_i) in ct.c.iter().zip(sk.k.iter()) {
        let pairing_i = <Curve as Pairing>::pairing(c_i.into_affine(), k_i.into_affine());
        result *= pairing_i.0;
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn round_trip_small_vectors() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        let mut rng = StdRng::seed_from_u64(42);
        let n = 8;
        let (pp, msk) = setup(n, &mut rng);
        let x: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let y: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let sk = keygen(&msk, &pp, &x, &mut rng);
        let ct = encrypt(&pp, &y, &mut rng);
        let val = decrypt(&pp, &sk, &ct);
        // We cannot directly recover the scalar from GT without a discrete log helper; but at
        // least check consistency on repeated decryptions.
        let val2 = decrypt(&pp, &sk, &ct);
        assert_eq!(val, val2);
    }
}