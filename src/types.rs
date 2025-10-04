use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub type Curve = Bls12_381;
pub type Scalar = Fr;
pub type G1 = G1Projective;
pub type G2 = G2Projective;
pub type GT = <Curve as Pairing>::TargetField;

/// Public parameters contain the dual orthonormal bases for DPVS
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicParams {
    /// Dimension n of the inner product vectors
    pub n: usize,
    /// Basis B in G1: matrix of size (2n+2) x (2n+2), but we only store generators
    pub b_basis: Vec<G1>,
}

/// Master secret key contains the dual basis in G2
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct MasterSecretKey {
    /// Dual basis B* in G2: orthonormal to B
    pub b_star_basis: Vec<G2>,
}

/// Function key for vector x (in G2)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct FunctionKey {
    /// Key vector in G2 (DPVS encoding of x with randomness)
    pub k: Vec<G2>,
}

/// Ciphertext for vector y (in G1)
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Ciphertext {
    /// Ciphertext vector in G1 (DPVS encoding of y with randomness)
    pub c: Vec<G1>,
}