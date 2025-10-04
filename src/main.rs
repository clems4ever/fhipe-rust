mod setup;
mod keygen;

use setup::ipe_setup;
use keygen::ipe_keygen;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use rand::rngs::StdRng;
use ark_std::rand::SeedableRng;

fn main() {
    // Example usage
    let lambda = 128; // Security parameter
    let n = 5;        // Vector dimension
    
    println!("=== FHIPE Demo ===\n");
    
    // Step 1: Setup
    println!("Step 1: Running IPE.Setup(1^λ, n)...");
    let (pp, msk) = ipe_setup(lambda, n);
    
    println!("FHIPE Setup completed:");
    println!("  Security parameter λ = {}", pp.security_param);
    println!("  Dimension n = {}", pp.dimension);
    println!("  Generated g1 ∈ G1");
    println!("  Generated g2 ∈ G2");
    println!("  Generated B matrix ({}x{})", n, n);
    println!("  Generated B* matrix ({}x{})\n", n, n);
    
    // Step 2: KeyGen
    println!("Step 2: Running IPE.KeyGen(msk, x)...");
    let mut rng = StdRng::seed_from_u64(42);
    
    // Create a test vector x
    let x: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    
    let _sk = ipe_keygen(&msk, &x, &mut rng);
    
    println!("Secret key generated:");
    println!("  K1 = g1^(α·det(B))");
    println!("  K2 = g1^(α·x·B)");
    println!("  Key generation successful!\n");
}
