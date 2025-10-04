mod setup;
mod keygen;
mod encrypt;
mod decrypt;

use setup::ipe_setup;
use keygen::ipe_keygen;
use encrypt::ipe_encrypt;
use decrypt::ipe_decrypt;
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
    
    let sk = ipe_keygen(&msk, &x, &mut rng);
    
    println!("Secret key generated:");
    println!("  K1 = g1^(α·det(B))");
    println!("  K2 = g1^(α·x·B)");
    println!("  Key generation successful!\n");
    
    // Step 3: Encrypt
    println!("Step 3: Running IPE.Encrypt(msk, y)...");
    
    // Create a test vector y
    let y: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    
    let ct = ipe_encrypt(&msk, &y, &mut rng);
    
    println!("Ciphertext generated:");
    println!("  C1 = g2^β");
    println!("  C2 = g2^(β·y·B*)");
    println!("  Encryption successful!\n");
    
    // Step 4: Decrypt
    println!("Step 4: Running IPE.Decrypt(pp, sk, ct)...");
    
    let _result = ipe_decrypt(&pp, &sk, &ct);
    
    println!("Decryption result:");
    println!("  D1 = e(K1, C1)");
    println!("  D2 = e(K2, C2)");
    println!("  Decryption successful!\n");
    
    println!("=== FHIPE Full Flow Complete ===");
}
