mod setup;
mod keygen;
mod encrypt;
mod decrypt;

use setup::ipe_setup;
use keygen::ipe_keygen;
use encrypt::ipe_encrypt;
use decrypt::{ipe_decrypt, recover_inner_product};
use ark_bls12_381::Fr;
use rand::rngs::StdRng;
use ark_std::rand::SeedableRng;

fn inner_product(x: &[Fr], y: &[Fr]) -> Fr {
    assert_eq!(x.len(), y.len(), "Vectors must have the same dimension");
    x.iter().zip(y.iter()).map(|(xi, yi)| *xi * yi).sum()
}

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
    
    // Create test vectors with small values so inner product is in search space
    // For demonstration: x = [1, 2, 3, 4, 5], y = [1, 1, 1, 1, 1]
    // Inner product = 1+2+3+4+5 = 15
    let x: Vec<Fr> = (1..=n).map(|i| Fr::from(i as u64)).collect();
    let y: Vec<Fr> = vec![Fr::from(1u64); n];
    
    println!("  Using test vectors:");
    println!("  x = [1, 2, 3, 4, 5]");
    println!("  y = [1, 1, 1, 1, 1]");
    println!("  Expected <x, y> = 15");
    
    let sk = ipe_keygen(&msk, &x, &mut rng);
    
    println!("Secret key generated:");
    println!("  K1 = g1^(α·det(B))");
    println!("  K2 = g1^(α·x·B)");
    println!("  Key generation successful!\n");
    
    // Step 3: Encrypt
    println!("\nStep 3: Running IPE.Encrypt(msk, y)...");
    
    // y is already defined above
    let ct = ipe_encrypt(&msk, &y, &mut rng);
    
    println!("Ciphertext generated:");
    println!("  C1 = g2^β");
    println!("  C2 = g2^(β·y·B*)");
    println!("  Encryption successful!\n");
    
    // Step 4: Decrypt
    println!("Step 4: Running IPE.Decrypt(pp, sk, ct)...");
    
    let result = ipe_decrypt(&pp, &sk, &ct);
    
    println!("Decryption result:");
    println!("  D1 = e(K1, C1)");
    println!("  D2 = e(K2, C2)");
    println!("  Decryption successful!\n");
    
    // Step 5: Compute the actual inner product
    println!("Step 5: Computing inner product <x, y>...");
    
    let inner_prod = inner_product(&x, &y);
    println!("  Direct computation: <x, y> = {:?}\n", inner_prod);
    
    // Step 6: Recover inner product from decryption using search
    println!("Step 6: Recovering inner product from decryption...");
    println!("  Building search space S...");
    
    // Create a search space
    // In practice, S would be defined by the application
    // For demonstration, we'll use a small range
    let mut search_space = Vec::new();
    
    // For demo, create a small search space
    // In practice, S = {0, 1, ..., poly(λ)} or application-specific values
    for i in 0..1000 {
        search_space.push(Fr::from(i as u64));
    }
    
    println!("  Search space size: |S| = {}", search_space.len());
    println!("  Searching for z such that (D1)^z = D2...");
    
    match recover_inner_product(&result, &search_space) {
        Some(recovered) => {
            println!("  ✓ SUCCESS: Found z = {:?}", recovered);
            
            // Check if it matches the actual inner product
            if recovered == inner_prod {
                println!("  ✓ VERIFIED: Recovered value matches actual inner product!\n");
            } else {
                println!("  ⚠ WARNING: Recovered value differs from expected inner product");
                println!("    Expected: {:?}", inner_prod);
                println!("    Got:      {:?}\n", recovered);
            }
        }
        None => {
            println!("  ✗ NOT FOUND: Inner product not in search space S");
            println!("    The actual inner product may be outside the search range");
            println!("    Actual <x, y> = {:?}\n", inner_prod);
        }
    }
    
    println!("=== FHIPE Full Flow Complete ===");
    println!("\nIPE Decryption Property:");
    println!("  The algorithm searches for z ∈ S such that (D1)^z = D2");
    println!("  where D1 = e(K1, C1) and D2 = e(K2, C2)");
    println!("  This z equals the inner product <x, y>");
}
