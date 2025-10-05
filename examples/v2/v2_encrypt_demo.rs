use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::rand::SeedableRng;
use fhipe_rust::v2::setup::ipe_setup;
use fhipe_rust::v2::encrypt::ipe_encrypt;
use rand::rngs::StdRng;

fn main() {
    println!("=== FHIPE v2: Encryption with Correlated Bases ===\n");
    
    let lambda = 128;
    let n = 5;
    let search_space_size = 1000;
    
    // Setup
    println!("1. Running IPE Setup...");
    let (_pp, msk) = ipe_setup(lambda, n, search_space_size);
    println!("   ✓ Generated master secret key with {} correlated bases", n);
    println!("   ✓ Uᵢ = g₁^(γᵢ), Vᵢ = g₂^(γᵢ⁻¹) for i = 0..{}", n-1);
    
    // Create test vector
    let mut rng = StdRng::seed_from_u64(42);
    let y: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    println!("\n2. Encrypting vector y with {} elements", n);
    
    // Encrypt
    let _ct = ipe_encrypt(&msk, &y, &mut rng);
    
    println!("\n3. Ciphertext Structure:");
    println!("   C1 = g₂^β            (single G2 element)");
    println!("   C̃2 = ∏ᵢ Vᵢ^(β·vᵢ)    (single G2 element - aggregated!)");
    println!("\n   where v = y·B* is the encoded vector");
    
    println!("\n4. Key Difference from v1:");
    println!("   v1: C2 was a VECTOR of {} G2 elements", n);
    println!("   v2: C̃2 is a SINGLE G2 element (aggregated using correlated bases)");
    
    println!("\n5. Benefits:");
    println!("   • Ciphertext size reduced from {} G2 elements to 2 G2 elements", n+1);
    println!("   • Decryption will use SINGLE pairing instead of {} pairings", n);
    println!("   • Expected ~{}x speedup in pairing computation", n);
    
    println!("\n✓ Encryption completed successfully!");
    println!("\nNext steps:");
    println!("  • Update KeyGen to produce K̃₂ = ∏ᵢ Uᵢ^(α·uᵢ)");
    println!("  • Update Decrypt to compute e(K̃₂, C̃₂) = e(g₁, g₂)^(αβ·det(B)·⟨x,y⟩)");
}
