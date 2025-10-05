use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use fhipe_rust::v2::setup::ipe_setup;

fn main() {
    println!("=== Verifying Correlated Bases ===\n");
    
    let lambda = 128;
    let n = 5;
    let search_space_size = 1000;
    
    let (_pp, msk) = ipe_setup(lambda, n, search_space_size);
    
    println!("Setup complete. Generated {} correlated bases.", n);
    println!("Verifying that e(Uᵢ, Vᵢ) = e(g₁, g₂) for all i...\n");
    
    // Compute the reference pairing e(g₁, g₂)
    let e_g1_g2 = Bls12_381::pairing(msk.g1, msk.g2);
    
    // Verify each correlated base pair
    for i in 0..n {
        let e_ui_vi = Bls12_381::pairing(msk.u_bases[i], msk.v_bases[i]);
        
        if e_ui_vi == e_g1_g2 {
            println!("✓ Base pair {}: e(U_{}, V_{}) = e(g₁, g₂)", i, i, i);
        } else {
            println!("✗ Base pair {}: MISMATCH!", i);
            panic!("Correlated bases verification failed!");
        }
    }
    
    println!("\n✓ All correlated bases verified successfully!");
    println!("\nThis confirms that:");
    println!("  • Uᵢ = g₁^(γᵢ)");
    println!("  • Vᵢ = g₂^(γᵢ⁻¹)");
    println!("  • e(Uᵢ, Vᵢ) = e(g₁^(γᵢ), g₂^(γᵢ⁻¹)) = e(g₁, g₂)^(γᵢ·γᵢ⁻¹) = e(g₁, g₂)");
}
