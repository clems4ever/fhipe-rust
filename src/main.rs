mod setup;

use setup::{ipe_setup};

fn main() {
    // Example usage
    let lambda = 128; // Security parameter
    let n = 5;        // Vector dimension
    
    let (pp, _msk) = ipe_setup(lambda, n);
    
    println!("FHIPE Setup completed:");
    println!("  Security parameter λ = {}", pp.security_param);
    println!("  Dimension n = {}", pp.dimension);
    println!("  Generated g1 ∈ G1");
    println!("  Generated g2 ∈ G2");
    println!("  Generated B matrix ({}x{})", n, n);
    println!("  Generated B* matrix ({}x{})", n, n);
}
