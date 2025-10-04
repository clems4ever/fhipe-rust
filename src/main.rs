use fhipe_rust::{setup, keygen, encrypt, decrypt};
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn main() {
    // Quick demo: run setup, keygen, encrypt, decrypt, and print a short digest
    let mut rng = StdRng::seed_from_u64(1234);
    let n = 8;
    let (pp, msk) = setup(n, &mut rng);

    let n = 8;
    let x: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    let y: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

    let sk = keygen(&msk, &pp, &x, &mut rng);
    let ct = encrypt(&pp, &y, &mut rng);
    let gt = decrypt(&pp, &sk, &ct);

    // Print a compact hex-like digest of the target field element by serializing it
    use ark_serialize::CanonicalSerialize;
    let mut bytes = Vec::new();
    gt.serialize_compressed(&mut bytes).unwrap();
    let digest: String = bytes.iter().take(16).map(|b| format!("{:02x}", b)).collect();
    println!("FH-IPE demo pairing digest: {}... ({} bytes)", digest, bytes.len());
}
