# fhipe-rust

Function-Hiding Inner Product Encryption implementation based on [ePrint 2016/440](https://eprint.iacr.org/2016/440).

Uses Dual Pairing Vector Spaces (DPVS) construction with BLS12-381 curve via Arkworks.

## Usage

```rust
use fhipe_rust::{setup, keygen, encrypt, decrypt};
use ark_bls12_381::Fr;
use rand::rngs::StdRng;
use rand::SeedableRng;

let mut rng = StdRng::seed_from_u64(42);
let n = 8; // vector dimension

// Setup with dimension n -> returns (PublicParams, MasterSecretKey)
let (pp, msk) = setup(n, &mut rng);

// Create vectors (as field elements)
let x: Vec<Fr> = /* ... */;
let y: Vec<Fr> = /* ... */;

// Generate key for x (requires master secret key!)
let sk = keygen(&msk, &pp, &x, &mut rng);

// Encrypt y (only needs public params)
let ct = encrypt(&pp, &y, &mut rng);

// Decrypt to get e(g1, g2)^<x,y> in GT
let result = decrypt(&pp, &sk, &ct);
```

**Note**: This is a research implementation. Not audited for production use.
