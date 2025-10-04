use ark_ff::PrimeField;

pub fn ensure_same_length<T, U>(a: &[T], b: &[U]) {
    assert_eq!(
        a.len(),
        b.len(),
        "mismatched vector lengths: {} vs {}",
        a.len(),
        b.len()
    );
}

pub fn i64_to_field<F: PrimeField>(x: i64) -> F {
    if x >= 0 {
        F::from(x as u64)
    } else {
        let mut v = F::from((-x) as u64);
        v = -v;
        v
    }
}

pub fn field_inner_product<F: PrimeField>(x: &[F], y: &[F]) -> F {
    ensure_same_length(x, y);
    x.iter()
        .zip(y.iter())
        .fold(F::ZERO, |acc, (a, b)| acc + (*a) * (*b))
}