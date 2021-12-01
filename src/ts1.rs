use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar as Fr};
use group::prime::PrimeCurveAffine;

// Generates a random `Fr` using the algorithm from Filecoin's first trusted-setup.
pub fn rand_fr_ts1(mut rng: impl rand_ts1::RngCore) -> Fr {
    use fff::{Field, PrimeField};

    let fr = paired::bls12_381::Fr::random(&mut rng);
    let mut u64s_le = [0u64; 4];
    u64s_le.copy_from_slice(fr.into_repr().as_ref());
    let opt = Fr::from_u64s_le(&u64s_le);
    assert!(
        bool::from(opt.is_some()),
        "failed to convert random TS1 Fr to TS2 Fr"
    );
    opt.unwrap()
}

// Generates a random `G1Projective` using the algorithm from Filecoin's first trusted-setup.
pub fn rand_g1_ts1(mut rng: impl rand_ts1::RngCore) -> G1Projective {
    use groupy::{CurveAffine, CurveProjective};
    use paired::bls12_381::G1;

    let g1 = G1::random(&mut rng);
    let mut bytes = [0u8; 96];
    bytes.copy_from_slice(g1.into_affine().into_uncompressed().as_ref());
    let opt = G1Affine::from_uncompressed(&bytes);
    assert!(
        bool::from(opt.is_some()),
        "random TS1 G1 point is not valid TS2 G1 point"
    );
    opt.unwrap().to_curve()
}

// Generates a random `G2Projective` using the algorithm from Filecoin's first trusted-setup.
pub fn rand_g2_ts1(mut rng: impl rand_ts1::RngCore) -> G2Projective {
    use groupy::{CurveAffine, CurveProjective};
    use paired::bls12_381::G2;

    let g2 = G2::random(&mut rng);
    let mut bytes = [0u8; 192];
    bytes.copy_from_slice(g2.into_affine().into_uncompressed().as_ref());
    let opt = G2Affine::from_uncompressed(&bytes);
    assert!(
        bool::from(opt.is_some()),
        "random TS1 G2 point is not valid TS2 G2 point"
    );
    opt.unwrap().to_curve()
}

// Generates a random `G2Projective` from a given seed `digest` using the algorithm from Filecoin's
// first trusted-setup.
pub fn hash_to_g2_ts1(digest: &[u8]) -> G2Projective {
    use rand_chacha_ts1::ChaChaRng;
    use rand_ts1::SeedableRng;

    assert!(digest.len() >= 32);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);
    rand_g2_ts1(&mut ChaChaRng::from_seed(seed))
}
