mod mimc;

use std::path::Path;

use bellperson::groth16::{create_random_proof, prepare_verifying_key, verify_proof};
use blstrs::Scalar as Fr;
use ff::Field;
use filecoin_phase2::{verify_contribution, MPCParameters};
use rand::thread_rng;

use mimc::{mimc as mimc_hash, MiMCDemo, MIMC_ROUNDS};

#[test]
fn test_large_params() {
    assert!(
        Path::new("./phase1radix2m10").exists(),
        "the phase1 file `phase1radix2m10` must be in the crate's top level directory"
    );

    let mut rng = thread_rng();

    let constants = (0..MIMC_ROUNDS)
        .map(|_| Fr::random(&mut rng))
        .collect::<Vec<_>>();

    let circuit = MiMCDemo {
        xl: None,
        xr: None,
        constants: &constants,
    };

    let mut params = MPCParameters::new(circuit, true).unwrap();
    let old_params = params.copy();
    params.contribute(&mut rng);

    let first_contrib = verify_contribution(&old_params, &params).expect("should verify");

    let old_params = params.copy();
    params.contribute(&mut rng);

    let second_contrib = verify_contribution(&old_params, &params).expect("should verify");

    let all_contributions = params
        .verify(
            MiMCDemo {
                xl: None,
                xr: None,
                constants: &constants,
            },
            true,
        )
        .unwrap();

    assert!(all_contributions.contains(&first_contrib));
    assert!(all_contributions.contains(&second_contrib));

    // Create a Groth16 proof using the generated parameters and verfy that the proof is valid.
    let groth_params = params.get_params();

    // Generate a random preimage and compute the image.
    let xl = Fr::random(&mut rng);
    let xr = Fr::random(&mut rng);
    let image = mimc_hash(xl, xr, &constants);

    let circuit = MiMCDemo {
        xl: Some(xl),
        xr: Some(xr),
        constants: &constants,
    };
    let proof = create_random_proof(circuit, groth_params, &mut rng).unwrap();

    let pvk = prepare_verifying_key(&groth_params.vk);
    assert!(verify_proof(&pvk, &proof, &[image]).unwrap());
}
