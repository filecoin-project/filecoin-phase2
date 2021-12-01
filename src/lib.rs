//! # zk-SNARK MPCs, made easy.
//!
//! ## Make your circuit
//!
//! Grab the [`bellperson`](https://github.com/filecoin-project/bellman) crate. Bellman
//! provides a trait called `Circuit`, which you must implement
//! for your computation.
//!
//! Here's a silly example: proving you know the cube root of
//! a field element.
//!
//! ```compile_fail,no_run
//! use fff::Field;
//! use bellperson::{
//!     Circuit,
//!     ConstraintSystem,
//!     SynthesisError,
//!     bls::Engine,
//! };
//!
//! struct CubeRoot<E: Engine> {
//!     cube_root: Option<E::Fr>
//! }
//!
//! impl<E: Engine> Circuit<E> for CubeRoot<E> {
//!     fn synthesize<CS: ConstraintSystem<E>>(
//!         self,
//!         cs: &mut CS
//!     ) -> Result<(), SynthesisError>
//!     {
//!         // Witness the cube root
//!         let root = cs.alloc(|| "root", || {
//!             self.cube_root.ok_or(SynthesisError::AssignmentMissing)
//!         })?;
//!
//!         // Witness the square of the cube root
//!         let square = cs.alloc(|| "square", || {
//!             self.cube_root
//!                 .ok_or(SynthesisError::AssignmentMissing)
//!                 .map(|mut root| {root.square(); root })
//!         })?;
//!
//!         // Enforce that `square` is root^2
//!         cs.enforce(
//!             || "squaring",
//!             |lc| lc + root,
//!             |lc| lc + root,
//!             |lc| lc + square
//!         );
//!
//!         // Witness the cube, as a public input
//!         let cube = cs.alloc_input(|| "cube", || {
//!             self.cube_root
//!                 .ok_or(SynthesisError::AssignmentMissing)
//!                 .map(|root| {
//!                     let mut tmp = root;
//!                     tmp.square();
//!                     tmp.mul_assign(&root);
//!                     tmp
//!                 })
//!         })?;
//!
//!         // Enforce that `cube` is root^3
//!         // i.e. that `cube` is `root` * `square`
//!         cs.enforce(
//!             || "cubing",
//!             |lc| lc + root,
//!             |lc| lc + square,
//!             |lc| lc + cube
//!         );
//!
//!         Ok(())
//!     }
//! }
//! ```
//!
//! ## Create some proofs
//!
//! Now that we have `CubeRoot<E>` implementing `Circuit`,
//! let's create some parameters and make some proofs.
//!
//! ```compile_fail,no_run
//! use bellperson::bls::{Bls12, Fr};
//! use bellperson::groth16::{
//!     generate_random_parameters,
//!     create_random_proof,
//!     prepare_verifying_key,
//!     verify_proof
//! };
//! use rand::rngs::OsRng;
//!
//! let rng = &mut OsRng::new();
//!
//! // Create public parameters for our circuit
//! let params = {
//!     let circuit = CubeRoot::<Bls12> {
//!         cube_root: None
//!     };
//!
//!     generate_random_parameters::<Bls12, _, _>(
//!         circuit,
//!         rng
//!     ).unwrap()
//! };
//!
//! // Prepare the verifying key for verification
//! let pvk = prepare_verifying_key(&params.vk);
//!
//! // Let's start making proofs!
//! for _ in 0..50 {
//!     // Verifier picks a cube in the field.
//!     // Let's just make a random one.
//!     let root = Fr::rand(rng);
//!     let mut cube = root;
//!     cube.square();
//!     cube.mul_assign(&root);
//!
//!     // Prover gets the cube, figures out the cube
//!     // root, and makes the proof:
//!     let proof = create_random_proof(
//!         CubeRoot::<Bls12> {
//!             cube_root: Some(root)
//!         }, &params, rng
//!     ).unwrap();
//!
//!     // Verifier checks the proof against the cube
//!     assert!(verify_proof(&pvk, &proof, &[cube]).unwrap());
//! }
//! ```
//! ## Creating parameters
//!
//! Notice in the previous example that we created our zk-SNARK
//! parameters by calling `generate_random_parameters`. However,
//! if you wanted you could have called `generate_parameters`
//! with some secret numbers you chose, and kept them for
//! yourself. Given those numbers, you can create false proofs.
//!
//! In order to convince others you didn't, a multi-party
//! computation (MPC) can be used. The MPC has the property that
//! only one participant needs to be honest for the parameters to
//! be secure. This crate (`filecoin-phase2`) is about creating parameters
//! securely using such an MPC.
//!
//! Let's start by using `filecoin-phase2` to create some base parameters
//! for our circuit:
//!
//! ```compile_fail,no_run
//! let mut params = crate::MPCParameters::new(CubeRoot {
//!     cube_root: None
//! }).unwrap();
//! ```
//!
//! The first time you try this, it will try to read a file like
//! `phase1radix2m2` from the current directory. You need to grab
//! that from the [Powers of Tau](https://lists.z.cash.foundation/pipermail/zapps-wg/2018/000362.html).
//!
//! These parameters are not safe to use; false proofs can be
//! created for them. Let's contribute some randomness to these
//! parameters.
//!
//! ```compile_fail,no_run
//! // Contribute randomness to the parameters. Remember this hash,
//! // it's how we know our contribution is in the parameters!
//! let hash = params.contribute(rng);
//! ```
//!
//! These parameters are now secure to use, so long as you weren't
//! malicious. That may not be convincing to others, so let them
//! contribute randomness too! `params` can be serialized and sent
//! elsewhere, where they can do the same thing and send new
//! parameters back to you. Only one person needs to be honest for
//! the final parameters to be secure.
//!
//! Once you're done setting up the parameters, you can verify the
//! parameters:
//!
//! ```compile_fail,no_run
//! let contributions = params.verify(CubeRoot {
//!     cube_root: None
//! }).expect("parameters should be valid!");
//!
//! // We need to check the `contributions` to see if our `hash`
//! // is in it (see above, when we first contributed)
//! assert!(crate::contains_contribution(&contributions, &hash));
//! ```
//!
//! Great, now if you're happy, grab the Groth16 `Parameters` with
//! `params.params()`, so that you can interact with the bellman APIs
//! just as before.
#![deny(clippy::all, clippy::perf, clippy::correctness, rust_2018_idioms)]
#![allow(clippy::result_unit_err)]

pub mod small;
pub mod ts1;

use std::fmt::{self, Debug, Formatter};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::sync::Arc;
use std::time::Instant;

use bellperson::{
    groth16::{Parameters, VerifyingKey},
    multicore::Worker,
    Circuit, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
};
use blake2b_simd::State as Blake2b;
use blstrs::{Bls12, Fp, Fp2, G1Affine, G1Projective, G2Affine, G2Projective, Scalar as Fr};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve, Group, Wnaf, WnafGroup};
use log::{error, info};
use pairing::PairingCurveAffine;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::small::MPCSmall;

type G1BaseField = Fp;
type G2BaseField = Fp2;

#[inline(always)]
fn error_not_on_curve() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "not on curve")
}

#[inline(always)]
fn error_point_at_inf() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "point at infinity")
}

#[inline(always)]
fn error_not_in_subgroup() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "not in subgroup")
}

/// This is our assembly structure that we'll use to synthesize the
/// circuit into a QAP.
struct KeypairAssembly {
    num_inputs: usize,
    num_aux: usize,
    num_constraints: usize,
    at_inputs: Vec<Vec<(Fr, usize)>>,
    bt_inputs: Vec<Vec<(Fr, usize)>>,
    ct_inputs: Vec<Vec<(Fr, usize)>>,
    at_aux: Vec<Vec<(Fr, usize)>>,
    bt_aux: Vec<Vec<(Fr, usize)>>,
    ct_aux: Vec<Vec<(Fr, usize)>>,
}

impl KeypairAssembly {
    /// Returns the size (stack plus heap) of the `KeypairAssembly` in bytes.
    fn size(&self) -> usize {
        use std::mem::{size_of, size_of_val};

        let mut size = 3 * size_of::<usize>();
        size += 6 * size_of::<Vec<Vec<(Fr, usize)>>>();
        size += size_of_val::<[Vec<(Fr, usize)>]>(&self.at_inputs);
        size += size_of_val::<[Vec<(Fr, usize)>]>(&self.bt_inputs);
        size += size_of_val::<[Vec<(Fr, usize)>]>(&self.ct_inputs);
        size += size_of_val::<[Vec<(Fr, usize)>]>(&self.at_aux);
        size += size_of_val::<[Vec<(Fr, usize)>]>(&self.bt_aux);
        size += size_of_val::<[Vec<(Fr, usize)>]>(&self.ct_aux);

        for el in self.at_inputs.iter() {
            size += size_of_val::<[(Fr, usize)]>(el);
        }
        for el in self.bt_inputs.iter() {
            size += size_of_val::<[(Fr, usize)]>(el);
        }
        for el in self.ct_inputs.iter() {
            size += size_of_val::<[(Fr, usize)]>(el);
        }
        for el in self.at_aux.iter() {
            size += size_of_val::<[(Fr, usize)]>(el);
        }
        for el in self.bt_aux.iter() {
            size += size_of_val::<[(Fr, usize)]>(el);
        }
        for el in self.ct_aux.iter() {
            size += size_of_val::<[(Fr, usize)]>(el);
        }

        size
    }
}

impl ConstraintSystem<Fr> for KeypairAssembly {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        // There is no assignment, so we don't even invoke the
        // function for obtaining one.

        let index = self.num_aux;
        self.num_aux += 1;

        self.at_aux.push(vec![]);
        self.bt_aux.push(vec![]);
        self.ct_aux.push(vec![]);

        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    fn alloc_input<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        // There is no assignment, so we don't even invoke the
        // function for obtaining one.

        let index = self.num_inputs;
        self.num_inputs += 1;

        self.at_inputs.push(vec![]);
        self.bt_inputs.push(vec![]);
        self.ct_inputs.push(vec![]);

        Ok(Variable::new_unchecked(Index::Input(index)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<Fr>) -> LinearCombination<Fr>,
        LB: FnOnce(LinearCombination<Fr>) -> LinearCombination<Fr>,
        LC: FnOnce(LinearCombination<Fr>) -> LinearCombination<Fr>,
    {
        fn eval(
            l: LinearCombination<Fr>,
            inputs: &mut [Vec<(Fr, usize)>],
            aux: &mut [Vec<(Fr, usize)>],
            this_constraint: usize,
        ) {
            for (var, &coeff) in l.iter() {
                match var.get_unchecked() {
                    Index::Input(id) => inputs[id].push((coeff, this_constraint)),
                    Index::Aux(id) => aux[id].push((coeff, this_constraint)),
                }
            }
        }

        eval(
            a(LinearCombination::zero()),
            &mut self.at_inputs,
            &mut self.at_aux,
            self.num_constraints,
        );
        eval(
            b(LinearCombination::zero()),
            &mut self.bt_inputs,
            &mut self.bt_aux,
            self.num_constraints,
        );
        eval(
            c(LinearCombination::zero()),
            &mut self.ct_inputs,
            &mut self.ct_aux,
            self.num_constraints,
        );

        self.num_constraints += 1;
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

/// MPC parameters are just like bellman `Parameters` except, when serialized,
/// they contain a transcript of contributions at the end, which can be verified.
#[derive(Clone, PartialEq)]
pub struct MPCParameters {
    params: Parameters<Bls12>,
    cs_hash: [u8; 64],
    contributions: Vec<PublicKey>,
}

// Required by `assert_eq!()`.
impl Debug for MPCParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MPCParameters")
            .field("params", &"<bellman::groth16::Parameters>")
            .field("cs_hash", &self.cs_hash)
            .field("contributions", &self.contributions.to_vec())
            .finish()
    }
}

impl MPCParameters {
    /// Create new Groth16 parameters (compatible with bellman) for a given circuit. The resulting
    /// parameters are unsafe to use until there are contributions (see `contribute()`).
    ///
    /// If `check_subgroup` is `false` this function does not peroform the slow check that
    /// deserialized points are in their expected subgroup (either G1 or G2).
    //
    // Note: `MPCParameters::new()` is compatible with both ts1 and ts2.
    pub fn new<C: Circuit<Fr>>(
        circuit: C,
        check_subgroup: bool,
    ) -> Result<MPCParameters, SynthesisError> {
        let mut assembly = KeypairAssembly {
            num_inputs: 0,
            num_aux: 0,
            num_constraints: 0,
            at_inputs: vec![],
            bt_inputs: vec![],
            ct_inputs: vec![],
            at_aux: vec![],
            bt_aux: vec![],
            ct_aux: vec![],
        };

        // Allocate the "one" input variable
        assembly.alloc_input(|| "", || Ok(Fr::one()))?;

        // Synthesize the circuit.
        info!("MPCParameters::new() synthesizing circuit");
        let dt_synth = Instant::now();
        circuit.synthesize(&mut assembly)?;
        info!(
            "MPCParameters::new() sucessfully synthesized circuit, dt_synth={}s",
            dt_synth.elapsed().as_secs(),
        );

        // Input constraints to ensure full density of IC query
        // x * 0 = 0
        for i in 0..assembly.num_inputs {
            assembly.enforce(
                || "",
                |lc| lc + Variable::new_unchecked(Index::Input(i)),
                |lc| lc,
                |lc| lc,
            );
        }

        info!(
            "phase2::MPCParameters::new() Constraint System: n_constraints={}, n_inputs={}, n_aux={}, memsize={}b",
            assembly.num_constraints,
            assembly.num_inputs,
            assembly.num_aux,
            assembly.size()
        );

        // Compute the size of our evaluation domain, `m = 2^exp`.
        let mut m = 1;
        let mut exp = 0;
        while m < assembly.num_constraints {
            m *= 2;
            exp += 1;

            // Powers of Tau ceremony can't support more than 2^30
            if exp > 30 {
                return Err(SynthesisError::PolynomialDegreeTooLarge);
            }
        }

        // Try to load "phase1radix2m{}"
        info!(
            "phase2::MPCParameters::new() phase1.5_file=phase1radix2m{}",
            exp
        );
        let f = match File::open(format!("phase1radix2m{}", exp)) {
            Ok(f) => f,
            Err(e) => {
                error!("Could not find phase1.5 file: `phase1radix2m{}`", exp);
                panic!("Couldn't load phase1radix2m{}: {:?}", exp, e);
            }
        };
        let mut f = BufReader::with_capacity(1024 * 1024, f);

        let alpha = read_g1(&mut f, check_subgroup)?;
        let beta_g1 = read_g1(&mut f, check_subgroup)?;
        let beta_g2 = read_g2(&mut f, check_subgroup)?;

        info!("phase2::MPCParameters::new() reading coeffs_g1 from phase1.5 file");
        let mut coeffs_g1 = Vec::with_capacity(m);
        for _ in 0..m {
            coeffs_g1.push(read_g1(&mut f, check_subgroup)?);
        }

        info!("phase2::MPCParameters::new() reading coeffs_g2 from phase1.5 file");
        let mut coeffs_g2 = Vec::with_capacity(m);
        for _ in 0..m {
            coeffs_g2.push(read_g2(&mut f, check_subgroup)?);
        }

        info!("phase2::MPCParameters::new() reading alpha_coeffs_g1 from phase1.5 file");
        let mut alpha_coeffs_g1 = Vec::with_capacity(m);
        for _ in 0..m {
            alpha_coeffs_g1.push(read_g1(&mut f, check_subgroup)?);
        }

        info!("phase2::MPCParameters::new() reading beta_coeffs_g1 from phase1.5 file");
        let mut beta_coeffs_g1 = Vec::with_capacity(m);
        for _ in 0..m {
            beta_coeffs_g1.push(read_g1(&mut f, check_subgroup)?);
        }

        // These are `Arc` so that later it'll be easier
        // to use multiexp during QAP evaluation (which
        // requires a futures-based API)
        let coeffs_g1 = Arc::new(coeffs_g1);
        let coeffs_g2 = Arc::new(coeffs_g2);
        let alpha_coeffs_g1 = Arc::new(alpha_coeffs_g1);
        let beta_coeffs_g1 = Arc::new(beta_coeffs_g1);

        let mut ic = vec![G1Projective::identity(); assembly.num_inputs];
        info!("phase2::MPCParameters::new() initialized ic vector");
        let mut l = vec![G1Projective::identity(); assembly.num_aux];
        info!("phase2::MPCParameters::new() initialized l vector");
        let mut a_g1 = vec![G1Projective::identity(); assembly.num_inputs + assembly.num_aux];
        info!("phase2::MPCParameters::new() initialized a_g1 vector");
        let mut b_g1 = vec![G1Projective::identity(); assembly.num_inputs + assembly.num_aux];
        info!("phase2::MPCParameters::new() initialized b_g1 vector");
        let mut b_g2 = vec![G2Projective::identity(); assembly.num_inputs + assembly.num_aux];
        info!("phase2::MPCParameters::new() initialized b_g2 vector");

        #[allow(clippy::too_many_arguments)]
        fn eval(
            // Lagrange coefficients for tau
            coeffs_g1: Arc<Vec<G1Affine>>,
            coeffs_g2: Arc<Vec<G2Affine>>,
            alpha_coeffs_g1: Arc<Vec<G1Affine>>,
            beta_coeffs_g1: Arc<Vec<G1Affine>>,

            // QAP polynomials
            at: &[Vec<(Fr, usize)>],
            bt: &[Vec<(Fr, usize)>],
            ct: &[Vec<(Fr, usize)>],

            // Resulting evaluated QAP polynomials
            a_g1: &mut [G1Projective],
            b_g1: &mut [G1Projective],
            b_g2: &mut [G2Projective],
            ext: &mut [G1Projective],

            // Worker
            worker: &Worker,
        ) {
            // Sanity check
            assert_eq!(a_g1.len(), at.len());
            assert_eq!(a_g1.len(), bt.len());
            assert_eq!(a_g1.len(), ct.len());
            assert_eq!(a_g1.len(), b_g1.len());
            assert_eq!(a_g1.len(), b_g2.len());
            assert_eq!(a_g1.len(), ext.len());

            // Evaluate polynomials in multiple threads
            worker.scope(a_g1.len(), |scope, chunk| {
                for ((((((a_g1, b_g1), b_g2), ext), at), bt), ct) in a_g1
                    .chunks_mut(chunk)
                    .zip(b_g1.chunks_mut(chunk))
                    .zip(b_g2.chunks_mut(chunk))
                    .zip(ext.chunks_mut(chunk))
                    .zip(at.chunks(chunk))
                    .zip(bt.chunks(chunk))
                    .zip(ct.chunks(chunk))
                {
                    let coeffs_g1 = coeffs_g1.clone();
                    let coeffs_g2 = coeffs_g2.clone();
                    let alpha_coeffs_g1 = alpha_coeffs_g1.clone();
                    let beta_coeffs_g1 = beta_coeffs_g1.clone();

                    scope.execute(move || {
                        for ((((((a_g1, b_g1), b_g2), ext), at), bt), ct) in a_g1
                            .iter_mut()
                            .zip(b_g1.iter_mut())
                            .zip(b_g2.iter_mut())
                            .zip(ext.iter_mut())
                            .zip(at.iter())
                            .zip(bt.iter())
                            .zip(ct.iter())
                        {
                            for &(coeff, lag) in at {
                                *a_g1 += coeffs_g1[lag] * coeff;
                                *ext += beta_coeffs_g1[lag] * coeff;
                            }

                            for &(coeff, lag) in bt {
                                *b_g1 += coeffs_g1[lag] * coeff;
                                *b_g2 += coeffs_g2[lag] * coeff;
                                *ext += alpha_coeffs_g1[lag] * coeff;
                            }

                            for &(coeff, lag) in ct {
                                *ext += coeffs_g1[lag] * coeff;
                            }
                        }

                        // Normalize projective points
                        batch_normalization_g1(a_g1);
                        batch_normalization_g1(b_g1);
                        batch_normalization_g2(b_g2);
                        batch_normalization_g1(ext);
                    });
                }
            });
        }

        let worker = Worker::new();

        // Evaluate for inputs.
        info!("phase2::MPCParameters::new() evaluating polynomials for inputs");
        eval(
            coeffs_g1.clone(),
            coeffs_g2.clone(),
            alpha_coeffs_g1.clone(),
            beta_coeffs_g1.clone(),
            &assembly.at_inputs,
            &assembly.bt_inputs,
            &assembly.ct_inputs,
            &mut a_g1[0..assembly.num_inputs],
            &mut b_g1[0..assembly.num_inputs],
            &mut b_g2[0..assembly.num_inputs],
            &mut ic,
            &worker,
        );

        // Evaluate for auxillary variables.
        info!("phase2::MPCParameters::new() evaluating polynomials for auxillary variables");
        eval(
            coeffs_g1.clone(),
            coeffs_g2.clone(),
            alpha_coeffs_g1.clone(),
            beta_coeffs_g1.clone(),
            &assembly.at_aux,
            &assembly.bt_aux,
            &assembly.ct_aux,
            &mut a_g1[assembly.num_inputs..],
            &mut b_g1[assembly.num_inputs..],
            &mut b_g2[assembly.num_inputs..],
            &mut l,
            &worker,
        );

        // Don't allow any elements be unconstrained, so that
        // the L query is always fully dense.
        for e in l.iter() {
            if e.is_identity().into() {
                return Err(SynthesisError::UnconstrainedVariable);
            }
        }

        let vk = VerifyingKey::<Bls12> {
            alpha_g1: alpha,
            beta_g1,
            beta_g2,
            gamma_g2: G2Affine::generator(),
            delta_g1: G1Affine::generator(),
            delta_g2: G2Affine::generator(),
            ic: ic.into_par_iter().map(|e| e.to_affine()).collect(),
        };

        // Reclaim the memory used by these vectors prior to reading in `h`.
        drop(coeffs_g1);
        drop(coeffs_g2);
        drop(alpha_coeffs_g1);
        drop(beta_coeffs_g1);

        info!("phase2::MPCParameters::new() reading h from phase1.5 file");
        let mut h = Vec::with_capacity(m - 1);
        for _ in 0..(m - 1) {
            h.push(read_g1(&mut f, check_subgroup)?);
        }

        let params = Parameters {
            vk,
            h: Arc::new(h),
            l: Arc::new(l.into_par_iter().map(|e| e.to_affine()).collect()),

            // Filter points at infinity away from A/B queries
            a: Arc::new(
                a_g1.into_par_iter()
                    .filter(|e| !bool::from(e.is_identity()))
                    .map(|e| e.to_affine())
                    .collect(),
            ),
            b_g1: Arc::new(
                b_g1.into_par_iter()
                    .filter(|e| !bool::from(e.is_identity()))
                    .map(|e| e.to_affine())
                    .collect(),
            ),
            b_g2: Arc::new(
                b_g2.into_par_iter()
                    .filter(|e| !bool::from(e.is_identity()))
                    .map(|e| e.to_affine())
                    .collect(),
            ),
        };

        info!(
            "phase2::MPCParameters::new() vector lengths: ic={}, h={}, l={}, a={}, b_g1={}, b_g2={}",
            params.vk.ic.len(),
            params.h.len(),
            params.l.len(),
            params.a.len(),
            params.b_g1.len(),
            params.b_g2.len()
        );

        let cs_hash = {
            let sink = io::sink();
            let mut sink = HashWriter::new(sink);

            params.write(&mut sink).unwrap();

            sink.into_hash()
        };

        info!(
            "phase2::MPCParameters::new() cs_hash={}",
            pretty_cs_hash(&cs_hash)
        );

        Ok(MPCParameters {
            params,
            cs_hash,
            contributions: vec![],
        })
    }

    /// Get the underlying Groth16 `Parameters`
    pub fn get_params(&self) -> &Parameters<Bls12> {
        &self.params
    }

    pub fn n_contributions(&self) -> usize {
        self.contributions.len()
    }

    /// Contributes some randomness to the parameters. Only one
    /// contributor needs to be honest for the parameters to be
    /// secure.
    ///
    /// This function returns a "hash" that is bound to the
    /// contribution. Contributors can use this hash to make
    /// sure their contribution is in the final parameters, by
    /// checking to see if it appears in the output of
    /// `MPCParameters::verify`.
    // TODO: make this compatible with ts1
    // pub fn contribute_ts1(&mut self, rng: impl rand_ts1::RngCore) -> [u8; 64] {
    pub fn contribute(&mut self, rng: impl RngCore) -> [u8; 64] {
        // Generate a keypair
        // TODO: make this compatible with ts1
        // let (pubkey, privkey) = keypair_ts1(rng, self);
        let (pubkey, privkey) = keypair(rng, self);

        let delta_inv = match privkey.delta.invert() {
            opt if opt.is_some().into() => opt.unwrap(),
            _ => panic!("private-key's `delta` is zero, cannot invert"),
        };

        info!("phase2::MPCParameters::contribute() performing batch exponentiation of l");
        batch_exp(Arc::get_mut(&mut self.params.l).unwrap(), delta_inv);

        info!("phase2::MPCParameters::contribute() performing batch exponentiation of h");
        batch_exp(Arc::get_mut(&mut self.params.h).unwrap(), delta_inv);

        info!("phase2::MPCParameters::contribute() finished batch exponentiations");

        self.params.vk.delta_g1 = (self.params.vk.delta_g1 * privkey.delta).to_affine();
        self.params.vk.delta_g2 = (self.params.vk.delta_g2 * privkey.delta).to_affine();

        self.contributions.push(pubkey.clone());

        // Calculate the hash of the public key and return it
        {
            let sink = io::sink();
            let mut sink = HashWriter::new(sink);
            pubkey.write(&mut sink).unwrap();
            sink.into_hash()
        }
    }

    /// Verify the correctness of the parameters, given a circuit
    /// instance. This will return all of the hashes that
    /// contributors obtained when they ran
    /// `MPCParameters::contribute`, for ensuring that contributions
    /// exist in the final parameters.
    pub fn verify<C: Circuit<Fr>>(
        &self,
        circuit: C,
        check_subgroup: bool,
    ) -> Result<Vec<[u8; 64]>, ()> {
        let initial_params = MPCParameters::new(circuit, check_subgroup).map_err(|_| ())?;

        // H/L will change, but should have same length
        if initial_params.params.h.len() != self.params.h.len() {
            error!("phase2::MPCParameters::verify() h's length has changed");
            return Err(());
        }
        if initial_params.params.l.len() != self.params.l.len() {
            error!("phase2::MPCParameters::verify() l's length has changed");
            return Err(());
        }

        // A/B_G1/B_G2 doesn't change at all
        if initial_params.params.a != self.params.a {
            error!("phase2::MPCParameters::verify() evaluated QAP a polynomial has changed");
            return Err(());
        }
        if initial_params.params.b_g1 != self.params.b_g1 {
            error!("phase2::MPCParameters::verify() evaluated QAP b_g1 polynomial has changed");
            return Err(());
        }
        if initial_params.params.b_g2 != self.params.b_g2 {
            error!("phase2::MPCParameters::verify() evaluated QAP b_g2 polynomial has changed");
            return Err(());
        }

        // alpha/beta/gamma don't change
        if initial_params.params.vk.alpha_g1 != self.params.vk.alpha_g1 {
            error!("phase2::MPCParameters::verify() vk's alpha has changed");
            return Err(());
        }
        if initial_params.params.vk.beta_g1 != self.params.vk.beta_g1 {
            error!("phase2::MPCParameters::verify() vk's beta_g1 has changed");
            return Err(());
        }
        if initial_params.params.vk.beta_g2 != self.params.vk.beta_g2 {
            error!("phase2::MPCParameters::verify() vk's beta_g2 has changed");
            return Err(());
        }
        if initial_params.params.vk.gamma_g2 != self.params.vk.gamma_g2 {
            error!("phase2::MPCParameters::verify() vk's gamma has changed");
            return Err(());
        }

        // IC shouldn't change, as gamma doesn't change
        if initial_params.params.vk.ic != self.params.vk.ic {
            error!("phase2::MPCParameters::verify() vk's ic has changed");
            return Err(());
        }

        // cs_hash should be the same
        if initial_params.cs_hash != self.cs_hash {
            error!("phase2::MPCParameters::verify() cs_hash has changed");
            return Err(());
        }

        let sink = io::sink();
        let mut sink = HashWriter::new(sink);
        sink.write_all(&initial_params.cs_hash).unwrap();

        let mut current_delta = G1Affine::generator();
        let mut result = vec![];

        for pubkey in &self.contributions {
            let mut our_sink = sink.clone();
            our_sink.write_all(&pubkey.s.to_uncompressed()).unwrap();
            our_sink
                .write_all(&pubkey.s_delta.to_uncompressed())
                .unwrap();

            pubkey.write(&mut sink).unwrap();

            let h = our_sink.into_hash();

            // The transcript must be consistent
            if pubkey.transcript != h {
                error!("phase2::MPCParameters::verify() transcripts differ");
                return Err(());
            }

            // TODO: make this compatible with ts1
            // let r = hash_to_g2_ts1(&h).to_affine();
            let r = hash_to_g2(&h).to_affine();

            // Check the signature of knowledge
            if !same_ratio((r, pubkey.r_delta), (pubkey.s, pubkey.s_delta)) {
                error!("phase2::MPCParameters::verify() pubkey's r and s were shifted by different deltas");
                return Err(());
            }

            // Check the change from the old delta is consistent
            if !same_ratio((current_delta, pubkey.delta_after), (r, pubkey.r_delta)) {
                error!("phase2::MPCParameters::verify() contribution's delta and r where shifted differently");
                return Err(());
            }

            current_delta = pubkey.delta_after;

            {
                let sink = io::sink();
                let mut sink = HashWriter::new(sink);
                pubkey.write(&mut sink).unwrap();
                result.push(sink.into_hash());
            }
        }

        // Current parameters should have consistent delta in G1
        if current_delta != self.params.vk.delta_g1 {
            error!("phase2::MPCParameters::verify() vk's delta_g1 differs from calculated delta");
            return Err(());
        }

        // Current parameters should have consistent delta in G2
        if !same_ratio(
            (G1Affine::generator(), current_delta),
            (G2Affine::generator(), self.params.vk.delta_g2),
        ) {
            error!("phase2::MPCParameters::verify() shift in vk's delta_g2 is inconsistent with calculated delta");
            return Err(());
        }

        // H and L queries should be updated with delta^-1
        if !same_ratio(
            merge_pairs(&initial_params.params.h, &self.params.h),
            (self.params.vk.delta_g2, G2Affine::generator()), // reversed for inverse
        ) {
            error!("phase2::MPCParameters::verify() h queries have not shifted by delta^-1");
            return Err(());
        }

        if !same_ratio(
            merge_pairs(&initial_params.params.l, &self.params.l),
            (self.params.vk.delta_g2, G2Affine::generator()), // reversed for inverse
        ) {
            error!("phase2::MPCParameters::verify() l queries have not shifted by delta^-1");
            return Err(());
        }

        Ok(result)
    }

    /// Serialize these parameters. The serialized parameters
    /// can be read by bellman as Groth16 `Parameters`.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.params.write(&mut writer)?;
        writer.write_all(&self.cs_hash)?;

        writer.write_u32::<BigEndian>(self.contributions.len() as u32)?;
        for pubkey in &self.contributions {
            pubkey.write(&mut writer)?;
        }

        Ok(())
    }

    /// Serializes these parameters as `MPCSmall`.
    pub fn write_small<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.params.vk.delta_g1.to_uncompressed())?;
        writer.write_all(&self.params.vk.delta_g2.to_uncompressed())?;

        writer.write_u32::<BigEndian>(self.params.h.len() as u32)?;
        for h in &*self.params.h {
            writer.write_all(&h.to_uncompressed())?;
        }

        writer.write_u32::<BigEndian>(self.params.l.len() as u32)?;
        for l in &*self.params.l {
            writer.write_all(&l.to_uncompressed())?;
        }

        writer.write_all(&self.cs_hash)?;

        writer.write_u32::<BigEndian>(self.contributions.len() as u32)?;
        for pubkey in &self.contributions {
            pubkey.write(&mut writer)?;
        }

        Ok(())
    }

    /// Deserialize these parameters. If `check_subgroup` is `false` this function does not peroform
    /// the slow check that deserialized points are in their expected subgroup (either G1 or G2).
    pub fn read<R: Read>(mut reader: R, check_subgroup: bool) -> io::Result<MPCParameters> {
        let params = Parameters::read(&mut reader, check_subgroup)?;

        let mut cs_hash = [0u8; 64];
        reader.read_exact(&mut cs_hash)?;

        let contributions_len = reader.read_u32::<BigEndian>()? as usize;

        let mut contributions = vec![];
        for _ in 0..contributions_len {
            contributions.push(PublicKey::read(&mut reader, check_subgroup)?);
        }

        info!(
            "phase2::MPCParameters::read() vector lengths: ic={}, h={}, l={}, a={}, b_g1={}, \
            b_g2={}, contributions={}",
            params.vk.ic.len(),
            params.h.len(),
            params.l.len(),
            params.a.len(),
            params.b_g1.len(),
            params.b_g2.len(),
            contributions.len(),
        );

        Ok(MPCParameters {
            params,
            cs_hash,
            contributions,
        })
    }

    // memcpy's the potentially large vectors behind Arc's (duplicates the arrays on the stack,
    // does not increment ref-counts in `self`).
    pub fn copy(&self) -> Self {
        let mut params = self.clone();
        params.params.h = Arc::new((*self.params.h).clone());
        params.params.l = Arc::new((*self.params.l).clone());
        params.params.a = Arc::new((*self.params.a).clone());
        params.params.b_g1 = Arc::new((*self.params.b_g1).clone());
        params.params.b_g2 = Arc::new((*self.params.b_g2).clone());
        params
    }

    // memcpy's the potentially large h and l vectors behind Arc's into a new `MPCSmall` (duplicates
    // the h and l arrays on the stack, does not increment ref-counts for the h and l Arc's in `self`).
    pub fn copy_small(&self) -> MPCSmall {
        MPCSmall {
            delta_g1: self.params.vk.delta_g1,
            delta_g2: self.params.vk.delta_g2,
            h: (*self.params.h).clone(),
            l: (*self.params.l).clone(),
            cs_hash: self.cs_hash,
            contributions: self.contributions.clone(),
        }
    }

    // Updates `self` with a contribution (or contributions) that is in the `MPCSmall` params form.
    // `MPCSmall` must contain at least one new contribution. This decrements the strong ref-counts
    // by one for any Arc clones that were made from `self.h` and `self.l`. If either of `self`'s h
    // and l Arc's have ref-count 1, then they will be dropped.
    pub fn add_contrib(&mut self, contrib: MPCSmall) {
        assert_eq!(
            self.cs_hash, contrib.cs_hash,
            "large and small params have different cs_hash"
        );

        assert_eq!(
            self.params.h.len(),
            contrib.h.len(),
            "large and small params have different h length"
        );
        assert_eq!(
            self.params.l.len(),
            contrib.l.len(),
            "large and small params have different l length"
        );

        assert!(
            self.contributions.len() < contrib.contributions.len(),
            "small params do not contain additional contributions"
        );
        assert_eq!(
            &self.contributions[..],
            &contrib.contributions[..self.contributions.len()],
            "small params cannot change prior contributions in large params"
        );

        // Unwrapping here is safe because we have already asserted that `contrib` contains at least
        // one (new) contribution.
        assert_eq!(
            contrib.delta_g1,
            contrib.contributions.last().unwrap().delta_after,
            "small params are internally inconsistent wrt. G1 deltas"
        );

        let MPCSmall {
            delta_g1,
            delta_g2,
            h,
            l,
            contributions,
            ..
        } = contrib;
        self.params.vk.delta_g1 = delta_g1;
        self.params.vk.delta_g2 = delta_g2;
        self.params.h = Arc::new(h);
        self.params.l = Arc::new(l);
        self.contributions = contributions;
    }

    // Returns true if a pair of large and small MPC params contain equal values. It is not required
    // that `self`'s h and l Arc's point to the same memory locations as `small`'s non-Arc h and l
    // vectors.
    pub fn has_last_contrib(&self, small: &MPCSmall) -> bool {
        self.params.vk.delta_g1 == small.delta_g1
            && self.params.vk.delta_g2 == small.delta_g2
            && *self.params.h == small.h
            && *self.params.l == small.l
            && self.cs_hash == small.cs_hash
            && self.contributions == small.contributions
    }
}

/// This allows others to verify that you contributed. The hash produced
/// by `MPCParameters::contribute` is just a BLAKE2b hash of this object.
#[derive(Clone, PartialEq)]
struct PublicKey {
    /// This is the delta (in G1) after the transformation, kept so that we
    /// can check correctness of the public keys without having the entire
    /// interstitial parameters for each contribution.
    delta_after: G1Affine,

    /// Random element chosen by the contributor.
    s: G1Affine,

    /// That element, taken to the contributor's secret delta.
    s_delta: G1Affine,

    /// r is H(last_pubkey | s | s_delta), r_delta proves knowledge of delta
    r_delta: G2Affine,

    /// Hash of the transcript (used for mapping to r)
    transcript: [u8; 64],
}

// Required by `assert_eq!()`.
impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("delta_after", &self.delta_after)
            .field("s", &self.s)
            .field("s_delta", &self.s_delta)
            .field("r_delta", &self.r_delta)
            .field("transcript", &self.transcript.to_vec())
            .finish()
    }
}

#[inline]
pub fn read_g1<R: Read>(reader: &mut R, check_subgroup: bool) -> io::Result<G1Affine> {
    let mut repr = [0u8; G1Affine::uncompressed_size()];
    reader.read_exact(&mut repr)?;

    let opt = G1Affine::from_uncompressed_unchecked(&repr);
    let is_valid: bool = opt.is_some().into();
    if !is_valid {
        return Err(error_not_on_curve());
    }

    let affine = opt.unwrap();

    if affine.is_identity().into() {
        return Err(error_point_at_inf());
    }

    if check_subgroup {
        let is_in_subgroup: bool = affine.is_torsion_free().into();
        if !is_in_subgroup {
            return Err(error_not_in_subgroup());
        }
    }

    Ok(affine)
}

#[inline]
pub fn read_g2<R: Read>(reader: &mut R, check_subgroup: bool) -> io::Result<G2Affine> {
    let mut repr = [0u8; G2Affine::uncompressed_size()];
    reader.read_exact(&mut repr)?;

    let opt = G2Affine::from_uncompressed_unchecked(&repr);
    let is_valid: bool = opt.is_some().into();
    if !is_valid {
        return Err(error_not_on_curve());
    }

    let affine = opt.unwrap();

    if affine.is_identity().into() {
        return Err(error_point_at_inf());
    }

    if check_subgroup {
        let is_in_subgroup: bool = affine.is_torsion_free().into();
        if !is_in_subgroup {
            return Err(error_not_in_subgroup());
        }
    }

    Ok(affine)
}

impl PublicKey {
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.delta_after.to_uncompressed())?;
        writer.write_all(&self.s.to_uncompressed())?;
        writer.write_all(&self.s_delta.to_uncompressed())?;
        writer.write_all(&self.r_delta.to_uncompressed())?;
        writer.write_all(&self.transcript)?;

        Ok(())
    }

    fn read<R: Read>(mut reader: R, check_subgroup: bool) -> io::Result<PublicKey> {
        let delta_after = read_g1(&mut reader, check_subgroup)?;
        let s = read_g1(&mut reader, check_subgroup)?;
        let s_delta = read_g1(&mut reader, check_subgroup)?;
        let r_delta = read_g2(&mut reader, check_subgroup)?;
        let mut transcript = [0u8; 64];
        reader.read_exact(&mut transcript)?;

        Ok(PublicKey {
            delta_after,
            s,
            s_delta,
            r_delta,
            transcript,
        })
    }
}

/// Verify a contribution, given the old parameters and
/// the new parameters. Returns the hash of the contribution.
pub fn verify_contribution(before: &MPCParameters, after: &MPCParameters) -> Result<[u8; 64], ()> {
    if after.contributions.len() != (before.contributions.len() + 1) {
        error!(
            "phase2::verify_contribution() 'after' params do not contain exactly one more \
            contribution than the 'before' params: n_contributions_before={}, \
            n_contributions_after={}",
            before.contributions.len(),
            after.contributions.len()
        );
        return Err(());
    }

    // None of the previous transformations should change
    if before.contributions != after.contributions[..after.contributions.len() - 1] {
        error!("phase2::verify_contribution() 'after' params contributions differ from 'before' params contributions");
        return Err(());
    }

    // H/L will change, but should have same length
    if before.params.h.len() != after.params.h.len() {
        error!("phase2::verify_contribution() length of h has changed");
        return Err(());
    }
    if before.params.l.len() != after.params.l.len() {
        error!("phase2::verify_contribution() length of l has changed");
        return Err(());
    }

    // A, B_G1, and B_G2 don't change
    if before.params.a != after.params.a {
        error!("phase2::verify_contribution() evaluated QAP a polynomial has changed");
        return Err(());
    }
    if before.params.b_g1 != after.params.b_g1 {
        error!("phase2::verify_contribution() evaluated QAP b_g1 polynomial has changed");
        return Err(());
    }
    if before.params.b_g2 != after.params.b_g2 {
        error!("phase2::verify_contribution() evaluated QAP b_g2 polynomial has changed");
        return Err(());
    }

    // alpha, beta, and gamma don't change
    if before.params.vk.alpha_g1 != after.params.vk.alpha_g1 {
        error!("phase2::verify_contribution() vk's alpha_g1 hash changed");
        return Err(());
    }
    if before.params.vk.beta_g1 != after.params.vk.beta_g1 {
        error!("phase2::verify_contribution() vk's beta_g1 has changed");
        return Err(());
    }
    if before.params.vk.beta_g2 != after.params.vk.beta_g2 {
        error!("phase2::verify_contribution() vk's beta_g2 changed");
        return Err(());
    }
    if before.params.vk.gamma_g2 != after.params.vk.gamma_g2 {
        error!("phase2::verify_contribution() vk's gamma_g2 has changed");
        return Err(());
    }

    // IC shouldn't change, as gamma doesn't change
    if before.params.vk.ic != after.params.vk.ic {
        error!("phase2::verify_contribution() vk's ic has changed");
        return Err(());
    }

    // cs_hash should be the same
    if before.cs_hash != after.cs_hash {
        error!("phase2::verify_contribution() cs_hash has changed");
        return Err(());
    }

    let sink = io::sink();
    let mut sink = HashWriter::new(sink);
    sink.write_all(&before.cs_hash).unwrap();

    for pubkey in &before.contributions {
        pubkey.write(&mut sink).unwrap();
    }

    let pubkey = after.contributions.last().unwrap();
    sink.write_all(&pubkey.s.to_uncompressed()).unwrap();
    sink.write_all(&pubkey.s_delta.to_uncompressed()).unwrap();

    let h = sink.into_hash();

    // The transcript must be consistent
    if pubkey.transcript != h {
        error!("phase2::verify_contribution() inconsistent transcript");
        return Err(());
    }

    // TODO: make this compatible with ts1
    // let r = hash_to_g2_ts1(&h).to_affine();
    let r = hash_to_g2(&h).to_affine();

    // Check the signature of knowledge
    if !same_ratio((r, pubkey.r_delta), (pubkey.s, pubkey.s_delta)) {
        error!("phase2::verify_contribution() contribution's r and s were shifted with different deltas");
        return Err(());
    }

    // Check the change from the old delta is consistent
    if !same_ratio(
        (before.params.vk.delta_g1, pubkey.delta_after),
        (r, pubkey.r_delta),
    ) {
        error!("phase2::verify_contribution() contribution's delta and r where shifted with different delta");
        return Err(());
    }

    // Current parameters should have consistent delta in G1
    if pubkey.delta_after != after.params.vk.delta_g1 {
        error!(
            "phase2::verify_contribution() contribution's delta in G1 differs from vk's delta_g1"
        );
        return Err(());
    }

    // Current parameters should have consistent delta in G2
    if !same_ratio(
        (G1Affine::generator(), pubkey.delta_after),
        (G2Affine::generator(), after.params.vk.delta_g2),
    ) {
        error!("phase2::verify_contribution() contribution's shift in delta (G1) is inconsistent with vk's shift in delta (G2)");
        return Err(());
    }

    // H and L queries should be updated with delta^-1
    if !same_ratio(
        merge_pairs(&before.params.h, &after.params.h),
        (after.params.vk.delta_g2, before.params.vk.delta_g2), // reversed for inverse
    ) {
        error!("phase2::verify_contribution() h was not updated by delta^-1");
        return Err(());
    }
    if !same_ratio(
        merge_pairs(&before.params.l, &after.params.l),
        (after.params.vk.delta_g2, before.params.vk.delta_g2), // reversed for inverse
    ) {
        error!("phase2::verify_contribution() l was not updated by delta^-1");
        return Err(());
    }

    let sink = io::sink();
    let mut sink = HashWriter::new(sink);
    pubkey.write(&mut sink).unwrap();

    Ok(sink.into_hash())
}

/// Checks if pairs have the same ratio.
pub(crate) fn same_ratio<G1: PairingCurveAffine>(g1: (G1, G1), g2: (G1::Pair, G1::Pair)) -> bool {
    g1.0.pairing_with(&g2.1) == g1.1.pairing_with(&g2.0)
}

/// Computes a random linear combination over v1/v2.
///
/// Checking that many pairs of elements are exponentiated by
/// the same `x` can be achieved (with high probability) with
/// the following technique:
///
/// Given v1 = [a, b, c] and v2 = [as, bs, cs], compute
/// (a*r1 + b*r2 + c*r3, (as)*r1 + (bs)*r2 + (cs)*r3) for some
/// random r1, r2, r3. Given (g, g^s)...
///
/// e(g, (as)*r1 + (bs)*r2 + (cs)*r3) = e(g^s, a*r1 + b*r2 + c*r3)
///
/// ... with high probability.
///
/// The type parameter `G` should be an affine curve (i.e. `G: PrimeCurveAffine`) whose [projective]
/// points (`G::Curve`) can be multiplied by scalars (`G::Scalar`) via Wnaf (i.e.
/// `G::Curve: WnafGroup`).
///
/// This function returns a 2-tuple of affine points `(G, G)`; the first tuple value is the
/// output of the random linear-combination of `v1`'s elements and the second tuple value the output
/// of `v2`'s random linear-combination.
/// linear-combination of `v2`.
pub(crate) fn merge_pairs<G>(v1: &[G], v2: &[G]) -> (G, G)
where
    G: PrimeCurveAffine,
    G::Curve: WnafGroup,
{
    use rand::thread_rng;
    use std::sync::Mutex;

    assert_eq!(v1.len(), v2.len());

    let chunk = (v1.len() / num_cpus::get()) + 1;

    // Initialize the first and second linear-combination sums to zero, i.e. the point-at-infinity.
    let s = Arc::new(Mutex::new(G::Curve::identity()));
    let sx = Arc::new(Mutex::new(G::Curve::identity()));

    // Zip and chunk the two input arrays. Launch a thread for each chunk which computes a random
    // linear-combination of its first chunk's values and its second chunk's values using the same
    // set of random values for both chunks. The `i`-th element of the first and second chunks are
    // scaled by the same random scalar.
    crossbeam::thread::scope(|scope| {
        for (v1, v2) in v1.chunks(chunk).zip(v2.chunks(chunk)) {
            let s = s.clone();
            let sx = sx.clone();

            scope.spawn(move |_| {
                // We do not need to be overly cautious of the RNG
                // used for this check.
                let mut rng = thread_rng();

                let mut wnaf = Wnaf::new();

                // Store the sums for this thread's first and second linear-combinations; these sums
                // will be added to the first and second arrays' totals at the end of the thread.
                let mut local_s = G::Curve::identity();
                let mut local_sx = G::Curve::identity();

                // For the `i`-th element in each chunk, generate a random value and scale the
                // `i`-th element in the first and second chunks by that random value, then add the
                // first and second scaled values to their corresponding sums.
                for (v1, v2) in v1.iter().zip(v2.iter()) {
                    // This call to `random` does not need to be compatible with ts1's `random`
                    // because we just need a uniformly sampled scalar, which can be done with
                    // either ts1 or ts2.
                    let rho = G::Scalar::random(&mut rng);
                    let mut wnaf = wnaf.scalar(&rho);
                    let v1 = wnaf.base(v1.to_curve());
                    let v2 = wnaf.base(v2.to_curve());

                    local_s += v1;
                    local_sx += v2;
                }

                *s.lock().unwrap() += local_s;
                *sx.lock().unwrap() += local_sx;
            });
        }
    })
    .unwrap();

    let s = s.lock().unwrap().to_affine();
    let sx = sx.lock().unwrap().to_affine();

    (s, sx)
}

/// This needs to be destroyed by at least one participant
/// for the final parameters to be secure.
struct PrivateKey {
    delta: Fr,
}

/// Compute a keypair, given the current parameters. Keypairs
/// cannot be reused for multiple contributions or contributions
/// in different parameters.
// TODO: make this compatible with ts1
// fn keypair_ts1(mut rng: impl rand_ts1::RngCore, current: &MPCParameters) -> (PublicKey, PrivateKey) {
fn keypair(mut rng: impl RngCore, current: &MPCParameters) -> (PublicKey, PrivateKey) {
    // Sample random delta
    // TODO: make this compatible with ts1
    // let delta = rand_fr_ts1(&mut rng);
    let delta = Fr::random(&mut rng);

    // Compute delta s-pair in G1
    // TODO: make this compatible with ts1
    // let s = rand_g1_ts1(&mut rng).to_affine();
    let s = G1Projective::random(&mut rng).to_affine();
    let s_delta: G1Affine = (s * delta).to_affine();

    // H(cs_hash | <previous pubkeys> | s | s_delta)
    let h = {
        let sink = io::sink();
        let mut sink = HashWriter::new(sink);

        sink.write_all(&current.cs_hash).unwrap();
        for pubkey in &current.contributions {
            pubkey.write(&mut sink).unwrap();
        }
        sink.write_all(&s.to_uncompressed()).unwrap();
        sink.write_all(&s_delta.to_uncompressed()).unwrap();

        sink.into_hash()
    };

    // This avoids making a weird assumption about the hash into the
    // group.
    let transcript = h;

    // Compute delta s-pair in G2
    // TODO: make this compatible with ts1
    // let r = hash_to_g2_ts1(&h).to_affine();
    let r = hash_to_g2(&h).to_affine();
    let r_delta = (r * delta).to_affine();

    // Update `delta_g1`.
    let delta_after = (current.params.vk.delta_g1 * delta).to_affine();

    (
        PublicKey {
            delta_after,
            s,
            s_delta,
            r_delta,
            transcript,
        },
        PrivateKey { delta },
    )
}

/// Hashes to G2 using the first 32 bytes of `digest`. Panics if `digest` is less
/// than 32 bytes.
pub(crate) fn hash_to_g2(digest: &[u8]) -> G2Projective {
    assert!(digest.len() >= 32);

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);

    G2Projective::random(&mut ChaChaRng::from_seed(seed))
}

/// Abstraction over a writer which hashes the data being written.
pub(crate) struct HashWriter<W: Write> {
    writer: W,
    hasher: Blake2b,
}

impl Clone for HashWriter<io::Sink> {
    fn clone(&self) -> HashWriter<io::Sink> {
        HashWriter {
            writer: io::sink(),
            hasher: self.hasher.clone(),
        }
    }
}

impl<W: Write> HashWriter<W> {
    /// Construct a new `HashWriter` given an existing `writer` by value.
    pub fn new(writer: W) -> Self {
        HashWriter {
            writer,
            hasher: Blake2b::new(),
        }
    }

    /// Destroy this writer and return the hash of what was written.
    pub fn into_hash(self) -> [u8; 64] {
        let mut tmp = [0u8; 64];
        tmp.copy_from_slice(self.hasher.finalize().as_ref());
        tmp
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes = self.writer.write(buf)?;

        if bytes > 0 {
            self.hasher.update(&buf[0..bytes]);
        }

        Ok(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[inline(always)]
fn is_normalized_g1(proj: &G1Projective) -> bool {
    proj.is_identity().into() || proj.z() == G1BaseField::one()
}

#[inline(always)]
fn is_normalized_g2(proj: &G2Projective) -> bool {
    proj.is_identity().into() || proj.z() == G2BaseField::one()
}

fn batch_normalization_g1(proj: &mut [G1Projective]) {
    // Montgomery’s Trick and Fast Implementation of Masked AES
    // Genelle, Prouff and Quisquater
    // Section 3.2

    // First pass: compute [z_1, (z_1)(z_2), (z_1)(z_2)(z_3), ..., (z_1)...(z_n)]
    let mut prod = Vec::with_capacity(proj.len());
    let mut tmp = G1BaseField::one();
    for g in proj.iter() {
        // Ignore normalized elements
        if !is_normalized_g1(g) {
            tmp *= g.z();
            prod.push(tmp);
        }
    }

    // Invert `tmp`.
    tmp = tmp.invert().unwrap(); // Guaranteed to be nonzero.

    // Second pass: iterate backwards to compute inverses
    for (g, s) in proj
        .iter_mut()
        // Backwards
        .rev()
        // Ignore normalized elements
        .filter(|g| !is_normalized_g1(g))
        // Backwards, skip last element, fill in one for last term.
        .zip(
            prod.into_iter()
                .rev()
                .skip(1)
                .chain(Some(G1BaseField::one())),
        )
    {
        // Update `g.z` and `tmp` simultaneously: `g.z = tmp * s = 1/g.z` and `tmp = tmp * g.z`.
        let z_inv = tmp * s;
        tmp *= g.z();
        *g = G1Projective::from_raw_unchecked(g.x(), g.y(), z_inv);
    }

    // Perform affine transformations
    for g in proj.iter_mut().filter(|g| !is_normalized_g1(g)) {
        let z = g.z(); // 1/z
        let z_sq = z.square(); // 1/z^2
        let x_new = g.x() * z_sq; // x/z^2
        let z_cube = z_sq * z; // 1/z^3
        let y_new = g.y() * z_cube; // y/z^3
        let z_new = G1BaseField::one(); // z = 1
        *g = G1Projective::from_raw_unchecked(x_new, y_new, z_new);
    }
}

fn batch_normalization_g2(proj: &mut [G2Projective]) {
    // Montgomery’s Trick and Fast Implementation of Masked AES
    // Genelle, Prouff and Quisquater
    // Section 3.2

    // First pass: compute [z_1, (z_1)(z_2), (z_1)(z_2)(z_3), ..., (z_1)...(z_n)]
    let mut prod = Vec::with_capacity(proj.len());
    let mut tmp = G2BaseField::one();
    for g in proj.iter() {
        // Ignore normalized elements
        if !is_normalized_g2(g) {
            tmp *= g.z();
            prod.push(tmp);
        }
    }

    // Invert `tmp`.
    tmp = tmp.invert().unwrap(); // Guaranteed to be nonzero.

    // Second pass: iterate backwards to compute inverses
    for (g, s) in proj
        .iter_mut()
        // Backwards
        .rev()
        // Ignore normalized elements
        .filter(|g| !is_normalized_g2(g))
        // Backwards, skip last element, fill in one for last term.
        .zip(
            prod.into_iter()
                .rev()
                .skip(1)
                .chain(Some(G2BaseField::one())),
        )
    {
        // Update `g.z` and `tmp` simultaneously: `g.z = tmp * s = 1/g.z` and `tmp = tmp * g.z`.
        let z_inv = tmp * s;
        tmp *= g.z();
        *g = G2Projective::from_raw_unchecked(g.x(), g.y(), z_inv);
    }

    // Perform affine transformations
    for g in proj.iter_mut().filter(|g| !is_normalized_g2(g)) {
        let z = g.z(); // 1/z
        let z_sq = z.square(); // 1/z^2
        let x_new = g.x() * z_sq; // x/z^2
        let z_cube = z_sq * z; // 1/z^3
        let y_new = g.y() * z_cube; // y/z^3
        let z_new = G2BaseField::one(); // z = 1
        *g = G2Projective::from_raw_unchecked(x_new, y_new, z_new);
    }
}

// Replaces each affine point in `bases` with its scalar product with `coeff`.
//
// Note that our curve groups are written additively, thus this method is not exponentiating as the
// name "batch_exp" would suggest (which would be the case if our curve groups were written
// multiplicatively), but rather batch scalar multiplying.
fn batch_exp(bases: &mut [G1Affine], coeff: Fr) {
    let mut projective = vec![G1Projective::identity(); bases.len()];

    let cpus = num_cpus::get();
    let chunk_size = if bases.len() < cpus {
        1
    } else {
        bases.len() / cpus
    };

    // Perform wNAF over multiple cores, placing results into `projective`.
    crossbeam::thread::scope(|scope| {
        for (bases, projective) in bases
            .chunks_mut(chunk_size)
            .zip(projective.chunks_mut(chunk_size))
        {
            scope.spawn(move |_| {
                let mut wnaf = Wnaf::new();
                for (base, projective) in bases.iter().zip(projective.iter_mut()) {
                    *projective = wnaf.base(base.to_curve(), 1).scalar(&coeff);
                }
                batch_normalization_g1(projective);
                projective
                    .iter()
                    .zip(bases.iter_mut())
                    .for_each(|(projective, affine)| {
                        *affine = projective.to_affine();
                    });
            });
        }
    })
    .unwrap();
}

#[inline]
pub fn pretty_cs_hash(cs_hash: &[u8; 64]) -> String {
    let s = hex::encode(cs_hash);
    format!("{}...{}", &s[..10], &s[128 - 10..])
}
