#![allow(unused, unreachable_code, dead_code)]

use ark_bls12_381::{Fr, G1Affine};
use ark_ff::*;
use ark_poly::{
    univariate::{DensePolynomial, SparsePolynomial},
    EvaluationDomain, GeneralEvaluationDomain, Polynomial, UVPolynomial,
};
use ark_serialize::CanonicalDeserialize;
use hidden_in_plain_sight::{generate::kzg_commit, PUZZLE_DESCRIPTION};
use prompt::{puzzle, welcome};
use rayon::prelude::*;

fn read_cha_from_file() -> (Vec<G1Affine>, Vec<Vec<Fr>>, Fr, Fr, G1Affine, Fr, Fr) {
    use std::fs::File;
    use std::io::prelude::*;

    let mut file = File::open("challenge_data").unwrap();
    let mut bytes: Vec<u8> = vec![];
    file.read_to_end(&mut bytes).unwrap();

    let setup_bytes: Vec<u8> = bytes[0..98312].to_vec();
    let accts_bytes: Vec<u8> = bytes[98312..1130320].to_vec();
    let cha_1_bytes: Vec<u8> = bytes[1130320..1130352].to_vec();
    let cha_2_bytes: Vec<u8> = bytes[1130352..1130384].to_vec();
    let commt_bytes: Vec<u8> = bytes[1130384..1130480].to_vec();
    let opn_1_bytes: Vec<u8> = bytes[1130480..1130512].to_vec();
    let opn_2_bytes: Vec<u8> = bytes[1130512..1130544].to_vec();

    let setup = Vec::<G1Affine>::deserialize_unchecked(&setup_bytes[..]).unwrap();
    let accts = Vec::<Vec<Fr>>::deserialize_unchecked(&accts_bytes[..]).unwrap();
    let cha_1 = Fr::deserialize_unchecked(&cha_1_bytes[..]).unwrap();
    let cha_2 = Fr::deserialize_unchecked(&cha_2_bytes[..]).unwrap();
    let commt = G1Affine::deserialize_unchecked(&commt_bytes[..]).unwrap();
    let opn_1 = Fr::deserialize_unchecked(&opn_1_bytes[..]).unwrap();
    let opn_2 = Fr::deserialize_unchecked(&opn_2_bytes[..]).unwrap();

    (setup, accts, cha_1, cha_2, commt, opn_1, opn_2)
}

fn find_constants(
    acct_poly: &DensePolynomial<Fr>,
    vanishing_cha_1: Fr,
    vanishing_cha_2: Fr,
    cha_1: Fr,
    cha_2: Fr,
    opn_1: Fr,
    opn_2: Fr,
) -> (Fr, Fr) {
    // let acct_poly = DensePolynomial::from_coefficients_vec(domain.ifft(&target_acct));
    let p_cha_1 = acct_poly.evaluate(&cha_1);
    let p_cha_2 = acct_poly.evaluate(&cha_2);
    let left_1 = (opn_1 - acct_poly.evaluate(&cha_1)) / vanishing_cha_1;
    let left_2 = (opn_2 - acct_poly.evaluate(&cha_2)) / vanishing_cha_2;
    let b1 = (left_2 - left_1) / (cha_2 - cha_1);
    let b0 = left_1 - b1 * cha_1;
    (b0, b1)
}

fn exploit(domain: GeneralEvaluationDomain<Fr>) -> (Vec<Fr>, Fr, Fr) {
    let (setup, accts, cha_1, cha_2, commt, opn_1, opn_2) = read_cha_from_file();
    assert_eq!(accts.len(), 1000);
    let vanishing_poly = domain.vanishing_polynomial();
    let vanishing_cha_1 = vanishing_poly.evaluate(&cha_1);
    let vanishing_cha_2 = vanishing_poly.evaluate(&cha_2);
    for (i, target_acct) in accts.iter().enumerate() {
        let acct_poly = DensePolynomial::from_coefficients_vec(domain.ifft(&target_acct));
        let (b0, b1) = find_constants(
            &acct_poly,
            vanishing_cha_1,
            vanishing_cha_2,
            cha_1,
            cha_2,
            opn_1,
            opn_2,
        );
        let blinding_poly = DensePolynomial::from_coefficients_vec(vec![b0, b1]);
        let blinded_acct_poly = acct_poly + blinding_poly.mul_by_vanishing_poly(domain);
        let commitment: G1Affine = kzg_commit(&blinded_acct_poly, &setup);
        if commitment != commt {
            println!("commitment mismatch {}", i);
        } else {
            println!("FOUND IT: answer!! {}", i);
            return (accts[i].clone(), b0, b1);
        }
    }
    panic!("Couldn't deanonimize")
}

fn exploit_par(domain: GeneralEvaluationDomain<Fr>) -> (Vec<Fr>, Fr, Fr) {
    let (setup, accts, cha_1, cha_2, commt, opn_1, opn_2) = read_cha_from_file();

    let vanishing_poly = domain.vanishing_polynomial();
    let vanishing_cha_1 = vanishing_poly.evaluate(&cha_1);
    let vanishing_cha_2 = vanishing_poly.evaluate(&cha_2);

    let target = accts
        .par_iter()
        .map(|acct| {
            let acct_poly = DensePolynomial::from_coefficients_vec(domain.ifft(&acct));
            let (b0, b1) = find_constants(
                &acct_poly,
                vanishing_cha_1,
                vanishing_cha_2,
                cha_1,
                cha_2,
                opn_1,
                opn_2,
            );
            let blinding_poly = DensePolynomial::from_coefficients_vec(vec![b0, b1]);
            let blinded_acct_poly = acct_poly + blinding_poly.mul_by_vanishing_poly(domain);
            let commitment: G1Affine = kzg_commit(&blinded_acct_poly, &setup);
            if commitment == commt {
                println!("FOUND IT");
                Some((acct.clone(), b0, b1))
            } else {
                None
            }
        })
        .filter(|x| x.is_some())
        .map(|x| x.unwrap())
        .collect::<Vec<_>>();

    assert_eq!(target.len(), 1);
    (target[0].clone())
}

fn explain_solution() {
    println!(
        "
    Solution explanation:

    Q(x) = P(x) + (b_0 + b_1x) • Z_H(x)
    (Q(x) - P(x)) / Z_H(x) = (b_0 + b_1x)

    System of equations {{
        (Q(cha_1) - P(cha_1)) / Z_H(cha_1) = (b_0 + b_1 * cha_1)
        (Q(cha_2) - P(cha_2)) / Z_H(cha_2) = (b_0 + b_1 * cha_2)
    }}
    left(x) = (Q(x) - P(x)) / Z_H(x)

    System of equations {{
        left(cha_1) = (b_0 + b_1 * cha_1)
        left(cha_2) = (b_0 + b_1 * cha_2)
    }}

    b_0 = left(cha_1) - b_1 * cha_1
    b_1 = (left(cha_2) - left(cha_1)) / (cha_2 - cha_1)

    with blinding polynomial we can compute commitment(Q) for every account in the list and check which is equal to the receipient commitment.
    "
    );
}

fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);

    let (setup, accts, cha_1, cha_2, commt, opn_1, opn_2) = read_cha_from_file();

    let domain: GeneralEvaluationDomain<Fr> =
        GeneralEvaluationDomain::new(accts.len() + 2).unwrap();

    let (target_acct, b0, b1) = exploit_par(domain);

    let acct_poly = DensePolynomial::from_coefficients_vec(domain.ifft(&target_acct));
    let blinding_poly = DensePolynomial::from_coefficients_vec(vec![b0, b1]);
    let solution_blinded_acct = acct_poly + blinding_poly.mul_by_vanishing_poly(domain);

    let solution_commitment = kzg_commit(&solution_blinded_acct, &setup);
    assert_eq!(solution_commitment, commt);
    explain_solution()
}
