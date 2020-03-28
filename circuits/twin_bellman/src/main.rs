use bellman::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
        sha256::sha256,
    },
    groth16, Circuit, ConstraintSystem, SynthesisError,
};
use pairing::bls12_381::Bls12;
use pairing::Engine;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

fn convert_to_bits(num: u128) -> Vec<bool> {
    num.to_be_bytes()
        .into_iter()
        .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8).rev())
        .flatten()
        .collect()
}

fn hash_amount<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    amount: u128,
    nonce: u128,
) -> Result<Vec<Boolean>, SynthesisError> {
    let amount_bits = convert_to_bits(amount);
    let nonce_bits = convert_to_bits(nonce);

    let mut preimage = [false; 256];
    for i in 0..128 {
        preimage[i] = amount_bits[i];
        preimage[i + 128] = nonce_bits[i];
    }

    let preimage_bits = preimage
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            AllocatedBit::alloc(cs.namespace(|| format!("preimage bits {}", i)), Some(*b))
        })
        .map(|b| b.map(Boolean::from))
        .collect::<Result<Vec<_>, _>>()?;

    sha256(cs.namespace(|| "sha256(amount + nonce)"), &preimage_bits)
}

struct Zk42 {
    input_amount: u128,
    input_nonce: u128,
    output_amount: u128,
    output_nonce: u128,
}

impl<E: Engine> Circuit<E> for Zk42 {
    fn synthesize<CS: ConstraintSystem<E>>(self, mut cs: &mut CS) -> Result<(), SynthesisError> {
        if self.input_amount < self.output_amount {
            return Err(SynthesisError::Unsatisfiable);
        }

        let mut input_output_hashes = hash_amount(&mut cs, self.input_amount, self.input_nonce)?;
        let output_amount_hash = hash_amount(&mut cs, self.output_amount, self.output_nonce)?;
        input_output_hashes.extend(output_amount_hash);

        multipack::pack_into_inputs(
            cs.namespace(|| "input + output amount hashes"),
            &input_output_hashes,
        )
    }
}

fn combine(amount: u128, nonce: u128) -> [u8; 32] {
    let amount_bytes = amount.to_be_bytes();
    let nonce_bytes = nonce.to_be_bytes();

    let mut bytes = [0u8; 32];
    for i in 0..16 {
        bytes[i] = amount_bytes[i];
        bytes[i + 16] = nonce_bytes[i];
    }

    bytes
}

pub fn main() {
    let params = {
        let c = Zk42 {
            input_amount: 0,
            input_nonce: 0,
            output_amount: 0,
            output_nonce: 0,
        };
        groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).expect("setup")
    };

    let c = Zk42 {
        input_amount: 2,
        input_nonce: 1,
        output_amount: 1,
        output_nonce: 2020,
    };

    let mut input_output_hash = Sha256::digest(&combine(c.input_amount, c.input_nonce)).to_vec();
    input_output_hash.extend(Sha256::digest(&combine(c.output_amount, c.output_nonce)));

    let hash_bits = multipack::bytes_to_bits(&input_output_hash);
    let inputs = multipack::compute_multipacking::<Bls12>(&hash_bits);

    let vk = groth16::prepare_verifying_key(&params.vk);
    let proof = groth16::create_random_proof(c, &params, &mut OsRng).expect("create proof");

    assert!(groth16::verify_proof(&vk, &proof, &inputs).expect("verify"));
}
