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

struct Twin {
    input_amount: u128,
    input_nonce: u128,
    output_amount: u128,
    output_nonce: u128,
}

impl<E: Engine> Circuit<E> for Twin {
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

pub struct Params<E: Engine>(groth16::Parameters<E>);

impl<E: Engine> Params<E> {
    pub fn verifying_key(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.vk.write(&mut bytes).expect("write key");
        bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.write(&mut bytes).expect("write params");
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Params<E>, std::io::Error> {
        let p = groth16::Parameters::read(bytes, true)?;
        Ok(Params(p))
    }
}

pub fn trust_setup() -> Params<Bls12> {
    let params = {
        let c = Twin {
            input_amount: 0,
            input_nonce: 0,
            output_amount: 0,
            output_nonce: 0,
        };
        groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).expect("setup")
    };

    Params(params)
}

#[derive(Debug, Clone, Copy)]
pub struct Witness {
    pub input_amount: u128,
    pub input_nonce: u128,
    pub output_amount: u128,
    pub output_nonce: u128,
}

pub struct Proof(groth16::Proof<Bls12>);

impl Proof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.write(&mut bytes).expect("write params");
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Proof, std::io::Error> {
        let p = groth16::Proof::read(bytes)?;
        Ok(Proof(p))
    }
}

pub fn generate_proof(witness: Witness, params: &Vec<u8>) -> Proof {
    let c = Twin {
        input_amount: witness.input_amount,
        input_nonce: witness.input_nonce,
        output_amount: witness.output_amount,
        output_nonce: witness.output_nonce,
    };

    let params = Params::from_bytes(params.as_ref()).expect("read params");
    let proof = groth16::create_random_proof(c, &params.0, &mut OsRng).expect("create proof");

    Proof(proof)
}

pub struct Input {
    pub from_hash: Vec<u8>,
    pub to_hash: Vec<u8>,
}

struct VerifyingKey(groth16::VerifyingKey<Bls12>);

impl VerifyingKey {
    fn from_bytes(bytes: &[u8]) -> Result<VerifyingKey, std::io::Error> {
        let k = groth16::VerifyingKey::read(bytes)?;
        Ok(VerifyingKey(k))
    }
}

pub fn verify(vk_bytes: &Vec<u8>, proof: &Vec<u8>, input: Input) -> bool {
    let Input { from_hash, to_hash } = input;
    let mut combined_hash = from_hash.clone();
    combined_hash.extend(to_hash);

    let verifying_key = VerifyingKey::from_bytes(vk_bytes).expect("read verifying key");
    let verifying_key = groth16::prepare_verifying_key(&verifying_key.0);

    let hash_bits = multipack::bytes_to_bits(&combined_hash);
    let inputs = multipack::compute_multipacking::<Bls12>(&hash_bits);

    let proof = Proof::from_bytes(proof.as_ref()).expect("read proof");

    groth16::verify_proof::<Bls12>(&verifying_key, &proof.0, &inputs).expect("verify proof")
}

#[cfg(test)]
mod tests {
    use super::*;

    use sha2::{Digest, Sha256};

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

    #[test]
    fn basic_test() {
        let params = trust_setup();
        let witness = Witness {
            input_amount: 2,
            input_nonce: 10,
            output_amount: 2,
            output_nonce: 20,
        };

        let proof = generate_proof(witness, &params.to_bytes());

        let input_hash = Sha256::digest(&combine(2, 10)).to_vec();
        let output_hash = Sha256::digest(&combine(2, 20)).to_vec();

        let input = Input {
            from_hash: input_hash,
            to_hash: output_hash,
        };

        assert!(verify(&params.verifying_key(), &proof.to_bytes(), input))
    }
}
