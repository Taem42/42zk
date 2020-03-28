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

#[derive(Debug, Clone, Copy)]
pub struct Amount {
    pub value: u128,
    pub nonce: u128,
}

impl Amount {
    pub fn new(value: u128, nonce: u128) -> Self {
        Amount { value, nonce }
    }

    pub fn hash<E: Engine, CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        let amount_bits = convert_to_bits(self.value);
        let nonce_bits = convert_to_bits(self.nonce);

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
}

struct Mixer {
    inputs: Vec<Amount>,
    outputs: Vec<Amount>,
}

impl Mixer {
    pub fn recursive_hash<E: Engine, CS: ConstraintSystem<E>>(
        mut cs: CS,
        amounts: Vec<Amount>,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        let hashes = amounts
            .into_iter()
            .map(|a| a.hash(&mut cs))
            .collect::<Result<Vec<Vec<_>>, _>>()?;

        hashes
            .into_iter()
            .try_fold(Vec::new(), |acc: Vec<Boolean>, h| {
                let mut combined_bits = Vec::with_capacity(256);
                combined_bits.extend(acc);
                combined_bits.extend(h);

                sha256(cs.namespace(|| "recursive hash amount"), &combined_bits)
            })
    }
}

impl<E: Engine> Circuit<E> for Mixer {
    fn synthesize<CS: ConstraintSystem<E>>(self, mut cs: &mut CS) -> Result<(), SynthesisError> {
        let inputs_sum: u128 = self.inputs.iter().map(|a| a.value).sum();
        let outputs_sum: u128 = self.outputs.iter().map(|a| a.value).sum();
        if inputs_sum < outputs_sum {
            return Err(SynthesisError::Unsatisfiable);
        }

        let amounts = self
            .inputs
            .into_iter()
            .chain(self.outputs.into_iter())
            .collect::<Vec<_>>();

        let recursive_hash = Mixer::recursive_hash(&mut cs, amounts)?;
        multipack::pack_into_inputs(cs.namespace(|| "recursive hash"), &recursive_hash)
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

pub fn trust_setup(inputs_size: u8, outputs_size: u8) -> Params<Bls12> {
    let params = {
        let c = Mixer {
            inputs: (0..inputs_size)
                .map(|_| Amount::new(254, 1))
                .collect::<Vec<_>>(),
            outputs: (0..outputs_size)
                .map(|_| Amount::new(1, 1))
                .collect::<Vec<_>>(),
        };

        groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).expect("setup")
    };

    Params(params)
}

#[derive(Debug, Clone)]
pub struct Witness {
    pub inputs: Vec<Amount>,
    pub outputs: Vec<Amount>,
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
    let c = Mixer {
        inputs: witness.inputs,
        outputs: witness.outputs,
    };

    let params = Params::from_bytes(params.as_ref()).expect("read params");
    let proof = groth16::create_random_proof(c, &params.0, &mut OsRng).expect("create proof");

    Proof(proof)
}

pub struct Input {
    recursive_hash: Vec<u8>,
}

struct VerifyingKey(groth16::VerifyingKey<Bls12>);

impl VerifyingKey {
    fn from_bytes(bytes: &[u8]) -> Result<VerifyingKey, std::io::Error> {
        let k = groth16::VerifyingKey::read(bytes)?;
        Ok(VerifyingKey(k))
    }
}

pub fn verify(vk_bytes: &Vec<u8>, proof: &Vec<u8>, input: Input) -> bool {
    let verifying_key = VerifyingKey::from_bytes(vk_bytes).expect("read verifying key");
    let verifying_key = groth16::prepare_verifying_key(&verifying_key.0);

    let hash_bits = multipack::bytes_to_bits(&input.recursive_hash);
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
        let params = trust_setup(2, 1); // Support up to 2 inputs and 1 outputs
        println!("complete trust setup");

        let witness = Witness {
            inputs: vec![Amount::new(1, 1), Amount::new(2, 2)],
            outputs: vec![Amount::new(3, 2)],
        };

        let proof = generate_proof(witness, &params.to_bytes());
        println!("complete generate proof");

        let amounts = vec![combine(1, 1), combine(2, 2), combine(3, 2)];

        let amount_hashes = amounts
            .into_iter()
            .map(|a| Sha256::digest(&a).to_vec())
            .collect::<Vec<_>>();

        let recursive_hash = amount_hashes.into_iter().fold(Vec::new(), |mut acc, h| {
            acc.extend(h);
            Sha256::digest(&acc).to_vec()
        });

        let input = Input { recursive_hash };
        println!("complete input");

        assert!(verify(&params.verifying_key(), &proof.to_bytes(), input))
    }
}
