use halo::{
    sha256::sha256, unpack_fe, AllocatedBit, AllocatedNum, Boolean, Coeff, ConstraintSystem, Ec0,
    Ec1, Field, LinearCombination, Params, RecursiveCircuit, RecursiveProof, SynthesisError,
    UInt64,
};

fn lc_from_bits<F: Field, CS: ConstraintSystem<F>>(bits: &[Boolean]) -> LinearCombination<F> {
    let mut lc = LinearCombination::zero();
    let mut coeff = Coeff::One;
    for bit in bits {
        lc = lc + &bit.lc(CS::ONE, coeff);
        coeff = coeff.double();
    }
    lc
}

fn bits_to_num<F: Field, CS: ConstraintSystem<F>>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<AllocatedNum<F>, SynthesisError> {
    // Construct the number from its bits
    let value =
        bits.iter()
            .rev()
            .map(|b| b.get_value().map(F::from))
            .fold(Some(F::zero()), |acc, bit| match (acc, bit) {
                (Some(acc), Some(bit)) => Some(acc + acc + bit),
                _ => None,
            });

    // Witness the number
    let num = AllocatedNum::alloc(cs.namespace(|| "num"), || {
        value.ok_or(SynthesisError::AssignmentMissing)
    })?;

    // Constrain the witnessed number
    let bits_lc = lc_from_bits::<F, CS>(bits);
    cs.enforce_zero(bits_lc - &num.lc());

    Ok(num)
}

fn enforce_equality<F: Field, CS: ConstraintSystem<F>>(mut cs: CS, a: &[Boolean], b: &[Boolean]) {
    assert_eq!(a.len(), b.len());

    let mut a_lc = LinearCombination::zero();
    let mut b_lc = LinearCombination::zero();
    let mut coeff = Coeff::One;
    for (a_bit, b_bit) in a.into_iter().zip(b.into_iter()) {
        a_lc = a_lc + &a_bit.lc(CS::ONE, coeff);
        b_lc = b_lc + &b_bit.lc(CS::ONE, coeff);
        coeff = coeff.double();
    }
    cs.enforce_zero(a_lc - &b_lc);
}

#[derive(Debug, Clone, Copy)]
struct Transaction {
    from: u16,
    to: u16,
    amount: u128,
}

impl Transaction {
    fn to_bytes(&self) -> Vec<u8> {
        let from = self.from.to_le_bytes();
        let to = self.to.to_le_bytes();
        let amount = self.amount.to_le_bytes();

        from.iter()
            .chain(to.iter())
            .chain(amount.iter())
            .cloned()
            .collect()
    }
}

struct ChainState {
    height: u64,
    root_hash: [u8; 32],
    balances: [u128; 8],
    tx: Option<Transaction>,
}

impl ChainState {
    fn to_bits(self) -> Vec<bool> {
        let balance_bytes = self
            .balances
            .iter()
            .map(|b| b.to_le_bytes().to_vec())
            .flatten()
            .collect::<Vec<_>>();

        let mut bytes = self.height.to_le_bytes().to_vec();
        bytes.extend(self.root_hash.to_vec());
        bytes.extend(balance_bytes);

        if let Some(tx) = self.tx {
            bytes.extend(tx.to_bytes());
        }

        bytes
            .iter()
            .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
            .flatten()
            .collect()
    }

    #[cfg(test)]
    fn alloc_bits<F: Field, CS: ConstraintSystem<F>>(
        self,
        mut cs: CS,
    ) -> Result<Vec<AllocatedBit>, SynthesisError> {
        self.to_bits()
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                AllocatedBit::alloc(cs.namespace(|| format!("input bit {}", i)), || Ok(b))
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

struct CTransaction<F: Field> {
    from: u16,               // 16
    to: u16,                 // 16
    amount: AllocatedNum<F>, // 128
}

impl<F: Field> CTransaction<F> {
    fn from_bits<CS: ConstraintSystem<F>>(
        mut cs: CS,
        bits: &[Boolean],
    ) -> Result<Self, SynthesisError> {
        if bits.len() != 8 * (4 + 16) {
            return Err(SynthesisError::Unsatisfiable);
        }

        let convert_to_num = |bits: &[Boolean]| -> Result<_, _> {
            let num = bits
                .iter()
                .map(|b| b.get_value())
                .enumerate()
                .map(|(i, bit)| bit.map(|b| if b { 1 << i } else { 0 }))
                .fold(Some(0), |acc, bit| match (acc, bit) {
                    (Some(acc), Some(bit)) => Some(acc + bit),
                    _ => None,
                });

            num.ok_or_else(|| SynthesisError::Unsatisfiable)
        };

        let from = convert_to_num(&bits[0..16])?;
        if from >= 8 {
            return Err(SynthesisError::Violation);
        }

        let to = convert_to_num(&bits[16..32])?;
        if to >= 8 {
            return Err(SynthesisError::Violation);
        }

        let amount = bits_to_num(cs.namespace(|| "tx amount"), &bits[32..8 * (4 + 16)])?;

        Ok(CTransaction { from, to, amount })
    }
}

struct CChainState<F: Field> {
    height: AllocatedNum<F>,        // 8 * 8
    root_hash: Vec<Boolean>,        // 32 * 8
    balances: Vec<AllocatedNum<F>>, // 8 * 8 * 16
    balances_bits: Vec<Vec<Boolean>>,
    tx: Option<CTransaction<F>>,
}

impl<F: Field> CChainState<F> {
    fn from_bits<CS: ConstraintSystem<F>>(
        mut cs: CS,
        bits: &[AllocatedBit],
    ) -> Result<Self, SynthesisError> {
        let bits = bits.iter().cloned().map(Boolean::from).collect::<Vec<_>>();

        let height = bits_to_num(cs.namespace(|| "height"), &bits[0..8 * 8])?;
        let root_hash = bits[8 * 8..(8 * 8 + 8 * 32)].to_vec();
        let balances = bits[(8 * 8 + 8 * 32)..(8 * 8 + 8 * 32 + 8 * 8 * 16)]
            .chunks(8 * 16)
            .map(|balance_bits| bits_to_num(cs.namespace(|| "balance"), &balance_bits))
            .collect::<Result<Vec<_>, _>>()?;
        let balances_bits = bits[(8 * 8 + 8 * 32)..(8 * 8 + 8 * 32 + 8 * 8 * 16)]
            .chunks(8 * 16)
            .map(|bits| bits.to_vec())
            .collect::<Vec<Vec<Boolean>>>();

        let tx_bits = &bits[(8 * 32 + 8 * 8 * 16)..];
        let mut tx = None;
        if !tx_bits.is_empty() {
            tx = Some(CTransaction::from_bits(cs, tx_bits)?);
        }

        let chain_state = CChainState {
            height,
            root_hash,
            balances,
            balances_bits,
            tx,
        };

        Ok(chain_state)
    }

    fn hash_leaf<CS: ConstraintSystem<F>>(
        cs: CS,
        left: &Vec<Boolean>,
        right: &Vec<Boolean>,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        let mut combined = left.clone();
        combined.extend(right.clone());

        sha256(cs, &combined)
    }

    fn merkle_root_hash<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        let leaf_hashes = self
            .balances_bits
            .iter()
            .map(|balance| sha256(cs.namespace(|| "hash(balance)"), &balance))
            .collect::<Result<Vec<_>, _>>()?;

        let mut root_hash = leaf_hashes;
        while root_hash.len() > 1 {
            root_hash = root_hash
                .chunks(2)
                .map(|left_right| {
                    Self::hash_leaf(
                        cs.namespace(|| "merkle hash"),
                        &left_right[0],
                        &left_right[1],
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
        }

        Ok(root_hash
            .pop()
            .ok_or_else(|| SynthesisError::Unsatisfiable)?)
    }
}

struct ReachCircuit;

impl<F: Field> RecursiveCircuit<F> for ReachCircuit {
    fn base_payload(&self) -> Vec<bool> {
        let genesis = ChainState {
            height: 0,
            root_hash: [0u8; 32],
            balances: [0u128; 8],
            tx: None,
        };

        genesis.to_bits()
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        old_payload: &[AllocatedBit],
        new_payload: &[AllocatedBit],
    ) -> Result<(), SynthesisError> {
        let prev_state = CChainState::from_bits(cs.namespace(|| "previous state"), old_payload)?;
        let curr_state = CChainState::from_bits(cs.namespace(|| "current status"), new_payload)?;
        if curr_state.tx.is_none() {
            return Err(SynthesisError::Unsatisfiable);
        }

        cs.enforce_zero(curr_state.height.lc() - &prev_state.height.lc() - CS::ONE);

        let prev_root_hash = prev_state.merkle_root_hash(cs.namespace(|| "previous root hash"))?;
        enforce_equality(
            cs.namespace(|| "match previous root hash"),
            &prev_state.root_hash,
            &prev_root_hash,
        );

        let curr_root_hash = curr_state.merkle_root_hash(cs.namespace(|| "current root hash"))?;
        enforce_equality(
            cs.namespace(|| "match current root hash"),
            &curr_state.root_hash,
            &curr_root_hash,
        );

        let tx = curr_state.tx.ok_or_else(|| SynthesisError::Unsatisfiable)?;
        if tx.from == tx.to {
            // Mint
            cs.enforce_zero(
                curr_state.balances[tx.to as usize].lc()
                    - &prev_state.balances[tx.to as usize].lc()
                    - &tx.amount.lc(),
            );
        } else {
            // Transfer
            cs.enforce_zero(
                prev_state.balances[tx.from as usize].lc()
                    - &curr_state.balances[tx.from as usize].lc()
                    - &tx.amount.lc(),
            );

            cs.enforce_zero(
                curr_state.balances[tx.to as usize].lc()
                    - &prev_state.balances[tx.to as usize].lc()
                    - &tx.amount.lc(),
            );
        }

        Ok(())
    }
}
