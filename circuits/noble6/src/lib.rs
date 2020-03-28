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

    fn alloc_bits<F: Field, CS: ConstraintSystem<F>>(
        self,
        mut cs: CS,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        self.to_bits()
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                AllocatedBit::alloc(cs.namespace(|| format!("input bit {}", i)), || Ok(b))
            })
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()
    }
}

struct CTransaction<F: Field> {
    from: AllocatedNum<F>,   // 16
    to: AllocatedNum<F>,     // 16
    amount: AllocatedNum<F>, // 128
}

impl<F: Field> CTransaction<F> {
    fn from_bits<CS: ConstraintSystem<F>>(
        mut cs: CS,
        bits: &[Boolean],
    ) -> Result<Self, SynthesisError> {
        let from = bits_to_num(cs.namespace(|| "tx from"), &bits[0..16])?;
        let to = bits_to_num(cs.namespace(|| "tx to"), &bits[16..32])?;
        let amount = bits_to_num(cs.namespace(|| "tx amount"), &bits[32..8 * (4 + 16)])?;

        Ok(CTransaction { from, to, amount })
    }
}

struct CChainState<F: Field> {
    height: AllocatedNum<F>,        // 8 * 8
    root_hash: Vec<Boolean>,        // 32 * 8
    balances: Vec<AllocatedNum<F>>, // 8 * 8 * 16
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

        let tx_bits = &bits[(8 * 32 + 8 * 8 * 16)..];
        let mut tx = None;
        if !tx_bits.is_empty() {
            tx = Some(CTransaction::from_bits(cs, tx_bits)?);
        }

        let chain_state = CChainState {
            height,
            root_hash,
            balances,
            tx,
        };

        Ok(chain_state)
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

        todo!()
    }
}
