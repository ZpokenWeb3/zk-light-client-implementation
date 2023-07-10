use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::biguint::CircuitBuilderBiguint;
use crate::hash::{HashInputTarget, HashOutputTarget, WitnessHash};
use crate::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::u32::interleaved_u32::CircuitBuilderB32;

const KECCAK256_C: usize = 1600;
pub const KECCAK256_R: usize = 1088;

pub trait WitnessHashKeccak<F: PrimeField64>: Witness<F> {
    fn set_keccak256_input_target(&mut self, target: &HashInputTarget, value: &[u8]);
    fn set_keccak256_output_target(&mut self, target: &HashOutputTarget, value: &[u8]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessHashKeccak<F> for T {
    fn set_keccak256_input_target(&mut self, target: &HashInputTarget, value: &[u8]) {
        let mut input_biguint = BigUint::from_bytes_le(value);
        let input_len_bits = value.len() * 8;
        let num_actual_blocks = 1 + input_len_bits / KECCAK256_R;
        let padded_len_bits = num_actual_blocks * KECCAK256_R;

        // bit right after the end of the message
        input_biguint.set_bit(input_len_bits as u64, true);

        // last bit of the last block
        input_biguint.set_bit(padded_len_bits as u64 - 1, true);

        self.set_hash_input_le_target(target, &input_biguint);
        self.set_hash_blocks_target(target, num_actual_blocks);
    }

    fn set_keccak256_output_target(&mut self, target: &HashOutputTarget, value: &[u8]) {
        self.set_hash_output_le_target(target, value);
    }
}

pub trait CircuitBuilderHashKeccak<F: RichField + Extendable<D>, const D: usize> {
    fn hash_keccak256(&mut self, hash: &HashInputTarget) -> HashOutputTarget;
    fn _hash_keccak256_f1600(&mut self, state: &mut [[U32Target; 2]; 25]);
}

#[rustfmt::skip]
pub const KECCAKF_ROTC: [u8; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
];

#[rustfmt::skip]
pub const KECCAKF_PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
];

#[rustfmt::skip]
pub const KECCAKF_RNDC: [[u32; 2]; 24] = [
    [0x00000001, 0x00000000], [0x00008082, 0x00000000],
    [0x0000808A, 0x80000000], [0x80008000, 0x80000000],
    [0x0000808B, 0x00000000], [0x80000001, 0x00000000],
    [0x80008081, 0x80000000], [0x00008009, 0x80000000],
    [0x0000008A, 0x00000000], [0x00000088, 0x00000000],
    [0x80008009, 0x00000000], [0x8000000A, 0x00000000],
    [0x8000808B, 0x00000000], [0x0000008B, 0x80000000],
    [0x00008089, 0x80000000], [0x00008003, 0x80000000],
    [0x00008002, 0x80000000], [0x00000080, 0x80000000],
    [0x0000800A, 0x00000000], [0x8000000A, 0x80000000],
    [0x80008081, 0x80000000], [0x00008080, 0x80000000],
    [0x80000001, 0x00000000], [0x80008008, 0x80000000],
];

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHashKeccak<F, D>
    for CircuitBuilder<F, D>
{
    fn _hash_keccak256_f1600(&mut self, s: &mut [[U32Target; 2]; 25]) {
        let zero = self.zero_u32();
        let mut bc = [[zero; 2]; 5];

        let mut keccakf_rndc = Vec::new();
        for item in &KECCAKF_RNDC {
            keccakf_rndc.push([self.constant_u32(item[0]), self.constant_u32(item[1])]);
        }

        // for round in 0..24 {
        for rndc in keccakf_rndc.iter().take(24) {
            // Theta
            for i in 0..5 {
                bc[i] =
                    self.unsafe_xor_many_u64(&[s[i], s[i + 5], s[i + 10], s[i + 15], s[i + 20]]);
            }

            for i in 0..5 {
                let t1 = self.lrot_u64(&bc[(i + 1) % 5], 1);
                let t2 = self.xor_u64(&bc[(i + 4) % 5], &t1);
                for j in 0..5 {
                    s[5 * j + i] = self.xor_u64(&s[5 * j + i], &t2);
                }
            }

            // Rho Pi
            let mut t = s[1];
            for i in 0..24 {
                let j = KECCAKF_PILN[i];
                let tmp = s[j];
                s[j] = self.lrot_u64(&t, KECCAKF_ROTC[i]);
                t = tmp;
            }

            // Chi
            for j in 0..5 {
                for i in 0..5 {
                    bc[i] = s[5 * j + i];
                }
                for i in 0..5 {
                    let t1 = self.not_u64(&bc[(i + 1) % 5]);
                    let t2 = self.and_u64(&bc[(i + 2) % 5], &t1);
                    s[5 * j + i] = self.xor_u64(&s[5 * j + i], &t2);
                }
            }

            // Iota
            s[0] = self.xor_u64(&s[0], rndc);
        }
    }

    fn hash_keccak256(&mut self, hash: &HashInputTarget) -> HashOutputTarget {
        let output = self.add_virtual_biguint_target(8);

        let chunks_len = KECCAK256_R / 64;
        let zero = self.zero_u32();
        let mut state = [[zero; 2]; KECCAK256_C / 64];
        let mut next_state = [[zero; 2]; KECCAK256_C / 64];

        // first block. xor = use input as initial state
        for (i, s) in state.iter_mut().enumerate().take(chunks_len) {
            s[0] = hash.input.limbs[2 * i];
            s[1] = hash.input.limbs[2 * i + 1];
        }

        self._hash_keccak256_f1600(&mut state);

        // other blocks
        for (k, blk) in hash.blocks.iter().enumerate() {
            // xor
            let input_start = (k + 1) * chunks_len * 2;
            for (i, s) in state.iter().enumerate() {
                if i < chunks_len {
                    next_state[i][0] = self.xor_u32(s[0], hash.input.limbs[input_start + i * 2]);
                    next_state[i][1] =
                        self.xor_u32(s[1], hash.input.limbs[input_start + i * 2 + 1]);
                } else {
                    next_state[i][0] = s[0];
                    next_state[i][1] = s[1];
                }
            }

            self._hash_keccak256_f1600(&mut next_state);

            // conditionally set old or new state, depending if block needs to be processed
            for (i, s) in next_state.iter().enumerate() {
                state[i] = self.conditional_u64(s, &state[i], *blk);
            }
        }

        // squeeze
        let output_len = output.num_limbs();
        for (i, s) in state.iter().enumerate().take(output_len / 2) {
            self.connect_u32(s[0], output.limbs[2 * i]);
            self.connect_u32(s[1], output.limbs[2 * i + 1]);
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use hex;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, KeccakGoldilocksConfig, PoseidonGoldilocksConfig};
    use sha3::{Digest, Keccak256};

    use crate::hash::keccak256::{CircuitBuilderHashKeccak, WitnessHashKeccak, KECCAK256_R};
    use crate::hash::CircuitBuilderHash;

    #[test]
    fn test_keccak256_short() {
        let tests = [
            [
                // empty string
                "",
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            ],
            [
                // empty trie
                "80",
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            ],
            [
                // short hash, e.g. last step of storage proof
                "e19f37a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee301",
                "19225e4ee19eb5a11e5260392e6d5154d4bc6a35d89c9d18bf6a63104e9bbcc2",
            ],
        ];

        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let hash_target = builder.add_virtual_hash_input_target(1, KECCAK256_R);
        let hash_output = builder.hash_keccak256(&hash_target);
        let num_gates = builder.num_gates();
        // let copy_constraints = builder.copy_constraints.len();
        let copy_constraints = "<private>";
        let data = builder.build::<C>();
        println!(
            "keccak256 num_gates={}, copy_constraints={}, quotient_degree_factor={}",
            num_gates, copy_constraints, data.common.quotient_degree_factor
        );

        for t in tests {
            let input = hex::decode(t[0]).unwrap();
            let output = hex::decode(t[1]).unwrap();

            // test program
            let mut hasher = Keccak256::new();
            hasher.update(input.as_slice());
            let result = hasher.finalize();
            assert_eq!(result[..], output[..]);

            // test circuit
            let mut pw = PartialWitness::new();
            pw.set_keccak256_input_target(&hash_target, &input);
            pw.set_keccak256_output_target(&hash_output, &output);

            let proof = data.prove(pw).unwrap();
            assert!(data.verify(proof).is_ok());
        }
    }

    #[test]
    fn test_keccak256_long() {
        let tests = [
            [
                // storage proof
                "f90211a0dc6ab9a606e3ef2e125ebd792c502cb6500aa1d1a80fa6e706482175742f4744a0bcb03c1a82cc80a677c98fe35c8ff953d1de3b1322a33f2c8d10132eac5639bfa02d81761f56b3bcd9137ef6823f879ba41c32c925c95f4658a7b1418d14424175a0c1c4d0f264475235249547fdfe63cf4aed82ef8cfc3019ed217fcf5f25620067a0f6d7a23257b2c155b5c4ffb37d76d4e6e8fae6bdab5d3cf2d868d4741b80d214a0f7bb2681b64939b292248bd66c21c40d54fca9460abda45da28a50b746b1b2a1a037bfc201846115d4d0e85eb6b3f0920817a7e0081bcb8bdaeb9c7dcf726b0885a0a238a31e3c6a36f24afa650058eabbf3682cc83a576d58453b7b74a3ffac8d1aa03315cb55fbc6bc9d9987cd0e2001f39305961856126d0ef7280d01d45c0b27d5a03cfc7bd374410e92dba88a3a8ce380a6ceed3ea977ee64f904e3723ce4afed01a0e5d3350effa6d755100afa3e4560d39ddc2dd35988f65bc0931f924134c4a2aba07609fdcdd38bf9e2f7b35b022a30e564877323f4d38381b3c792ac21f7617e28a0cd43ad06bbdd7d4dcf450e5212325ae2b177e80701c64f492b6e095e0cd43bbba0652063acc150fc0a729761d4fd80f230329e2eef41cb0dda1df74a4002ba6c4ca0ee0c0661fec773e14f94d8977e69cb22b41cc15fe9c682160488c0a2aa7daf4ba0d4cb2d1c9f1ff574d4854301a6ea891143e123d4dd04db1432509c2307f10a2180",
                "578d0063e7f59c51a1b609f98ab8447cfb69422e3e92cc3cafdc3499735d98a8",
            ],
            [
                // account proof
                "f90211a0160c36cc6e1f0499f82e964ad41216e3222f9e439c2c8ecebb9f6d8e8682fbd3a0c9288b274cda35ac8ea4ecc51a40b6291d965f66f8dbd029e9419e583d7f0d6aa08a768a530c839cd9ba26f39f381a4e6d1c75bdbaccfd0e08773275460bebb392a0e8b3c8ca435de4f3614f65507f2ffdf77f446f66dfe295fa57287d838505d85ca0d073345bee411e9ee68097c6797025bdbae114c2847821fb12e8d5876cc74fd5a07471033f73ed2b5f1de920765c8d8c895016833aea875cbedfac28eeaf78b38ca073ef613ea081010ff0c3e685dcdd7599e2724121629d736ae206a779524619cca0062fee86b0c595607a46b39da1db0b8d6950f7ceb15a4240b26502bd28f71266a037433cfba971c3f88dd48a9ba77f00af7b916c813ef05e1621439ce39c06f676a081a896e219d44b627d81c27d6af8deacedf503aac7a709325f244add2ad4320da086fd39396891a30937f64e299a7d2fb85814a910c477cee64b0db109d92206aaa023ed91b155f896a409658f30d87f3f16d5bc6193b4ac2e3d5524a980e57149d4a09885e8e7165d55d4a32b0f8b226c382c6aa6d632ca68bdd79a17fd65c31c7fc0a08a04011c30e2fa3121663b88a08732017130f702a24dfe6107ca5757a8caf92aa0ac8239f39a106972436c768499afcc787d257c3d7928bfa524e90752500f4334a0e68fba45dceffc99e87785a850a7fefa813a803f2eb13359e5602d98fce7845080",
                "f530311917cff532bf25f103e7a0c092be92ace7e919f7a4f644e5b011e677f3",
            ],
            [
                // med hash
                "f9015180a060f3bdb593359882a705ff924581eb99537f2428a007a0006f459182f07dba16a06776a7e6abd64250488ed106c0fbd66ee338b7ce59ae967714ce43ecd5a3de97a0f8d6740520928d0e540bf439f1c214ce434f349e4c9b71bb9fcce14144a48914a0f31b2b9570033a103b8a4c0db8debbff2cf8dc4eb2ed31fa292d41c7adf13dc980808080a016a530127910d9d4a89450f0c9dc075545441126b222396eb28e30c73c01c8a9a05d9eb59dae800d3f8cfe8efdfa86776fc7f3b09dfc5b2f537b2c2abda9787755a0bcdc8744035201f5d8d9bd0f440887a40d8cafc3f986f20ce276b1b1e37c01fda0f56f6a7cbf29f15d0923780608ffbb5671fcb518b482812bb8a02b46bae016f0a0cc20fa696765f56b03c14de2b16ab042f191dafb61df0dab8e1101cc08e78f3980a0e1328f040062749d53d278300e0e9857744279645fbc7a3ae11fcb87a6e000e680",
                "d4cb2d1c9f1ff574d4854301a6ea891143e123d4dd04db1432509c2307f10a21",
            ],
            [
                // short hash
                "e19f37a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee301",
                "19225e4ee19eb5a11e5260392e6d5154d4bc6a35d89c9d18bf6a63104e9bbcc2",
            ],
        ];

        // build circuit once
        const D: usize = 2;
        type C = KeccakGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let hash_target = builder.add_virtual_hash_input_target(4, KECCAK256_R);
        let hash_output = builder.hash_keccak256(&hash_target);
        let num_gates = builder.num_gates();
        // let copy_constraints = builder.copy_constraints.len();
        let copy_constraints = "<private>";
        let data = builder.build::<C>();
        println!(
            "keccak256(4) num_gates={}, copy_constraints={}, quotient_degree_factor={}",
            num_gates, copy_constraints, data.common.quotient_degree_factor
        );

        for t in tests {
            let input = hex::decode(t[0]).unwrap();
            let output = hex::decode(t[1]).unwrap();

            // test program
            let mut hasher = Keccak256::new();
            hasher.update(input.as_slice());
            let result = hasher.finalize();
            assert_eq!(result[..], output[..]);

            // test circuit
            let mut pw = PartialWitness::new();
            pw.set_keccak256_input_target(&hash_target, &input);
            pw.set_keccak256_output_target(&hash_output, &output);

            let proof = data.prove(pw).unwrap();
            assert!(data.verify(proof).is_ok());
        }
    }
}
