use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::gadgets::biguint::CircuitBuilderBiguint;
use plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use plonky2_u32::gadgets::interleaved_u32::CircuitBuilderB32;

use crate::types::{Hash256Target, HashInputTarget, HashOutputTarget, WitnessHash};
pub trait WitnessHashSha2<F: PrimeField64>: Witness<F> {
    fn set_sha256_input_target(&mut self, target: &HashInputTarget, value: &[u8]);
    fn set_sha256_output_target(&mut self, target: &HashOutputTarget, value: &[u8]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessHashSha2<F> for T {
    fn set_sha256_input_target(&mut self, target: &HashInputTarget, value: &[u8]) {
        // sha256 padding
        let mut input_biguint = BigUint::from_bytes_le(value);
        let input_len_bits = value.len() as u64 * 8;
        // append 0x8000...
        input_biguint.set_bit(input_len_bits + 7, true);
        let len_bytes = input_len_bits.to_be_bytes();
        // append big-endian u64 bit len
        for (i, b) in len_bytes.iter().enumerate() {
            for j in 0..8 {
                let pos = target.input_bits - 64 + i * 8 + j;
                input_biguint.set_bit(pos as u64, b & (1 << j) > 0);
            }
        }
        self.set_hash_input_be_target(target, &input_biguint);
    }

    fn set_sha256_output_target(&mut self, target: &HashOutputTarget, value: &[u8]) {
        let output_biguint = BigUint::from_bytes_le(value);
        self.set_hash_output_be_target(target, &output_biguint);
    }
}

pub trait CircuitBuilderHashSha2<F: RichField + Extendable<D>, const D: usize> {
    fn add_u32_lo(&mut self, a: U32Target, b: U32Target) -> U32Target;

    fn hash_sha256(&mut self, hash: &HashInputTarget) -> HashOutputTarget;
    fn sha256_input_padding(&mut self, target: &HashInputTarget, padding_len: u64);
    fn two_to_one_sha256(&mut self, left: Hash256Target, right: Hash256Target) -> Hash256Target;
}

/// Initial state for SHA-256.
#[rustfmt::skip]
pub const H256_256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Constants necessary for SHA-256 family of digests.
#[rustfmt::skip]
pub const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// (a rrot r1) xor (a rrot r2) xor (a rsh s3)
fn sigma<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U32Target,
    r1: u8,
    r2: u8,
    s3: u8,
) -> U32Target {
    let x = builder.rrot_u32(a, r1);
    let y = builder.rrot_u32(a, r2);
    let z = builder.rsh_u32(a, s3);

    builder.unsafe_xor_many_u32(&[x, y, z])
}

/// (a rrot r1) xor (a rrot r2) xor (a rrot r3)
fn big_sigma<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U32Target,
    r1: u8,
    r2: u8,
    r3: u8,
) -> U32Target {
    let x = builder.rrot_u32(a, r1);
    let y = builder.rrot_u32(a, r2);
    let z = builder.rrot_u32(a, r3);

    builder.unsafe_xor_many_u32(&[x, y, z])
}

/// (e and f) xor ((not e) and g)
fn ch<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    e: U32Target,
    f: U32Target,
    g: U32Target,
) -> U32Target {
    let not_e = builder.not_u32(e);

    let ef = builder.and_xor_u32(e, f).0;
    let eg = builder.and_xor_u32(not_e, g).0;

    builder.and_xor_b32_to_u32(ef, eg).1
}

/// (a and b) xor (a and c) xor (b and c)
/// = (a and (b xor c)) xor (b and c)
/// we can calculate (b xor c), (b and c) in a single op
fn maj<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U32Target,
    b: U32Target,
    c: U32Target,
) -> U32Target {
    let (b_and_c, b_xor_c) = builder.and_xor_u32(b, c);

    let a = builder.interleave_u32(a);
    let abc = builder.and_xor_b32(a, b_xor_c).0;

    builder.and_xor_b32_to_u32(abc, b_and_c).1
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHashSha2<F, D>
    for CircuitBuilder<F, D>
{
    fn add_u32_lo(&mut self, a: U32Target, b: U32Target) -> U32Target {
        self.add_u32(a, b).0
    }

    // add sha256 padding in circuit, useful when the len of the input is constant / known
    // currently only handles len multiple of 32, e.g. 512 used in Ethereum Simple Serialize
    fn sha256_input_padding(&mut self, target: &HashInputTarget, padding_len: u64) {
        let limbs = &target.input.limbs;
        let len = limbs.len();
        let start = len - (padding_len as usize / 32);
        let padding_len_le = padding_len.to_le();

        let padding_start = self.constant_u32(0x80000000);
        self.connect_u32(limbs[start], padding_start);

        let zero_u32 = self.zero_u32();
        for &limb in limbs.iter().take(len - 1).skip(start + 1) {
            self.connect_u32(limb, zero_u32);
        }

        // last 64 bits
        let padding_end1 = self.constant_u32((padding_len_le >> 32) as u32);
        let padding_end0 = self.constant_u32(padding_len_le as u32);
        self.connect_u32(limbs[len - 2], padding_end1);
        self.connect_u32(limbs[len - 1], padding_end0);
    }

    // https://en.wikipedia.org/wiki/SHA-2#Pseudocode
    fn hash_sha256(&mut self, hash: &HashInputTarget) -> HashOutputTarget {
        let output = self.add_virtual_biguint_target(8);
        let input = &hash.input.limbs;
        let input_bits = hash.input_bits;
        let block_num = input_bits / 512;

        let mut state = Vec::<U32Target>::new();

        // Initialize hash values:
        // (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19)
        for item in &H256_256 {
            state.push(self.constant_u32(*item));
        }

        // Initialize array of round constants:
        // (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
        let mut k256 = Vec::new();
        for item in &K32 {
            k256.push(self.constant_u32(*item));
        }

        // Pre-processing (Padding)
        // Padding is done by the Witness when setting the input value to the target

        // Process the message in successive 512-bit chunks
        for blk in 0..block_num {
            let mut w: [U32Target; 16] = input[blk * 16..blk * 16 + 16].try_into().unwrap();

            // Initialize working variables to current hash value
            let mut a = state[0];
            let mut b = state[1];
            let mut c = state[2];
            let mut d = state[3];
            let mut e = state[4];
            let mut f = state[5];
            let mut g = state[6];
            let mut h = state[7];

            for i in 0..64 {
                // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
                if i >= 16 {
                    let s0 = sigma(self, w[(i + 1) & 0xf], 7, 18, 3);
                    let s1 = sigma(self, w[(i + 14) & 0xf], 17, 19, 10);
                    w[i & 0xf] = self.add_many_u32(&[s0, s1, w[(i + 9) & 0xf], w[i & 0xf]]).0;
                }

                // Compression function main loop
                let big_s1_e = big_sigma(self, e, 6, 11, 25);
                let ch_efg = ch(self, e, f, g);
                let temp1 = self
                    .add_many_u32(&[h, big_s1_e, ch_efg, k256[i], w[i & 0xf]])
                    .0;

                let big_s0_a = big_sigma(self, a, 2, 13, 22);
                let maj_abc = maj(self, a, b, c);
                let temp2 = self.add_u32_lo(big_s0_a, maj_abc);

                h = g;
                g = f;
                f = e;
                e = self.add_u32_lo(d, temp1);
                d = c;
                c = b;
                b = a;
                a = self.add_u32_lo(temp1, temp2); // add_many_u32 of 3 elements is the same
            }

            // Add the compressed chunk to the current hash value
            state[0] = self.add_u32_lo(state[0], a);
            state[1] = self.add_u32_lo(state[1], b);
            state[2] = self.add_u32_lo(state[2], c);
            state[3] = self.add_u32_lo(state[3], d);
            state[4] = self.add_u32_lo(state[4], e);
            state[5] = self.add_u32_lo(state[5], f);
            state[6] = self.add_u32_lo(state[6], g);
            state[7] = self.add_u32_lo(state[7], h);
        }

        // Produce the final hash value (big-endian)
        for (i, item) in state.iter().enumerate().take(8) {
            self.connect_u32(output.limbs[i], *item);
        }
        output
    }

    // https://en.wikipedia.org/wiki/SHA-2#Pseudocode
    fn two_to_one_sha256(&mut self, left: Hash256Target, right: Hash256Target) -> Hash256Target {
        let mut state: Hash256Target = [
            self.constant_u32(H256_256[0]),
            self.constant_u32(H256_256[1]),
            self.constant_u32(H256_256[2]),
            self.constant_u32(H256_256[3]),
            self.constant_u32(H256_256[4]),
            self.constant_u32(H256_256[5]),
            self.constant_u32(H256_256[6]),
            self.constant_u32(H256_256[7]),
        ];

        // Initialize array of round constants:
        // (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
        let mut k256 = Vec::new();
        for item in &K32 {
            k256.push(self.constant_u32(*item));
        }

        // Pre-processing (Padding)
        // Padding is done by the Witness when setting the input value to the target

        // Process the 512-bit message
        let mut w: [U32Target; 16] = [
            left[0], left[1], left[2], left[3], left[4], left[5], left[6], left[7], right[0],
            right[1], right[2], right[3], right[4], right[5], right[6], right[7],
        ];

        // Initialize working variables to current hash value
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
            if i >= 16 {
                let s0 = sigma(self, w[(i + 1) & 0xf], 7, 18, 3);
                let s1 = sigma(self, w[(i + 14) & 0xf], 17, 19, 10);
                w[i & 0xf] = self.add_many_u32(&[s0, s1, w[(i + 9) & 0xf], w[i & 0xf]]).0;
            }

            // Compression function main loop
            let big_s1_e = big_sigma(self, e, 6, 11, 25);
            let ch_efg = ch(self, e, f, g);
            let temp1 = self
                .add_many_u32(&[h, big_s1_e, ch_efg, k256[i], w[i & 0xf]])
                .0;

            let big_s0_a = big_sigma(self, a, 2, 13, 22);
            let maj_abc = maj(self, a, b, c);
            let temp2 = self.add_u32_lo(big_s0_a, maj_abc);

            h = g;
            g = f;
            f = e;
            e = self.add_u32_lo(d, temp1);
            d = c;
            c = b;
            b = a;
            a = self.add_u32_lo(temp1, temp2); // add_many_u32 of 3 elements is the same
        }

        // Add the compressed chunk to the current hash value
        state[0] = self.add_u32_lo(state[0], a);
        state[1] = self.add_u32_lo(state[1], b);
        state[2] = self.add_u32_lo(state[2], c);
        state[3] = self.add_u32_lo(state[3], d);
        state[4] = self.add_u32_lo(state[4], e);
        state[5] = self.add_u32_lo(state[5], f);
        state[6] = self.add_u32_lo(state[6], g);
        state[7] = self.add_u32_lo(state[7], h);

        // round 2
        let zero = self.constant_u32(0);
        let cx80 = self.constant_u32(0x80000000);
        let c512 = self.constant_u32(512);

        let mut w: [U32Target; 16] = [
            cx80, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero, zero,
            zero, c512,
        ];

        // Initialize working variables to current hash value
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
            if i >= 16 {
                let s0 = sigma(self, w[(i + 1) & 0xf], 7, 18, 3);
                let s1 = sigma(self, w[(i + 14) & 0xf], 17, 19, 10);
                w[i & 0xf] = self.add_many_u32(&[s0, s1, w[(i + 9) & 0xf], w[i & 0xf]]).0;
            }

            // Compression function main loop
            let big_s1_e = big_sigma(self, e, 6, 11, 25);
            let ch_efg = ch(self, e, f, g);
            let temp1 = self
                .add_many_u32(&[h, big_s1_e, ch_efg, k256[i], w[i & 0xf]])
                .0;

            let big_s0_a = big_sigma(self, a, 2, 13, 22);
            let maj_abc = maj(self, a, b, c);
            let temp2 = self.add_u32_lo(big_s0_a, maj_abc);

            h = g;
            g = f;
            f = e;
            e = self.add_u32_lo(d, temp1);
            d = c;
            c = b;
            b = a;
            a = self.add_u32_lo(temp1, temp2); // add_many_u32 of 3 elements is the same
        }

        // Add the compressed chunk to the current hash value
        state[0] = self.add_u32_lo(state[0], a);
        state[1] = self.add_u32_lo(state[1], b);
        state[2] = self.add_u32_lo(state[2], c);
        state[3] = self.add_u32_lo(state[3], d);
        state[4] = self.add_u32_lo(state[4], e);
        state[5] = self.add_u32_lo(state[5], f);
        state[6] = self.add_u32_lo(state[6], g);
        state[7] = self.add_u32_lo(state[7], h);
        state
    }
}

#[cfg(test)]
mod tests {
    use hex;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use sha2::{Digest, Sha256};

    use crate::merkle_utils::Hash256;
    use crate::sha256::{CircuitBuilderHashSha2, WitnessHashSha2};
    use crate::types::{CircuitBuilderHash, WitnessHash};

    pub const SHA256_BLOCK: usize = 512;

    #[test]
    fn test_sha256_long() {
        let tests = [
            [
                "600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000",
                "e2bbaa7bedab290cf7988037a06d154d18a6ee308753f247a575620ec7e80167",
            ],
            [
                "600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000",
                "809015abf113afc95c4a55bfdf8a161a2d0dfd95d623b6f9cbaa2699252478b2",
            ],
            [
                "600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000",
                "9e05820fb000642e0f36ad7696f92d95c965cb27a8dc093d81a0d37b260a0f8e",
            ],
            [
                "600D540000000000000000000000000000000000000000000000000000000000",
                "a324d6ee65ee3599f9538eb1951a66ec2cb79031346afe1fd2ca4449522550e7",
            ],
            [
                "600D5400000000000000000000000000",
                "a8a27baae0b4516db52187ff191eb411a0d7ed2c7d9a551a4b371922cdf44b5a",
            ],
            [
                "600D540000000000",
                "f8a6d119d121859f8a874992ffb12d31b66f1ef2b26556780a5717817688863c",
            ],
            [
                "600D5400",
                "30cea5362411ac24c327773d1d20a90b22eb3e697124434d4d524942e81b775c",
            ],
            [
                "600D",
                "efe762fd3125bc89baa0db7fc1a72a135b653ac289e24b75aa7ef6967b4c1f1d",
            ],
            [
                "60",
                "8d33f520a3c4cef80d2453aef81b612bfe1cb44c8b2025630ad38662763f13d3",
            ],
        ];

        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        for i in tests {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let len_in_bits: usize = hex::decode(i[0]).unwrap().len() * 8;
            let block_count = (len_in_bits + 64 + SHA256_BLOCK) / SHA256_BLOCK;
            let hash_target = builder.add_virtual_hash_input_target(block_count, SHA256_BLOCK);
            let hash_output = builder.hash_sha256(&hash_target);

            let data = builder.build::<C>();

            let input = hex::decode(i[0]).unwrap();
            let output = hex::decode(i[1]).unwrap();

            // test program
            let mut hasher = Sha256::new();
            hasher.update(input.as_slice());
            let result = hasher.finalize();
            assert_eq!(result[..], output[..]);

            // test circuit
            let mut pw = PartialWitness::new();
            pw.set_sha256_input_target(&hash_target, &input);
            pw.set_sha256_output_target(&hash_output, &output);

            let proof = data.prove(pw).unwrap();
            assert!(data.verify(proof).is_ok());
        }
        
    }
}
