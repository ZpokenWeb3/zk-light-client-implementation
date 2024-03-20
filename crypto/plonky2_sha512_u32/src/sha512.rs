use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_u32::gadgets::{arithmetic_u32::{CircuitBuilderU32, U32Target}, interleaved_u32::CircuitBuilderB32};

use crate::types::{HashInputTarget, HashOutputTarget, U64Target, WitnessHash};

pub trait WitnessHashSha2<F: PrimeField64>: Witness<F> {
    fn set_sha512_input_target(&mut self, target: &HashInputTarget, value: &[u8]);
    fn set_sha512_output_target(&mut self, target: &HashOutputTarget, value: &[u8]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessHashSha2<F> for T {
    fn set_sha512_input_target(&mut self, target: &HashInputTarget, value: &[u8]) {
        // sha512 padding
        let mut message: Vec<u8> = value.to_vec();
        let input_len_bits = message.len() as u128 * 8;
        // append 0x8000...
        let len_bytes = input_len_bits.to_be_bytes();
        let k: usize = (896 - (input_len_bits % 1024) - 1) as usize;
        message.push(0b10000000);
        for _ in 0..(k - 1) / 8 {
            message.push(0);
        }
        message.extend_from_slice(&len_bytes);
        let input_biguint = BigUint::from_bytes_be(message.as_slice());
        self.set_hash_input_target(target, &input_biguint);
    }

    fn set_sha512_output_target(&mut self, target: &HashOutputTarget, value: &[u8]) {
        let output_biguint = BigUint::from_bytes_be(value);
        self.set_hash_output_target(target, &output_biguint);
    }
}

pub trait CircuitBuilderHashSha2<F: RichField + Extendable<D>, const D: usize> {
    fn add_u64(&mut self, a: U64Target, b: U64Target) -> U64Target;
    fn add_many_u64(&mut self, values: &[U64Target]) -> U64Target;
    fn hash_sha512(&mut self, hash: &HashInputTarget) -> HashOutputTarget;
}

/// Initial state for SHA-256.
#[rustfmt::skip]
pub const H512_512: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// Constants necessary for SHA-512 family of digests.
#[rustfmt::skip]
pub const K64: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// (a rrot r1) xor (a rrot r2) xor (a rsh s3)
fn sigma<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U64Target,
    r1: u8,
    r2: u8,
    s3: u8,
) -> U64Target {
    // rrot
    let x = builder.lrot_u64(&[a.lo, a.hi], 64 - r1);
    let y = builder.lrot_u64(&[a.lo, a.hi], 64 - r2);
    // shift
    let shft_high = builder.rsh_u32(a.hi, s3);
    let carry = builder.lsh_u32(a.hi, 32 - s3);
    let w_lo = builder.rsh_u32(a.lo, s3);
    let not_carry = builder.not_u32(carry);
    let not_lo = builder.not_u32(w_lo);
    let shft_and = builder.and_u32(not_lo, not_carry);
    let shft_lo = builder.not_u32(shft_and);
    // xor
    let xor_lo_hi = builder.unsafe_xor_many_u64(&[x, y, [shft_lo, shft_high]]);
    U64Target { hi: xor_lo_hi[1], lo: xor_lo_hi[0] }
}

/// (a rrot r1) xor (a rrot r2) xor (a rrot r3)
fn big_sigma<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U64Target,
    r1: u8,
    r2: u8,
    r3: u8,
) -> U64Target {
    // rrot
    let x = builder.lrot_u64(&[a.lo, a.hi], 64 - r1);
    let y = builder.lrot_u64(&[a.lo, a.hi], 64 - r2);
    let z = builder.lrot_u64(&[a.lo, a.hi], 64 - r3);
    // xor
    let xor_lo_hi = builder.unsafe_xor_many_u64(&[x, y, z]);
    U64Target { hi: xor_lo_hi[1], lo: xor_lo_hi[0] }
}

/// (e and f) xor ((not e) and g)
fn ch<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    e: U64Target,
    f: U64Target,
    g: U64Target,
) -> U64Target {
    // not e
    let not_e = builder.not_u64(&[e.lo, e.hi]);
    // and
    let ef = builder.and_u64(&[e.lo, e.hi], &[f.lo, f.hi]);
    let eg = builder.and_u64(&not_e, &[g.lo, g.hi]);
    // xor
    let xor_lo_hi = builder.xor_u64(&ef, &eg);
    U64Target { hi: xor_lo_hi[1], lo: xor_lo_hi[0] }
}

/// (a and b) xor (a and c) xor (b and c)
/// = (a and (b xor c)) xor (b and c)
/// we can calculate (b xor c), (b and c) in a single op
fn maj<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: U64Target,
    b: U64Target,
    c: U64Target,
) -> U64Target {
    // and
    let ab = builder.and_u64(&[a.lo, a.hi], &[b.lo, b.hi]);
    let ac = builder.and_u64(&[a.lo, a.hi], &[c.lo, c.hi]);
    let bc = builder.and_u64(&[b.lo, b.hi], &[c.lo, c.hi]);
    // xor
    let xor_lo_hi = builder.unsafe_xor_many_u64(&[ab, ac, bc]);
    U64Target { hi: xor_lo_hi[1], lo: xor_lo_hi[0] }
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHashSha2<F, D>
for CircuitBuilder<F, D>
{
    fn add_u64(&mut self, a: U64Target, b: U64Target) -> U64Target {
        let zero = self.zero_u32();
        let (output_lo, carry) = self.add_u32s_with_carry(&[a.lo, b.lo], zero);
        let (output_hi, _) = self.add_u32s_with_carry(&[a.hi, b.hi], carry);
        U64Target { hi: output_hi, lo: output_lo }
    }

    fn add_many_u64(&mut self, values: &[U64Target]) -> U64Target {
        let lo: Vec<U32Target> = values.iter().map(|x| x.lo).collect();
        let hi: Vec<U32Target> = values.iter().map(|x| x.hi).collect();
        let (lo_sum, carry) = self.add_many_u32(&lo);
        let (hi_sum, _) = self.add_many_u32(&[hi, [carry].to_vec()].concat());
        U64Target { hi: hi_sum, lo: lo_sum }
    }

    // https://en.wikipedia.org/wiki/SHA-2#Pseudocode
    fn hash_sha512(&mut self, hash: &HashInputTarget) -> Vec<U64Target> {
        let mut output = vec![];
        for _ in 0..8 {
            output.push(U64Target { hi: self.add_virtual_u32_target(), lo: self.add_virtual_u32_target() });
        }
        let input = hash.input.clone();
        let input_bits = hash.input_bits;
        let block_num = input_bits / 1024;

        let mut state = Vec::<U64Target>::new();

        // Initialize hash values:
        // (first 64 bits of the fractional parts of the square roots of the first 8 primes)
        for item in &H512_512 {
            state.push(U64Target { hi: self.constant_u32((item >> 32) as u32), lo: self.constant_u32((item & 0xFFFFFFFF) as u32) });
        }

        // Initialize array of round constants:
        // (first 64 bits of the fractional parts of the cube roots of the first 80 primes)
        let mut k512 = Vec::new();
        for item in &K64 {
            k512.push(U64Target { hi: self.constant_u32((item >> 32) as u32), lo: self.constant_u32((item & 0xFFFFFFFF) as u32) });
        }

        // Pre-processing (Padding)
        // Padding is done by the Witness when setting the input value to the target

        // Process the message in successive 1024-bit chunks

        for block in 0..block_num {
            let mut w: Vec<U64Target> = input[block * 16..block * 16 + 16].try_into().unwrap();
            for i in 16..80 {
                let s0 = sigma(self, w[i - 15], 1, 8, 7);
                let s1 = sigma(self, w[i - 2], 19, 61, 6);
                w.push(self.add_many_u64(&[w[i - 16], s0, s1, w[i - 7]]));
            }

            let mut a = state[0];
            let mut b = state[1];
            let mut c = state[2];
            let mut d = state[3];
            let mut e = state[4];
            let mut f = state[5];
            let mut g = state[6];
            let mut h = state[7];
            for i in 0..80 {
                let big_s0_a = big_sigma(self, a, 28, 34, 39);
                let maj_abc = maj(self, a, b, c);
                let temp2 = self.add_u64(big_s0_a, maj_abc);

                let big_s1_e = big_sigma(self, e, 14, 18, 41);
                let ch_efg = ch(self, e, f, g);
                let temp1 = self.add_many_u64(&[h, big_s1_e, ch_efg, k512[i], w[i]]);
                h = g;
                g = f;
                f = e;
                e = self.add_u64(d, temp1);
                d = c;
                c = b;
                b = a;
                a = self.add_u64(temp1, temp2);
            }


            state[0] = self.add_u64(state[0], a);
            state[1] = self.add_u64(state[1], b);
            state[2] = self.add_u64(state[2], c);
            state[3] = self.add_u64(state[3], d);
            state[4] = self.add_u64(state[4], e);
            state[5] = self.add_u64(state[5], f);
            state[6] = self.add_u64(state[6], g);
            state[7] = self.add_u64(state[7], h);
        }

        // Produce the final hash value (big-endian)
        for (i, item) in state.iter().enumerate() {
            self.connect_u32(output[i].lo, item.lo);
            self.connect_u32(output[i].hi, item.hi);
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
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use sha2::{Digest, Sha512};

    use crate::sha512::{CircuitBuilderHashSha2, WitnessHashSha2};
    use crate::types::CircuitBuilderHash;

    pub const SHA512_BLOCK: usize = 1024;

    #[test]
    fn test_sha512_long() {
        let tests = [
            [
                "600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000",
                "627ee229e2fe283c2501d8d1f289a0376f88c5d928328e0b836d11b17bf94c227bacf16404cd77e9f1d64ab49717e6295ba1c5f00107db82fb8d606222278d96",
            ],
        ];

        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input_len_bits = hex::decode(tests[0][0]).unwrap().len() * 8;
        let block_count = (input_len_bits + 128 + SHA512_BLOCK) / SHA512_BLOCK;
        let hash_target = builder.add_virtual_hash_input_target(block_count, SHA512_BLOCK);
        let hash_output = builder.hash_sha512(&hash_target);
        for i in 0..hash_output.len() {
            builder.register_public_input(hash_output[i].lo.0);
            builder.register_public_input(hash_output[i].hi.0);
        }
        let data = builder.build::<C>();

        let input = hex::decode(tests[0][0]).unwrap();
        let output = hex::decode(tests[0][1]).unwrap();

        // test program
        let mut hasher = Sha512::new();
        hasher.update(input.as_slice());
        let result = hasher.finalize();

        assert_eq!(result[..], output[..]);

        // test circuit
        let mut pw = PartialWitness::new();
        pw.set_sha512_input_target(&hash_target, &input);
        pw.set_sha512_output_target(&hash_output, &output);

        let proof = data.prove(pw).unwrap();
        assert!(data.verify(proof).is_ok());
    }
}
