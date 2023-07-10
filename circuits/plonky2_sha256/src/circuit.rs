use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};

#[rustfmt::skip]
pub const H256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

/// Constants necessary for SHA-256 family of digests.
#[rustfmt::skip]
pub const K256: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
];

#[derive(Debug, Clone)]
pub struct Sha256Targets {
    pub message: Vec<BoolTarget>,
    pub digest: Vec<BoolTarget>,
}

pub fn array_to_bits(bytes: &[u8]) -> Vec<bool> {
    let len = bytes.len();
    let mut ret = Vec::new();
    for i in 0..len {
        for j in 0..8 {
            let b = (bytes[i] >> (7 - j)) & 1;
            ret.push(b == 1);
        }
    }
    ret
}

pub fn u32_to_bits_target<F: RichField + Extendable<D>, const D: usize, const B: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
) -> Vec<BoolTarget> {
    let mut res = Vec::new();
    let bit_targets = builder.split_le_base::<B>(a.0, 32);
    for i in (0..32).rev() {
        res.push(BoolTarget::new_unsafe(bit_targets[i]));
    }
    res
}

pub fn bits_to_u32_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits_target: Vec<BoolTarget>,
) -> U32Target {
    let bit_len = bits_target.len();
    assert_eq!(bit_len, 32);
    U32Target(builder.le_sum(bits_target[0..32].iter().rev()))
}

// define ROTATE(x, y)  (((x)>>(y)) | ((x)<<(32-(y))))
fn rotate32(y: usize) -> Vec<usize> {
    let mut res = Vec::new();
    for i in 32 - y..32 {
        res.push(i);
    }
    for i in 0..32 - y {
        res.push(i);
    }
    res
}

// x>>y
// Assume: 0 at index 32
fn shift32(y: usize) -> Vec<usize> {
    let mut res = Vec::new();
    for _ in 32 - y..32 {
        res.push(32);
    }
    for i in 0..32 - y {
        res.push(i);
    }
    res
}

/*
a ^ b ^ c = a+b+c - 2*a*b - 2*a*c - 2*b*c + 4*a*b*c
          = a*( 1 - 2*b - 2*c + 4*b*c ) + b + c - 2*b*c
          = a*( 1 - 2*b -2*c + 4*m ) + b + c - 2*m
where m = b*c
 */
fn xor3<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: BoolTarget,
    b: BoolTarget,
    c: BoolTarget,
) -> BoolTarget {
    let m = builder.mul(b.target, c.target);
    let two_b = builder.add(b.target, b.target);
    let two_c = builder.add(c.target, c.target);
    let two_m = builder.add(m, m);
    let four_m = builder.add(two_m, two_m);
    let one = builder.one();
    let one_sub_two_b = builder.sub(one, two_b);
    let one_sub_two_b_sub_two_c = builder.sub(one_sub_two_b, two_c);
    let one_sub_two_b_sub_two_c_add_four_m = builder.add(one_sub_two_b_sub_two_c, four_m);
    let mut res = builder.mul(a.target, one_sub_two_b_sub_two_c_add_four_m);
    res = builder.add(res, b.target);
    res = builder.add(res, c.target);

    BoolTarget::new_unsafe(builder.sub(res, two_m))
}

//#define Sigma0(x)    (ROTATE((x), 2) ^ ROTATE((x),13) ^ ROTATE((x),22))
fn big_sigma0<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
) -> U32Target {
    let a_bits = u32_to_bits_target::<F, D, 2>(builder, a);
    let rotate2 = rotate32(2);
    let rotate13 = rotate32(13);
    let rotate22 = rotate32(22);
    let mut res_bits = Vec::new();
    for i in 0..32 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate2[i]],
            a_bits[rotate13[i]],
            a_bits[rotate22[i]],
        ));
    }
    bits_to_u32_target(builder, res_bits)
}

//#define Sigma1(x)    (ROTATE((x), 6) ^ ROTATE((x),11) ^ ROTATE((x),25))
fn big_sigma1<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
) -> U32Target {
    let a_bits = u32_to_bits_target::<F, D, 2>(builder, a);
    let rotate6 = rotate32(6);
    let rotate11 = rotate32(11);
    let rotate25 = rotate32(25);
    let mut res_bits = Vec::new();
    for i in 0..32 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate6[i]],
            a_bits[rotate11[i]],
            a_bits[rotate25[i]],
        ));
    }
    bits_to_u32_target(builder, res_bits)
}

//#define sigma0(x)    (ROTATE((x), 7) ^ ROTATE((x),18) ^ ((x)>> 3))
fn sigma0<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
) -> U32Target {
    let mut a_bits = u32_to_bits_target::<F, D, 2>(builder, a);
    a_bits.push(builder.constant_bool(false));
    let rotate7 = rotate32(7);
    let rotate18 = rotate32(18);
    let shift3 = shift32(3);
    let mut res_bits = Vec::new();
    for i in 0..32 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate7[i]],
            a_bits[rotate18[i]],
            a_bits[shift3[i]],
        ));
    }
    bits_to_u32_target(builder, res_bits)
}

//#define sigma1(x)    (ROTATE((x),17) ^ ROTATE((x),19) ^ ((x)>>10))
fn sigma1<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
) -> U32Target {
    let mut a_bits = u32_to_bits_target::<F, D, 2>(builder, a);
    a_bits.push(builder.constant_bool(false));
    let rotate17 = rotate32(17);
    let rotate19 = rotate32(19);
    let shift10 = shift32(10);
    let mut res_bits = Vec::new();
    for i in 0..32 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate17[i]],
            a_bits[rotate19[i]],
            a_bits[shift10[i]],
        ));
    }
    bits_to_u32_target(builder, res_bits)
}

/*
ch = a&b ^ (!a)&c
   = a*(b-c) + c
 */
fn ch<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
    b: &U32Target,
    c: &U32Target,
) -> U32Target {
    let a_bits = u32_to_bits_target::<F, D, 2>(builder, a);
    let b_bits = u32_to_bits_target::<F, D, 2>(builder, b);
    let c_bits = u32_to_bits_target::<F, D, 2>(builder, c);
    let mut res_bits = Vec::new();
    for i in 0..32 {
        let b_sub_c = builder.sub(b_bits[i].target, c_bits[i].target);
        let a_mul_b_sub_c = builder.mul(a_bits[i].target, b_sub_c);
        let a_mul_b_sub_c_add_c = builder.add(a_mul_b_sub_c, c_bits[i].target);
        res_bits.push(BoolTarget::new_unsafe(a_mul_b_sub_c_add_c));
    }
    bits_to_u32_target(builder, res_bits)
}

/*
maj = a&b ^ a&c ^ b&c
    = a*b   +  a*c  +  b*c  -  2*a*b*c
    = a*( b + c - 2*b*c ) + b*c
    = a*( b + c - 2*m ) + m
where m = b*c
 */
fn maj<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
    b: &U32Target,
    c: &U32Target,
) -> U32Target {
    let a_bits = u32_to_bits_target::<F, D, 2>(builder, a);
    let b_bits = u32_to_bits_target::<F, D, 2>(builder, b);
    let c_bits = u32_to_bits_target::<F, D, 2>(builder, c);
    let mut res_bits = Vec::new();
    for i in 0..32 {
        let m = builder.mul(b_bits[i].target, c_bits[i].target);
        let two = builder.two();
        let two_m = builder.mul(two, m);
        let b_add_c = builder.add(b_bits[i].target, c_bits[i].target);
        let b_add_c_sub_two_m = builder.sub(b_add_c, two_m);
        let a_mul_b_add_c_sub_two_m = builder.mul(a_bits[i].target, b_add_c_sub_two_m);
        let res = builder.add(a_mul_b_add_c_sub_two_m, m);

        res_bits.push(BoolTarget::new_unsafe(res));
    }
    bits_to_u32_target(builder, res_bits)
}

fn add_u32<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &U32Target,
    b: &U32Target,
) -> U32Target {
    let (res, _carry) = builder.add_u32(*a, *b);
    res
}

// padded_msg_len = block_count x 512 bits
// Size: msg_len_in_bits (L) |  p bits   | 64 bits
// Bits:      msg            | 100...000 |    L
pub fn sha256_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_len_in_bits: usize,
) -> Sha256Targets {
    let mut message = Vec::new();
    let mut digest = Vec::new();
    let block_count = (msg_len_in_bits + 65 + 511) / 512;
    let padded_msg_len = 512 * block_count;
    let p = padded_msg_len - 64 - msg_len_in_bits;
    assert!(p > 1);

    for _ in 0..msg_len_in_bits {
        message.push(builder.add_virtual_bool_target_safe());
    }
    message.push(builder.constant_bool(true));
    for _ in 0..p - 1 {
        message.push(builder.constant_bool(false));
    }
    for i in 0..64 {
        let b = ((msg_len_in_bits as u64) >> (63 - i)) & 1;
        message.push(builder.constant_bool(b == 1));
    }

    // init states
    let mut state = Vec::new();
    for i in 0..8 {
        state.push(builder.constant_u32(H256[i]));
    }

    let mut k256 = Vec::new();
    for i in 0..64 {
        k256.push(builder.constant_u32(K256[i]));
    }

    for blk in 0..block_count {
        let mut x = Vec::new();
        let mut a = state[0].clone();
        let mut b = state[1].clone();
        let mut c = state[2].clone();
        let mut d = state[3].clone();
        let mut e = state[4].clone();
        let mut f = state[5].clone();
        let mut g = state[6].clone();
        let mut h = state[7].clone();

        for i in 0..16 {
            let index = blk as usize * 512 + i * 32;
            let u32_target = builder.le_sum(message[index..index + 32].iter().rev());

            x.push(U32Target(u32_target));
            let mut t1 = h.clone();
            let big_sigma1_e = big_sigma1(builder, &e);
            t1 = add_u32(builder, &t1, &big_sigma1_e);
            let ch_e_f_g = ch(builder, &e, &f, &g);
            t1 = add_u32(builder, &t1, &ch_e_f_g);
            t1 = add_u32(builder, &t1, &k256[i]);
            t1 = add_u32(builder, &t1, &x[i]);

            let mut t2 = big_sigma0(builder, &a);
            let maj_a_b_c = maj(builder, &a, &b, &c);
            t2 = add_u32(builder, &t2, &maj_a_b_c);

            h = g;
            g = f;
            f = e;
            e = add_u32(builder, &d, &t1);
            d = c;
            c = b;
            b = a;
            a = add_u32(builder, &t1, &t2);
        }

        for i in 16..64 {
            let s0 = sigma0(builder, &x[(i + 1) & 0x0f]);
            let s1 = sigma1(builder, &x[(i + 14) & 0x0f]);

            let s0_add_s1 = add_u32(builder, &s0, &s1);
            let s0_add_s1_add_x = add_u32(builder, &s0_add_s1, &x[(i + 9) & 0xf]);
            x[i & 0xf] = add_u32(builder, &x[i & 0xf], &s0_add_s1_add_x);

            let big_sigma0_a = big_sigma0(builder, &a);
            let big_sigma1_e = big_sigma1(builder, &e);
            let ch_e_f_g = ch(builder, &e, &f, &g);
            let maj_a_b_c = maj(builder, &a, &b, &c);

            let h_add_sigma1 = add_u32(builder, &h, &big_sigma1_e);
            let h_add_sigma1_add_ch_e_f_g = add_u32(builder, &h_add_sigma1, &ch_e_f_g);
            let h_add_sigma1_add_ch_e_f_g_add_k256 =
                add_u32(builder, &h_add_sigma1_add_ch_e_f_g, &k256[i]);

            let t1 = add_u32(builder, &x[i & 0xf], &h_add_sigma1_add_ch_e_f_g_add_k256);
            let t2 = add_u32(builder, &big_sigma0_a, &maj_a_b_c);

            h = g;
            g = f;
            f = e;
            e = add_u32(builder, &d, &t1);
            d = c;
            c = b;
            b = a;
            a = add_u32(builder, &t1, &t2);
        }

        state[0] = add_u32(builder, &state[0], &a);
        state[1] = add_u32(builder, &state[1], &b);
        state[2] = add_u32(builder, &state[2], &c);
        state[3] = add_u32(builder, &state[3], &d);
        state[4] = add_u32(builder, &state[4], &e);
        state[5] = add_u32(builder, &state[5], &f);
        state[6] = add_u32(builder, &state[6], &g);
        state[7] = add_u32(builder, &state[7], &h);
    }

    for i in 0..8 {
        let bit_targets = builder.split_le_base::<2>(state[i].0, 32);
        for j in (0..32).rev() {
            digest.push(BoolTarget::new_unsafe(bit_targets[j]));
        }
    }

    Sha256Targets { message, digest }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use rand::Rng;

    use crate::circuit::{array_to_bits, sha256_circuit};

    const EXPECTED_RES: [u8; 256] = [
        0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0,
        0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0,
        0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1,
        0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0,
        1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1,
        1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1,
        1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0,
        0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
    ];

    #[test]
    fn test_sha256() -> Result<()> {
        let mut msg = vec![0; 128 as usize];
        for i in 0..127 {
            msg[i] = i as u8;
        }

        let msg_bits = array_to_bits(&msg);
        let len = msg.len() * 8;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = sha256_circuit(&mut builder, len);
        let mut pw = PartialWitness::new();

        for i in 0..len {
            pw.set_bool_target(targets.message[i], msg_bits[i]);
        }

        for i in 0..EXPECTED_RES.len() {
            if EXPECTED_RES[i] == 1 {
                builder.assert_one(targets.digest[i].target);
            } else {
                builder.assert_zero(targets.digest[i].target);
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    #[should_panic]
    fn test_sha256_failure() {
        let mut msg = vec![0; 128 as usize];
        for i in 0..127 {
            msg[i] = i as u8;
        }

        let msg_bits = array_to_bits(&msg);
        let len = msg.len() * 8;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = sha256_circuit(&mut builder, len);
        let mut pw = PartialWitness::new();

        for i in 0..len {
            pw.set_bool_target(targets.message[i], msg_bits[i]);
        }

        let mut rng = rand::thread_rng();
        let rnd = rng.gen_range(0..256);
        for i in 0..EXPECTED_RES.len() {
            let b = (i == rnd && EXPECTED_RES[i] != 1) || (i != rnd && EXPECTED_RES[i] == 1);
            if b {
                builder.assert_one(targets.digest[i].target);
            } else {
                builder.assert_zero(targets.digest[i].target);
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof).expect("");
    }
}
