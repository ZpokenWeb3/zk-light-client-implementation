use num::bigint::BigUint;
use num::FromPrimitive;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::gadgets::biguint::{BigUintTarget, CircuitBuilderBiguint};
use plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};

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

pub struct Sha512Targets {
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

pub fn biguint_to_bits_target<F: RichField + Extendable<D>, const D: usize, const B: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &BigUintTarget,
) -> Vec<BoolTarget> {
    let mut res = Vec::new();
    for i in (0..a.num_limbs()).rev() {
        let bit_targets = builder.split_le_base::<B>(a.get_limb(i).0, 32);
        for j in (0..32).rev() {
            res.push(BoolTarget::new_unsafe(bit_targets[j]));
        }
    }
    res
}

pub fn bits_to_biguint_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits_target: Vec<BoolTarget>,
) -> BigUintTarget {
    let bit_len = bits_target.len();
    assert_eq!(bit_len % 32, 0);

    let mut u32_targets = Vec::new();
    for i in 0..bit_len / 32 {
        u32_targets.push(U32Target(
            builder.le_sum(bits_target[i * 32..(i + 1) * 32].iter().rev()),
        ));
    }
    u32_targets.reverse();
    BigUintTarget { limbs: u32_targets }
}

// define ROTATE(x, y)  (((x)>>(y)) | ((x)<<(64-(y))))
fn rotate64(y: usize) -> Vec<usize> {
    let mut res = Vec::new();
    for i in 64 - y..64 {
        res.push(i);
    }
    for i in 0..64 - y {
        res.push(i);
    }
    res
}

// x>>y
// Assume: 0 at index 64
fn shift64(y: usize) -> Vec<usize> {
    let mut res = Vec::new();
    for _ in 64 - y..64 {
        res.push(64);
    }
    for i in 0..64 - y {
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

//define Sigma0(x)    (ROTATE((x),28) ^ ROTATE((x),34) ^ ROTATE((x),39))
fn big_sigma0<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &BigUintTarget,
) -> BigUintTarget {
    let a_bits = biguint_to_bits_target::<F, D, 2>(builder, a);
    let rotate28 = rotate64(28);
    let rotate34 = rotate64(34);
    let rotate39 = rotate64(39);
    let mut res_bits = Vec::new();
    for i in 0..64 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate28[i]],
            a_bits[rotate34[i]],
            a_bits[rotate39[i]],
        ));
    }
    bits_to_biguint_target(builder, res_bits)
}

//define Sigma1(x)    (ROTATE((x),14) ^ ROTATE((x),18) ^ ROTATE((x),41))
fn big_sigma1<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &BigUintTarget,
) -> BigUintTarget {
    let a_bits = biguint_to_bits_target::<F, D, 2>(builder, a);
    let rotate14 = rotate64(14);
    let rotate18 = rotate64(18);
    let rotate41 = rotate64(41);
    let mut res_bits = Vec::new();
    for i in 0..64 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate14[i]],
            a_bits[rotate18[i]],
            a_bits[rotate41[i]],
        ));
    }
    bits_to_biguint_target(builder, res_bits)
}

//define sigma0(x)    (ROTATE((x), 1) ^ ROTATE((x), 8) ^ ((x)>> 7))
fn sigma0<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &BigUintTarget,
) -> BigUintTarget {
    let mut a_bits = biguint_to_bits_target::<F, D, 2>(builder, a);
    a_bits.push(builder.constant_bool(false));
    let rotate1 = rotate64(1);
    let rotate8 = rotate64(8);
    let shift7 = shift64(7);
    let mut res_bits = Vec::new();
    for i in 0..64 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate1[i]],
            a_bits[rotate8[i]],
            a_bits[shift7[i]],
        ));
    }
    bits_to_biguint_target(builder, res_bits)
}

//define sigma1(x)    (ROTATE((x),19) ^ ROTATE((x),61) ^ ((x)>> 6))
fn sigma1<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &BigUintTarget,
) -> BigUintTarget {
    let mut a_bits = biguint_to_bits_target::<F, D, 2>(builder, a);
    a_bits.push(builder.constant_bool(false));
    let rotate19 = rotate64(19);
    let rotate61 = rotate64(61);
    let shift6 = shift64(6);
    let mut res_bits = Vec::new();
    for i in 0..64 {
        res_bits.push(xor3(
            builder,
            a_bits[rotate19[i]],
            a_bits[rotate61[i]],
            a_bits[shift6[i]],
        ));
    }
    bits_to_biguint_target(builder, res_bits)
}

/*
ch = a&b ^ (!a)&c
   = a*(b-c) + c
 */
fn ch<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &BigUintTarget,
    b: &BigUintTarget,
    c: &BigUintTarget,
) -> BigUintTarget {
    let a_bits = biguint_to_bits_target::<F, D, 2>(builder, a);
    let b_bits = biguint_to_bits_target::<F, D, 2>(builder, b);
    let c_bits = biguint_to_bits_target::<F, D, 2>(builder, c);
    let mut res_bits = Vec::new();
    for i in 0..64 {
        let b_sub_c = builder.sub(b_bits[i].target, c_bits[i].target);
        let a_mul_b_sub_c = builder.mul(a_bits[i].target, b_sub_c);
        let a_mul_b_sub_c_add_c = builder.add(a_mul_b_sub_c, c_bits[i].target);
        res_bits.push(BoolTarget::new_unsafe(a_mul_b_sub_c_add_c));
    }
    bits_to_biguint_target(builder, res_bits)
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
    a: &BigUintTarget,
    b: &BigUintTarget,
    c: &BigUintTarget,
) -> BigUintTarget {
    let a_bits = biguint_to_bits_target::<F, D, 2>(builder, a);
    let b_bits = biguint_to_bits_target::<F, D, 2>(builder, b);
    let c_bits = biguint_to_bits_target::<F, D, 2>(builder, c);
    let mut res_bits = Vec::new();
    for i in 0..64 {
        let m = builder.mul(b_bits[i].target, c_bits[i].target);
        let two = builder.two();
        let two_m = builder.mul(two, m);
        let b_add_c = builder.add(b_bits[i].target, c_bits[i].target);
        let b_add_c_sub_two_m = builder.sub(b_add_c, two_m);
        let a_mul_b_add_c_sub_two_m = builder.mul(a_bits[i].target, b_add_c_sub_two_m);
        let res = builder.add(a_mul_b_add_c_sub_two_m, m);

        res_bits.push(BoolTarget::new_unsafe(res));
    }
    bits_to_biguint_target(builder, res_bits)
}

fn add_biguint_2limbs<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &BigUintTarget,
    b: &BigUintTarget,
) -> BigUintTarget {
    assert_eq!(a.num_limbs(), 2);
    assert_eq!(b.num_limbs(), 2);

    let mut combined_limbs = vec![];
    let mut carry = builder.zero_u32();
    for i in 0..2 {
        let a_limb = (i < a.num_limbs())
            .then(|| a.limbs[i])
            .unwrap_or_else(|| builder.zero_u32());
        let b_limb = (i < b.num_limbs())
            .then(|| b.limbs[i])
            .unwrap_or_else(|| builder.zero_u32());

        let (new_limb, new_carry) = builder.add_many_u32(&[carry, a_limb, b_limb]);
        carry = new_carry;
        combined_limbs.push(new_limb);
    }

    BigUintTarget {
        limbs: combined_limbs,
    }
}

// padded_msg_len = block_count x 1024 bits
// Size: msg_len_in_bits (L) |  p bits   | 128 bits
// Bits:      msg            | 100...000 |    L
pub fn sha256_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_len_in_bits: u128,
) -> Sha512Targets {
    let mut message = Vec::new();
    let mut digest = Vec::new();
    let block_count = (msg_len_in_bits + 129 + 1023) / 1024;
    let padded_msg_len = 1024 * block_count;
    let p = padded_msg_len - 128 - msg_len_in_bits;
    assert!(p > 1);

    for _ in 0..msg_len_in_bits {
        message.push(builder.add_virtual_bool_target_unsafe());
    }
    message.push(builder.constant_bool(true));
    for _ in 0..p - 1 {
        message.push(builder.constant_bool(false));
    }
    for i in 0..128 {
        let b = ((msg_len_in_bits as u128) >> (127 - i)) & 1;
        message.push(builder.constant_bool(b == 1));
    }

    // init states
    let mut state = Vec::new();
    for i in 0..8 {
        state.push(builder.constant_biguint(&BigUint::from_u64(H512_512[i]).unwrap()));
    }

    let mut k512 = Vec::new();
    for i in 0..80 {
        k512.push(builder.constant_biguint(&BigUint::from_u64(K64[i]).unwrap()));
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
            let index = blk as usize * 1024 + i * 64;
            let u32_0 = builder.le_sum(message[index..index + 32].iter().rev());
            let u32_1 = builder.le_sum(message[index + 32..index + 64].iter().rev());

            let mut u32_targets = Vec::new();
            u32_targets.push(U32Target(u32_1));
            u32_targets.push(U32Target(u32_0));
            let big_int = BigUintTarget { limbs: u32_targets };

            x.push(big_int);
            let mut t1 = h.clone();
            let big_sigma1_e = big_sigma1(builder, &e);
            t1 = add_biguint_2limbs(builder, &t1, &big_sigma1_e);
            let ch_e_f_g = ch(builder, &e, &f, &g);
            t1 = add_biguint_2limbs(builder, &t1, &ch_e_f_g);
            t1 = add_biguint_2limbs(builder, &t1, &k512[i]);
            t1 = add_biguint_2limbs(builder, &t1, &x[i]);

            let mut t2 = big_sigma0(builder, &a);
            let maj_a_b_c = maj(builder, &a, &b, &c);
            t2 = add_biguint_2limbs(builder, &t2, &maj_a_b_c);

            h = g;
            g = f;
            f = e;
            e = add_biguint_2limbs(builder, &d, &t1);
            d = c;
            c = b;
            b = a;
            a = add_biguint_2limbs(builder, &t1, &t2);
        }

        for i in 16..80 {
            let s0 = sigma0(builder, &x[(i + 1) & 0x0f]);
            let s1 = sigma1(builder, &x[(i + 14) & 0x0f]);

            let s0_add_s1 = add_biguint_2limbs(builder, &s0, &s1);
            let s0_add_s1_add_x = add_biguint_2limbs(builder, &s0_add_s1, &x[(i + 9) & 0xf]);
            x[i & 0xf] = add_biguint_2limbs(builder, &x[i & 0xf], &s0_add_s1_add_x);

            let big_sigma0_a = big_sigma0(builder, &a);
            let big_sigma1_e = big_sigma1(builder, &e);
            let ch_e_f_g = ch(builder, &e, &f, &g);
            let maj_a_b_c = maj(builder, &a, &b, &c);

            let h_add_sigma1 = add_biguint_2limbs(builder, &h, &big_sigma1_e);
            let h_add_sigma1_add_ch_e_f_g = add_biguint_2limbs(builder, &h_add_sigma1, &ch_e_f_g);
            let h_add_sigma1_add_ch_e_f_g_add_k512 =
                add_biguint_2limbs(builder, &h_add_sigma1_add_ch_e_f_g, &k512[i]);

            let t1 = add_biguint_2limbs(builder, &x[i & 0xf], &h_add_sigma1_add_ch_e_f_g_add_k512);
            let t2 = add_biguint_2limbs(builder, &big_sigma0_a, &maj_a_b_c);

            h = g;
            g = f;
            f = e;
            e = add_biguint_2limbs(builder, &d, &t1);
            d = c;
            c = b;
            b = a;
            a = add_biguint_2limbs(builder, &t1, &t2);
        }

        state[0] = add_biguint_2limbs(builder, &state[0], &a);
        state[1] = add_biguint_2limbs(builder, &state[1], &b);
        state[2] = add_biguint_2limbs(builder, &state[2], &c);
        state[3] = add_biguint_2limbs(builder, &state[3], &d);
        state[4] = add_biguint_2limbs(builder, &state[4], &e);
        state[5] = add_biguint_2limbs(builder, &state[5], &f);
        state[6] = add_biguint_2limbs(builder, &state[6], &g);
        state[7] = add_biguint_2limbs(builder, &state[7], &h);
    }

    for i in 0..8 {
        for j in (0..2).rev() {
            let bit_targets = builder.split_le_base::<2>(state[i].get_limb(j).0, 32);
            for k in (0..32).rev() {
                digest.push(BoolTarget::new_unsafe(bit_targets[k]));
            }
        }
    }

    Sha512Targets { message, digest }
}

#[cfg(test)]
mod tests {
    use crate::circuit::{array_to_bits, sha256_circuit};
    use anyhow::Result;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use rand::Rng;

    const EXPECTED_RES: [u8; 512] = [
        0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1,
        0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0,
        1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1,
        0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1,
        1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
        0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0,
        1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1,
        1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0,
        1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1,
        1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1,
        1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0,
        1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0,
        1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1,
        0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1,
        0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1,
        0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0,
        0, 1,
    ];

    #[test]
    fn test_sha512() -> Result<()> {
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
        let targets = sha256_circuit(&mut builder, len as u128);
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
    fn test_sha512_failure() {
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
        let targets = sha256_circuit(&mut builder, len as u128);
        let mut pw = PartialWitness::new();

        for i in 0..len {
            pw.set_bool_target(targets.message[i], msg_bits[i]);
        }

        let mut rng = rand::thread_rng();
        let rnd = rng.gen_range(0..512);
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
