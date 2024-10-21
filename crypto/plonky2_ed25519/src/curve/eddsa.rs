use curve25519_dalek::edwards::CompressedEdwardsY;
use num::{BigUint, Integer};
use plonky2::field::types::Field;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::curve::curve_types::{AffinePoint, Curve};
use crate::curve::ed25519::mul_naive;
use crate::curve::ed25519::Ed25519;
use crate::field::ed25519_base::Ed25519Base;
use crate::field::ed25519_scalar::Ed25519Scalar;

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct EDDSASignature<C: Curve> {
    pub r: AffinePoint<C>,
    pub s: C::ScalarField,
}

pub fn point_decompress(s: &[u8]) -> AffinePoint<Ed25519> {
    let mut s32 = [0u8; 32];
    s32.copy_from_slice(s);
    let compressed = CompressedEdwardsY(s32);

    let point = compressed.decompress().unwrap();
    let x_biguint = BigUint::from_bytes_le(&point.get_x().as_bytes());
    let y_biguint = BigUint::from_bytes_le(&point.get_y().as_bytes());
    AffinePoint::nonzero(
        Ed25519Base::from_noncanonical_biguint(x_biguint),
        Ed25519Base::from_noncanonical_biguint(y_biguint),
    )
}

pub fn verify_message(msg: &[u8], sigv: &[u8], pkv: &[u8]) -> bool {
    let mut data = Vec::new();
    data.extend_from_slice(&sigv[..32]);
    data.extend_from_slice(pkv);
    data.extend_from_slice(msg);
    let data_u8 = data.as_slice();

    let mut hasher = Sha512::new();
    hasher.update(data_u8);
    let hash = hasher.finalize();
    let h_big_int = BigUint::from_bytes_le(hash.as_slice());
    let h_mod_25519 = h_big_int.mod_floor(&Ed25519Scalar::order());
    let h = Ed25519Scalar::from_noncanonical_biguint(h_mod_25519);

    let pk = point_decompress(pkv);
    assert!(pk.is_valid());
    let r = point_decompress(&sigv[..32]);
    let s = Ed25519Scalar::from_noncanonical_biguint(BigUint::from_bytes_le(&sigv[32..]));

    let g = Ed25519::GENERATOR_PROJECTIVE;
    let sb = mul_naive(s, g);
    let ha = mul_naive(h, pk.to_projective());
    let rhs = r + ha.to_affine();

    sb.to_affine() == rhs
}

#[cfg(test)]
mod tests {
    use crate::curve::eddsa::verify_message;
    use ed25519_compact::*;
    use rand::random;

    #[test]
    fn test_eddsa_native() {

	const MSGLEN1: usize = 100;
        const MSGLEN2: usize = 1000;

        let msg1: Vec<u8> = (0..MSGLEN1).map(|_| random::<u8>() as u8).collect();
        let keys1 = KeyPair::generate();
        let pk1 = keys1.pk.to_vec();
        let sig1 = keys1.sk.sign(msg1.clone(), None).to_vec();

        let msg2: Vec<u8> = (0..MSGLEN2).map(|_| random::<u8>() as u8).collect();
        let keys2 = KeyPair::generate();
        let pk2 = keys2.pk.to_vec();
        let sig2 = keys2.sk.sign(msg2.clone(), None).to_vec();	

        let result = verify_message(
            &msg1,
            &sig1,
            &pk1,
        );
        assert!(result);
        let result = verify_message(
            &msg2,
            &sig2,
            &pk2,
        );
        assert!(result);
    }
}
