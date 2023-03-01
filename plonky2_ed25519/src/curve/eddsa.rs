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

pub const SAMPLE_MSG1: &str = "test message";
pub const SAMPLE_MSG2: &str = "plonky2";
pub const SAMPLE_PK1: [u8; 32] = [
    59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29,
    226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41,
];
pub const SAMPLE_SIG1: [u8; 64] = [
    104, 196, 204, 44, 176, 120, 225, 128, 47, 67, 245, 210, 247, 65, 201, 66, 34, 159, 217, 32,
    175, 224, 14, 12, 31, 231, 83, 160, 214, 122, 250, 68, 250, 203, 33, 143, 184, 13, 247, 140,
    185, 25, 122, 25, 253, 195, 83, 102, 240, 255, 30, 21, 108, 249, 77, 184, 36, 72, 9, 198, 49,
    12, 68, 8,
];
pub const SAMPLE_SIG2: [u8; 64] = [
    130, 82, 60, 170, 184, 218, 199, 182, 66, 19, 182, 14, 141, 214, 229, 180, 43, 19, 227, 183,
    130, 204, 69, 112, 171, 113, 6, 111, 218, 227, 249, 85, 57, 216, 145, 63, 71, 192, 201, 10, 54,
    234, 203, 8, 63, 240, 226, 101, 84, 167, 36, 246, 153, 35, 31, 52, 244, 82, 239, 137, 18, 62,
    134, 7,
];

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct EDDSASignature<C: Curve> {
    pub r: AffinePoint<C>,
    pub s: C::ScalarField,
}

// TODO: remove the dependency of curve25519_dalek
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
    use crate::curve::eddsa::{
        verify_message, SAMPLE_MSG1, SAMPLE_MSG2, SAMPLE_PK1, SAMPLE_SIG1, SAMPLE_SIG2,
    };

    #[test]
    fn test_eddsa_native() {
        let result = verify_message(
            SAMPLE_MSG1.as_bytes(),
            SAMPLE_SIG1.as_slice(),
            SAMPLE_PK1.as_slice(),
        );
        assert!(result);
        let result = verify_message(
            SAMPLE_MSG2.as_bytes(),
            SAMPLE_SIG2.as_slice(),
            SAMPLE_PK1.as_slice(),
        );
        assert!(result);
    }
}
