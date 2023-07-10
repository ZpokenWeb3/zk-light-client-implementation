use std::marker::PhantomData;

use plonky2::field::extension::Extendable;
use plonky2::field::types::{Field, PrimeField, Sample};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartitionWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::gadgets::biguint::GeneratedValuesBigUint;
use plonky2_sha512::circuit::biguint_to_bits_target;

use crate::curve::curve_types::{AffinePoint, Curve, CurveScalar};
use crate::curve::eddsa::point_decompress;
use crate::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};

/// A Target representing an affine point on the curve `C`. We use incomplete arithmetic for efficiency,
/// so we assume these points are not zero.
#[derive(Clone, Debug)]
pub struct AffinePointTarget<C: Curve> {
    pub x: NonNativeTarget<C::BaseField>,
    pub y: NonNativeTarget<C::BaseField>,
}

impl<C: Curve> AffinePointTarget<C> {
    pub fn to_vec(&self) -> Vec<NonNativeTarget<C::BaseField>> {
        vec![self.x.clone(), self.y.clone()]
    }
}

pub trait CircuitBuilderCurve<F: RichField + Extendable<D>, const D: usize> {
    fn constant_affine_point<C: Curve>(&mut self, point: AffinePoint<C>) -> AffinePointTarget<C>;

    fn connect_affine_point<C: Curve>(
        &mut self,
        lhs: &AffinePointTarget<C>,
        rhs: &AffinePointTarget<C>,
    );

    fn add_virtual_affine_point_target<C: Curve>(&mut self) -> AffinePointTarget<C>;

    fn curve_assert_valid<C: Curve>(&mut self, p: &AffinePointTarget<C>);

    fn curve_neg<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> AffinePointTarget<C>;

    fn curve_conditional_neg<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        b: BoolTarget,
    ) -> AffinePointTarget<C>;

    fn curve_double<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> AffinePointTarget<C>;

    fn curve_repeated_double<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: usize,
    ) -> AffinePointTarget<C>;

    /// Add two points, which are assumed to be non-equal.
    fn curve_add<C: Curve>(
        &mut self,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
    ) -> AffinePointTarget<C>;

    fn curve_conditional_add<C: Curve>(
        &mut self,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
        b: BoolTarget,
    ) -> AffinePointTarget<C>;

    fn curve_scalar_mul<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: &NonNativeTarget<C::ScalarField>,
    ) -> AffinePointTarget<C>;

    fn point_compress<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> Vec<BoolTarget>;

    fn point_decompress<C: Curve>(&mut self, p: &Vec<BoolTarget>) -> AffinePointTarget<C>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderCurve<F, D>
    for CircuitBuilder<F, D>
{
    fn constant_affine_point<C: Curve>(&mut self, point: AffinePoint<C>) -> AffinePointTarget<C> {
        // TODO: Why not zero here?
        // debug_assert!(!point.zero);
        AffinePointTarget {
            x: self.constant_nonnative(point.x),
            y: self.constant_nonnative(point.y),
        }
    }

    fn connect_affine_point<C: Curve>(
        &mut self,
        lhs: &AffinePointTarget<C>,
        rhs: &AffinePointTarget<C>,
    ) {
        self.connect_nonnative(&lhs.x, &rhs.x);
        self.connect_nonnative(&lhs.y, &rhs.y);
    }

    fn add_virtual_affine_point_target<C: Curve>(&mut self) -> AffinePointTarget<C> {
        let x = self.add_virtual_nonnative_target();
        let y = self.add_virtual_nonnative_target();

        AffinePointTarget { x, y }
    }

    // y^2 = a + x^2 + b*x^2*y^2
    fn curve_assert_valid<C: Curve>(&mut self, p: &AffinePointTarget<C>) {
        let a = self.constant_nonnative(C::A);
        let d = self.constant_nonnative(C::D);

        let y_squared = self.mul_nonnative(&p.y, &p.y);
        let x_squared = self.mul_nonnative(&p.x, &p.x);
        let x_squared_y_squared = self.mul_nonnative(&x_squared, &y_squared);
        let d_x_squared_y_squared = self.mul_nonnative(&d, &x_squared_y_squared);
        let a_plus_x_squared = self.add_nonnative(&a, &x_squared);
        let rhs = self.add_nonnative(&a_plus_x_squared, &d_x_squared_y_squared);

        self.connect_nonnative(&y_squared, &rhs);
    }

    fn curve_neg<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> AffinePointTarget<C> {
        let neg_x = self.neg_nonnative(&p.x);
        AffinePointTarget {
            x: neg_x,
            y: p.y.clone(),
        }
    }

    fn curve_conditional_neg<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        b: BoolTarget,
    ) -> AffinePointTarget<C> {
        AffinePointTarget {
            x: self.nonnative_conditional_neg(&p.x, b),
            y: p.y.clone(),
        }
    }

    // https://www.hyperelliptic.org/EFD/g1p/auto-twisted.html
    fn curve_double<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> AffinePointTarget<C> {
        let AffinePointTarget { x, y } = p;
        let one = self.constant_nonnative(C::BaseField::ONE);
        let d = self.constant_nonnative(C::D);

        let xx = self.mul_nonnative(x, x);
        let yy = self.mul_nonnative(y, y);
        let xy = self.mul_nonnative(x, y);

        let xy_plus_xy = self.add_nonnative(&xy, &xy);
        let xx_plus_yy = self.add_nonnative(&xx, &yy);

        let xxyy = self.mul_nonnative(&xx, &yy);
        let dxxyy = self.mul_nonnative(&d, &xxyy);
        let neg_dxxyy = self.neg_nonnative(&dxxyy);
        let one_plus_dxxyy = self.add_nonnative(&one, &dxxyy);
        let one_minus_dxxyy = self.add_nonnative(&one, &neg_dxxyy);
        let inv_one_plus_dxxyy = self.inv_nonnative(&one_plus_dxxyy);
        let inv_one_minus_dxxyy = self.inv_nonnative(&one_minus_dxxyy);

        let x3 = self.mul_nonnative(&xy_plus_xy, &inv_one_plus_dxxyy);
        let y3 = self.mul_nonnative(&xx_plus_yy, &inv_one_minus_dxxyy);

        AffinePointTarget { x: x3, y: y3 }
    }

    fn curve_repeated_double<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: usize,
    ) -> AffinePointTarget<C> {
        let mut result = p.clone();

        for _ in 0..n {
            result = self.curve_double(&result);
        }

        result
    }

    // https://www.hyperelliptic.org/EFD/g1p/auto-twisted.html
    fn curve_add<C: Curve>(
        &mut self,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
    ) -> AffinePointTarget<C> {
        let AffinePointTarget { x: x1, y: y1 } = p1;
        let AffinePointTarget { x: x2, y: y2 } = p2;
        let one = self.constant_nonnative(C::BaseField::ONE);
        let d = self.constant_nonnative(C::D);

        let x1y2 = self.mul_nonnative(x1, y2);
        let y1x2 = self.mul_nonnative(y1, x2);
        let y1y2 = self.mul_nonnative(y1, y2);
        let x1x2 = self.mul_nonnative(x1, x2);

        let x1y2_add_y1x2 = self.add_nonnative(&x1y2, &y1x2);
        let y1y2_add_x1x2 = self.add_nonnative(&y1y2, &x1x2);

        let x1x2y1y2 = self.mul_nonnative(&x1y2, &y1x2);
        let dx1x2y1y2 = self.mul_nonnative(&d, &x1x2y1y2);
        let neg_dx1x2y1y2 = self.neg_nonnative(&dx1x2y1y2);
        let one_add_dx1x2y1y2 = self.add_nonnative(&one, &dx1x2y1y2);
        let one_neg_dx1x2y1y2 = self.add_nonnative(&one, &neg_dx1x2y1y2);
        let inv_one_add_dx1x2y1y2 = self.inv_nonnative(&one_add_dx1x2y1y2);
        let inv_one_neg_dx1x2y1y2 = self.inv_nonnative(&one_neg_dx1x2y1y2);

        let x3 = self.mul_nonnative(&x1y2_add_y1x2, &inv_one_add_dx1x2y1y2);
        let y3 = self.mul_nonnative(&y1y2_add_x1x2, &inv_one_neg_dx1x2y1y2);

        AffinePointTarget { x: x3, y: y3 }
    }

    fn curve_conditional_add<C: Curve>(
        &mut self,
        p1: &AffinePointTarget<C>,
        p2: &AffinePointTarget<C>,
        b: BoolTarget,
    ) -> AffinePointTarget<C> {
        let not_b = self.not(b);
        let sum = self.curve_add(p1, p2);
        let x_if_true = self.mul_nonnative_by_bool(&sum.x, b);
        let y_if_true = self.mul_nonnative_by_bool(&sum.y, b);
        let x_if_false = self.mul_nonnative_by_bool(&p1.x, not_b);
        let y_if_false = self.mul_nonnative_by_bool(&p1.y, not_b);

        let x = self.add_nonnative(&x_if_true, &x_if_false);
        let y = self.add_nonnative(&y_if_true, &y_if_false);

        AffinePointTarget { x, y }
    }

    fn curve_scalar_mul<C: Curve>(
        &mut self,
        p: &AffinePointTarget<C>,
        n: &NonNativeTarget<C::ScalarField>,
    ) -> AffinePointTarget<C> {
        let bits = self.split_nonnative_to_bits(n);

        let rando = (CurveScalar(C::ScalarField::rand()) * C::GENERATOR_PROJECTIVE).to_affine();
        let randot = self.constant_affine_point(rando);
        // Result starts at `rando`, which is later subtracted, because we don't support arithmetic with the zero point.
        let mut result = self.add_virtual_affine_point_target();
        self.connect_affine_point(&randot, &result);

        let mut two_i_times_p = self.add_virtual_affine_point_target();
        self.connect_affine_point(p, &two_i_times_p);

        for &bit in bits.iter() {
            let not_bit = self.not(bit);

            let result_plus_2_i_p = self.curve_add(&result, &two_i_times_p);

            let new_x_if_bit = self.mul_nonnative_by_bool(&result_plus_2_i_p.x, bit);
            let new_x_if_not_bit = self.mul_nonnative_by_bool(&result.x, not_bit);
            let new_y_if_bit = self.mul_nonnative_by_bool(&result_plus_2_i_p.y, bit);
            let new_y_if_not_bit = self.mul_nonnative_by_bool(&result.y, not_bit);

            let new_x = self.add_nonnative(&new_x_if_bit, &new_x_if_not_bit);
            let new_y = self.add_nonnative(&new_y_if_bit, &new_y_if_not_bit);

            result = AffinePointTarget { x: new_x, y: new_y };

            two_i_times_p = self.curve_double(&two_i_times_p);
        }

        // Subtract off result's intial value of `rando`.
        let neg_r = self.curve_neg(&randot);
        result = self.curve_add(&result, &neg_r);

        result
    }

    // A point
    //    (x,y) is represented in extended homogeneous coordinates (X, Y, Z,
    //    T), with x = X/Z, y = Y/Z, x * y = T/Z.
    // def point_compress(P):
    //     zinv = modp_inv(P[2])
    //     x = P[0] * zinv % p
    //     y = P[1] * zinv % p
    //     return int.to_bytes(y | ((x & 1) << 255), 32, "little")
    // If Z=1,
    //     x = P[0]
    //     y = P[1]
    //     return int.to_bytes(y | ((x & 1) << 255), 32, "little")
    fn point_compress<C: Curve>(&mut self, p: &AffinePointTarget<C>) -> Vec<BoolTarget> {
        let mut bits = biguint_to_bits_target::<F, D, 2>(self, &p.y.value);
        let x_bits_low_32 = self.split_le_base::<2>(p.x.value.get_limb(0).0, 32);

        let a = bits[0].target.clone();
        let b = x_bits_low_32[0];
        // a | b = a + b - a * b
        let a_add_b = self.add(a, b);
        let ab = self.mul(a, b);
        bits[0] = BoolTarget::new_unsafe(self.sub(a_add_b, ab));
        bits
    }

    fn point_decompress<C: Curve>(&mut self, pv: &Vec<BoolTarget>) -> AffinePointTarget<C> {
        assert_eq!(pv.len(), 256);
        let p = self.add_virtual_affine_point_target();

        self.add_simple_generator(CurvePointDecompressionGenerator::<F, D, C> {
            pv: pv.clone(),
            p: p.clone(),
            _phantom: PhantomData,
        });

        let pv2 = self.point_compress(&p);
        for i in 0..256 {
            self.connect(pv[i].target, pv2[i].target);
        }
        p
    }
}

#[derive(Debug, Clone)]
struct CurvePointDecompressionGenerator<F: RichField + Extendable<D>, const D: usize, C: Curve> {
    pv: Vec<BoolTarget>,
    p: AffinePointTarget<C>,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, C: Curve> SimpleGenerator<F>
    for CurvePointDecompressionGenerator<F, D, C>
{
    fn dependencies(&self) -> Vec<Target> {
        self.pv.iter().cloned().map(|l| l.target).collect()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let mut bits = Vec::new();
        for i in 0..256 {
            bits.push(witness.get_bool_target(self.pv[i].clone()));
        }
        let mut s: [u8; 32] = [0; 32];
        for i in 0..32 {
            for j in 0..8 {
                if bits[i * 8 + j] {
                    s[31 - i] += 1 << (7 - j);
                }
            }
        }
        let point = point_decompress(s.as_slice());

        out_buffer.set_biguint_target(&self.p.x.value, &point.x.to_canonical_biguint());
        out_buffer.set_biguint_target(&self.p.y.value, &point.y.to_canonical_biguint());
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Neg;

    use anyhow::Result;
    use plonky2::field::types::{Field, Sample};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::curve::curve_types::{AffinePoint, Curve, CurveScalar};
    use crate::curve::ed25519::Ed25519;
    use crate::field::ed25519_base::Ed25519Base;
    use crate::field::ed25519_scalar::Ed25519Scalar;
    use crate::gadgets::curve::CircuitBuilderCurve;
    use crate::gadgets::nonnative::CircuitBuilderNonNative;

    #[test]
    fn test_curve_point_is_valid() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g = Ed25519::GENERATOR_AFFINE;
        let g_target = builder.constant_affine_point(g);
        let neg_g_target = builder.curve_neg(&g_target);

        builder.curve_assert_valid(&g_target);
        builder.curve_assert_valid(&neg_g_target);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    #[should_panic]
    fn test_curve_point_is_not_valid() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g = Ed25519::GENERATOR_AFFINE;
        let not_g = AffinePoint::<Ed25519> {
            x: g.x,
            y: g.y + Ed25519Base::ONE,
            zero: g.zero,
        };
        let not_g_target = builder.constant_affine_point(not_g);

        builder.curve_assert_valid(&not_g_target);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof).unwrap()
    }

    #[test]
    fn test_curve_double() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g = Ed25519::GENERATOR_AFFINE;
        let g_target = builder.constant_affine_point(g);
        let neg_g_target = builder.curve_neg(&g_target);

        let double_g = g.double();
        let double_g_expected = builder.constant_affine_point(double_g);
        builder.curve_assert_valid(&double_g_expected);

        let double_neg_g = (-g).double();
        let double_neg_g_expected = builder.constant_affine_point(double_neg_g);
        builder.curve_assert_valid(&double_neg_g_expected);

        let double_g_actual = builder.curve_double(&g_target);
        let double_neg_g_actual = builder.curve_double(&neg_g_target);
        builder.curve_assert_valid(&double_g_actual);
        builder.curve_assert_valid(&double_neg_g_actual);

        builder.connect_affine_point(&double_g_expected, &double_g_actual);
        builder.connect_affine_point(&double_neg_g_expected, &double_neg_g_actual);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    fn test_curve_add() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g = Ed25519::GENERATOR_AFFINE;
        let double_g = g.double();
        let g_plus_2g = g + double_g;
        let g_plus_2g_expected = builder.constant_affine_point(g_plus_2g);
        builder.curve_assert_valid(&g_plus_2g_expected);

        let g_target = builder.constant_affine_point(g);
        let double_g_target = builder.curve_double(&g_target);
        let g_plus_2g_actual = builder.curve_add(&g_target, &double_g_target);
        builder.curve_assert_valid(&g_plus_2g_actual);

        builder.connect_affine_point(&g_plus_2g_expected, &g_plus_2g_actual);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    fn test_curve_conditional_add() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g = Ed25519::GENERATOR_AFFINE;
        let double_g = g.double();
        let g_plus_2g = g + double_g;
        let g_plus_2g_expected = builder.constant_affine_point(g_plus_2g);

        let g_expected = builder.constant_affine_point(g);
        let double_g_target = builder.curve_double(&g_expected);
        let t = builder._true();
        let f = builder._false();
        let g_plus_2g_actual = builder.curve_conditional_add(&g_expected, &double_g_target, t);
        let g_actual = builder.curve_conditional_add(&g_expected, &double_g_target, f);

        builder.connect_affine_point(&g_plus_2g_expected, &g_plus_2g_actual);
        builder.connect_affine_point(&g_expected, &g_actual);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    #[ignore]
    fn test_curve_mul() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let g = Ed25519::GENERATOR_PROJECTIVE.to_affine();
        let five = Ed25519Scalar::from_canonical_usize(5);
        let neg_five = five.neg();
        let neg_five_scalar = CurveScalar::<Ed25519>(neg_five);
        let neg_five_g = (neg_five_scalar * g.to_projective()).to_affine();
        let neg_five_g_expected = builder.constant_affine_point(neg_five_g);
        builder.curve_assert_valid(&neg_five_g_expected);

        let g_target = builder.constant_affine_point(g);
        let neg_five_target = builder.constant_nonnative(neg_five);
        let neg_five_g_actual = builder.curve_scalar_mul(&g_target, &neg_five_target);
        builder.curve_assert_valid(&neg_five_g_actual);

        builder.connect_affine_point(&neg_five_g_expected, &neg_five_g_actual);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    #[ignore]
    fn test_curve_random() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let rando =
            (CurveScalar(Ed25519Scalar::rand()) * Ed25519::GENERATOR_PROJECTIVE).to_affine();
        assert!(rando.is_valid());
        let randot = builder.constant_affine_point(rando);

        let two_target = builder.constant_nonnative(Ed25519Scalar::TWO);
        let randot_doubled = builder.curve_double(&randot);
        let randot_times_two = builder.curve_scalar_mul(&randot, &two_target);
        builder.connect_affine_point(&randot_doubled, &randot_times_two);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }

    #[test]
    fn test_point_compress_decompress() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let rando =
            (CurveScalar(Ed25519Scalar::rand()) * Ed25519::GENERATOR_PROJECTIVE).to_affine();
        assert!(rando.is_valid());

        let randot = builder.constant_affine_point(rando);

        let rando_compressed = builder.point_compress(&randot);
        let rando_decompressed = builder.point_decompress(&rando_compressed);

        builder.connect_affine_point(&randot, &rando_decompressed);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }
}
