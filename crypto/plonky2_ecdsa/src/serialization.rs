use alloc::vec::Vec;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use plonky2_u32::serialization::{ReadU32, WriteU32};

use crate::gadgets::biguint::BigUintTarget;

pub trait WriteBigUintTarget {
    fn write_biguint_target(&mut self, biguint_target: BigUintTarget) -> IoResult<()>;
}

impl WriteBigUintTarget for Vec<u8> {
    fn write_biguint_target(&mut self, biguint_target: BigUintTarget) -> IoResult<()> {
        let num_limbs = biguint_target.num_limbs();
        let num_limbs_be = num_limbs.to_be_bytes();
        for byte in &num_limbs_be {
            self.write_u8(*byte)?
        }
        for limb in &biguint_target.limbs {
            self.write_target_u32(*limb)?;
        }

        Ok(())
    }
}

pub trait ReadBigUintTarget {
    fn read_biguint_target(&mut self) -> IoResult<BigUintTarget>;
}

impl ReadBigUintTarget for Buffer<'_> {
    fn read_biguint_target(&mut self) -> IoResult<BigUintTarget> {
        let mut num_limbs_be = [0_u8; core::mem::size_of::<usize>()];

        self.read_exact(&mut num_limbs_be)?;

        let num_limbs = usize::from_be_bytes(num_limbs_be);
        let mut limbs = Vec::new();

        for _ in 0..num_limbs {
            let limb = self.read_target_u32()?;
            limbs.push(limb)
        }

        Ok(BigUintTarget { limbs })
    }
}

#[cfg(test)]
mod tests {
    use plonky2::iop::{target::Target, wire::Wire};
    use plonky2_u32::gadgets::arithmetic_u32::U32Target;

    use super::*;

    #[test]
    fn test_read_write_biguint_target() {
        let biguint_target = BigUintTarget {
            limbs: vec![
                U32Target(Target::VirtualTarget { index: 0 }),
                U32Target(Target::Wire(Wire { row: 0, column: 0 })),
            ],
        };
        let mut buff = vec![];
        buff.write_biguint_target(biguint_target.clone())
            .expect("Failed to write `BigUintTarget`");

        let mut len_bytes = [0u8; core::mem::size_of::<usize>()];
        len_bytes.copy_from_slice(&buff[0..core::mem::size_of::<usize>()]);
        assert_eq!(usize::from_be_bytes(len_bytes), 2);

        let mut buff = Buffer::new(&buff);
        let expected_biguint_target = buff
            .read_biguint_target()
            .expect("Failed to read `BigUintTarget`");

        assert_eq!(
            biguint_target.limbs.len(),
            expected_biguint_target.limbs.len()
        );

        for (limb, expected_limb) in biguint_target
            .limbs
            .iter()
            .zip(expected_biguint_target.limbs)
        {
            assert_eq!(limb.0, expected_limb.0);
        }
    }
}
