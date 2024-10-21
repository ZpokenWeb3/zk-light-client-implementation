#![no_main]

use libfuzzer_sys::{
    arbitrary::{Arbitrary, Error, Unstructured},
    fuzz_target,
};
use near_bft_finality::utils::vec_u32_to_u8;

#[derive(Debug)]
pub struct U32 {
    data: Vec<u32>,
}

impl<'a> Arbitrary<'a> for U32 {
    fn arbitrary(raw: &mut Unstructured<'a>) -> Result<Self, Error> {
        let len = raw.int_in_range(0..=100)?;
        let mut data = vec![0; len as usize];
        for elem in &mut data {
            *elem = raw.arbitrary()?;
        }
        Ok(U32 { data })
    }
}

fuzz_target!(|data: U32| {
    let data_u32 = &data.data;
    let data_u8 = vec_u32_to_u8(data_u32);
    assert_eq!(data_u32.len() * 4, data_u8.len());
});
