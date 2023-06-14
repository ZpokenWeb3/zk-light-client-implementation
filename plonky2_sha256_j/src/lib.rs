// use jemallocator as recommended by plonky2
extern crate alloc;
// use jemallocator::Jemalloc;
// #[global_allocator]
// static GLOBAL: Jemalloc = Jemalloc;

pub mod hash;
pub mod nonnative;
pub mod u32;

pub use nonnative::biguint;
