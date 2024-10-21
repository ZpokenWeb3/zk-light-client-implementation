#![allow(incomplete_features)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![feature(generic_const_exprs)]
#![feature(adt_const_params)]

//! This crate provides functionalities for proving current block based on the previous one.
//!
//! # Modules
//!
//! - `prove_bft`: Contains functionality for proving block BFT finality.
//! - `prove_block_data`: Contains functionality for proving block entities.
//! - `prove_crypto`: Provides cryptographic proof functionalities.
//! - `service`: Defines services for handling proving blocks.
//! - `types`: Defines custom data types used across the crate.
//! - `utils`: Contains utility functions and helpers to load blocks, validators and converting types.

pub mod prove_bft;
pub mod prove_block_data;
pub mod prove_crypto;
pub mod types;
pub mod utils;
