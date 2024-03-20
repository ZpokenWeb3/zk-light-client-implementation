#![allow(incomplete_features)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![feature(generic_const_exprs)]
#![feature(adt_const_params)]

//! This crate provides functionalities for proving current block based on the previous one.
//!
//! # Modules
//!
//! - `prove_block`: Contains functionality for proving blocks.
//! - `prove_primitives`: Contains primitive data types used in proofs.
//! - `prove_crypto`: Provides cryptographic proof functionalities.
//! - `recursion`: Provides utilities for recursive proving.
//! - `service`: Defines services for handling proving blocks.
//! - `types`: Defines custom data types used across the crate.
//! - `utils`: Contains utility functions and helpers to load blocks, validators and converting types.

pub mod prove_block;
pub mod prove_primitives;
pub mod prove_crypto;
pub mod recursion;
pub mod service;
pub mod types;
pub mod utils;
