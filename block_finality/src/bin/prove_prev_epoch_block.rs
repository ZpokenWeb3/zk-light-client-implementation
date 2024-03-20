use std::env;

use anyhow::Result;
use env_logger::{DEFAULT_FILTER_ENV, Env, try_init_from_env};
use log::Level;
use plonky2::util::timing::TimingTree;

use block_finality::service::prove_prev_epoch_block;

#[tokio::main]
pub async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    let prev_block_hash = &args[1];
    let mut timing = TimingTree::new("prove previous epoch block & save proof", Level::Info);
    prove_prev_epoch_block(prev_block_hash, &mut timing).await?;
    timing.print();
    Ok(())
}
