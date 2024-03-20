use std::env;

use anyhow::Result;
use env_logger::{DEFAULT_FILTER_ENV, Env, try_init_from_env};
use log::Level;
use plonky2::util::timing::TimingTree;

use block_finality::service::prove_current_epoch_block;

#[tokio::main]
pub async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let prev_hash = &args[1];

    let hash = &args[2];

    let next_hash = &args[3];

    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    let mut timing = TimingTree::new("To prove current block", Level::Info);
    prove_current_epoch_block(prev_hash, hash, next_hash, None, &mut timing).await?;
    timing.print();
    Ok(())
}
