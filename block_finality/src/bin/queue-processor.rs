use std::env;
use std::time::Duration;

use anyhow::Error;
use derive_more::Constructor;
use env_logger::{DEFAULT_FILTER_ENV, Env, try_init_from_env};
use futures::StreamExt;
use log::{info, Level};
use plonky2::util::timing::TimingTree;
use serde::{Deserialize, Serialize};

use block_finality::service::{prove_current_epoch_block, prove_prev_epoch_block};

#[derive(Debug, Deserialize, Serialize)]
pub struct ProvingTask {
    pub previous_epoch_hash: String,
    pub current_hash: String,
    pub next_hash: String,
}

#[derive(Debug, Deserialize, Constructor, Serialize)]
pub struct ProvingResult {
    pub current_hash: String,
    pub status: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info,debug"));
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://195.189.60.190:4222".to_string());
    info!("Nats URL: {}", nats_url);
    let client = nats::Options::new()
        .reconnect_delay_callback(|attempts| {
            info!("No of attempts to reconnect: {}", attempts);
            Duration::from_millis(std::cmp::min((attempts * 100) as u64, 8000))
        })
        .connect(nats_url)?;
    let sub = client.subscribe("PROVING_TASKS")?;
    loop {
        if let Some(msg) = sub.next() {
            if let Ok(payload) = serde_json::from_slice::<ProvingTask>(msg.data.as_ref()) {
                info!("Received valid JSON payload: {:?}", payload);
                let mut timing = TimingTree::new("To prove block", Level::Info);
                let _ = prove_prev_epoch_block(&payload.previous_epoch_hash, &mut timing).await?;
                prove_current_epoch_block(
                    &payload.previous_epoch_hash,
                    &payload.current_hash,
                    &payload.next_hash,
                    Some(client.clone()),
                    &mut timing,
                )
                    .await?;
                timing.print();
                let _ = client.publish("PROVING_RESULTS", serde_json::to_vec(&ProvingResult::new(payload.current_hash, "OK".to_string()))?);
            } else {
                info!("Received invalid JSON payload: {:?}", msg.subject);
            }
        }
    }
}
