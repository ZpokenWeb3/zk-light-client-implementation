use async_nats::jetstream;
use async_nats::jetstream::consumer::PullConsumer;
use async_nats::jetstream::stream::{ConsumerLimits, RetentionPolicy};
use futures::stream::StreamExt;
use host::service::generate_random_proof;
use host::types::{RandomProvingResult, RandomProvingTask};
use log::info;
use serde_json::json;
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), async_nats::Error> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    //let nats_url = env::var("NATS_URL").expect("NATS_URL parameter missed").as_str();
    let nats_url = "nats://127.0.0.1:4222";

    let client = async_nats::ConnectOptions::new()
        .reconnect_delay_callback(|attempts| {
            info!("No of attempts to reconnect: {}", attempts);
            Duration::from_millis(std::cmp::min((attempts * 100) as u64, 8000))
        })
        .connect(nats_url)
        .await
        .unwrap();


    let jetstream = jetstream::new(client.clone());
    let stream_name = String::from("PROVING_STREAM");
    let stream = jetstream
        .create_stream(jetstream::stream::Config {
            name: stream_name,
            subjects: vec!["PROVE_RANDOM".into()],
            retention: RetentionPolicy::WorkQueue,
            allow_direct: true,
            consumer_limits: Some(ConsumerLimits {
                inactive_threshold: Duration::from_secs(5),
                max_ack_pending: 1000,
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    let consumer: PullConsumer = stream
        .create_consumer(jetstream::consumer::pull::Config {
            durable_name: Some("consumer".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    while let Some(message) = consumer
        .stream()
        .max_messages_per_batch(1)
        .messages()
        .await
        .unwrap()
        .next()
        .await
    {
        let message = message.unwrap();
        if let Ok(payload) = serde_json::from_slice::<RandomProvingTask>(&message.payload) {
            info!("Received payload: {:?}", payload);
            let result = generate_random_proof(&payload).await;
            let output = if result.is_err() {
                RandomProvingResult {
                    epoch_id_i_block_hash: payload.epoch_id_i_hash_i,
                    journal: "".to_string(),
                    proof: "".to_string(),
                    status: "FAILED".to_string(),
                }
            } else {
                result.unwrap()
            };

            info!("Send payload: {:?}", output);
            client.publish("RANDOM_PROVING_RESULT",
                           serde_json::to_vec(&json!(output))?.into()).await?;
        } else {
            info!("Received invalid JSON payload: {:?}", message.subject);
        }
        message.ack().await?;
    }

    Ok(())
}
