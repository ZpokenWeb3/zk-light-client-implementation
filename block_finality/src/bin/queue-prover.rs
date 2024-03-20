use std::collections::HashMap;
use std::env;
use std::time::Duration;

use async_nats::jetstream;
use async_nats::jetstream::consumer::PullConsumer;
use async_nats::jetstream::stream::RetentionPolicy;
use env_logger::{DEFAULT_FILTER_ENV, Env, try_init_from_env};
use futures::stream::StreamExt;
use log::{info, Level};
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use serde::Deserializer;
use serde::ser::SerializeSeq;
use serde::Serializer;
use serde_json::json;

use block_finality::prove_crypto::{ed25519_proof, get_ed25519_targets};
use block_finality::types::{InputTask, OutputTask};
use plonky2_ed25519::gadgets::eddsa::EDDSATargets;

const D: usize = 2;

type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;


#[tokio::main]
async fn main() -> Result<(), async_nats::Error> {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info,debug"));
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://195.189.60.190:4222".into());
    info!("Nats URL: {}", nats_url);
    // Cached proving schema and targets in order to reuse depending on message length
    let mut circuit_state: HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)> = HashMap::new();
    let client = async_nats::ConnectOptions::new()
        .reconnect_delay_callback(|attempts| {
            info!("No of attempts to reconnect: {}", attempts);
            Duration::from_millis(std::cmp::min((attempts * 100) as u64, 8000))
        })
        .connect(nats_url)
        .await
        .unwrap();
    //Creating jetstream nats and consumer in order to parallel signatures proving
    let jetstream = jetstream::new(client.clone());
    let stream_name = String::from("SIGNATURES_STREAM");
    let consumer: PullConsumer = jetstream
        .create_stream(jetstream::stream::Config {
            name: stream_name,
            subjects: vec!["PROVE_SIGNATURE".into()],
            retention: RetentionPolicy::WorkQueue,
            allow_direct: true,
            ..Default::default()
        })
        .await.unwrap()
        .create_consumer(jetstream::consumer::pull::Config {
            durable_name: Some("consumer".into()),
            ..Default::default()
        })
        .await.unwrap();
    info!("Connection : {:?}", client.connection_state());
    while let Some(message) = consumer.stream().max_messages_per_batch(1).messages().await.unwrap().next().await {
        let message = message.unwrap();
        if let Ok(payload) = serde_json::from_slice::<InputTask>(&message.payload) {
            info!("Incoming signature index: {}", payload.signature_index);
            let message_len_in_bits = payload.message.len() * 8;
            let mut timing = TimingTree::new("prove signature && send to pipeline", Level::Info);
            match circuit_state.get(&message_len_in_bits) {
                None => {
                    let circuit_data = timed!(timing, "create proving scheme && targets",
                        get_ed25519_targets(message_len_in_bits)
                        .expect("Error creating digital signature circuit or targets"));
                    circuit_state.insert(message_len_in_bits, circuit_data.clone());
                    let proof = timed!(timing, "prove signature",
                        ed25519_proof::<F, C, D>(&payload.message, &payload.approval, &payload.validator, circuit_data.clone())
                        .expect("Error proving digital signature"));
                    let output_bytes = timed!(timing, "serialize proof and verifier data for aggregation", {
                        let deserialized_proof = proof.to_bytes();
                        let deserialized_verifier_data = circuit_data.0.verifier_only.to_bytes().unwrap();
                        let output = OutputTask {
                            proof: deserialized_proof,
                            verifier_data: deserialized_verifier_data,
                            signature_index: payload.signature_index,
                        };
                        serde_json::to_vec(&json!(output))?
                        }
                    );
                    timing.print();
                    client.publish("PROCESS_SIGNATURE_RESULT".to_string(), output_bytes.into()).await?;
                }
                Some(hashed_circuit) => {
                    let deref_circuit_data = hashed_circuit.to_owned();
                    let proof = timed!(timing, "prove signature", ed25519_proof(&payload.message, &payload.approval, &payload.validator, deref_circuit_data.clone())
                        .expect("Error proving digital signature"));
                    let output_bytes = timed!(timing, "serialize proof and verifier data for aggregation", {
                        let deserialized_proof = proof.to_bytes();
                        let deserialized_verifier_data = deref_circuit_data.0.verifier_only.to_bytes().unwrap();
                        let output = OutputTask {
                            proof: deserialized_proof,
                            verifier_data: deserialized_verifier_data,
                            signature_index: payload.signature_index,
                        };
                        serde_json::to_vec(&json!(output))?
                        }
                    );
                    timing.print();
                    client.publish("PROCESS_SIGNATURE_RESULT".to_string(), output_bytes.into()).await?;
                }
            }
        } else {
            info!("Received invalid JSON payload: {:?}", message.subject);
        }
        message.ack().await?;
    }

    Ok::<(), async_nats::Error>(())
}
