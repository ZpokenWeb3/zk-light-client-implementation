FROM rust:latest as builder
ARG NIGHTLY_VERSION=2023-10-24

RUN rustup toolchain install nightly-${NIGHTLY_VERSION}

WORKDIR .

# Copy the Cargo.toml and Cargo.lock files to the working directory
COPY Cargo.toml Cargo.lock ./

# Copy the source code into the container
COPY ./block_finality ./block_finality
COPY ./near_state_proofs ./near_state_proofs
COPY ./crypto ./crypto

# Build your Rust application
RUN cargo +nightly-${NIGHTLY_VERSION} build --release --bin queue-processor

FROM ubuntu:22.04

COPY --from=builder ./target/release/queue-processor ./target/release/queue-processor
RUN apt-get update \
    && apt-get install -y libc6 \
    && rm -rf /var/lib/apt/lists/*

# Specify the entry point for your application
CMD ["./target/release/queue-processor"]