use std::collections::HashMap;
use std::env;
use risc0_build::{embed_methods_with_options, DockerOptions, GuestOptions};
use risc0_build_ethereum::generate_solidity_files;

const SOLIDITY_IMAGE_ID_PATH: &str = "../../contracts/foundry-hardhat/src/ImageID.sol";
const SOLIDITY_ELF_PATH: &str = "../../contracts/foundry-hardhat/tests/Elf.sol";
fn main() {
    // Builds can be made deterministic, and thereby reproducible, by using Docker to build the
    // guest. Check the RISC0_USE_DOCKER variable and use Docker to build the guest if set.
    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");
    let use_docker = env::var("RISC0_USE_DOCKER").ok().map(|_| DockerOptions {
        root_dir: Some("../".into()),
    });

    // Generate Rust source files for the methods crate.
    let guests = embed_methods_with_options(HashMap::from([(
        "near_risc0",
        GuestOptions {
            features: Vec::new(),
            use_docker,
        },
    )]));

    // Generate Solidity source files for use with Forge.
    let solidity_opts = risc0_build_ethereum::Options::default()
        .with_image_id_sol_path(SOLIDITY_IMAGE_ID_PATH)
        .with_elf_sol_path(SOLIDITY_ELF_PATH);

    generate_solidity_files(guests.as_slice(), &solidity_opts).unwrap();
}
