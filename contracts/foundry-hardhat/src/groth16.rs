// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloy::sol_types::SolValue;
use anyhow::Result;
use risc0_zkvm::{sha::Digestible, Groth16ReceiptVerifierParameters};

/// ABI encoding of the seal.
pub fn abi_encode(seal: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    Ok(encode(seal)?.abi_encode())
}

/// Encoding of a Groth16 seal by prefixing it with the verifier selector.
///
/// The verifier selector is determined from the first 4 bytes of the hash of the verifier
/// parameters including the Groth16 verification key and the control IDs that commit to the RISC
/// Zero circuits.
///
/// NOTE: Selector value of the current zkVM version is used. If you need to use a selector from a
/// different version of the zkVM, use the [encode_seal] method instead.
pub fn encode(seal: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    let verifier_parameters_digest = Groth16ReceiptVerifierParameters::default().digest();
    let selector = &verifier_parameters_digest.as_bytes()[..4];
    // Create a new vector with the capacity to hold both selector and seal
    let mut selector_seal = Vec::with_capacity(selector.len() + seal.as_ref().len());
    selector_seal.extend_from_slice(selector);
    selector_seal.extend_from_slice(seal.as_ref());

    Ok(selector_seal)
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use regex::Regex;

    use super::*;
    use std::fs;

    const CONTROL_ID_PATH: &str = "./src/groth16/ControlID.sol";
    const CONTROL_ROOT: &str = "CONTROL_ROOT";
    const BN254_CONTROL_ID: &str = "BN254_CONTROL_ID";

    fn parse_digest(file_path: &str, name: &str) -> Result<String, anyhow::Error> {
        let content = fs::read_to_string(file_path)?;
        let re_digest = Regex::new(&format!(r#"{}\s*=\s*hex"([0-9a-fA-F]+)""#, name))?;
        re_digest
            .captures(&content)
            .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
            .ok_or(anyhow!("{name} not found"))
    }
    #[test]
    fn control_root_is_consistent() {
        let params = Groth16ReceiptVerifierParameters::default();
        let expected_control_root = params.control_root.to_string();
        let control_root = parse_digest(CONTROL_ID_PATH, CONTROL_ROOT).unwrap();
        assert_eq!(control_root, expected_control_root);
    }

    #[test]
    fn bn254_control_id_is_consistent() {
        let params = Groth16ReceiptVerifierParameters::default();
        let mut expected_bn254_control_id = params.bn254_control_id;
        expected_bn254_control_id.as_mut_bytes().reverse();
        let expected_bn254_control_id = hex::encode(expected_bn254_control_id);
        let bn254_control_id = parse_digest(CONTROL_ID_PATH, BN254_CONTROL_ID).unwrap();

        assert_eq!(bn254_control_id, expected_bn254_control_id);
    }
}
