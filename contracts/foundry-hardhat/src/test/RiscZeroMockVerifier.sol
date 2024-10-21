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
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.9;

import {
    ExitCode,
    IRiscZeroVerifier,
    Output,
    OutputLib,
    Receipt,
    ReceiptClaim,
    ReceiptClaimLib,
    SystemExitCode,
    VerificationFailed
} from "../IRiscZeroVerifier.sol";

/// @notice Error raised when this verifier receives a receipt with a selector that does not match
///         its own. The selector value is calculated from the verifier parameters, and so this
///         usually indicates a mismatch between the version of the prover and this verifier.
error SelectorMismatch(bytes4 received, bytes4 expected);

/// @notice Mock verifier contract for RISC Zero receipts of execution.
contract RiscZeroMockVerifier is IRiscZeroVerifier {
    using ReceiptClaimLib for ReceiptClaim;
    using OutputLib for Output;

    /// @notice A short key attached to the seal to select the correct verifier implementation.
    /// @dev A selector is not intended to be collision resistant, in that it is possible to find
    ///      two preimages that result in the same selector. This is acceptable since it's purpose
    ///      to a route a request among a set of trusted verifiers, and to make errors of sending a
    ///      receipt to a mismatching verifiers easier to debug. It is analogous to the ABI
    ///      function selectors.
    bytes4 public immutable SELECTOR;

    constructor(bytes4 selector) {
        SELECTOR = selector;
    }

    /// @inheritdoc IRiscZeroVerifier
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) public view {
        _verifyIntegrity(seal, ReceiptClaimLib.ok(imageId, journalDigest).digest());
    }

    /// @inheritdoc IRiscZeroVerifier
    function verifyIntegrity(Receipt calldata receipt) public view {
        _verifyIntegrity(receipt.seal, receipt.claimDigest);
    }

    /// @notice internal implementation of verifyIntegrity, factored to avoid copying calldata bytes to memory.
    function _verifyIntegrity(bytes calldata seal, bytes32 claimDigest) internal view {
        // Check that the seal has a matching selector. Mismatch generally  indicates that the
        // prover and this verifier are using different parameters, and so the verification
        // will not succeed.
        if (SELECTOR != bytes4(seal[:4])) {
            revert SelectorMismatch({received: bytes4(seal[:4]), expected: SELECTOR});
        }

        // Require that the rest of the seal be exactly equal to the claim digest.
        if (keccak256(seal[4:]) != keccak256(abi.encodePacked(claimDigest))) {
            revert VerificationFailed();
        }
    }

    /// @notice Construct a mock receipt for the given image ID and journal.
    function mockProve(bytes32 imageId, bytes32 journalDigest) public view returns (Receipt memory) {
        return mockProve(ReceiptClaimLib.ok(imageId, journalDigest).digest());
    }

    /// @notice Construct a mock receipt for the given claim digest.
    /// @dev You can calculate the claimDigest from a ReceiptClaim by using ReceiptClaimLib.
    function mockProve(bytes32 claimDigest) public view returns (Receipt memory) {
        return Receipt(abi.encodePacked(SELECTOR, claimDigest), claimDigest);
    }
}
