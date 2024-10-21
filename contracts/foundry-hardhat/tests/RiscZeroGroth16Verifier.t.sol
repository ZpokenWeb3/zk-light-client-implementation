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

pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

import {
    ExitCode,
    IRiscZeroVerifier,
    Output,
    OutputLib,
    // Receipt needs to be renamed due to collision with type on the Test contract.
    Receipt as RiscZeroReceipt,
    ReceiptClaim,
    ReceiptClaimLib,
    SystemExitCode,
    SystemState,
    SystemStateLib,
    VerificationFailed
} from "../src/IRiscZeroVerifier.sol";
import {ControlID, RiscZeroGroth16Verifier} from "../src/groth16/RiscZeroGroth16Verifier.sol";
import {TestReceipt} from "./TestReceipt.sol";

contract RiscZeroGroth16VerifierTest is Test {
    using OutputLib for Output;
    using ReceiptClaimLib for ReceiptClaim;
    using SystemStateLib for SystemState;

    ReceiptClaim internal TEST_RECEIPT_CLAIM = ReceiptClaim(
        TestReceipt.IMAGE_ID,
        SystemState(0, bytes32(0)).digest(),
        ExitCode(SystemExitCode.Halted, 0),
        bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
        Output(sha256(TestReceipt.JOURNAL), bytes32(0)).digest()
    );

    RiscZeroReceipt internal TEST_RECEIPT = RiscZeroReceipt(TestReceipt.SEAL, TEST_RECEIPT_CLAIM.digest());

    RiscZeroGroth16Verifier internal verifier;

    function setUp() external {
        verifier = new RiscZeroGroth16Verifier(ControlID.CONTROL_ROOT, ControlID.BN254_CONTROL_ID);
    }

    function testConsistentSystemStateZeroDigest() external pure {
        require(
            ReceiptClaimLib.SYSTEM_STATE_ZERO_DIGEST
                == sha256(
                    abi.encodePacked(
                        SystemStateLib.TAG_DIGEST,
                        // down
                        bytes32(0),
                        // data
                        uint32(0),
                        // down.length
                        uint16(1) << 8
                    )
                )
        );
    }

    function testVerifyKnownGoodReceipt() external view {
        verifier.verifyIntegrity(TEST_RECEIPT);
    }

    function testVerifyKnownGoodImageIdAndJournal() public view{
        verifier.verify(TEST_RECEIPT.seal, TestReceipt.IMAGE_ID, sha256(TestReceipt.JOURNAL));
    }

    function expectVerificationFailure(bytes memory seal, ReceiptClaim memory claim) internal {
        bytes32 claim_digest = claim.digest();
        vm.expectRevert(VerificationFailed.selector);
        verifier.verifyIntegrity(RiscZeroReceipt(seal, claim_digest));
    }

    // A no-so-thorough test to make sure changing the bits causes a failure.
    function testVerifyMangledReceipts() external {
        ReceiptClaim memory mangled_claim = TEST_RECEIPT_CLAIM;
        bytes memory mangled_seal = TEST_RECEIPT.seal;

        // All of these need to expect revert.
        console2.log("verification of mangled seal value");
        mangled_seal[4] ^= bytes1(uint8(1));
        expectVerificationFailure(mangled_seal, TEST_RECEIPT_CLAIM);
        mangled_seal = TEST_RECEIPT.seal;

        console2.log("verification of mangled preStateDigest value");
        mangled_claim.preStateDigest ^= bytes32(uint256(1));
        expectVerificationFailure(TEST_RECEIPT.seal, mangled_claim);
        mangled_claim = TEST_RECEIPT_CLAIM;

        console2.log("verification of mangled postStateDigest value");
        mangled_claim.postStateDigest ^= bytes32(uint256(1));
        expectVerificationFailure(TEST_RECEIPT.seal, mangled_claim);
        mangled_claim = TEST_RECEIPT_CLAIM;

        console2.log("verification of mangled exitCode value");
        mangled_claim.exitCode = ExitCode(SystemExitCode.SystemSplit, 0);
        expectVerificationFailure(TEST_RECEIPT.seal, mangled_claim);
        mangled_claim = TEST_RECEIPT_CLAIM;

        console2.log("verification of mangled input value");
        mangled_claim.input ^= bytes32(uint256(1));
        expectVerificationFailure(TEST_RECEIPT.seal, mangled_claim);
        mangled_claim = TEST_RECEIPT_CLAIM;

        console2.log("verification of mangled output value");
        mangled_claim.output ^= bytes32(uint256(1));
        expectVerificationFailure(TEST_RECEIPT.seal, mangled_claim);
        mangled_claim = TEST_RECEIPT_CLAIM;

        bytes32 test_claim_digest = TEST_RECEIPT_CLAIM.digest();
        console2.log("verification of mangled claim digest value (low bit)");
        vm.expectRevert(VerificationFailed.selector);
        verifier.verifyIntegrity(RiscZeroReceipt(mangled_seal, test_claim_digest ^ bytes32(uint256(1))));

        console2.log("verification of mangled claim digest value (high bit)");
        vm.expectRevert(VerificationFailed.selector);
        verifier.verifyIntegrity(RiscZeroReceipt(mangled_seal, test_claim_digest ^ bytes32(uint256(1) << 255)));

        // Just a quick sanity check. This should pass.
        verifier.verifyIntegrity(RiscZeroReceipt(TEST_RECEIPT.seal, TEST_RECEIPT_CLAIM.digest()));
    }

    function testSelectorIsStable() external view {
        require(verifier.SELECTOR() == hex"50bd1769");
    }
}
