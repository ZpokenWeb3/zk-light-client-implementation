// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Verifier.sol";
import "../src/NearBlockVerification.sol";

contract NearBlockVerificationTest is Test {
    Verifier public verifier;
    NearBlockVerification public nearBlockVerification;

    uint256[4] public inputs;
    uint256[8] public proof;
    uint256[4] public incorrectInputs;
    uint256[8] public incorrectProof;

    event ProofVerifiedAndSaved(
        uint256[4] indexed input,
        uint256[8] proof
    );

    event CompressedProofVerifiedAndSaved(
        uint256[4] indexed input,
        uint256[4] compressedProof
    );

    function setUp() public {
        verifier = new Verifier();
        nearBlockVerification = new NearBlockVerification();
        nearBlockVerification.initialize(address(verifier));

        inputs = [
            946114226032418920967126594582827844,
            252211404666022190610388135805056990747,
            250203699874957393754930603326313200955,
            294168951901226811933587358204780889671
        ];

        proof = [
            6302162678823841200396915311228777342524310647178952242621209430860606417875,
            5688874101604422809062392686067769974466336383547871872297604857481113209311,
            13067201362306888280420276685585448577630319898210624528091944232563639673903,
            15253040417767205464665745126190612115773771949281934081886164082116687122186,
            1286287796680172736180296629792415589426353119726353867523801064677953938381,
            10072443203863058952492408939658944706911871289381911835060263441184101246878,
            13594152181780533529094098669508003919098231319348108349232488431856536079741,
            19991156839958621917471713965247457880542796239191147501866226782529365125613
        ];

        incorrectInputs = [
            946114226032418920967126594582827840,
            252211404666022190610388135805056990740,
            250203699874957393754930603326313200950,
            294168951901226811933587358204780889670
        ];

        incorrectProof = [
            6302162678823841200396915311228777342524310647178952242621209430860606417870,
            5688874101604422809062392686067769974466336383547871872297604857481113209310,
            13067201362306888280420276685585448577630319898210624528091944232563639673900,
            15253040417767205464665745126190612115773771949281934081886164082116687122180,
            1286287796680172736180296629792415589426353119726353867523801064677953938380,
            10072443203863058952492408939658944706911871289381911835060263441184101246870,
            13594152181780533529094098669508003919098231319348108349232488431856536079740,
            19991156839958621917471713965247457880542796239191147501866226782529365125610
        ];
    }

    function testSuccessfulVerifyAndSaveProof() public {
        nearBlockVerification.verifyAndSaveProof(inputs, proof);
    }

    function testHandleIncorrectProof() public {
        vm.expectRevert(Verifier.ProofInvalid.selector);
        nearBlockVerification.verifyAndSaveProof(incorrectInputs, proof);

        vm.expectRevert(Verifier.ProofInvalid.selector);
        nearBlockVerification.verifyAndSaveProof(inputs, incorrectProof);
    }

    function testSuccessfulVerifyAndSaveCompressedProof() public {
        uint256[4] memory compressedProof = verifier.compressProof(proof);
        nearBlockVerification.verifyAndSaveCompressedProof(inputs, compressedProof);
    }

    function testIsProofedWhenInputIsNotProofed() public view {
        uint256[2] memory unProofedInput = [uint256(250203699874957393754930603326313200955), uint256(294168951901226811933587358204780889671)];

        assertFalse(nearBlockVerification.isProofed(unProofedInput));
        assertFalse(nearBlockVerification.isProofed([inputs[0], inputs[1]]));
        assertFalse(nearBlockVerification.isProofed([inputs[2], inputs[3]]));
    }

    function testIsProofedWhenInputIsProofed() public {
        nearBlockVerification.verifyAndSaveProof(inputs, proof);

        assertTrue(nearBlockVerification.isProofed([inputs[2], inputs[3]]));
    }

    function testToHash() public view {
        bytes memory proofedInputHashBytes = hex"00b63708658aa1456ac96ff803915344bdbe264fded3c726a10e8defce103e1b";
        assertEq(nearBlockVerification.toHash([inputs[0], inputs[1]]), proofedInputHashBytes);

        proofedInputHashBytes = hex"bc3b7ad2c4a1269c8bbc161ee8d9fd3bdd4ee11af49aede8eb8a920e9e344647";
        assertEq(nearBlockVerification.toHash([inputs[2], inputs[3]]), proofedInputHashBytes);
    }

    function testIsProofedHashWhenInputHashNotProofed() public view {
        bytes memory unProofedInputHash = hex"00b63708658aa1456ac96ff803915344bdbe264fded3c726a10e8defce103e1b";
        assertFalse(nearBlockVerification.isProofedHash(unProofedInputHash));

        unProofedInputHash = hex"bc3b7ad2c4a1269c8bbc161ee8d9fd3bdd4ee11af49aede8eb8a920e9e344647";
        assertFalse(nearBlockVerification.isProofedHash(unProofedInputHash));
    }

    function testIsProofedHashWhenInputHashIsProofed() public {
        bytes memory proofedInputHash = hex"bc3b7ad2c4a1269c8bbc161ee8d9fd3bdd4ee11af49aede8eb8a920e9e344647";
        assertFalse(nearBlockVerification.isProofedHash(proofedInputHash));

        nearBlockVerification.verifyAndSaveProof(inputs, proof);

        proofedInputHash = hex"bc3b7ad2c4a1269c8bbc161ee8d9fd3bdd4ee11af49aede8eb8a920e9e344647";
        assertTrue(nearBlockVerification.isProofedHash(proofedInputHash));
    }

    function testSetVerifier() public {
        assertEq(address(nearBlockVerification.getVerifier()), address(verifier));

        Verifier newVerifier = new Verifier();
        nearBlockVerification.setVerifier(address(newVerifier));
        assertEq(address(nearBlockVerification.getVerifier()), address(newVerifier));
    }

    function testProofVerifiedAndSavedEvent() public {
        vm.expectEmit(true, false, false, true, address(nearBlockVerification));
        emit NearBlockVerification.ProofVerifiedAndSaved(inputs, proof);

        nearBlockVerification.verifyAndSaveProof(inputs, proof);
    }

    function testCompressedProofVerifiedAndSavedEvent() public {
        uint256[4] memory compressedProof = verifier.compressProof(proof);

        vm.expectEmit(true, false, false, true, address(nearBlockVerification));
        emit NearBlockVerification.CompressedProofVerifiedAndSaved(inputs, compressedProof);

        nearBlockVerification.verifyAndSaveCompressedProof(inputs, compressedProof);
    }
}
