// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.16;

interface IVerifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[16] calldata input
    ) external view;

    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[16] calldata input
    ) external view;
}

contract NearBlockVerificationWith16InputsIA {
    IVerifier public _verifier;
    address public owner;

    mapping(bytes => bool) proofedHashes;

    event ProofVerifiedAndSaved(
        uint256[16] indexed input,
        uint256[8] proof
    );

    event CompressedProofVerifiedAndSaved(
        uint256[16] indexed input,
        uint256[4] compressedProof
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Caller is not the owner");
        _;
    }

    constructor(address verifier) {
        _verifier = IVerifier(verifier);
        owner = msg.sender;
    }

    function setVerifier(address verifier) external onlyOwner {
        _verifier = IVerifier(verifier);
    }

    function verifyAndSaveProof(
        uint256[16] calldata input,
        uint256[8] calldata proof
    ) public {
        _verifier.verifyProof(
            proof,
            input
        );

        bytes memory hash = secondHash(input);
        proofedHashes[hash] = true;

        emit ProofVerifiedAndSaved(input, proof);
    }

    function verifyAndSaveCompressedProof(
        uint256[16] calldata input,
        uint256[4] calldata proof
    ) public {
        _verifier.verifyCompressedProof(
            proof,
            input
        );

        bytes memory hash = secondHash(input);
        proofedHashes[hash] = true;

        emit CompressedProofVerifiedAndSaved(input, proof);
    }

    function isProofed(
        uint256[8] calldata input
    ) public view returns (bool) {
        return proofedHashes[toHash(input)];
    }

    function isProofedHash(
        bytes calldata hash
    ) public view returns (bool) {
        return proofedHashes[hash];
    }

    function toHash(uint256[8] memory array) public pure returns (bytes memory result) {
        result = new bytes(32);
        assembly {
            let dest := add(result, 32)

            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                let value := mload(add(array, mul(i, 32)))

                mstore8(dest, byte(28, value))
                dest := add(dest, 1)

                mstore8(dest, byte(29, value))
                dest := add(dest, 1)

                mstore8(dest, byte(30, value))
                dest := add(dest, 1)

                mstore8(dest, byte(31, value))
                dest := add(dest, 1)
            }
            mstore(result, 32)
        }

        return result;
    }

    function secondHash(uint256[16] memory array) public pure returns (bytes memory result) {
        result = new bytes(32);
        assembly {
            let dest := add(result, 32)

            for { let i := 8 } lt(i, 16) { i := add(i, 1) } {
                let value := mload(add(array, mul(i, 32)))

                mstore8(dest, byte(28, value))
                dest := add(dest, 1)

                mstore8(dest, byte(29, value))
                dest := add(dest, 1)

                mstore8(dest, byte(30, value))
                dest := add(dest, 1)

                mstore8(dest, byte(31, value))
                dest := add(dest, 1)
            }
            mstore(result, 32)
        }

        return result;
    }
}
