// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/// @title IVerifier interface for the Verifier contract
interface IVerifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[4] calldata input
    ) external view;

    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[4] calldata input
    ) external view;
}

/// @title NearBlockVerification contract for proof verification and saving the results
contract NearBlockVerification is OwnableUpgradeable, PausableUpgradeable {
    /// @custom:storage-location erc7201:near.block.verification.storage
    struct Layout {
        IVerifier _verifier;
        mapping(bytes => bool) proofedHashes;
    }

    // keccak256(abi.encode(uint256(keccak256("near.block.verification.storage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant STORAGE_LOCATION =
        0x7e1ac6ea8c17a8ee916e4637e2ea51559be498738ae8f34b89590ade1015f100;

    /// @notice Private function to retrieve storage layout
    function _getStorage() private pure returns (Layout storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }

    /// @notice Event emitted when a proof is successfully verified and Near block hash saved
    /// @param input the public inputs used in the verification
    /// @param proof the proof used for verification
    event ProofVerifiedAndSaved(
        uint256[4] indexed input,
        uint256[8] proof
    );

    /// @notice Event emitted when a compressed proof is successfully verified and Near block hash saved
    /// @param input the public inputs used in the verification
    /// @param compressedProof the compressed proof used for verification
    event CompressedProofVerifiedAndSaved(
        uint256[4] indexed input,
        uint256[4] compressedProof
    );

    /// @notice Initializes the NearBlockVerification contract
    /// @dev Only callable once, and only callable by deployer
    /// @param verifier the initial Verifier contract address
    function initialize (address verifier)
        external
        initializer
    {
        Layout storage $ = _getStorage();
        $._verifier = IVerifier(verifier);

        _transferOwnership(msg.sender);
    }

    /// @notice Get the verifier contract address
    /// @return the address of the Verifier contract
    function getVerifier() external view returns (IVerifier) {
        return _getStorage()._verifier;
    }

    /// @notice Set a new Verifier contract address
    /// @dev Only callable by the owner
    /// @param verifier the new Verifier contract address
    function setVerifier(address verifier) external onlyOwner {
        Layout storage $ = _getStorage();
        $._verifier = IVerifier(verifier);
    }

    /// @notice Verify a proof and save the Near block hash
    /// @dev The public inputs consists of a previous block hash and a block hash.
    /// Each hash consists of 2 numbers of 256 bits
    /// @param input the public inputs for the proof
    /// @param proof the proof to be verified
    function verifyAndSaveProof(
        uint256[4] calldata input,
        uint256[8] calldata proof
    ) public whenNotPaused {
        Layout storage $ = _getStorage();

        // verify the proof using the Verifier contract
        $._verifier.verifyProof(proof, input);

        // calculate the Near block hash from the public input
        bytes memory hash = secondHash(input);

        // save the Near block hash as proofed
        $.proofedHashes[hash] = true;
        emit ProofVerifiedAndSaved(input, proof);
    }

    /// @notice Verify a compressed proof and save the Near block hash
    /// @dev The public inputs consists of a previous block hash and a block hash.
    /// Each hash consists of 2 numbers of 256 bits
    /// @param input the public inputs for the proof
    /// @param compressedProof the compressed proof to be verified
    function verifyAndSaveCompressedProof(
        uint256[4] calldata input,
        uint256[4] calldata compressedProof
    ) public whenNotPaused {
        Layout storage $ = _getStorage();

        // verify the compressed proof using the Verifier contract
        $._verifier.verifyCompressedProof(compressedProof, input);

        // calculate the Near block hash from the public input
        bytes memory hash = secondHash(input);

        // save the Near block hash as proofed
        $.proofedHashes[hash] = true;

        emit CompressedProofVerifiedAndSaved(input, compressedProof);
    }

    /// @notice Checks whether the specified public input has been checked and saved
    /// @dev The public input is a Near block hash represented as 2 numbers of 256 bits each
    /// @param input the public input to check for proof status
    /// @return a boolean indicating whether the input is proofed or not
    function isProofed(
        uint256[2] calldata input
    ) public view returns (bool) {
        return _getStorage().proofedHashes[toHash(input)];
    }

    /// @notice Checks whether the specified Near block hash has been checked and saved
    /// @dev The Near block hash is represented as a byte array
    /// @param hash the hash to check for proof status
    /// @return a boolean indicating whether the hash is proofed or not
    function isProofedHash(
        bytes calldata hash
    ) public view returns (bool) {
        return _getStorage().proofedHashes[hash];
    }

    /// @notice Convert an array of 256-bit integers to a hash
    /// @param array the array of 256-bit integers to convert
    /// @return the resulting hash
    function toHash(
        uint256[2] memory array
    ) public pure returns (bytes memory) {
        // initialize an empty byte array to store the result
        bytes memory result = abi.encodePacked();

        for (uint i = 0; i < 2; i++) {
            // convert each element to a 128-bit unsigned integer and append it to the result
            result = abi.encodePacked(result, uint128(array[i]));
        }

        return result;
    }

    /// @notice Internal function to convert the second half of an array of 256-bit integers to a hash
    /// @param array the array of 256-bit integers to convert
    /// @return the resulting hash
    function secondHash(
        uint256[4] memory array
    ) internal pure returns (bytes memory) {
        // initialize an empty byte array to store the result
        bytes memory result = abi.encodePacked();

        // iterate through the second half of the input array
        for (uint i = 2; i < 4; i++) {
            // convert each element to a 128-bit unsigned integer and append it to the result
            result = abi.encodePacked(result, uint128(array[i]));
        }

        return result;
    }
}
