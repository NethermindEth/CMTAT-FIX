// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@fixdescriptorkit/contracts/src/IFixDescriptor.sol";
import "@fixdescriptorkit/contracts/src/FixDescriptorLib.sol";

/**
 * @title FixDescriptorModule
 * @notice Module for managing FIX descriptor storage and verification
 * @dev Handles storage, retrieval, and verification of descriptors for a single token
 *      Uses FixDescriptorLib as the underlying implementation
 *      This module is designed for single-token engines (one engine per token)
 */
abstract contract FixDescriptorModule {
    using FixDescriptorLib for FixDescriptorLib.Storage;

    /// @notice Single descriptor storage for the bound token
    FixDescriptorLib.Storage internal _descriptor;

    /**
     * @notice Get the descriptor for the bound token
     * @return descriptor The FixDescriptor struct
     */
    function _getDescriptor() internal view returns (IFixDescriptor.FixDescriptor memory descriptor) {
        return _descriptor.getDescriptor();
    }

    /**
     * @notice Set or update the descriptor for the bound token
     * @dev Emits appropriate event based on whether this is first initialization or update
     *      Delegates to FixDescriptorLib.setDescriptor()
     * @param descriptor The complete FixDescriptor struct
     */
    function _setDescriptor(IFixDescriptor.FixDescriptor calldata descriptor) internal {
        _descriptor.setDescriptor(descriptor);
    }

    /**
     * @notice Check if the descriptor has been initialized
     * @return True if descriptor is initialized
     */
    function _isInitialized() internal view returns (bool) {
        return _descriptor.isInitialized();
    }

    /**
     * @notice Verify a specific field against the committed descriptor
     * @dev Delegates to FixDescriptorLib.verifyFieldProof()
     * @param pathSBE SBE-encoded bytes of the field path
     * @param value Raw FIX value bytes
     * @param proof Merkle proof (sibling hashes)
     * @param directions Direction array (true=right child, false=left child)
     * @return valid True if the proof is valid
     */
    function _verifyField(
        bytes calldata pathSBE,
        bytes calldata value,
        bytes32[] calldata proof,
        bool[] calldata directions
    ) internal view returns (bool valid) {
        return _descriptor.verifyFieldProof(pathSBE, value, proof, directions);
    }

    /**
     * @notice Get SBE data chunk from SSTORE2 storage
     * @dev Delegates to FixDescriptorLib.getFixSBEChunk()
     * @param start Start offset (in the data, not including STOP byte)
     * @param size Number of bytes to read
     * @return chunk The requested SBE data
     */
    function _getSBEChunk(
        uint256 start,
        uint256 size
    ) internal view returns (bytes memory chunk) {
        return _descriptor.getFixSBEChunk(start, size);
    }
}
