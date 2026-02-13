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

    /*//////////////////////////////////////////////////////////////
                        DEPLOYMENT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deploy SBE data using SSTORE2 pattern and set descriptor
     * @dev Deploys data to contract bytecode, then sets the descriptor with the pointer
     *      This combines deployment and descriptor setting in one operation
     * @param sbeData Raw SBE-encoded data to deploy
     * @param descriptor Descriptor struct (fixSBEPtr and fixSBELen will be set automatically)
     * @return sbePtr Address of the deployed SBE data contract
     */
    function _deployAndSetDescriptor(
        bytes memory sbeData,
        IFixDescriptor.FixDescriptor memory descriptor
    ) internal returns (address sbePtr) {
        // Deploy SBE data using SSTORE2 pattern
        sbePtr = _deploySBE(sbeData);

        // Verify deployment succeeded
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(sbePtr)
        }
        require(codeSize == sbeData.length + 1, "FixDescriptorModule: Invalid SBE size");

        // Update descriptor with deployed pointer and length
        descriptor.fixSBEPtr = sbePtr;
        descriptor.fixSBELen = uint32(sbeData.length);

        // Set descriptor using memory-compatible helper
        _setDescriptorMemory(descriptor);

        return sbePtr;
    }

    /**
     * @notice Set descriptor from memory (helper for deployment)
     * @dev Internal helper to set descriptor from memory struct
     *      Manually sets the descriptor fields since FixDescriptorLib.setDescriptor() expects calldata
     *      This is a workaround for the memory/calldata limitation when deploying SBE data
     * @param descriptor Descriptor struct in memory
     */
    function _setDescriptorMemory(IFixDescriptor.FixDescriptor memory descriptor) internal {
        // Manually set descriptor fields to work around memory/calldata conversion
        // We need to access the storage directly and set fields manually
        bytes32 oldRoot = _descriptor.descriptor.fixRoot;
        _descriptor.descriptor = descriptor;

        if (_descriptor.initialized) {
            emit IFixDescriptor.FixDescriptorUpdated(
                oldRoot,
                descriptor.fixRoot,
                descriptor.fixSBEPtr
            );
        } else {
            emit IFixDescriptor.FixDescriptorSet(
                descriptor.fixRoot,
                descriptor.dictHash,
                descriptor.fixSBEPtr,
                descriptor.fixSBELen
            );
            _descriptor.initialized = true;
        }
    }

    /**
     * @notice Initialize descriptor from constructor
     * @dev Called during constructor to initialize descriptor storage
     *      Bypasses access control since constructor caller is implicitly authorized
     *      If sbeData is provided, deploys it and updates descriptor pointer/length
     * @param sbeData Raw SBE-encoded data to deploy (empty bytes if not initializing)
     * @param descriptor Descriptor struct (fixSBEPtr and fixSBELen will be set if sbeData is provided)
     */
    function _initializeDescriptorFromConstructor(
        bytes memory sbeData,
        IFixDescriptor.FixDescriptor memory descriptor
    ) internal {
        address sbePtr = address(0);
        
        // If SBE data is provided, deploy it
        if (sbeData.length > 0) {
            sbePtr = _deploySBE(sbeData);
            
            // Verify deployment succeeded
            uint256 codeSize;
            assembly {
                codeSize := extcodesize(sbePtr)
            }
            require(codeSize == sbeData.length + 1, "FixDescriptorModule: Invalid SBE size");
            
            // Update descriptor with deployed pointer and length
            descriptor.fixSBEPtr = sbePtr;
            descriptor.fixSBELen = uint32(sbeData.length);
        }
        
        // Validate descriptor has required fields
        require(descriptor.fixRoot != bytes32(0), "FixDescriptorModule: Invalid descriptor root");
        
        // Set descriptor storage directly (will emit event)
        _setDescriptorMemory(descriptor);
    }

    /**
     * @notice Deploy data to a contract using SSTORE2 pattern
     * @dev Uses the same pattern as DataContractFactory - deploys data as contract bytecode
     *      Prepend STOP opcode (0x00) to prevent calls to the contract
     * @param data The data to store
     * @return ptr Address of the deployed data contract
     */
    function _deploySBE(bytes memory data) internal returns (address ptr) {
        // Prepend STOP opcode (0x00) to prevent calls to the contract
        bytes memory runtimeCode = abi.encodePacked(hex"00", data);

        // Create initialization code that returns the runtime code
        // Pattern from 0xSequence SSTORE2:
        // 0x63 - PUSH4 (size)
        // size - runtime code size (4 bytes)
        // 0x80 - DUP1
        // 0x60 0x0E - PUSH1 14 (offset where runtime code starts)
        // 0x60 0x00 - PUSH1 0 (memory destination)
        // 0x39 - CODECOPY
        // 0x60 0x00 - PUSH1 0 (offset in memory to return from)
        // 0xF3 - RETURN
        bytes memory creationCode = abi.encodePacked(
            hex"63",
            uint32(runtimeCode.length),
            hex"80600e6000396000f3",
            runtimeCode
        );

        assembly {
            ptr := create(0, add(creationCode, 0x20), mload(creationCode))
        }

        require(ptr != address(0), "FixDescriptorModule: Deployment failed");
    }
}
