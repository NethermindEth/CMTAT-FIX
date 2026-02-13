// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@fixdescriptorkit/contracts/src/IFixDescriptor.sol";
import "./FixDescriptorModule.sol";

/**
 * @title FixDescriptorDeploymentModule
 * @notice Module for deploying SBE data using SSTORE2 pattern
 * @dev Handles deployment of SBE-encoded data to contract bytecode storage
 *      Uses the same SSTORE2 pattern as DataContractFactory
 *      This module extends FixDescriptorModule to provide deployment functionality
 */
abstract contract FixDescriptorDeploymentModule is FixDescriptorModule {
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
        require(codeSize == sbeData.length + 1, "FixDescriptorDeploymentModule: Invalid SBE size");

        // Update descriptor with deployed pointer and length
        descriptor.fixSBEPtr = sbePtr;
        descriptor.fixSBELen = uint32(sbeData.length);

        // Set descriptor using memory-compatible helper
        _setDescriptorMemory(descriptor);

        return sbePtr;
    }

    /**
     * @notice Set descriptor from memory (helper for deployment module)
     * @dev Internal helper to set descriptor from memory struct
     *      Manually sets the descriptor fields since FixDescriptorLib expects calldata
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
            require(codeSize == sbeData.length + 1, "FixDescriptorDeploymentModule: Invalid SBE size");
            
            // Update descriptor with deployed pointer and length
            descriptor.fixSBEPtr = sbePtr;
            descriptor.fixSBELen = uint32(sbeData.length);
        }
        
        // Validate descriptor has required fields
        require(descriptor.fixRoot != bytes32(0), "FixDescriptorDeploymentModule: Invalid descriptor root");
        
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

        require(ptr != address(0), "FixDescriptorDeploymentModule: Deployment failed");
    }
}
