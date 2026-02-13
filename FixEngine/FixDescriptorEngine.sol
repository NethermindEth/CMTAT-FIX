// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import "./interfaces/IFixDescriptorEngine.sol";
import "./modules/FixDescriptorModule.sol";
import "./modules/VersionModule.sol";

/**
 * @title FixDescriptorEngine
 * @notice Engine contract for managing FIX descriptor for a single bound token
 * @dev Follows CMTAT engine pattern similar to SnapshotEngine
 *      One engine instance is bound to one token at construction time
 */
contract FixDescriptorEngine is
    FixDescriptorModule,
    VersionModule,
    AccessControl,
    IFixDescriptorEngine
{
    /// @notice Role for setting descriptors
    bytes32 public constant DESCRIPTOR_ADMIN_ROLE = keccak256("DESCRIPTOR_ADMIN_ROLE");

    /// @notice The token this engine is bound to
    address public immutable override token;

    /**
     * @notice Constructor
     * @param token_ Address of the token contract this engine will manage
     * @param admin Address to grant DEFAULT_ADMIN_ROLE
     * @param sbeData_ Optional SBE-encoded data to deploy and initialize descriptor (empty bytes if not initializing)
     * @param descriptor_ Optional descriptor struct to initialize (empty struct if not initializing)
     * @dev If both sbeData_ and descriptor_ are provided (non-empty), the descriptor will be initialized during construction.
     *      This allows the engine to be fully ready immediately after deployment.
     *      If sbeData_ is empty or descriptor_.fixRoot is zero, no initialization occurs (backward compatible).
     */
    constructor(
        address token_,
        address admin,
        bytes memory sbeData_,
        IFixDescriptor.FixDescriptor memory descriptor_
    ) {
        require(token_ != address(0), "FixDescriptorEngine: Invalid token address");
        require(admin != address(0), "FixDescriptorEngine: Invalid admin address");
        token = token_;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        
        // Initialize descriptor if both sbeData and descriptor are provided
        if (sbeData_.length > 0 && descriptor_.fixRoot != bytes32(0)) {
            _initializeDescriptorFromConstructor(sbeData_, descriptor_);
        } else if (descriptor_.fixRoot != bytes32(0)) {
            // If descriptor is provided but no SBE data, assume fixSBEPtr is already set
            // This allows initialization with pre-deployed SBE data
            _initializeDescriptorFromConstructor("", descriptor_);
        }
    }

    /**
     * @notice Returns `true` if `account` has been granted `role`
     * @dev Override to give Default Admin all roles (like SnapshotEngine)
     *      Matches SnapshotEngine pattern exactly
     * @param role The role identifier
     * @param account The account address
     * @return True if account has role
     */
    function hasRole(
        bytes32 role,
        address account
    ) public view virtual override(AccessControl) returns (bool) {
        // The Default Admin has all roles
        if (AccessControl.hasRole(DEFAULT_ADMIN_ROLE, account)) {
            return true;
        } else {
            return AccessControl.hasRole(role, account);
        }
    }

    /**
     * @notice Get the complete FIX descriptor for the bound token
     * @return descriptor The FixDescriptor struct
     */
    function getFixDescriptor() external view override returns (IFixDescriptor.FixDescriptor memory descriptor) {
        return _getDescriptor();
    }

    /**
     * @notice Get the Merkle root commitment for the bound token
     * @return root The fixRoot for verification
     */
    function getFixRoot() external view override returns (bytes32 root) {
        IFixDescriptor.FixDescriptor memory descriptor = _getDescriptor();
        return descriptor.fixRoot;
    }

    /**
     * @notice Verify a specific field against the committed descriptor for the bound token
     * @param pathSBE SBE-encoded bytes of the field path
     * @param value Raw FIX value bytes
     * @param proof Merkle proof (sibling hashes)
     * @param directions Direction array (true=right child, false=left child)
     * @return valid True if the proof is valid
     */
    function verifyField(
        bytes calldata pathSBE,
        bytes calldata value,
        bytes32[] calldata proof,
        bool[] calldata directions
    ) external view override returns (bool valid) {
        return _verifyField(pathSBE, value, proof, directions);
    }

    /**
     * @notice Get SBE data chunk from SSTORE2 storage for the bound token
     * @param start Start offset (in the data, not including STOP byte)
     * @param size Number of bytes to read
     * @return chunk The requested SBE data
     */
    function getFixSBEChunk(
        uint256 start,
        uint256 size
    ) external view override returns (bytes memory chunk) {
        return _getSBEChunk(start, size);
    }

    /**
     * @notice Set or update the FIX descriptor for the bound token
     * @dev Can only be called by authorized roles
     * @param descriptor The complete FixDescriptor struct
     */
    function setFixDescriptor(IFixDescriptor.FixDescriptor calldata descriptor) external override onlyRole(DESCRIPTOR_ADMIN_ROLE) {
        _setDescriptor(descriptor);
    }

    /**
     * @notice Deploy SBE data and set descriptor in one transaction
     * @dev Deploys SBE data using SSTORE2 pattern, then sets the descriptor
     *      This is a convenience function that combines deployment and descriptor setting
     * @param sbeData Raw SBE-encoded data to deploy
     * @param descriptor Descriptor struct (fixSBEPtr and fixSBELen will be set automatically)
     * @return sbePtr Address of the deployed SBE data contract
     */
    function setFixDescriptorWithSBE(
        bytes memory sbeData,
        IFixDescriptor.FixDescriptor memory descriptor
    ) external override onlyRole(DESCRIPTOR_ADMIN_ROLE) returns (address sbePtr) {
        return _deployAndSetDescriptor(sbeData, descriptor);
    }
}
