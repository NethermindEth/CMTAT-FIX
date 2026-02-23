// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import "./interfaces/IFixDescriptorEngine.sol";
import "./modules/FixDescriptorModule.sol";
import "./modules/VersionModule.sol";

/**
 * @title FixDescriptorEngine
 * @notice Engine contract for managing FIX descriptor for a single bound token
 * @dev One engine instance is bound to one token at construction time
 */
contract FixDescriptorEngine is FixDescriptorModule, VersionModule, AccessControl, IFixDescriptorEngine {
    /// @notice Role for setting descriptors
    bytes32 public constant DESCRIPTOR_ADMIN_ROLE = keccak256("DESCRIPTOR_ADMIN_ROLE");

    /// @notice The token this engine is bound to
    address public immutable token;

    /**
     * @notice Restricts descriptor writes to engine admins or the bound token contract.
     * @dev The bound token path is used for role-gated forwarding functions on the token.
     */
    modifier onlyDescriptorAdminOrToken() {
        require(
            msg.sender == token || hasRole(DESCRIPTOR_ADMIN_ROLE, msg.sender),
            "FixDescriptorEngine: Missing descriptor admin role"
        );
        _;
    }

    /**
     * @notice Constructor
     * @param token_ Address of the token contract this engine will manage
     * @param admin Address to grant DEFAULT_ADMIN_ROLE
     * @param sbeData_ Optional SBE-encoded data to deploy and initialize descriptor
     * @param descriptor_ Optional descriptor struct to initialize
     */
    constructor(address token_, address admin, bytes memory sbeData_, IFixDescriptor.FixDescriptor memory descriptor_) {
        require(token_ != address(0), "FixDescriptorEngine: Invalid token address");
        require(admin != address(0), "FixDescriptorEngine: Invalid admin address");
        token = token_;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);

        if (sbeData_.length > 0 && descriptor_.fixRoot != bytes32(0)) {
            _initializeDescriptorFromConstructor(sbeData_, descriptor_);
        } else if (descriptor_.fixRoot != bytes32(0)) {
            _initializeDescriptorFromConstructor("", descriptor_);
        }
    }

    /**
     * @notice Returns `true` if `account` has been granted `role`
     * @dev Default Admin has all roles
     */
    function hasRole(bytes32 role, address account) public view virtual override(AccessControl) returns (bool) {
        if (AccessControl.hasRole(DEFAULT_ADMIN_ROLE, account)) {
            return true;
        } else {
            return AccessControl.hasRole(role, account);
        }
    }

    /**
     * @notice Get the complete FIX descriptor for the bound token
     * @dev Implements IFixDescriptor.getFixDescriptor()
     * @return descriptor The FixDescriptor struct
     */
    function getFixDescriptor() external view returns (IFixDescriptor.FixDescriptor memory descriptor) {
        return _getDescriptor();
    }

    /**
     * @notice Get the Merkle root commitment for the bound token
     * @dev Implements IFixDescriptor.getFixRoot()
     * @return root The fixRoot for verification
     */
    function getFixRoot() external view returns (bytes32 root) {
        IFixDescriptor.FixDescriptor memory descriptor = _getDescriptor();
        return descriptor.fixRoot;
    }

    /**
     * @notice Verify a specific field against the committed descriptor for the bound token
     * @dev Implements IFixDescriptor.verifyField()
     * @param pathCBOR CBOR-encoded bytes of the field path
     * @param value Raw FIX value bytes
     * @param proof Merkle proof (sibling hashes)
     * @param directions Direction array (true=right child, false=left child)
     * @return valid True if the proof is valid
     */
    function verifyField(
        bytes calldata pathCBOR,
        bytes calldata value,
        bytes32[] calldata proof,
        bool[] calldata directions
    ) external view returns (bool valid) {
        return _verifyField(pathCBOR, value, proof, directions);
    }

    /**
     * @notice Get SBE data chunk from SSTORE2 storage for the bound token
     * @param start Start offset (in the data, not including STOP byte)
     * @param size Number of bytes to read
     * @return chunk The requested SBE data
     */
    function getFixSBEChunk(uint256 start, uint256 size) external view returns (bytes memory chunk) {
        return _getSBEChunk(start, size);
    }

    /**
     * @notice Set or update the FIX descriptor for the bound token
     * @param descriptor The complete FixDescriptor struct
     */
    function setFixDescriptor(IFixDescriptor.FixDescriptor calldata descriptor) external onlyDescriptorAdminOrToken {
        _setDescriptor(descriptor);
    }

    /**
     * @notice Deploy SBE data and set descriptor in one transaction
     * @param sbeData Raw SBE-encoded data to deploy
     * @param descriptor Descriptor struct (fixSBEPtr and fixSBELen will be set automatically)
     * @return sbePtr Address of the deployed SBE data contract
     */
    function setFixDescriptorWithSBE(bytes memory sbeData, IFixDescriptor.FixDescriptor memory descriptor)
        external
        onlyDescriptorAdminOrToken
        returns (address sbePtr)
    {
        return _deployAndSetDescriptor(sbeData, descriptor);
    }
}
