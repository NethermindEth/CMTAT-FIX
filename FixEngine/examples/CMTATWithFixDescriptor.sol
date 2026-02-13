// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* ==== CMTAT === */
import {CMTATBaseRuleEngine} from "../../CMTAT/contracts/modules/1_CMTATBaseRuleEngine.sol";
/* ==== FixEngine === */
import {FixDescriptorEngineModule} from "../FixDescriptorEngineModule.sol";
import {IFixDescriptorEngine} from "../interfaces/IFixDescriptorEngine.sol";
/* ==== FixDescriptorKit === */
import {IFixDescriptor} from "@fixdescriptorkit/contracts/src/IFixDescriptor.sol";

/**
 * @title CMTATWithFixDescriptor
 * @notice CMTAT token contract with integrated FIX descriptor support via FixDescriptorEngine
 * @dev This contract demonstrates how to integrate FixDescriptorEngine with CMTAT tokens
 *      The contract forwards IFixDescriptor calls to the bound FixDescriptorEngine
 *      
 *      Usage:
 *      1. Deploy FixDescriptorEngine bound to this token
 *      2. Call setFixDescriptorEngine() to link the engine
 *      3. Use setFixDescriptorWithSBE() on the engine to deploy SBE data and set descriptor
 *      4. Query descriptor information via IFixDescriptor interface functions
 * 
 * @custom:example
 * ```solidity
 * // Deploy the CMTAT token
 * CMTATWithFixDescriptor token = new CMTATWithFixDescriptor();
 * token.initialize(admin, erc20Attrs, extraInfo, engines);
 * 
 * // Deploy FixDescriptorEngine bound to the token
 * FixDescriptorEngine engine = new FixDescriptorEngine(address(token), admin);
 * 
 * // Link the engine to the token
 * token.setFixDescriptorEngine(address(engine));
 * 
 * // Deploy SBE data and set descriptor in one transaction
 * bytes memory sbeData = hex"..."; // Your SBE-encoded FIX descriptor
 * IFixDescriptor.FixDescriptor memory descriptor = IFixDescriptor.FixDescriptor({
 *     fixMajor: 4,
 *     fixMinor: 4,
 *     dictHash: keccak256("dictionary"),
 *     fixRoot: merkleRoot,
 *     fixSBEPtr: address(0), // Will be set automatically
 *     fixSBELen: 0,          // Will be set automatically
 *     schemaURI: "ipfs://..."
 * });
 * engine.setFixDescriptorWithSBE(sbeData, descriptor);
 * 
 * // Now query descriptor via token interface
 * IFixDescriptor.FixDescriptor memory desc = token.getFixDescriptor();
 * bytes32 root = token.getFixRoot();
 * ```
 */
contract CMTATWithFixDescriptor is
    CMTATBaseRuleEngine,
    FixDescriptorEngineModule,
    IFixDescriptor
{
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Disable the possibility to initialize the implementation
        _disableInitializers();
    }

    /*//////////////////////////////////////////////////////////////
                        IFixDescriptor IMPLEMENTATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the complete FIX descriptor for this token
     * @dev Forwards call to the bound FixDescriptorEngine
     * @return descriptor The FixDescriptor struct
     */
    function getFixDescriptor() 
        external 
        view 
        override 
        returns (IFixDescriptor.FixDescriptor memory descriptor) 
    {
        address engine = fixDescriptorEngine();
        require(engine != address(0), "CMTATWithFixDescriptor: Engine not set");
        return IFixDescriptorEngine(engine).getFixDescriptor();
    }

    /**
     * @notice Get the Merkle root commitment for this token
     * @dev Forwards call to the bound FixDescriptorEngine
     * @return root The fixRoot for verification
     */
    function getFixRoot() external view override returns (bytes32 root) {
        address engine = fixDescriptorEngine();
        require(engine != address(0), "CMTATWithFixDescriptor: Engine not set");
        return IFixDescriptorEngine(engine).getFixRoot();
    }

    /**
     * @notice Verify a specific field against the committed descriptor
     * @dev Forwards call to the bound FixDescriptorEngine
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
        address engine = fixDescriptorEngine();
        require(engine != address(0), "CMTATWithFixDescriptor: Engine not set");
        return IFixDescriptorEngine(engine).verifyField(pathSBE, value, proof, directions);
    }

    /**
     * @notice Get SBE data chunk from SSTORE2 storage
     * @dev Forwards call to the bound FixDescriptorEngine
     * @param start Start offset (in the data, not including STOP byte)
     * @param size Number of bytes to read
     * @return chunk The requested SBE data
     */
    function getFixSBEChunk(
        uint256 start,
        uint256 size
    ) external view returns (bytes memory chunk) {
        address engine = fixDescriptorEngine();
        require(engine != address(0), "CMTATWithFixDescriptor: Engine not set");
        return IFixDescriptorEngine(engine).getFixSBEChunk(start, size);
    }

    /**
     * @notice Get the descriptor engine address
     * @dev Implements IFixDescriptor.getDescriptorEngine()
     * @return engine Address of the FixDescriptorEngine contract, or address(0) if not set
     */
    function getDescriptorEngine() external view override(FixDescriptorEngineModule, IFixDescriptor) returns (address engine) {
        return fixDescriptorEngine();
    }

    /**
     * @notice Authorize descriptor engine setting operation
     * @dev Uses CMTAT's AccessControl system
     *      Matches CMTAT pattern: _authorize* functions use onlyRole modifier
     */
    function _authorizeSetDescriptorEngine() internal virtual override onlyRole(DESCRIPTOR_ENGINE_ROLE) {
        // Nothing to do - access control handled by onlyRole modifier
    }

    /*//////////////////////////////////////////////////////////////
                        ERC165 SUPPORT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Query if a contract implements an interface
     * @dev Supports ERC165 and IFixDescriptor interface IDs
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return True if the contract implements the interface
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override
        returns (bool)
    {
        return 
            interfaceId == type(IFixDescriptor).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Convenience function to set descriptor with SBE data via engine
     * @dev This is a convenience wrapper that calls the engine's setFixDescriptorWithSBE
     *      Requires DESCRIPTOR_ADMIN_ROLE on the engine (not this contract)
     *      The caller must have DESCRIPTOR_ADMIN_ROLE on the FixDescriptorEngine
     * @param sbeData Raw SBE-encoded data to deploy
     * @param descriptor Descriptor struct (fixSBEPtr and fixSBELen will be set automatically)
     * @return sbePtr Address of the deployed SBE data contract
     */
    function setDescriptorWithSBE(
        bytes memory sbeData,
        IFixDescriptor.FixDescriptor memory descriptor
    ) external returns (address sbePtr) {
        address engine = fixDescriptorEngine();
        require(engine != address(0), "CMTATWithFixDescriptor: Engine not set");
        return IFixDescriptorEngine(engine).setFixDescriptorWithSBE(sbeData, descriptor);
    }

    /**
     * @notice Convenience function to set descriptor via engine (for pre-deployed SBE data)
     * @dev This is a convenience wrapper that calls the engine's setFixDescriptor
     *      Requires DESCRIPTOR_ADMIN_ROLE on the engine (not this contract)
     *      The caller must have DESCRIPTOR_ADMIN_ROLE on the FixDescriptorEngine
     * @param descriptor The complete FixDescriptor struct (with fixSBEPtr already set)
     */
    function setDescriptor(IFixDescriptor.FixDescriptor calldata descriptor) external {
        address engine = fixDescriptorEngine();
        require(engine != address(0), "CMTATWithFixDescriptor: Engine not set");
        IFixDescriptorEngine(engine).setFixDescriptor(descriptor);
    }
}
