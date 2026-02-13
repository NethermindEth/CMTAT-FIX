// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* ==== OpenZeppelin === */
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
/* ==== FixDescriptorKit === */
import "@fixdescriptorkit/contracts/src/IFixDescriptor.sol";
/* ==== FixEngine === */
import "./interfaces/IFixDescriptorEngine.sol";

/**
 * @title FixDescriptorEngineModule
 * @notice CMTAT module for integrating FixDescriptorEngine with CMTAT tokens
 * @dev Provides standard way to store and reference a FixDescriptorEngine for tokens
 *      Following the SnapshotEngineModule pattern - only stores/exposes engine address
 *      Uses ERC-7201 namespaced storage to avoid conflicts
 *      Users should call engine functions directly, not through this module
 */
abstract contract FixDescriptorEngineModule is Initializable {
    /* ============ ERC-7201 ============ */
    // keccak256(abi.encode(uint256(keccak256("CMTAT.storage.FixDescriptorEngineModule")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant FixDescriptorEngineModuleStorageLocation = 0xc09aa28957960c2b82e3fad477567fe122f23bca69560181151331ec7041c600;

    /* ==== ERC-7201 State Variables === */
    struct FixDescriptorEngineModuleStorage {
        address _fixDescriptorEngine;
    }

    /// @notice Role for setting descriptor engine
    bytes32 public constant DESCRIPTOR_ENGINE_ROLE = keccak256("DESCRIPTOR_ENGINE_ROLE");

    /// @notice Emitted when descriptor engine is set
    event FixDescriptorEngineSet(address indexed engine);

    /**
     * @notice Initialize the FixDescriptorEngineModule
     * @dev Should be called during CMTAT initialization
     * @param engine_ Address of the FixDescriptorEngine contract (can be address(0))
     */
    function __FixDescriptorEngineModule_init_unchained(address engine_)
        internal
        virtual
        onlyInitializing
    {
        if (engine_ != address(0)) {
            FixDescriptorEngineModuleStorage storage $ = _getFixDescriptorEngineModuleStorage();
            $._fixDescriptorEngine = engine_;
        }
    }

    /**
     * @notice Set the FIX descriptor engine address
     * @dev Can only be called by authorized roles
     *      Reverts if setting the same engine address
     * @param engine Address of the FixDescriptorEngine contract
     */
    function setFixDescriptorEngine(address engine) external virtual {
        _authorizeSetDescriptorEngine();
        FixDescriptorEngineModuleStorage storage $ = _getFixDescriptorEngineModuleStorage();
        require($._fixDescriptorEngine != engine, "FixDescriptorEngineModule: Same engine");
        $._fixDescriptorEngine = engine;
        emit FixDescriptorEngineSet(engine);
    }

    /**
     * @notice Authorize descriptor engine setting operation
     * @dev Override this function to implement access control
     *      Should use CMTAT's AccessControl system
     */
    function _authorizeSetDescriptorEngine() internal virtual;

    /**
     * @notice Get the descriptor engine address
     * @dev Implements IFixDescriptor.getDescriptorEngine() for interface compatibility
     *      Returns address(0) if engine is not set
     * @return engine Address of the FixDescriptorEngine contract, or address(0) if not set
     */
    function getDescriptorEngine() external view virtual returns (address engine) {
        FixDescriptorEngineModuleStorage storage $ = _getFixDescriptorEngineModuleStorage();
        return $._fixDescriptorEngine;
    }

    /**
     * @notice Get the FIX descriptor engine address (internal view)
     * @return engine Address of the FixDescriptorEngine contract, or address(0) if not set
     */
    function fixDescriptorEngine() public view returns (address engine) {
        FixDescriptorEngineModuleStorage storage $ = _getFixDescriptorEngineModuleStorage();
        return $._fixDescriptorEngine;
    }

    /* ============ ERC-7201 ============ */
    function _getFixDescriptorEngineModuleStorage()
        private
        pure
        returns (FixDescriptorEngineModuleStorage storage $)
    {
        assembly {
            $.slot := FixDescriptorEngineModuleStorageLocation
        }
    }
}
