// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IEAS } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import { Attestation } from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { SchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";

import { IOTTPRegistry } from "./IOTTPRegistry.sol";

/// @title OTTPObjectResolver
/// @notice EAS resolver for the OTTP Object schema. Validates that the attester owns the claimed `creatorId`.
/// @dev Schema: `bytes32 originUid, uint256 creatorId, string metadata`. Registered with revocable = false.
///      Authenticity only, never authority: this contract never reads `originUid` or `metadata`; origin/ownership
///      semantics are derived offchain per the OTTP indexer rules (O-1, O-2). Stateless and immutable.
contract OTTPObjectResolver is SchemaResolver {
    /// @notice The OTTP Registry this resolver validates against.
    IOTTPRegistry public immutable registry;

    /// @param eas The EAS contract (Base predeploy 0x4200000000000000000000000000000000000021).
    /// @param _registry The OTTPRegistry.
    constructor(IEAS eas, IOTTPRegistry _registry) SchemaResolver(eas) {
        require(address(_registry) != address(0), "Zero registry");
        registry = _registry;
    }

    /// @dev Decode the typed `creatorId`, reject 0, and require the attester to be its current wallet.
    function onAttest(
        Attestation calldata attestation,
        uint256 /* value */
    )
        internal
        view
        override
        returns (bool)
    {
        (, uint256 creatorId,) = abi.decode(attestation.data, (bytes32, uint256, string));
        require(creatorId != 0, "OTTP: creator id is zero");
        require(attestation.attester == registry.getWallet(creatorId), "OTTP: attester does not own this id");
        return true;
    }

    /// @dev The schema is registered revocable = false, so EAS reverts revocations in core before reaching this.
    ///      Deny as defense-in-depth: returning false makes EAS revert the revocation.
    function onRevoke(
        Attestation calldata,
        /* attestation */
        uint256 /* value */
    )
        internal
        pure
        override
        returns (bool)
    {
        return false;
    }
}
