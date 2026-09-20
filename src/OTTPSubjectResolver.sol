// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { IEAS } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import { Attestation } from "@ethereum-attestation-service/eas-contracts/contracts/Common.sol";
import { SchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";

import { IOTTPRegistry } from "./IOTTPRegistry.sol";

/// @title OTTPSubjectResolver
/// @notice EAS resolver for the OTTP Subject schema. Validates that the attester owns the claimed `ottpId`.
/// @dev Schema: `uint256 ottpId, string name, string metadata`. Registered with revocable = false.
///      Authenticity only, never authority: this contract never reads `name` or `metadata`.
///      Delegated attestations (attestByDelegation) arrive with `attestation.attester` = the signer, so direct and
///      delegated attestations are validated identically. Stateless and immutable.
contract OTTPSubjectResolver is SchemaResolver {
    /// @notice The OTTP Registry this resolver validates against.
    IOTTPRegistry public immutable registry;

    /// @param eas The EAS contract (Base predeploy 0x4200000000000000000000000000000000000021).
    /// @param _registry The OTTPRegistry.
    constructor(IEAS eas, IOTTPRegistry _registry) SchemaResolver(eas) {
        require(address(_registry) != address(0), "Zero registry");
        registry = _registry;
    }

    /// @dev Decode the typed `ottpId`, reject 0, and require the attester to be its current wallet.
    ///      Malformed data reverts at abi.decode, which correctly rejects the attestation.
    ///      `getWallet` on an unissued ID returns address(0), which can never equal an attester.
    function onAttest(
        Attestation calldata attestation,
        uint256 /* value */
    )
        internal
        view
        override
        returns (bool)
    {
        (uint256 ottpId,,) = abi.decode(attestation.data, (uint256, string, string));
        require(ottpId != 0, "OTTP: id is zero");
        // Unissued IDs map to address(0). The explicit non-zero check makes the guarantee independent of EAS
        // internals (EAS never yields a zero attester today, but this resolver is immutable).
        address owner = registry.getWallet(ottpId);
        require(owner != address(0) && attestation.attester == owner, "OTTP: attester does not own this id");
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
